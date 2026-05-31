use crate::analysis::abi::{AbiRegisters, abi_registers};
use crate::analysis::functions::{Function, FunctionManager};
use crate::analysis::xrefs::{XrefManager, XrefType};
use crate::arch::Architecture;
use crate::debuginfo::DebugInfo;
use crate::disasm::Disassembler;
use crate::il::mlil::{MlilExpr, MlilFunction, MlilStmt, apply_ssa, lower_to_mlil};
use crate::il::ssa::{DefUse, Site, model_call_effects};
use crate::loader::{BinaryFormat, Import};
use crate::memory::MemoryMap;
use crate::typelib::TypeLibraryManager;
use crate::types::{
    FunctionParameter, FunctionSignature, PrimitiveType, SignatureSource, TypeManager, TypeRef,
};
use std::collections::BTreeMap;

/// Backstop on backward-inference rounds. Inference is monotonic and converges
/// in as many rounds as the longest resolvable call chain is deep; this cap
/// just bounds pathological inputs (real chains are shallow).
const MAX_INFERENCE_ROUNDS: usize = 8;

/// Type information inferred for a single function.
#[derive(Debug, Clone, Default)]
pub struct FunctionTypeInfo {
    pub signature: Option<FunctionSignature>,
    pub var_types: BTreeMap<String, TypeRef>,
}

/// Per-function IL prepared for interprocedural inference: MLIL with call ABI
/// effects modelled, its def-use index, and the ABI register layout used.
///
/// This bundles the Phase-1 building blocks — the arch lifter, MLIL lowering,
/// call-effect modelling, SSA, and the def-use index — into the single artifact
/// the type propagator consumes to follow values across calls.
pub struct FunctionIl {
    pub mlil: MlilFunction,
    pub defuse: DefUse,
    pub abi: AbiRegisters,
}

impl FunctionIl {
    /// Lift `func` and build its IL + def-use index. Returns `None` when the
    /// architecture's ABI is not modelled, the function can't be read, or it
    /// disassembles to nothing.
    pub fn build(
        memory: &MemoryMap,
        disasm: &Disassembler,
        arch: Architecture,
        format: BinaryFormat,
        func: &Function,
    ) -> Option<FunctionIl> {
        let abi = abi_registers(arch, func.calling_convention, format)?;
        let size = func
            .end_address
            .and_then(|end| end.checked_sub(func.start_address))
            .map(|s| s as usize)
            .unwrap_or(0x400)
            .clamp(1, 0x4000);
        let insns = disasm
            .disassemble_range(memory, func.start_address, size)
            .ok()?;
        if insns.is_empty() {
            return None;
        }
        let llil = crate::il::lift_function(arch, &func.name, func.start_address, &insns);
        let mut mlil = lower_to_mlil(&llil);
        // Make call ABI effects explicit, then version definitions, then index.
        model_call_effects(&mut mlil, abi.arg_regs, abi.ret_reg);
        apply_ssa(&mut mlil);
        let defuse = DefUse::build(&mlil);
        Some(FunctionIl { mlil, defuse, abi })
    }
}

/// Propagates type information across function call sites.
pub struct TypePropagator<'a> {
    functions: &'a FunctionManager,
    xrefs: &'a XrefManager,
    type_libs: &'a TypeLibraryManager,
    imports: &'a [Import],
    /// Per-function IL keyed by start address, when available. Backward
    /// (IL-based) inference uses it; seed/forward passes work without it.
    il: Option<&'a BTreeMap<u64, FunctionIl>>,
}

impl<'a> TypePropagator<'a> {
    pub fn new(
        functions: &'a FunctionManager,
        xrefs: &'a XrefManager,
        type_libs: &'a TypeLibraryManager,
        imports: &'a [Import],
    ) -> Self {
        Self {
            functions,
            xrefs,
            type_libs,
            imports,
            il: None,
        }
    }

    /// Attach per-function IL (built via [`FunctionIl::build`]) so the
    /// propagator can follow values across calls during backward inference.
    pub fn with_il(mut self, il: &'a BTreeMap<u64, FunctionIl>) -> Self {
        self.il = Some(il);
        self
    }

    /// The prepared IL for the function at `addr`, if attached.
    pub fn function_il(&self, addr: u64) -> Option<&FunctionIl> {
        self.il.and_then(|m| m.get(&addr))
    }

    /// Run type propagation and return inferred type info per function address.
    ///
    /// Algorithm:
    /// 1. **Seed** — use debug info signatures, then fall back to type library
    ///    lookup for imports.
    /// 2. **Forward propagation** — for each Call xref where the target has a
    ///    known signature, propagate parameter types to the call site.
    /// 3. **Backward propagation** — if a function's return value flows into a
    ///    typed context, infer its return type.
    pub fn propagate(
        &self,
        debug_info: &DebugInfo,
        types: &TypeManager,
    ) -> BTreeMap<u64, FunctionTypeInfo> {
        let mut result: BTreeMap<u64, FunctionTypeInfo> = BTreeMap::new();

        // === Pass 1: Seed ===
        for &addr in self.functions.functions.keys() {
            let mut info = FunctionTypeInfo::default();

            // Priority 1: debug info
            if let Some(sig) = debug_info.function_signatures.get(&addr) {
                info.signature = Some(sig.clone());
            }
            // Priority 2: existing type manager signatures
            else if let Some(sig) = types.function_signatures.get(&addr) {
                info.signature = Some(sig.clone());
            }
            // Priority 3: import name → type library lookup
            else if let Some(import_name) = self.find_import_name(addr)
                && let Some(lib_sig) = self.type_libs.resolve_function(&import_name)
            {
                info.signature = Some(lib_sig.clone());
            }
            // Priority 4: function name → type library lookup
            else if let Some(func) = self.functions.functions.get(&addr)
                && !func.name.starts_with("sub_")
                && let Some(lib_sig) = self.type_libs.resolve_function(&func.name)
            {
                info.signature = Some(lib_sig.clone());
            }

            if info.signature.is_some() {
                result.insert(addr, info);
            }
        }

        // === Pass 2: Forward propagation ===
        // For each call xref where the target has a known signature,
        // record the signature for the call site's caller function.
        for (&to_addr, xrefs) in &self.xrefs.to_address_xrefs {
            let target_sig = result.get(&to_addr).and_then(|i| i.signature.clone());
            if let Some(sig) = target_sig {
                for xref in xrefs {
                    if xref.xref_type != XrefType::Call {
                        continue;
                    }
                    let caller_addr = self.find_containing_function(xref.from_address);
                    if let Some(caller) = caller_addr {
                        let caller_info = result.entry(caller).or_default();
                        // Store the called function's parameter types as variable hints
                        // at the call site
                        for (i, param) in sig.parameters.iter().enumerate() {
                            let var_name = format!("call_{:x}_arg{}", xref.from_address, i);
                            caller_info
                                .var_types
                                .insert(var_name, param.type_ref.clone());
                        }
                        // Store the return type
                        let ret_var = format!("call_{:x}_ret", xref.from_address);
                        caller_info
                            .var_types
                            .insert(ret_var, sig.return_type.clone());
                    }
                }
            }
        }

        // === Pass 3: Backward IL-based inference, iterated to a fixpoint ===
        // Following values across calls, infer an untyped function's return
        // type (its result flows into a typed callee's argument) and its
        // parameter types (a typed value flows into its arguments). Each round
        // can type new functions, which become evidence for the next round
        // (resolving a call chain one hop deeper). Inference is monotonic —
        // signatures are only ever added, never changed — so it converges;
        // `MAX_INFERENCE_ROUNDS` is a backstop. A no-op without IL (`with_il`).
        for _ in 0..MAX_INFERENCE_ROUNDS {
            let ret_types = self.infer_return_types(&result);
            let param_types = self.infer_param_types(&result);
            let targets: std::collections::BTreeSet<u64> = ret_types
                .keys()
                .chain(param_types.keys())
                .copied()
                .collect();
            let mut changed = false;
            for addr in targets {
                if result
                    .get(&addr)
                    .and_then(|i| i.signature.as_ref())
                    .is_some()
                {
                    continue; // never override a seeded/forward/already-inferred signature
                }
                let ret = ret_types.get(&addr).cloned();
                let params = param_types.get(&addr).cloned().unwrap_or_default();
                if ret.is_none() && params.is_empty() {
                    continue;
                }
                let name = self
                    .functions
                    .functions
                    .get(&addr)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("sub_{:x}", addr));
                let parameters = params
                    .into_iter()
                    .enumerate()
                    .map(|(i, type_ref)| FunctionParameter {
                        name: format!("arg{}", i),
                        type_ref,
                    })
                    .collect();
                result.entry(addr).or_default().signature = Some(FunctionSignature {
                    name,
                    // `Void` is this codebase's "unknown" placeholder when only
                    // the parameters could be recovered.
                    return_type: ret.unwrap_or(TypeRef::Primitive(PrimitiveType::Void)),
                    parameters,
                    calling_convention: String::new(),
                    is_variadic: false,
                    source: SignatureSource::Inferred,
                });
                changed = true;
            }
            if !changed {
                break; // fixpoint reached
            }
        }

        result
    }

    /// Backward return-type inference over the attached IL.
    ///
    /// For each caller's IL, find the pattern `g_ret = call G; arg = g_ret;
    /// call H(arg, …)` where `H` already has a signature: the return value of
    /// the (untyped) `G` is passed into a typed parameter of `H`, so `G`'s
    /// return type is that parameter's type. Candidates are unified across all
    /// call sites — a value is committed only when every site agrees.
    ///
    /// Uses [`DefUse::reaching_def`], a single-path approximation, so the
    /// cross-site unification is the safeguard against control-flow surprises.
    fn infer_return_types(
        &self,
        result: &BTreeMap<u64, FunctionTypeInfo>,
    ) -> BTreeMap<u64, TypeRef> {
        let Some(il_map) = self.il else {
            return BTreeMap::new();
        };
        let mut candidates: BTreeMap<u64, Vec<TypeRef>> = BTreeMap::new();

        for il in il_map.values() {
            let ret_reg = il.abi.ret_reg;
            let arg_regs = il.abi.arg_regs;
            for (inst_index, inst) in il.mlil.instructions.iter().enumerate() {
                for (stmt_index, stmt) in inst.stmts.iter().enumerate() {
                    // A call to a function H that already has a signature.
                    let Some(h_addr) = call_target(stmt) else {
                        continue;
                    };
                    let Some(h_sig) = result.get(&h_addr).and_then(|i| i.signature.as_ref()) else {
                        continue;
                    };
                    let call_site = Site {
                        inst_index,
                        stmt_index,
                        address: inst.address,
                    };
                    for (k, param) in h_sig.parameters.iter().enumerate() {
                        let Some(&arg_reg) = arg_regs.get(k) else {
                            break; // beyond register-passed arguments
                        };
                        // The value in arg_reg at this call came from a copy of
                        // the return register, which was defined by a call to G.
                        let Some(def_site) = il.defuse.reaching_def(arg_reg, call_site) else {
                            continue;
                        };
                        if !is_copy_from(stmt_at(il, def_site), arg_reg, ret_reg) {
                            continue;
                        }
                        let Some(call_g_site) = il.defuse.reaching_def(ret_reg, def_site) else {
                            continue;
                        };
                        if let Some(g_addr) = call_defining(stmt_at(il, call_g_site), ret_reg) {
                            candidates
                                .entry(g_addr)
                                .or_default()
                                .push(param.type_ref.clone());
                        }
                    }
                }
            }
        }

        // Commit only callees that are untyped and whose evidence is unanimous.
        let mut inferred = BTreeMap::new();
        for (g_addr, types) in candidates {
            if result
                .get(&g_addr)
                .and_then(|i| i.signature.as_ref())
                .is_some()
            {
                continue;
            }
            let first = &types[0];
            if types.iter().all(|t| t == first) {
                inferred.insert(g_addr, first.clone());
            }
        }
        inferred
    }

    /// Backward parameter-type inference over the attached IL.
    ///
    /// The mirror of [`Self::infer_return_types`]: when a typed value (here, the
    /// return value of a call to an already-typed function `H`) is moved into an
    /// argument register and passed to an untyped function `G`, that register's
    /// slot gives `G`'s parameter type. Candidates are unified per `(callee,
    /// slot)`; only a contiguous prefix of agreed-upon slots (arg0, arg1, …) is
    /// emitted, so no placeholder parameters are invented for gaps.
    fn infer_param_types(
        &self,
        result: &BTreeMap<u64, FunctionTypeInfo>,
    ) -> BTreeMap<u64, Vec<TypeRef>> {
        let Some(il_map) = self.il else {
            return BTreeMap::new();
        };
        // (callee addr, arg slot) -> candidate types.
        let mut candidates: BTreeMap<(u64, usize), Vec<TypeRef>> = BTreeMap::new();

        for il in il_map.values() {
            let ret_reg = il.abi.ret_reg;
            let arg_regs = il.abi.arg_regs;
            for (inst_index, inst) in il.mlil.instructions.iter().enumerate() {
                for (stmt_index, stmt) in inst.stmts.iter().enumerate() {
                    let Some(g_addr) = call_target(stmt) else {
                        continue;
                    };
                    let call_site = Site {
                        inst_index,
                        stmt_index,
                        address: inst.address,
                    };
                    for (k, &arg_reg) in arg_regs.iter().enumerate() {
                        let Some(def_site) = il.defuse.reaching_def(arg_reg, call_site) else {
                            continue;
                        };
                        if !is_copy_from(stmt_at(il, def_site), arg_reg, ret_reg) {
                            continue;
                        }
                        let Some(prod_site) = il.defuse.reaching_def(ret_reg, def_site) else {
                            continue;
                        };
                        if let Some(h_addr) = call_defining(stmt_at(il, prod_site), ret_reg)
                            && let Some(h_sig) =
                                result.get(&h_addr).and_then(|i| i.signature.as_ref())
                        {
                            candidates
                                .entry((g_addr, k))
                                .or_default()
                                .push(h_sig.return_type.clone());
                        }
                    }
                }
            }
        }

        // Unify each slot, then keep the contiguous prefix arg0, arg1, … .
        let mut per_slot: BTreeMap<u64, BTreeMap<usize, TypeRef>> = BTreeMap::new();
        for ((g_addr, slot), types) in candidates {
            let first = &types[0];
            if types.iter().all(|t| t == first) {
                per_slot
                    .entry(g_addr)
                    .or_default()
                    .insert(slot, first.clone());
            }
        }
        let mut out = BTreeMap::new();
        for (g_addr, slots) in per_slot {
            let mut params = Vec::new();
            let mut k = 0;
            while let Some(t) = slots.get(&k) {
                params.push(t.clone());
                k += 1;
            }
            if !params.is_empty() {
                out.insert(g_addr, params);
            }
        }
        out
    }

    /// Find the import name for a given address, if any.
    fn find_import_name(&self, addr: u64) -> Option<String> {
        self.imports
            .iter()
            .find(|imp| imp.address == addr)
            .map(|imp| imp.name.clone())
    }

    /// Find the function that contains a given address.
    fn find_containing_function(&self, addr: u64) -> Option<u64> {
        // Binary search for the function whose range includes addr
        for (&start, func) in self.functions.functions.iter().rev() {
            if addr >= start {
                if let Some(end) = func.end_address {
                    if addr < end {
                        return Some(start);
                    }
                } else {
                    return Some(start);
                }
            }
        }
        None
    }
}

/// The statement at `site` within a function's IL.
fn stmt_at(il: &FunctionIl, site: Site) -> Option<&MlilStmt> {
    il.mlil
        .instructions
        .get(site.inst_index)?
        .stmts
        .get(site.stmt_index)
}

/// If `stmt` is a (modelled) call to a direct target, return that address.
/// Calls are `Assign { src: Call { target: Const(addr), .. }, .. }` after
/// [`model_call_effects`].
fn call_target(stmt: &MlilStmt) -> Option<u64> {
    if let MlilStmt::Assign { src, .. } = stmt
        && let MlilExpr::Call { target, .. } = src
        && let MlilExpr::Const(addr) = target.as_ref()
    {
        return Some(*addr);
    }
    None
}

/// If `stmt` is a direct call that defines `ret_reg`, return the call target.
fn call_defining(stmt: Option<&MlilStmt>, ret_reg: &str) -> Option<u64> {
    let stmt = stmt?;
    if let MlilStmt::Assign { dest, .. } = stmt
        && dest.name == ret_reg
    {
        return call_target(stmt);
    }
    None
}

/// Whether `stmt` is `dest_reg = src_reg` (a plain register copy).
fn is_copy_from(stmt: Option<&MlilStmt>, dest_reg: &str, src_reg: &str) -> bool {
    matches!(
        stmt,
        Some(MlilStmt::Assign { dest, src: MlilExpr::Var(v) })
            if dest.name == dest_reg && v.name == src_reg
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::Function;
    use crate::analysis::xrefs::Xref;
    use crate::types::{FunctionParameter, PrimitiveType};

    #[test]
    fn seed_from_debug_info() {
        let mut functions = FunctionManager::default();
        functions.add_function(Function {
            name: "main".to_string(),
            start_address: 0x1000,
            end_address: Some(0x1100),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });

        let xrefs = XrefManager::new();
        let type_libs = TypeLibraryManager::default();
        let imports = vec![];

        let mut debug_info = DebugInfo::default();
        debug_info.function_signatures.insert(
            0x1000,
            FunctionSignature {
                name: "main".to_string(),
                return_type: TypeRef::Primitive(PrimitiveType::I32),
                parameters: vec![FunctionParameter {
                    name: "argc".to_string(),
                    type_ref: TypeRef::Primitive(PrimitiveType::I32),
                }],
                calling_convention: String::new(),
                is_variadic: false,
                source: SignatureSource::DebugInfo,
            },
        );

        let types = TypeManager::default();
        let propagator = TypePropagator::new(&functions, &xrefs, &type_libs, &imports);
        let result = propagator.propagate(&debug_info, &types);

        assert!(result.contains_key(&0x1000));
        let info = &result[&0x1000];
        assert_eq!(info.signature.as_ref().unwrap().name, "main");
    }

    #[test]
    fn seed_from_import_type_lib() {
        let mut functions = FunctionManager::default();
        functions.add_function(Function {
            name: "printf".to_string(),
            start_address: 0x2000,
            end_address: Some(0x2010),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });

        let xrefs = XrefManager::new();
        let mut type_libs = TypeLibraryManager::default();
        type_libs.load_for_platform("linux_x86_64");

        let imports = vec![Import {
            name: "printf".to_string(),
            library: "libc.so.6".to_string(),
            address: 0x2000,
        }];

        let debug_info = DebugInfo::default();
        let types = TypeManager::default();
        let propagator = TypePropagator::new(&functions, &xrefs, &type_libs, &imports);
        let result = propagator.propagate(&debug_info, &types);

        assert!(result.contains_key(&0x2000));
        let sig = result[&0x2000].signature.as_ref().unwrap();
        assert_eq!(sig.name, "printf");
        assert!(sig.is_variadic);
    }

    #[test]
    fn forward_propagation_at_call_site() {
        let mut functions = FunctionManager::default();
        functions.add_function(Function {
            name: "main".to_string(),
            start_address: 0x1000,
            end_address: Some(0x1100),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });
        functions.add_function(Function {
            name: "printf".to_string(),
            start_address: 0x2000,
            end_address: Some(0x2010),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });

        let mut xrefs = XrefManager::new();
        xrefs.add_xref(Xref {
            from_address: 0x1050,
            to_address: 0x2000,
            xref_type: XrefType::Call,
        });

        let mut type_libs = TypeLibraryManager::default();
        type_libs.load_for_platform("linux_x86_64");

        let imports = vec![Import {
            name: "printf".to_string(),
            library: "libc.so.6".to_string(),
            address: 0x2000,
        }];

        let debug_info = DebugInfo::default();
        let types = TypeManager::default();
        let propagator = TypePropagator::new(&functions, &xrefs, &type_libs, &imports);
        let result = propagator.propagate(&debug_info, &types);

        // main should have var_types populated from the printf call
        assert!(result.contains_key(&0x1000));
        let main_info = &result[&0x1000];
        assert!(main_info.var_types.contains_key("call_1050_arg0"));
    }

    #[test]
    fn function_il_build_models_calls() {
        use crate::analysis::functions::CallingConvention;
        use crate::arch::Architecture;
        use crate::memory::{MemorySegment, Permissions};

        // call 0x1005; mov rbx, rax; ret  (x86-64)
        let mut code = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call (rel32=0 -> 0x1005)
            0x48, 0x89, 0xC3, // mov rbx, rax
            0xC3, // ret
        ];
        code.resize(0x40, 0x00);
        let mut memory = MemoryMap::default();
        memory
            .add_segment(MemorySegment {
                name: "code".to_string(),
                start: 0x1000,
                size: code.len() as u64,
                data: code,
                permissions: Permissions::READ | Permissions::EXECUTE,
            })
            .unwrap();

        let func = Function {
            name: "f".to_string(),
            start_address: 0x1000,
            end_address: Some(0x1009),
            calling_convention: CallingConvention::SysVAmd64,
            stack_frame_size: 0,
        };
        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let il = FunctionIl::build(
            &memory,
            &disasm,
            Architecture::X86_64,
            BinaryFormat::Elf,
            &func,
        )
        .expect("IL should build for x86-64");

        // The call defines the return register (rax) at the call site...
        assert_eq!(il.defuse.defs_of("rax")[0].address, 0x1000);
        // ...uses the first SysV argument register there...
        assert_eq!(il.defuse.uses_of("rdi")[0].address, 0x1000);
        // ...and the post-call `mov rbx, rax` use is reached by that definition.
        let rax_use = il.defuse.uses_of("rax")[0];
        assert_eq!(
            il.defuse.reaching_def("rax", rax_use).unwrap().address,
            0x1000
        );
    }

    #[test]
    fn with_il_exposes_function_il() {
        use crate::analysis::functions::CallingConvention;
        use crate::arch::Architecture;
        use crate::memory::{MemorySegment, Permissions};

        let mut functions = FunctionManager::default();
        functions.add_function(Function {
            name: "f".to_string(),
            start_address: 0x1000,
            end_address: Some(0x1009),
            calling_convention: CallingConvention::SysVAmd64,
            stack_frame_size: 0,
        });
        let xrefs = XrefManager::new();
        let type_libs = TypeLibraryManager::default();
        let imports: Vec<Import> = vec![];

        let mut code = vec![0xC3u8]; // ret
        code.resize(0x40, 0x00);
        let mut memory = MemoryMap::default();
        memory
            .add_segment(MemorySegment {
                name: "code".to_string(),
                start: 0x1000,
                size: code.len() as u64,
                data: code,
                permissions: Permissions::READ | Permissions::EXECUTE,
            })
            .unwrap();
        let disasm = Disassembler::new(Architecture::X86_64).unwrap();

        let mut il_map = BTreeMap::new();
        let func = functions.get_function(0x1000).unwrap();
        il_map.insert(
            0x1000,
            FunctionIl::build(
                &memory,
                &disasm,
                Architecture::X86_64,
                BinaryFormat::Elf,
                func,
            )
            .unwrap(),
        );

        let propagator =
            TypePropagator::new(&functions, &xrefs, &type_libs, &imports).with_il(&il_map);
        assert!(propagator.function_il(0x1000).is_some());
        assert!(propagator.function_il(0x9999).is_none());
    }

    #[test]
    fn backward_infers_return_type_from_typed_arg() {
        use crate::analysis::abi::abi_registers;
        use crate::analysis::functions::CallingConvention;
        use crate::arch::Architecture;
        use crate::il::mlil::{MlilExpr, MlilInst, MlilStmt, SsaVar};
        use crate::il::ssa::DefUse;

        let var = |n: &str| SsaVar {
            name: n.to_string(),
            version: 0,
        };
        let call = |addr: u64, args: Vec<MlilExpr>| MlilExpr::Call {
            target: Box::new(MlilExpr::Const(addr)),
            args,
        };

        // Caller C @0x1000:
        //   rax = G()        ; G @0x4000 (untyped)
        //   rdi = rax        ; move return value into the first arg register
        //   rax = H(rdi)     ; H @0x5000 (typed: param0 = char*)
        let mlil = MlilFunction {
            name: "C".to_string(),
            entry: 0x1000,
            instructions: vec![
                MlilInst {
                    address: 0x1000,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(0x4000, vec![]),
                    }],
                },
                MlilInst {
                    address: 0x1004,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rdi"),
                        src: MlilExpr::Var(var("rax")),
                    }],
                },
                MlilInst {
                    address: 0x1008,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(0x5000, vec![MlilExpr::Var(var("rdi"))]),
                    }],
                },
            ],
        };
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::SysVAmd64,
            BinaryFormat::Elf,
        )
        .unwrap();
        let defuse = DefUse::build(&mlil);
        let mut il_map = BTreeMap::new();
        il_map.insert(0x1000, FunctionIl { mlil, defuse, abi });

        let mut functions = FunctionManager::default();
        for (a, name) in [(0x1000u64, "C"), (0x4000, "sub_4000"), (0x5000, "use_str")] {
            functions.add_function(Function {
                name: name.to_string(),
                start_address: a,
                end_address: None,
                calling_convention: CallingConvention::SysVAmd64,
                stack_frame_size: 0,
            });
        }
        let xrefs = XrefManager::new();
        let type_libs = TypeLibraryManager::default();
        let imports: Vec<Import> = vec![];

        let char_ptr = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Char)));
        let mut debug_info = DebugInfo::default();
        debug_info.function_signatures.insert(
            0x5000,
            FunctionSignature {
                name: "use_str".to_string(),
                return_type: TypeRef::Primitive(PrimitiveType::I32),
                parameters: vec![FunctionParameter {
                    name: "s".to_string(),
                    type_ref: char_ptr.clone(),
                }],
                calling_convention: String::new(),
                is_variadic: false,
                source: SignatureSource::DebugInfo,
            },
        );
        let types = TypeManager::default();

        let propagator =
            TypePropagator::new(&functions, &xrefs, &type_libs, &imports).with_il(&il_map);
        let result = propagator.propagate(&debug_info, &types);

        let g = result
            .get(&0x4000)
            .and_then(|i| i.signature.as_ref())
            .expect("G's return type should be inferred from the typed argument");
        assert_eq!(g.return_type, char_ptr);
        assert_eq!(g.name, "sub_4000");
    }

    #[test]
    fn backward_infers_param_type_from_typed_producer() {
        use crate::analysis::abi::abi_registers;
        use crate::analysis::functions::CallingConvention;
        use crate::arch::Architecture;
        use crate::il::mlil::{MlilExpr, MlilInst, MlilStmt, SsaVar};
        use crate::il::ssa::DefUse;

        let var = |n: &str| SsaVar {
            name: n.to_string(),
            version: 0,
        };
        let call = |addr: u64, args: Vec<MlilExpr>| MlilExpr::Call {
            target: Box::new(MlilExpr::Const(addr)),
            args,
        };

        // Caller C @0x1000:
        //   rax = H()        ; H @0x5000 (typed: returns char*)
        //   rdi = rax        ; move the typed value into the first arg register
        //   rax = G(rdi)     ; G @0x4000 (untyped) — its param0 is char*
        let mlil = MlilFunction {
            name: "C".to_string(),
            entry: 0x1000,
            instructions: vec![
                MlilInst {
                    address: 0x1000,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(0x5000, vec![]),
                    }],
                },
                MlilInst {
                    address: 0x1004,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rdi"),
                        src: MlilExpr::Var(var("rax")),
                    }],
                },
                MlilInst {
                    address: 0x1008,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(0x4000, vec![MlilExpr::Var(var("rdi"))]),
                    }],
                },
            ],
        };
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::SysVAmd64,
            BinaryFormat::Elf,
        )
        .unwrap();
        let defuse = DefUse::build(&mlil);
        let mut il_map = BTreeMap::new();
        il_map.insert(0x1000, FunctionIl { mlil, defuse, abi });

        let mut functions = FunctionManager::default();
        for (a, name) in [(0x1000u64, "C"), (0x4000, "sub_4000"), (0x5000, "make_str")] {
            functions.add_function(Function {
                name: name.to_string(),
                start_address: a,
                end_address: None,
                calling_convention: CallingConvention::SysVAmd64,
                stack_frame_size: 0,
            });
        }
        let xrefs = XrefManager::new();
        let type_libs = TypeLibraryManager::default();
        let imports: Vec<Import> = vec![];

        let char_ptr = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Char)));
        let mut debug_info = DebugInfo::default();
        debug_info.function_signatures.insert(
            0x5000,
            FunctionSignature {
                name: "make_str".to_string(),
                return_type: char_ptr.clone(),
                parameters: vec![],
                calling_convention: String::new(),
                is_variadic: false,
                source: SignatureSource::DebugInfo,
            },
        );
        let types = TypeManager::default();

        let propagator =
            TypePropagator::new(&functions, &xrefs, &type_libs, &imports).with_il(&il_map);
        let result = propagator.propagate(&debug_info, &types);

        let g = result
            .get(&0x4000)
            .and_then(|i| i.signature.as_ref())
            .expect("G's parameter type should be inferred from the typed producer");
        assert_eq!(g.parameters.len(), 1);
        assert_eq!(g.parameters[0].type_ref, char_ptr);
    }

    #[test]
    fn fixpoint_resolves_a_two_hop_chain() {
        use crate::analysis::abi::abi_registers;
        use crate::analysis::functions::CallingConvention;
        use crate::arch::Architecture;
        use crate::il::mlil::{MlilExpr, MlilInst, MlilStmt, SsaVar};
        use crate::il::ssa::DefUse;

        let var = |n: &str| SsaVar {
            name: n.to_string(),
            version: 0,
        };
        let call = |addr: u64, args: Vec<MlilExpr>| MlilExpr::Call {
            target: Box::new(MlilExpr::Const(addr)),
            args,
        };
        // `rax = call(callee); rdi = rax; rax = call(sink)(rdi)` at `base`.
        let route = |base: u64, callee: u64, sink: u64| {
            vec![
                MlilInst {
                    address: base,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(callee, vec![]),
                    }],
                },
                MlilInst {
                    address: base + 4,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rdi"),
                        src: MlilExpr::Var(var("rax")),
                    }],
                },
                MlilInst {
                    address: base + 8,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax"),
                        src: call(sink, vec![MlilExpr::Var(var("rdi"))]),
                    }],
                },
            ]
        };
        let abi = abi_registers(
            Architecture::X86_64,
            CallingConvention::SysVAmd64,
            BinaryFormat::Elf,
        )
        .unwrap();

        // F1: rax = C(); rdi = rax; B(rdi)   — round 1 types B.param0 from C.
        // F2: rax = A(); rdi = rax; B(rdi)   — round 2 types A.return from B.
        let mut il_map = BTreeMap::new();
        for (entry, callee, sink) in [(0x1000u64, 0x6000u64, 0x5000u64), (0x2000, 0x4000, 0x5000)] {
            let mlil = MlilFunction {
                name: format!("f_{entry:x}"),
                entry,
                instructions: route(entry, callee, sink),
            };
            let defuse = DefUse::build(&mlil);
            il_map.insert(entry, FunctionIl { mlil, defuse, abi });
        }

        let mut functions = FunctionManager::default();
        for a in [0x1000u64, 0x2000, 0x4000, 0x5000, 0x6000] {
            functions.add_function(Function {
                name: format!("sub_{a:x}"),
                start_address: a,
                end_address: None,
                calling_convention: CallingConvention::SysVAmd64,
                stack_frame_size: 0,
            });
        }
        let xrefs = XrefManager::new();
        let type_libs = TypeLibraryManager::default();
        let imports: Vec<Import> = vec![];

        // Only C @0x6000 is seeded; everything else must be derived.
        let char_ptr = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Char)));
        let mut debug_info = DebugInfo::default();
        debug_info.function_signatures.insert(
            0x6000,
            FunctionSignature {
                name: "make_str".to_string(),
                return_type: char_ptr.clone(),
                parameters: vec![],
                calling_convention: String::new(),
                is_variadic: false,
                source: SignatureSource::DebugInfo,
            },
        );
        let types = TypeManager::default();

        let propagator =
            TypePropagator::new(&functions, &xrefs, &type_libs, &imports).with_il(&il_map);
        let result = propagator.propagate(&debug_info, &types);

        // Round 1: B's first parameter inferred from the typed producer C.
        let b = result
            .get(&0x5000)
            .and_then(|i| i.signature.as_ref())
            .expect("B should be typed in round 1");
        assert_eq!(b.parameters.first().map(|p| &p.type_ref), Some(&char_ptr));
        // Round 2: A's return inferred only after B became typed — requires the
        // fixpoint loop; a single pass would leave A untyped.
        let a = result
            .get(&0x4000)
            .and_then(|i| i.signature.as_ref())
            .expect("A should be typed in round 2 via the fixpoint");
        assert_eq!(a.return_type, char_ptr);
    }
}
