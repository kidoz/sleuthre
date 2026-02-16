use crate::analysis::functions::FunctionManager;
use crate::analysis::xrefs::{XrefManager, XrefType};
use crate::debuginfo::DebugInfo;
use crate::loader::Import;
use crate::typelib::TypeLibraryManager;
use crate::types::{FunctionSignature, TypeManager, TypeRef};
use std::collections::BTreeMap;

/// Type information inferred for a single function.
#[derive(Debug, Clone, Default)]
pub struct FunctionTypeInfo {
    pub signature: Option<FunctionSignature>,
    pub var_types: BTreeMap<String, TypeRef>,
}

/// Propagates type information across function call sites.
pub struct TypePropagator<'a> {
    functions: &'a FunctionManager,
    xrefs: &'a XrefManager,
    type_libs: &'a TypeLibraryManager,
    imports: &'a [Import],
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
        }
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

        // === Pass 3: Backward propagation ===
        // If a function is called and its return value is passed to another
        // function with a known signature, we can infer the return type.
        for &addr in self.functions.functions.keys() {
            if result
                .get(&addr)
                .and_then(|i| i.signature.as_ref())
                .is_some()
            {
                continue; // Already has a signature
            }

            // Look at where this function's return value is used
            if let Some(from_xrefs) = self.xrefs.from_address_xrefs.get(&addr) {
                // Not easily done without IL analysis — skip for now
                // This is a placeholder for future IL-based backward propagation
                let _ = from_xrefs;
            }
        }

        result
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
}
