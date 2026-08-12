use crate::debuginfo::DebugInfo;
use crate::error::Error;
use crate::types::{
    CompoundType, FunctionParameter, FunctionSignature, PrimitiveType, SourceLineInfo, StructField,
    TypeRef, VariableInfo, VariableLocation,
};
use pdb::{FallibleIterator, PDB, TypeData, TypeFinder, TypeIndex};
use std::collections::HashMap;
use std::path::Path;

/// Upper bound on line-table rows collected across all modules.
const MAX_PDB_LINE_ROWS: usize = 2_000_000;

/// Upper bound on emitted compound types.
const MAX_PDB_TOTAL_TYPES: usize = 200_000;

/// Upper bound on fields parsed for one struct/union.
const MAX_PDB_STRUCT_FIELDS: usize = 10_000;

/// Upper bound on variants parsed for one enum.
const MAX_PDB_ENUM_VARIANTS: usize = 10_000;

/// Upper bound on `LF_FIELDLIST` continuation hops (guards against cyclic
/// continuation chains in a crafted PDB).
const MAX_FIELD_LIST_CHAIN: usize = 1_000;

/// Extract debug info from a PDB file.
pub fn extract_pdb_info(
    pdb_path: &Path,
    arch: crate::arch::Architecture,
    image_base: u64,
) -> crate::Result<DebugInfo> {
    let file = std::fs::File::open(pdb_path).map_err(Error::Io)?;
    let mut pdb =
        PDB::open(file).map_err(|e| Error::DebugInfo(format!("PDB open error: {}", e)))?;

    // Maps section-relative symbol offsets to RVAs. Without it, symbol
    // addresses below would be wrong (raw `offset.offset` drops the section).
    let address_map = pdb.address_map().ok();

    // The "/names" stream: line-program file names are references into it.
    let string_table = pdb.string_table().ok();

    let mut info = DebugInfo::default();
    let mut resolver = PdbTypeResolver::new();

    // Parse type information
    let type_info = pdb
        .type_information()
        .map_err(|e| Error::DebugInfo(format!("PDB type info error: {}", e)))?;
    let mut type_finder = type_info.finder();

    // First pass: index all types, and map every non-forward-reference
    // class/union/enum name to its defining record so forward references
    // (`size == 0`, no field list) can be resolved by name later.
    {
        let mut iter = type_info.iter();
        while let Ok(Some(item)) = iter.next() {
            type_finder.update(&iter);
            if let Ok(type_data) = item.parse() {
                let (name, forward) = match &type_data {
                    TypeData::Class(c) => (c.name, c.properties.forward_reference()),
                    TypeData::Union(u) => (u.name, u.properties.forward_reference()),
                    TypeData::Enumeration(e) => (e.name, e.properties.forward_reference()),
                    _ => continue,
                };
                if !forward {
                    let name = name.to_string().to_string();
                    if !name.is_empty() {
                        resolver.definitions.entry(name).or_insert(item.index());
                    }
                }
            }
        }
    }

    // Second pass: resolve types we care about
    {
        let mut iter = type_info.iter();
        while let Ok(Some(item)) = iter.next() {
            if info.types.len() >= MAX_PDB_TOTAL_TYPES {
                break;
            }
            if let Ok(type_data) = item.parse() {
                match type_data {
                    TypeData::Class(data) => {
                        let name = data.name.to_string().to_string();
                        // Forward references carry no layout; the defining
                        // occurrence (found by name in the first pass) is
                        // emitted on its own iteration turn.
                        if name.is_empty() || data.properties.forward_reference() {
                            continue;
                        }
                        let Some(field_list) = data.fields else {
                            continue;
                        };
                        let (fields, base) =
                            resolve_field_list(&type_finder, &mut resolver, field_list, arch);
                        if let Some(base_name) = base {
                            info.classes
                                .entry(name.clone())
                                .or_default()
                                .base
                                .get_or_insert(base_name);
                        }
                        info.types.push(CompoundType::Struct {
                            name,
                            fields,
                            size: data.size as usize,
                        });
                    }
                    TypeData::Union(data) => {
                        let name = data.name.to_string().to_string();
                        if !name.is_empty() && !data.properties.forward_reference() {
                            let (fields, _) =
                                resolve_field_list(&type_finder, &mut resolver, data.fields, arch);
                            info.types.push(CompoundType::Union {
                                name,
                                fields,
                                size: data.size as usize,
                            });
                        }
                    }
                    TypeData::Enumeration(data) => {
                        let name = data.name.to_string().to_string();
                        if !name.is_empty() && !data.properties.forward_reference() {
                            let variants = resolve_enum_variants(&type_finder, data.fields);
                            let underlying_size = resolve_type_size(
                                &type_finder,
                                &mut resolver,
                                data.underlying_type,
                                arch,
                            );
                            info.types.push(CompoundType::Enum {
                                name,
                                variants,
                                size: underlying_size,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Parse debug info stream for functions, locals, globals, and line tables
    let mut line_budget = MAX_PDB_LINE_ROWS;
    if let Ok(debug_info) = pdb.debug_information()
        && let Ok(mut modules) = debug_info.modules()
    {
        while let Ok(Some(module)) = modules.next() {
            if let Ok(Some(module_info)) = pdb.module_info(&module) {
                if let Ok(mut symbols) = module_info.symbols() {
                    parse_module_symbols(
                        &mut symbols,
                        &type_finder,
                        &mut resolver,
                        address_map.as_ref(),
                        image_base,
                        arch,
                        &mut info,
                    );
                }
                if let Ok(line_program) = module_info.line_program() {
                    collect_module_lines(
                        &line_program,
                        string_table.as_ref(),
                        address_map.as_ref(),
                        image_base,
                        &mut info,
                        &mut line_budget,
                    );
                }
            }
        }
    }

    // Parse global symbols: public functions plus S_GDATA32/S_LDATA32 and
    // thread-local statics that only appear in the globals stream.
    if let Ok(global_symbols) = pdb.global_symbols() {
        let mut iter = global_symbols.iter();
        while let Ok(Some(symbol)) = iter.next() {
            let Ok(symbol_data) = symbol.parse() else {
                continue;
            };
            match symbol_data {
                pdb::SymbolData::Public(public) => {
                    let name = public.name.to_string().to_string();
                    let Some(addr) =
                        section_offset_to_va(public.offset, address_map.as_ref(), image_base)
                    else {
                        continue;
                    };
                    if public.function && !info.function_signatures.contains_key(&addr) {
                        info.function_signatures.insert(
                            addr,
                            FunctionSignature {
                                name,
                                return_type: TypeRef::Primitive(PrimitiveType::Void),
                                parameters: Vec::new(),
                                calling_convention: String::new(),
                                is_variadic: false,
                                source: crate::types::SignatureSource::DebugInfo,
                            },
                        );
                    }
                }
                pdb::SymbolData::Data(data) => {
                    let name = data.name.to_string().to_string();
                    let Some(addr) =
                        section_offset_to_va(data.offset, address_map.as_ref(), image_base)
                    else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let type_ref = resolver.resolve(&type_finder, data.type_index, arch);
                    // Module streams carry the same symbol with equal detail —
                    // keep whichever was seen first.
                    info.global_variables.entry(addr).or_insert(VariableInfo {
                        name,
                        type_ref,
                        location: VariableLocation::Address(addr),
                    });
                }
                pdb::SymbolData::ThreadStorage(tls) => {
                    let name = tls.name.to_string().to_string();
                    let Some(addr) =
                        section_offset_to_va(tls.offset, address_map.as_ref(), image_base)
                    else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let type_ref = resolver.resolve(&type_finder, tls.type_index, arch);
                    info.global_variables.entry(addr).or_insert(VariableInfo {
                        name,
                        type_ref,
                        location: VariableLocation::Address(addr),
                    });
                }
                pdb::SymbolData::UserDefinedType(udt) => {
                    // S_UDT — a typedef in the source
                    let name = udt.name.to_string().to_string();
                    if name.is_empty() || info.types.len() >= MAX_PDB_TOTAL_TYPES {
                        continue;
                    }
                    let target = resolver.resolve(&type_finder, udt.type_index, arch);
                    // `typedef struct Foo Foo;` self-references add nothing
                    if matches!(&target, TypeRef::Named(n) if *n == name) {
                        continue;
                    }
                    info.types.push(CompoundType::Typedef { name, target });
                }
                // S_CONSTANT records carry a value but no address, so they
                // cannot live in the address-keyed globals map.
                _ => {}
            }
        }
    }

    Ok(info)
}

/// Collect one module's C13 line table into `source_lines`: each row maps an
/// instruction address to `file:line[:column]`. `budget` caps total rows
/// across all modules (line data is untrusted input).
fn collect_module_lines(
    program: &pdb::LineProgram<'_>,
    string_table: Option<&pdb::StringTable<'_>>,
    address_map: Option<&pdb::AddressMap<'_>>,
    image_base: u64,
    info: &mut DebugInfo,
    budget: &mut usize,
) {
    let mut lines = program.lines();
    while let Ok(Some(line)) = lines.next() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;

        let Some(addr) = section_offset_to_va(line.offset, address_map, image_base) else {
            continue;
        };
        let file = program
            .get_file_info(line.file_index)
            .ok()
            .and_then(|fi| string_table?.get(fi.name).ok())
            .map(|raw| raw.to_string().to_string())
            .unwrap_or_default();
        // Column 0 means "not recorded" in practice
        let column = line.column_start.filter(|&c| c != 0);

        info.source_lines.insert(
            addr,
            SourceLineInfo {
                file,
                line: line.line_start,
                column,
            },
        );
    }
}

/// Map a PDB section-relative symbol offset to a virtual address in the same
/// space as the loaded segments: section-relative → RVA (via the address map) →
/// `image_base + rva`. Returns `None` when the offset can't be resolved (so the
/// symbol is skipped rather than recorded at a bogus address).
fn section_offset_to_va(
    offset: pdb::PdbInternalSectionOffset,
    address_map: Option<&pdb::AddressMap<'_>>,
    image_base: u64,
) -> Option<u64> {
    offset
        .to_rva(address_map?)
        .map(|rva| image_base + rva.0 as u64)
}

/// Upper bound on locals collected for one procedure, so a crafted symbol
/// stream cannot balloon memory.
const MAX_PDB_LOCALS_PER_FUNCTION: usize = 10_000;

/// A procedure whose scope is currently open while walking a module's flat
/// symbol stream.
struct OpenProcedure {
    addr: u64,
    locals: Vec<VariableInfo>,
    /// Indices into `locals` of top-of-scope `S_REGREL32` entries with
    /// positive frame offsets, in order of appearance — MSVC emits stack
    /// parameters this way before any true local.
    regrel_param_indices: Vec<usize>,
    /// Names of `S_LOCAL` entries flagged `isparam`, in order — the only
    /// parameter-name source in optimized builds (locations live in DEFRANGE
    /// records the `pdb` crate does not surface).
    local_param_names: Vec<String>,
}

/// Walk one module's symbol stream. CodeView nests scopes in a flat stream:
/// `S_GPROC32`/`S_LPROC32`, `S_BLOCK32`, and `S_THUNK32` each open a scope
/// terminated by a matching `S_END`, so a depth counter of 1 means "directly
/// inside the procedure".
fn parse_module_symbols(
    symbols: &mut pdb::SymbolIter<'_>,
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    address_map: Option<&pdb::AddressMap<'_>>,
    image_base: u64,
    arch: crate::arch::Architecture,
    info: &mut DebugInfo,
) {
    let mut open: Option<OpenProcedure> = None;
    let mut depth: u32 = 0;

    while let Ok(Some(symbol)) = symbols.next() {
        let Ok(symbol_data) = symbol.parse() else {
            continue;
        };
        match symbol_data {
            pdb::SymbolData::Procedure(proc) => {
                // A procedure opening while another is still open means the
                // stream is malformed — finalize what we have.
                if let Some(p) = open.take() {
                    finalize_procedure(p, info);
                }
                depth = depth.saturating_add(1);

                let name = proc.name.to_string().to_string();
                let Some(addr) = section_offset_to_va(proc.offset, address_map, image_base) else {
                    continue;
                };
                let sig = resolve_procedure_type(type_finder, resolver, proc.type_index, arch);
                info.function_signatures.insert(
                    addr,
                    FunctionSignature {
                        name,
                        return_type: sig.return_type,
                        parameters: sig.parameters,
                        calling_convention: sig.calling_convention,
                        is_variadic: sig.is_variadic,
                        source: crate::types::SignatureSource::DebugInfo,
                    },
                );
                open = Some(OpenProcedure {
                    addr,
                    locals: Vec::new(),
                    regrel_param_indices: Vec::new(),
                    local_param_names: Vec::new(),
                });
            }
            pdb::SymbolData::Block(_) | pdb::SymbolData::Thunk(_) => {
                depth = depth.saturating_add(1);
            }
            pdb::SymbolData::ScopeEnd | pdb::SymbolData::ProcedureEnd => {
                depth = depth.saturating_sub(1);
                if depth == 0
                    && let Some(p) = open.take()
                {
                    finalize_procedure(p, info);
                }
            }
            pdb::SymbolData::RegisterRelative(reg_rel) => {
                if let Some(p) = open.as_mut() {
                    let name = reg_rel.name.to_string().to_string();
                    if name.is_empty() || p.locals.len() >= MAX_PDB_LOCALS_PER_FUNCTION {
                        continue;
                    }
                    let type_ref = resolver.resolve(type_finder, reg_rel.type_index, arch);
                    let location =
                        register_relative_location(arch, reg_rel.register.0, reg_rel.offset);
                    if depth == 1 && reg_rel.offset > 0 {
                        p.regrel_param_indices.push(p.locals.len());
                    }
                    p.locals.push(VariableInfo {
                        name,
                        type_ref,
                        location,
                    });
                }
            }
            pdb::SymbolData::Local(local) => {
                // S_LOCAL itself carries no location (that lives in follow-on
                // DEFRANGE records); record parameter names for signature
                // naming but never fabricate a local at a made-up offset.
                if let Some(p) = open.as_mut()
                    && local.flags.isparam
                    && p.local_param_names.len() < MAX_PDB_LOCALS_PER_FUNCTION
                {
                    let name = local.name.to_string().to_string();
                    if !name.is_empty() {
                        p.local_param_names.push(name);
                    }
                }
            }
            pdb::SymbolData::Data(data) => {
                let name = data.name.to_string().to_string();
                let Some(addr) = section_offset_to_va(data.offset, address_map, image_base) else {
                    continue;
                };
                let type_ref = resolver.resolve(type_finder, data.type_index, arch);
                info.global_variables.insert(
                    addr,
                    VariableInfo {
                        name,
                        type_ref,
                        location: VariableLocation::Address(addr),
                    },
                );
            }
            _ => {}
        }
    }

    // Malformed streams can leave the last procedure unterminated.
    if let Some(p) = open.take() {
        finalize_procedure(p, info);
    }
}

/// Close out a procedure scope: give its parameters real names when the
/// stream provided them, and store the remaining locals.
fn finalize_procedure(mut proc: OpenProcedure, info: &mut DebugInfo) {
    let param_count = info
        .function_signatures
        .get(&proc.addr)
        .map(|s| s.parameters.len())
        .unwrap_or(0);

    if param_count > 0 {
        if proc.regrel_param_indices.len() == param_count {
            // The positive-offset frame entries are the parameters themselves:
            // move their names onto the signature and drop them from locals.
            if let Some(sig) = info.function_signatures.get_mut(&proc.addr) {
                for (param, &idx) in sig.parameters.iter_mut().zip(&proc.regrel_param_indices) {
                    param.name.clone_from(&proc.locals[idx].name);
                }
            }
            let param_indices: std::collections::HashSet<usize> =
                proc.regrel_param_indices.iter().copied().collect();
            let mut i = 0;
            proc.locals.retain(|_| {
                let keep = !param_indices.contains(&i);
                i += 1;
                keep
            });
        } else if proc.local_param_names.len() == param_count
            && let Some(sig) = info.function_signatures.get_mut(&proc.addr)
        {
            for (param, name) in sig.parameters.iter_mut().zip(&proc.local_param_names) {
                param.name.clone_from(name);
            }
        }
    }

    if !proc.locals.is_empty() {
        info.local_variables.insert(proc.addr, proc.locals);
    }
}

/// Map a CodeView register code to a display name for the architecture.
/// Codes not in the table keep a numeric name rather than being dropped.
fn cv_register_name(arch: crate::arch::Architecture, reg: u16) -> String {
    use crate::arch::Architecture;
    let name: Option<&'static str> = match (arch, reg) {
        (Architecture::X86 | Architecture::X86_64, 17) => Some("eax"),
        (Architecture::X86 | Architecture::X86_64, 18) => Some("ecx"),
        (Architecture::X86 | Architecture::X86_64, 19) => Some("edx"),
        (Architecture::X86 | Architecture::X86_64, 20) => Some("ebx"),
        (Architecture::X86 | Architecture::X86_64, 21) => Some("esp"),
        (Architecture::X86 | Architecture::X86_64, 22) => Some("ebp"),
        (Architecture::X86 | Architecture::X86_64, 23) => Some("esi"),
        (Architecture::X86 | Architecture::X86_64, 24) => Some("edi"),
        (Architecture::X86_64, 328) => Some("rax"),
        (Architecture::X86_64, 329) => Some("rbx"),
        (Architecture::X86_64, 330) => Some("rcx"),
        (Architecture::X86_64, 331) => Some("rdx"),
        (Architecture::X86_64, 332) => Some("rsi"),
        (Architecture::X86_64, 333) => Some("rdi"),
        (Architecture::X86_64, 334) => Some("rbp"),
        (Architecture::X86_64, 335) => Some("rsp"),
        (Architecture::X86_64, 336) => Some("r8"),
        (Architecture::X86_64, 337) => Some("r9"),
        (Architecture::X86_64, 338) => Some("r10"),
        (Architecture::X86_64, 339) => Some("r11"),
        (Architecture::X86_64, 340) => Some("r12"),
        (Architecture::X86_64, 341) => Some("r13"),
        (Architecture::X86_64, 342) => Some("r14"),
        (Architecture::X86_64, 343) => Some("r15"),
        _ => None,
    };
    name.map(str::to_string)
        .unwrap_or_else(|| format!("r{}", reg))
}

/// Whether a CodeView register code is a frame/stack pointer — an
/// `S_REGREL32` off these registers is a stack slot.
fn is_cv_frame_register(arch: crate::arch::Architecture, reg: u16) -> bool {
    use crate::arch::Architecture;
    match arch {
        // CV_REG_ESP / CV_REG_EBP (also 16-bit SP/BP)
        Architecture::X86 => matches!(reg, 13 | 14 | 21 | 22),
        // CV_AMD64_RSP / CV_AMD64_RBP plus the 32-bit aliases
        Architecture::X86_64 => matches!(reg, 21 | 22 | 334 | 335),
        _ => false,
    }
}

/// Location of an `S_REGREL32` variable: a stack slot when relative to the
/// frame/stack pointer, otherwise pinned to the base register.
fn register_relative_location(
    arch: crate::arch::Architecture,
    reg: u16,
    offset: i32,
) -> VariableLocation {
    if is_cv_frame_register(arch, reg) {
        VariableLocation::Stack(offset as i64)
    } else {
        VariableLocation::Register(cv_register_name(arch, reg))
    }
}

struct PdbTypeResolver {
    cache: HashMap<u32, TypeRef>,
    /// Defining (non-forward-reference) record for each class/union/enum
    /// name, used to resolve forward references — e.g. for array element
    /// sizes — instead of skipping them.
    definitions: HashMap<String, TypeIndex>,
    /// Current nesting depth of in-flight `resolve` calls — see the cap
    /// check in [`PdbTypeResolver::resolve`].
    depth: u32,
}

/// Deepest legitimate type nesting we expect from a PDB; beyond this the
/// chain is treated as hostile and resolves to `void`.
const MAX_PDB_TYPE_DEPTH: u32 = 64;

impl PdbTypeResolver {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            definitions: HashMap::new(),
            depth: 0,
        }
    }

    fn resolve(
        &mut self,
        type_finder: &TypeFinder,
        type_index: TypeIndex,
        arch: crate::arch::Architecture,
    ) -> TypeRef {
        let idx = type_index.0;

        if let Some(cached) = self.cache.get(&idx) {
            return cached.clone();
        }

        // Handle built-in type indices (< 0x1000)
        if idx < 0x1000 {
            let prim = builtin_type(idx);
            self.cache.insert(idx, prim.clone());
            return prim;
        }

        // The placeholder protects against cycles, but a crafted acyclic
        // chain of pointer/modifier records could still overflow the stack —
        // PDB content is untrusted input, so depth is capped as well.
        if self.depth >= MAX_PDB_TYPE_DEPTH {
            return TypeRef::Primitive(PrimitiveType::Void);
        }

        // Placeholder for recursion
        self.cache
            .insert(idx, TypeRef::Named("<resolving>".to_string()));

        self.depth += 1;
        let resolved = self.resolve_inner(type_finder, type_index, arch);
        self.depth -= 1;
        self.cache.insert(idx, resolved.clone());
        resolved
    }

    fn resolve_inner(
        &mut self,
        type_finder: &TypeFinder,
        type_index: TypeIndex,
        arch: crate::arch::Architecture,
    ) -> TypeRef {
        let item = match type_finder.find(type_index) {
            Ok(item) => item,
            Err(_) => return TypeRef::Primitive(PrimitiveType::Void),
        };

        let type_data = match item.parse() {
            Ok(td) => td,
            Err(_) => return TypeRef::Primitive(PrimitiveType::Void),
        };

        match type_data {
            TypeData::Primitive(prim) => {
                builtin_type_from_pdb_primitive(prim.kind, prim.indirection.as_ref())
            }
            TypeData::Pointer(ptr) => {
                let inner = self.resolve(type_finder, ptr.underlying_type, arch);
                TypeRef::Pointer(Box::new(inner))
            }
            TypeData::Modifier(modifier) => {
                let inner = self.resolve(type_finder, modifier.underlying_type, arch);
                if modifier.constant {
                    TypeRef::Const(Box::new(inner))
                } else if modifier.volatile {
                    TypeRef::Volatile(Box::new(inner))
                } else {
                    inner
                }
            }
            TypeData::Bitfield(bf) => self.resolve(type_finder, bf.underlying_type, arch),
            TypeData::Array(arr) => {
                let element = self.resolve(type_finder, arr.element_type, arch);
                let elem_size =
                    type_size_hint(type_finder, &self.definitions, arr.element_type, arch, 0)
                        .max(1);
                // Dimensions come from the PDB verbatim; saturate instead of
                // overflowing on crafted values.
                let total_size = arr
                    .dimensions
                    .iter()
                    .copied()
                    .fold(0u32, |acc, d| acc.saturating_add(d));
                let count = (total_size as usize) / elem_size;
                TypeRef::Array {
                    element: Box::new(element),
                    count,
                }
            }
            TypeData::Procedure(proc) => {
                let return_type = proc
                    .return_type
                    .map(|ti| self.resolve(type_finder, ti, arch))
                    .unwrap_or(TypeRef::Primitive(PrimitiveType::Void));
                let params = self.resolve_argument_list(type_finder, proc.argument_list, arch);
                TypeRef::FunctionPointer {
                    return_type: Box::new(return_type),
                    params,
                    is_variadic: false,
                }
            }
            TypeData::Class(class) => TypeRef::Named(class.name.to_string().to_string()),
            TypeData::Union(union) => TypeRef::Named(union.name.to_string().to_string()),
            TypeData::Enumeration(en) => TypeRef::Named(en.name.to_string().to_string()),
            _ => TypeRef::Primitive(PrimitiveType::Void),
        }
    }

    fn resolve_argument_list(
        &mut self,
        type_finder: &TypeFinder,
        arg_list_index: TypeIndex,
        arch: crate::arch::Architecture,
    ) -> Vec<TypeRef> {
        let item = match type_finder.find(arg_list_index) {
            Ok(item) => item,
            Err(_) => return Vec::new(),
        };

        match item.parse() {
            Ok(TypeData::ArgumentList(args)) => args
                .arguments
                .iter()
                .map(|&ti| self.resolve(type_finder, ti, arch))
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn builtin_type(idx: u32) -> TypeRef {
    let base = idx & 0xFF;
    let mode = (idx >> 8) & 0xF;

    let base_type = match base {
        0x00 | 0x03 => TypeRef::Primitive(PrimitiveType::Void),
        0x10 => TypeRef::Primitive(PrimitiveType::I8),
        0x20 => TypeRef::Primitive(PrimitiveType::I16),
        0x68 => TypeRef::Primitive(PrimitiveType::I8),
        0x69 => TypeRef::Primitive(PrimitiveType::U8),
        0x70 => TypeRef::Primitive(PrimitiveType::Char),
        0x71 => TypeRef::Primitive(PrimitiveType::WChar),
        0x72 => TypeRef::Primitive(PrimitiveType::I16),
        0x73 => TypeRef::Primitive(PrimitiveType::U16),
        0x74 => TypeRef::Primitive(PrimitiveType::I32),
        0x75 => TypeRef::Primitive(PrimitiveType::U32),
        0x76 => TypeRef::Primitive(PrimitiveType::I64),
        0x77 => TypeRef::Primitive(PrimitiveType::U64),
        0x30 => TypeRef::Primitive(PrimitiveType::Bool),
        0x40 => TypeRef::Primitive(PrimitiveType::F32),
        0x41 => TypeRef::Primitive(PrimitiveType::F64),
        _ => TypeRef::Primitive(PrimitiveType::Void),
    };

    if mode > 0 {
        TypeRef::Pointer(Box::new(base_type))
    } else {
        base_type
    }
}

fn builtin_type_from_pdb_primitive(
    kind: pdb::PrimitiveKind,
    indirection: Option<&pdb::Indirection>,
) -> TypeRef {
    let base = match kind {
        pdb::PrimitiveKind::Void => TypeRef::Primitive(PrimitiveType::Void),
        pdb::PrimitiveKind::Char => TypeRef::Primitive(PrimitiveType::Char),
        pdb::PrimitiveKind::UChar => TypeRef::Primitive(PrimitiveType::U8),
        pdb::PrimitiveKind::RChar => TypeRef::Primitive(PrimitiveType::Char),
        pdb::PrimitiveKind::WChar => TypeRef::Primitive(PrimitiveType::WChar),
        pdb::PrimitiveKind::RChar16 => TypeRef::Primitive(PrimitiveType::WChar),
        pdb::PrimitiveKind::RChar32 => TypeRef::Primitive(PrimitiveType::U32),
        pdb::PrimitiveKind::I8 => TypeRef::Primitive(PrimitiveType::I8),
        pdb::PrimitiveKind::U8 => TypeRef::Primitive(PrimitiveType::U8),
        pdb::PrimitiveKind::Short => TypeRef::Primitive(PrimitiveType::I16),
        pdb::PrimitiveKind::UShort => TypeRef::Primitive(PrimitiveType::U16),
        pdb::PrimitiveKind::I16 => TypeRef::Primitive(PrimitiveType::I16),
        pdb::PrimitiveKind::U16 => TypeRef::Primitive(PrimitiveType::U16),
        pdb::PrimitiveKind::Long => TypeRef::Primitive(PrimitiveType::I32),
        pdb::PrimitiveKind::ULong => TypeRef::Primitive(PrimitiveType::U32),
        pdb::PrimitiveKind::I32 => TypeRef::Primitive(PrimitiveType::I32),
        pdb::PrimitiveKind::U32 => TypeRef::Primitive(PrimitiveType::U32),
        pdb::PrimitiveKind::Quad => TypeRef::Primitive(PrimitiveType::I64),
        pdb::PrimitiveKind::UQuad => TypeRef::Primitive(PrimitiveType::U64),
        pdb::PrimitiveKind::I64 => TypeRef::Primitive(PrimitiveType::I64),
        pdb::PrimitiveKind::U64 => TypeRef::Primitive(PrimitiveType::U64),
        pdb::PrimitiveKind::F32 => TypeRef::Primitive(PrimitiveType::F32),
        pdb::PrimitiveKind::F64 => TypeRef::Primitive(PrimitiveType::F64),
        pdb::PrimitiveKind::Bool8 => TypeRef::Primitive(PrimitiveType::Bool),
        pdb::PrimitiveKind::Bool16 => TypeRef::Primitive(PrimitiveType::Bool),
        pdb::PrimitiveKind::Bool32 => TypeRef::Primitive(PrimitiveType::Bool),
        pdb::PrimitiveKind::Bool64 => TypeRef::Primitive(PrimitiveType::Bool),
        pdb::PrimitiveKind::HRESULT => TypeRef::Primitive(PrimitiveType::I32),
        _ => TypeRef::Primitive(PrimitiveType::Void),
    };

    match indirection {
        None => base,
        Some(_) => TypeRef::Pointer(Box::new(base)),
    }
}

/// Resolve a `LF_FIELDLIST` chain into struct fields, following continuation
/// records (large classes split their field list). Returns the fields and the
/// name of the first `LF_BCLASS` base class, if any.
fn resolve_field_list(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    field_list_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> (Vec<StructField>, Option<String>) {
    let mut fields = Vec::new();
    let mut base: Option<String> = None;

    let mut next = Some(field_list_index);
    let mut hops = 0usize;
    while let Some(index) = next {
        hops += 1;
        if hops > MAX_FIELD_LIST_CHAIN {
            break;
        }
        let Ok(item) = type_finder.find(index) else {
            break;
        };
        let Ok(TypeData::FieldList(fl)) = item.parse() else {
            break;
        };
        for field in &fl.fields {
            match field {
                TypeData::Member(member) => {
                    if fields.len() >= MAX_PDB_STRUCT_FIELDS {
                        break;
                    }
                    let name = member.name.to_string().to_string();
                    let mut bit_offset = None;
                    let mut bit_size = None;
                    // A bitfield member's type is an LF_BITFIELD record
                    // wrapping the underlying integer type.
                    let type_ref = if let Ok(field_item) = type_finder.find(member.field_type)
                        && let Ok(TypeData::Bitfield(bf)) = field_item.parse()
                    {
                        bit_offset = Some(bf.position);
                        bit_size = Some(bf.length);
                        resolver.resolve(type_finder, bf.underlying_type, arch)
                    } else {
                        resolver.resolve(type_finder, member.field_type, arch)
                    };
                    fields.push(StructField {
                        name,
                        type_ref,
                        offset: member.offset as usize,
                        bit_offset,
                        bit_size,
                    });
                }
                TypeData::BaseClass(bc) => {
                    if base.is_none()
                        && let TypeRef::Named(base_name) =
                            resolver.resolve(type_finder, bc.base_class, arch)
                    {
                        base = Some(base_name);
                    }
                }
                _ => {}
            }
        }
        next = fl.continuation;
    }

    (fields, base)
}

fn resolve_enum_variants(
    type_finder: &TypeFinder,
    field_list_index: TypeIndex,
) -> Vec<(String, i64)> {
    let mut variants = Vec::new();

    let mut next = Some(field_list_index);
    let mut hops = 0usize;
    while let Some(index) = next {
        hops += 1;
        if hops > MAX_FIELD_LIST_CHAIN {
            break;
        }
        let Ok(item) = type_finder.find(index) else {
            break;
        };
        let Ok(TypeData::FieldList(fl)) = item.parse() else {
            break;
        };
        for field in &fl.fields {
            if let TypeData::Enumerate(en) = field {
                if variants.len() >= MAX_PDB_ENUM_VARIANTS {
                    break;
                }
                let name = en.name.to_string().to_string();
                let value = variant_value(&en.value);
                variants.push((name, value));
            }
        }
        next = fl.continuation;
    }

    variants
}

fn variant_value(v: &pdb::Variant) -> i64 {
    match *v {
        pdb::Variant::U8(x) => x as i64,
        pdb::Variant::U16(x) => x as i64,
        pdb::Variant::U32(x) => x as i64,
        pdb::Variant::U64(x) => x as i64,
        pdb::Variant::I8(x) => x as i64,
        pdb::Variant::I16(x) => x as i64,
        pdb::Variant::I32(x) => x as i64,
        pdb::Variant::I64(x) => x,
    }
}

/// Signature details recovered from a procedure's TPI record.
struct ProcSignature {
    return_type: TypeRef,
    parameters: Vec<FunctionParameter>,
    is_variadic: bool,
    calling_convention: String,
}

impl Default for ProcSignature {
    fn default() -> Self {
        Self {
            return_type: TypeRef::Primitive(PrimitiveType::Void),
            parameters: Vec::new(),
            is_variadic: false,
            calling_convention: String::new(),
        }
    }
}

/// Map a CodeView `CV_call_e` calling-convention code to a descriptive string.
fn cv_calling_convention_name(cc: u8) -> String {
    match cc {
        0x00 | 0x01 => "cdecl".to_string(),    // NEAR_C / FAR_C
        0x02 | 0x03 => "pascal".to_string(),   // NEAR_PASCAL / FAR_PASCAL
        0x04 | 0x05 => "fastcall".to_string(), // NEAR_FAST / FAR_FAST
        0x07 | 0x08 => "stdcall".to_string(),  // NEAR_STD / FAR_STD
        0x09 | 0x0a => "syscall".to_string(),  // NEAR_SYS / FAR_SYS
        0x0b => "thiscall".to_string(),
        0x0d => "generic".to_string(),
        0x11 => "armcall".to_string(),
        0x16 => "clrcall".to_string(),
        0x17 => "inline".to_string(),
        0x18 => "vectorcall".to_string(), // NEAR_VECTOR
        other => format!("cc_{:#x}", other),
    }
}

fn resolve_procedure_type(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    type_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> ProcSignature {
    let item = match type_finder.find(type_index) {
        Ok(item) => item,
        Err(_) => return ProcSignature::default(),
    };

    match item.parse() {
        Ok(TypeData::Procedure(proc)) => {
            let return_type = proc
                .return_type
                .map(|ti| resolver.resolve(type_finder, ti, arch))
                .unwrap_or(TypeRef::Primitive(PrimitiveType::Void));
            let (parameters, is_variadic) =
                resolve_argument_list_as_params(type_finder, resolver, proc.argument_list, arch);
            ProcSignature {
                return_type,
                parameters,
                is_variadic,
                calling_convention: cv_calling_convention_name(
                    proc.attributes.calling_convention(),
                ),
            }
        }
        Ok(TypeData::MemberFunction(mf)) => {
            let return_type = resolver.resolve(type_finder, mf.return_type, arch);
            let (parameters, is_variadic) =
                resolve_argument_list_as_params(type_finder, resolver, mf.argument_list, arch);
            ProcSignature {
                return_type,
                parameters,
                is_variadic,
                calling_convention: cv_calling_convention_name(mf.attributes.calling_convention()),
            }
        }
        _ => ProcSignature::default(),
    }
}

/// Resolve a TPI argument list into named parameters. A trailing `T_NOTYPE`
/// (type index 0) is CodeView's variadic sentinel, not a real parameter.
fn resolve_argument_list_as_params(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    arg_list_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> (Vec<FunctionParameter>, bool) {
    let item = match type_finder.find(arg_list_index) {
        Ok(item) => item,
        Err(_) => return (Vec::new(), false),
    };

    match item.parse() {
        Ok(TypeData::ArgumentList(args)) => {
            let mut arguments = args.arguments.as_slice();
            let is_variadic = arguments.last().is_some_and(|ti| ti.0 == 0);
            if is_variadic {
                arguments = &arguments[..arguments.len() - 1];
            }
            let params = arguments
                .iter()
                .enumerate()
                .map(|(i, &ti)| FunctionParameter {
                    name: format!("arg{}", i),
                    type_ref: resolver.resolve(type_finder, ti, arch),
                })
                .collect();
            (params, is_variadic)
        }
        _ => (Vec::new(), false),
    }
}

fn resolve_type_size(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    type_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> usize {
    let resolved = resolver.resolve(type_finder, type_index, arch);
    match resolved {
        TypeRef::Primitive(p) => p.size(arch),
        _ => 4,
    }
}

/// How many indirections `type_size_hint` may follow (forward reference →
/// definition, modifier → underlying, enum → integer type).
const MAX_SIZE_HINT_DEPTH: u32 = 8;

/// Best-effort byte size of a type, used to derive array element counts from
/// CodeView's byte-based array dimensions. Forward-referenced classes are
/// resolved by name to their defining occurrence.
fn type_size_hint(
    type_finder: &TypeFinder,
    definitions: &HashMap<String, TypeIndex>,
    type_index: TypeIndex,
    arch: crate::arch::Architecture,
    depth: u32,
) -> usize {
    if depth >= MAX_SIZE_HINT_DEPTH {
        return 1;
    }
    if type_index.0 < 0x1000 {
        return match builtin_type(type_index.0) {
            TypeRef::Primitive(p) => p.size(arch).max(1),
            TypeRef::Pointer(_) => arch.pointer_size(),
            _ => 1,
        };
    }
    let item = match type_finder.find(type_index) {
        Ok(item) => item,
        Err(_) => return 1,
    };

    match item.parse() {
        Ok(TypeData::Primitive(prim)) => {
            match builtin_type_from_pdb_primitive(prim.kind, prim.indirection.as_ref()) {
                TypeRef::Primitive(p) => p.size(arch).max(1),
                TypeRef::Pointer(_) => arch.pointer_size(),
                _ => 1,
            }
        }
        Ok(TypeData::Pointer(_)) => arch.pointer_size(),
        Ok(TypeData::Modifier(m)) => {
            type_size_hint(type_finder, definitions, m.underlying_type, arch, depth + 1)
        }
        Ok(TypeData::Class(c)) => {
            if c.properties.forward_reference() {
                let name = c.name.to_string();
                definitions
                    .get(name.as_ref())
                    .map(|&def| type_size_hint(type_finder, definitions, def, arch, depth + 1))
                    .unwrap_or(1)
            } else {
                (c.size as usize).max(1)
            }
        }
        Ok(TypeData::Union(u)) => {
            if u.properties.forward_reference() {
                let name = u.name.to_string();
                definitions
                    .get(name.as_ref())
                    .map(|&def| type_size_hint(type_finder, definitions, def, arch, depth + 1))
                    .unwrap_or(1)
            } else {
                (u.size as usize).max(1)
            }
        }
        Ok(TypeData::Enumeration(e)) => {
            type_size_hint(type_finder, definitions, e.underlying_type, arch, depth + 1)
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    #[test]
    fn calling_convention_names() {
        assert_eq!(cv_calling_convention_name(0x00), "cdecl");
        assert_eq!(cv_calling_convention_name(0x04), "fastcall");
        assert_eq!(cv_calling_convention_name(0x07), "stdcall");
        assert_eq!(cv_calling_convention_name(0x0b), "thiscall");
        assert_eq!(cv_calling_convention_name(0x18), "vectorcall");
        // Unknown codes stay visible instead of vanishing
        assert_eq!(cv_calling_convention_name(0x7f), "cc_0x7f");
    }

    #[test]
    fn cv_register_names() {
        assert_eq!(cv_register_name(Architecture::X86, 22), "ebp");
        assert_eq!(cv_register_name(Architecture::X86_64, 334), "rbp");
        assert_eq!(cv_register_name(Architecture::X86_64, 335), "rsp");
        assert_eq!(cv_register_name(Architecture::X86_64, 336), "r8");
        assert_eq!(cv_register_name(Architecture::X86_64, 17), "eax");
        assert_eq!(cv_register_name(Architecture::Arm64, 335), "r335");
    }

    #[test]
    fn register_relative_locations() {
        // EBP-relative on x86 is a stack slot (positive = parameter side)
        assert!(matches!(
            register_relative_location(Architecture::X86, 22, 8),
            VariableLocation::Stack(8)
        ));
        assert!(matches!(
            register_relative_location(Architecture::X86, 22, -12),
            VariableLocation::Stack(-12)
        ));
        // RSP-relative on x64 is a stack slot
        assert!(matches!(
            register_relative_location(Architecture::X86_64, 335, 0x20),
            VariableLocation::Stack(0x20)
        ));
        // Relative to a non-frame register keeps the register name
        match register_relative_location(Architecture::X86_64, 331, 0) {
            VariableLocation::Register(name) => assert_eq!(name, "rdx"),
            other => panic!("expected register location, got {:?}", other),
        }
    }
}
