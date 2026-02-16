use crate::debuginfo::DebugInfo;
use crate::error::Error;
use crate::types::{
    CompoundType, FunctionParameter, FunctionSignature, PrimitiveType, StructField, TypeRef,
    VariableInfo, VariableLocation,
};
use pdb::{FallibleIterator, PDB, TypeData, TypeFinder, TypeIndex};
use std::collections::HashMap;
use std::path::Path;

/// Extract debug info from a PDB file.
pub fn extract_pdb_info(
    pdb_path: &Path,
    arch: crate::arch::Architecture,
) -> crate::Result<DebugInfo> {
    let file = std::fs::File::open(pdb_path).map_err(Error::Io)?;
    let mut pdb =
        PDB::open(file).map_err(|e| Error::DebugInfo(format!("PDB open error: {}", e)))?;

    let mut info = DebugInfo::default();
    let mut resolver = PdbTypeResolver::new();

    // Parse type information
    let type_info = pdb
        .type_information()
        .map_err(|e| Error::DebugInfo(format!("PDB type info error: {}", e)))?;
    let mut type_finder = type_info.finder();

    // First pass: index all types
    {
        let mut iter = type_info.iter();
        while let Ok(Some(_item)) = iter.next() {
            type_finder.update(&iter);
        }
    }

    // Second pass: resolve types we care about
    {
        let mut iter = type_info.iter();
        while let Ok(Some(item)) = iter.next() {
            if let Ok(type_data) = item.parse() {
                match type_data {
                    TypeData::Class(data) => {
                        let name = data.name.to_string().to_string();
                        if !name.is_empty()
                            && data.size > 0
                            && let Some(field_list) = data.fields
                        {
                            let fields =
                                resolve_field_list(&type_finder, &mut resolver, field_list, arch);
                            info.types.push(CompoundType::Struct {
                                name,
                                fields,
                                size: data.size as usize,
                            });
                        }
                    }
                    TypeData::Union(data) => {
                        let name = data.name.to_string().to_string();
                        if !name.is_empty() {
                            let fields =
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
                        if !name.is_empty() {
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

    // Parse debug info stream for functions and globals
    if let Ok(debug_info) = pdb.debug_information()
        && let Ok(mut modules) = debug_info.modules()
    {
        while let Ok(Some(module)) = modules.next() {
            if let Ok(Some(module_info)) = pdb.module_info(&module)
                && let Ok(mut symbols) = module_info.symbols()
            {
                while let Ok(Some(symbol)) = symbols.next() {
                    if let Ok(symbol_data) = symbol.parse() {
                        match symbol_data {
                            pdb::SymbolData::Procedure(proc) => {
                                let name = proc.name.to_string().to_string();
                                let addr = proc.offset.offset as u64;
                                let (ret_type, params) = resolve_procedure_type(
                                    &type_finder,
                                    &mut resolver,
                                    proc.type_index,
                                    arch,
                                );
                                info.function_signatures.insert(
                                    addr,
                                    FunctionSignature {
                                        name,
                                        return_type: ret_type,
                                        parameters: params,
                                        calling_convention: String::new(),
                                        is_variadic: false,
                                    },
                                );
                            }
                            pdb::SymbolData::Data(data) => {
                                let name = data.name.to_string().to_string();
                                let addr = data.offset.offset as u64;
                                let type_ref =
                                    resolver.resolve(&type_finder, data.type_index, arch);
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
                }
            }
        }
    }

    // Parse global symbols
    if let Ok(global_symbols) = pdb.global_symbols() {
        let mut iter = global_symbols.iter();
        while let Ok(Some(symbol)) = iter.next() {
            if let Ok(symbol_data) = symbol.parse()
                && let pdb::SymbolData::Public(public) = symbol_data
            {
                let name = public.name.to_string().to_string();
                let addr = public.offset.offset as u64;
                if public.function && !info.function_signatures.contains_key(&addr) {
                    info.function_signatures.insert(
                        addr,
                        FunctionSignature {
                            name,
                            return_type: TypeRef::Primitive(PrimitiveType::Void),
                            parameters: Vec::new(),
                            calling_convention: String::new(),
                            is_variadic: false,
                        },
                    );
                }
            }
        }
    }

    Ok(info)
}

struct PdbTypeResolver {
    cache: HashMap<u32, TypeRef>,
}

impl PdbTypeResolver {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
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

        // Placeholder for recursion
        self.cache
            .insert(idx, TypeRef::Named("<resolving>".to_string()));

        let resolved = self.resolve_inner(type_finder, type_index, arch);
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
            TypeData::Array(arr) => {
                let element = self.resolve(type_finder, arr.element_type, arch);
                let elem_size = type_size_hint(type_finder, arr.element_type, arch).max(1);
                let total_size = arr.dimensions.iter().copied().sum::<u32>();
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

fn resolve_field_list(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    field_list_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> Vec<StructField> {
    let mut fields = Vec::new();

    let item = match type_finder.find(field_list_index) {
        Ok(item) => item,
        Err(_) => return fields,
    };

    if let Ok(TypeData::FieldList(fl)) = item.parse() {
        for field in &fl.fields {
            if let TypeData::Member(member) = field {
                let name = member.name.to_string().to_string();
                let type_ref = resolver.resolve(type_finder, member.field_type, arch);
                fields.push(StructField {
                    name,
                    type_ref,
                    offset: member.offset as usize,
                    bit_offset: None,
                    bit_size: None,
                });
            }
        }
    }

    fields
}

fn resolve_enum_variants(
    type_finder: &TypeFinder,
    field_list_index: TypeIndex,
) -> Vec<(String, i64)> {
    let mut variants = Vec::new();

    let item = match type_finder.find(field_list_index) {
        Ok(item) => item,
        Err(_) => return variants,
    };

    if let Ok(TypeData::FieldList(fl)) = item.parse() {
        for field in &fl.fields {
            if let TypeData::Enumerate(en) = field {
                let name = en.name.to_string().to_string();
                let value = variant_value(&en.value);
                variants.push((name, value));
            }
        }
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

fn resolve_procedure_type(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    type_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> (TypeRef, Vec<FunctionParameter>) {
    let item = match type_finder.find(type_index) {
        Ok(item) => item,
        Err(_) => {
            return (TypeRef::Primitive(PrimitiveType::Void), Vec::new());
        }
    };

    match item.parse() {
        Ok(TypeData::Procedure(proc)) => {
            let return_type = proc
                .return_type
                .map(|ti| resolver.resolve(type_finder, ti, arch))
                .unwrap_or(TypeRef::Primitive(PrimitiveType::Void));
            let params =
                resolve_argument_list_as_params(type_finder, resolver, proc.argument_list, arch);
            (return_type, params)
        }
        Ok(TypeData::MemberFunction(mf)) => {
            let return_type = resolver.resolve(type_finder, mf.return_type, arch);
            let params =
                resolve_argument_list_as_params(type_finder, resolver, mf.argument_list, arch);
            (return_type, params)
        }
        _ => (TypeRef::Primitive(PrimitiveType::Void), Vec::new()),
    }
}

fn resolve_argument_list_as_params(
    type_finder: &TypeFinder,
    resolver: &mut PdbTypeResolver,
    arg_list_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> Vec<FunctionParameter> {
    let item = match type_finder.find(arg_list_index) {
        Ok(item) => item,
        Err(_) => return Vec::new(),
    };

    match item.parse() {
        Ok(TypeData::ArgumentList(args)) => args
            .arguments
            .iter()
            .enumerate()
            .map(|(i, &ti)| FunctionParameter {
                name: format!("arg{}", i),
                type_ref: resolver.resolve(type_finder, ti, arch),
            })
            .collect(),
        _ => Vec::new(),
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

fn type_size_hint(
    type_finder: &TypeFinder,
    type_index: TypeIndex,
    arch: crate::arch::Architecture,
) -> usize {
    let item = match type_finder.find(type_index) {
        Ok(item) => item,
        Err(_) => return 1,
    };

    match item.parse() {
        Ok(TypeData::Primitive(prim)) => {
            let tr = builtin_type_from_pdb_primitive(prim.kind, None);
            match tr {
                TypeRef::Primitive(p) => p.size(arch).max(1),
                _ => 1,
            }
        }
        _ => 1,
    }
}
