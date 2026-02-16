use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Primitive type identifiers
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveType {
    Void,
    Bool,
    Char,
    WChar,
    U8,
    U16,
    U32,
    U64,
    USize,
    I8,
    I16,
    I32,
    I64,
    ISize,
    F32,
    F64,
    Pointer,
}

impl PrimitiveType {
    pub fn size(&self, arch: crate::arch::Architecture) -> usize {
        match self {
            Self::Void => 0,
            Self::Bool | Self::U8 | Self::I8 | Self::Char => 1,
            Self::U16 | Self::I16 | Self::WChar => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
            Self::Pointer | Self::USize | Self::ISize => arch.pointer_size(),
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Char => "char",
            Self::WChar => "wchar_t",
            Self::U8 => "uint8_t",
            Self::U16 => "uint16_t",
            Self::U32 => "uint32_t",
            Self::U64 => "uint64_t",
            Self::USize => "size_t",
            Self::I8 => "int8_t",
            Self::I16 => "int16_t",
            Self::I32 => "int32_t",
            Self::I64 => "int64_t",
            Self::ISize => "ssize_t",
            Self::F32 => "float",
            Self::F64 => "double",
            Self::Pointer => "void*",
        }
    }
}

/// A field within a struct or union
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub type_ref: TypeRef,
    pub offset: usize,
    /// Bit offset within the byte (for bitfields), None for normal fields
    pub bit_offset: Option<u8>,
    /// Bit size (for bitfields), None for normal fields
    pub bit_size: Option<u8>,
}

/// Reference to a type (by name or inline)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeRef {
    Primitive(PrimitiveType),
    Named(String),
    Array {
        element: Box<TypeRef>,
        count: usize,
    },
    Pointer(Box<TypeRef>),
    Const(Box<TypeRef>),
    Volatile(Box<TypeRef>),
    FunctionPointer {
        return_type: Box<TypeRef>,
        params: Vec<TypeRef>,
        is_variadic: bool,
    },
}

impl TypeRef {
    pub fn size(&self, arch: crate::arch::Architecture) -> usize {
        match self {
            Self::Primitive(p) => p.size(arch),
            Self::Pointer(_) | Self::FunctionPointer { .. } => arch.pointer_size(),
            Self::Array { element, count } => element.size(arch) * count,
            Self::Named(_) => 0, // Requires manager to resolve
            Self::Const(inner) | Self::Volatile(inner) => inner.size(arch),
        }
    }

    pub fn display_name(&self) -> String {
        match self {
            Self::Primitive(p) => p.display_name().to_string(),
            Self::Named(name) => name.clone(),
            Self::Array { element, count } => format!("{}[{}]", element.display_name(), count),
            Self::Pointer(inner) => format!("{}*", inner.display_name()),
            Self::Const(inner) => format!("const {}", inner.display_name()),
            Self::Volatile(inner) => format!("volatile {}", inner.display_name()),
            Self::FunctionPointer {
                return_type,
                params,
                is_variadic,
            } => {
                let params_str: Vec<String> = params.iter().map(|p| p.display_name()).collect();
                let mut s = params_str.join(", ");
                if *is_variadic {
                    if !params.is_empty() {
                        s.push_str(", ");
                    }
                    s.push_str("...");
                }
                format!("{} (*)({})", return_type.display_name(), s)
            }
        }
    }
}

/// Compound type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundType {
    Struct {
        name: String,
        fields: Vec<StructField>,
        size: usize,
    },
    Union {
        name: String,
        fields: Vec<StructField>,
        size: usize,
    },
    Enum {
        name: String,
        variants: Vec<(String, i64)>,
        size: usize,
    },
    Typedef {
        name: String,
        target: TypeRef,
    },
}

impl CompoundType {
    pub fn name(&self) -> &str {
        match self {
            Self::Struct { name, .. }
            | Self::Union { name, .. }
            | Self::Enum { name, .. }
            | Self::Typedef { name, .. } => name,
        }
    }

    pub fn size(&self, arch: crate::arch::Architecture) -> usize {
        match self {
            Self::Struct { size, .. } | Self::Union { size, .. } | Self::Enum { size, .. } => *size,
            Self::Typedef { target, .. } => target.size(arch),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Struct { .. } => "struct",
            Self::Union { .. } => "union",
            Self::Enum { .. } => "enum",
            Self::Typedef { .. } => "typedef",
        }
    }
}

/// A type annotation at a specific address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeAnnotation {
    pub address: u64,
    pub type_ref: TypeRef,
    pub name: String,
}

/// A function signature with full type information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: TypeRef,
    pub parameters: Vec<FunctionParameter>,
    pub calling_convention: String,
    pub is_variadic: bool,
}

/// A named, typed function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParameter {
    pub name: String,
    pub type_ref: TypeRef,
}

/// Information about a variable (local or global)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    pub name: String,
    pub type_ref: TypeRef,
    pub location: VariableLocation,
}

/// Where a variable is stored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableLocation {
    Stack(i64),
    Register(String),
    Address(u64),
}

/// Source-level line information for an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLineInfo {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

/// Manages all user-defined types and type annotations
#[derive(Default)]
pub struct TypeManager {
    pub types: BTreeMap<String, CompoundType>,
    pub annotations: BTreeMap<u64, TypeAnnotation>,
    pub function_signatures: BTreeMap<u64, FunctionSignature>,
    pub global_variables: BTreeMap<u64, VariableInfo>,
    pub local_variables: BTreeMap<u64, Vec<VariableInfo>>,
    pub source_lines: BTreeMap<u64, SourceLineInfo>,
    pub arch: crate::arch::Architecture,
}

impl TypeManager {
    pub fn size_of(&self, type_ref: &TypeRef) -> usize {
        match type_ref {
            TypeRef::Named(name) => self.get_type(name).map(|t| t.size(self.arch)).unwrap_or(0),
            _ => type_ref.size(self.arch),
        }
    }

    pub fn add_type(&mut self, ty: CompoundType) {
        self.types.insert(ty.name().to_string(), ty);
    }

    pub fn get_type(&self, name: &str) -> Option<&CompoundType> {
        self.types.get(name)
    }

    pub fn remove_type(&mut self, name: &str) -> Option<CompoundType> {
        self.types.remove(name)
    }

    pub fn add_struct_field(&mut self, struct_name: &str, field: StructField) {
        let field_size = self.size_of(&field.type_ref);
        if let Some(
            CompoundType::Struct { fields, size, .. } | CompoundType::Union { fields, size, .. },
        ) = self.types.get_mut(struct_name)
        {
            let field_end = field.offset + field_size;
            if field_end > *size {
                *size = field_end;
            }
            fields.push(field);
            fields.sort_by_key(|f| f.offset);
        }
    }

    pub fn annotate(&mut self, annotation: TypeAnnotation) {
        self.annotations.insert(annotation.address, annotation);
    }

    pub fn get_annotation(&self, address: u64) -> Option<&TypeAnnotation> {
        self.annotations.get(&address)
    }

    pub fn remove_annotation(&mut self, address: u64) -> Option<TypeAnnotation> {
        self.annotations.remove(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    #[test]
    fn primitive_sizes() {
        let arch = Architecture::X86_64;
        assert_eq!(PrimitiveType::U8.size(arch), 1);
        assert_eq!(PrimitiveType::U16.size(arch), 2);
        assert_eq!(PrimitiveType::U32.size(arch), 4);
        assert_eq!(PrimitiveType::U64.size(arch), 8);
        assert_eq!(PrimitiveType::F32.size(arch), 4);
        assert_eq!(PrimitiveType::F64.size(arch), 8);
        assert_eq!(PrimitiveType::Void.size(arch), 0);
        assert_eq!(PrimitiveType::Char.size(arch), 1);
        assert_eq!(PrimitiveType::WChar.size(arch), 2);
        assert_eq!(PrimitiveType::USize.size(arch), 8);
        assert_eq!(PrimitiveType::ISize.size(arch), 8);

        let arch32 = Architecture::X86;
        assert_eq!(PrimitiveType::USize.size(arch32), 4);
        assert_eq!(PrimitiveType::ISize.size(arch32), 4);
    }

    #[test]
    fn struct_creation() {
        let mut mgr = TypeManager::default();
        let s = CompoundType::Struct {
            name: "Point".to_string(),
            fields: vec![
                StructField {
                    name: "x".to_string(),
                    type_ref: TypeRef::Primitive(PrimitiveType::I32),
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                StructField {
                    name: "y".to_string(),
                    type_ref: TypeRef::Primitive(PrimitiveType::I32),
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
            size: 8,
        };
        mgr.add_type(s);
        let t = mgr.get_type("Point").unwrap();
        assert_eq!(t.size(Architecture::X86_64), 8);
        assert_eq!(t.kind_name(), "struct");
    }

    #[test]
    fn type_annotation() {
        let mut mgr = TypeManager::default();
        mgr.annotate(TypeAnnotation {
            address: 0x1000,
            type_ref: TypeRef::Primitive(PrimitiveType::U32),
            name: "counter".to_string(),
        });
        let ann = mgr.get_annotation(0x1000).unwrap();
        assert_eq!(ann.name, "counter");
    }

    #[test]
    fn type_ref_display() {
        assert_eq!(
            TypeRef::Primitive(PrimitiveType::U32).display_name(),
            "uint32_t"
        );
        assert_eq!(
            TypeRef::Array {
                element: Box::new(TypeRef::Primitive(PrimitiveType::U8)),
                count: 16
            }
            .display_name(),
            "uint8_t[16]"
        );
        assert_eq!(
            TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::I32))).display_name(),
            "int32_t*"
        );
        assert_eq!(
            TypeRef::Const(Box::new(TypeRef::Primitive(PrimitiveType::I32))).display_name(),
            "const int32_t"
        );
        assert_eq!(
            TypeRef::Volatile(Box::new(TypeRef::Primitive(PrimitiveType::U32))).display_name(),
            "volatile uint32_t"
        );
        assert_eq!(
            TypeRef::FunctionPointer {
                return_type: Box::new(TypeRef::Primitive(PrimitiveType::I32)),
                params: vec![
                    TypeRef::Pointer(Box::new(TypeRef::Const(Box::new(TypeRef::Primitive(
                        PrimitiveType::Char
                    ))))),
                    TypeRef::Primitive(PrimitiveType::I32),
                ],
                is_variadic: true,
            }
            .display_name(),
            "int32_t (*)(const char*, int32_t, ...)"
        );
    }

    #[test]
    fn enum_type() {
        let mut mgr = TypeManager::default();
        let e = CompoundType::Enum {
            name: "Color".to_string(),
            variants: vec![
                ("Red".to_string(), 0),
                ("Green".to_string(), 1),
                ("Blue".to_string(), 2),
            ],
            size: 4,
        };
        mgr.add_type(e);
        let t = mgr.get_type("Color").unwrap();
        assert_eq!(t.kind_name(), "enum");
        assert_eq!(t.size(Architecture::X86_64), 4);
    }

    #[test]
    fn function_signature_and_variables() {
        let mut mgr = TypeManager::default();
        mgr.function_signatures.insert(
            0x1000,
            FunctionSignature {
                name: "main".to_string(),
                return_type: TypeRef::Primitive(PrimitiveType::I32),
                parameters: vec![
                    FunctionParameter {
                        name: "argc".to_string(),
                        type_ref: TypeRef::Primitive(PrimitiveType::I32),
                    },
                    FunctionParameter {
                        name: "argv".to_string(),
                        type_ref: TypeRef::Pointer(Box::new(TypeRef::Pointer(Box::new(
                            TypeRef::Primitive(PrimitiveType::Char),
                        )))),
                    },
                ],
                calling_convention: "cdecl".to_string(),
                is_variadic: false,
            },
        );
        let sig = mgr.function_signatures.get(&0x1000).unwrap();
        assert_eq!(sig.name, "main");
        assert_eq!(sig.parameters.len(), 2);

        mgr.local_variables.insert(
            0x1000,
            vec![VariableInfo {
                name: "i".to_string(),
                type_ref: TypeRef::Primitive(PrimitiveType::I32),
                location: VariableLocation::Stack(-4),
            }],
        );
        assert_eq!(mgr.local_variables[&0x1000].len(), 1);

        mgr.source_lines.insert(
            0x1000,
            SourceLineInfo {
                file: "main.c".to_string(),
                line: 5,
                column: Some(1),
            },
        );
        assert_eq!(mgr.source_lines[&0x1000].file, "main.c");
    }
}
