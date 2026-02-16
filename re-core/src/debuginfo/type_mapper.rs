use crate::types::{CompoundType, FunctionParameter, PrimitiveType, StructField, TypeRef};
use gimli::{AttributeValue, DebuggingInformationEntry, Dwarf, Reader, Unit, UnitOffset};
use std::collections::HashMap;

/// Maps DWARF type offsets to our TypeRef system.
///
/// The key is `(unit header offset in .debug_info, die offset within unit)`.
pub struct TypeContext<R: Reader> {
    cache: HashMap<(usize, usize), TypeRef>,
    /// Types that have been fully resolved into CompoundTypes
    pub compound_types: Vec<CompoundType>,
    pub arch: crate::arch::Architecture,
    _phantom: std::marker::PhantomData<R>,
}

impl<R: Reader<Offset = usize>> TypeContext<R> {
    pub fn new(arch: crate::arch::Architecture) -> Self {
        Self {
            cache: HashMap::new(),
            compound_types: Vec::new(),
            arch,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Resolve a DWARF type DIE reference to our TypeRef.
    pub fn resolve_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        type_offset: UnitOffset<R::Offset>,
    ) -> TypeRef {
        let unit_header_offset = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0,
            gimli::UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        let key = (unit_header_offset, type_offset.0);

        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        // Insert a placeholder to handle recursive types
        self.cache
            .insert(key, TypeRef::Named("<resolving>".to_string()));

        let resolved = self.resolve_type_inner(dwarf, unit, type_offset);
        self.cache.insert(key, resolved.clone());
        resolved
    }

    fn resolve_type_inner(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        type_offset: UnitOffset<R::Offset>,
    ) -> TypeRef {
        let Ok(die) = unit.entry(type_offset) else {
            return TypeRef::Primitive(PrimitiveType::Void);
        };

        match die.tag() {
            gimli::DW_TAG_base_type => self.resolve_base_type(&die),
            gimli::DW_TAG_pointer_type => {
                let inner = self.resolve_referenced_type(dwarf, unit, &die);
                TypeRef::Pointer(Box::new(inner))
            }
            gimli::DW_TAG_const_type => {
                let inner = self.resolve_referenced_type(dwarf, unit, &die);
                TypeRef::Const(Box::new(inner))
            }
            gimli::DW_TAG_volatile_type => {
                let inner = self.resolve_referenced_type(dwarf, unit, &die);
                TypeRef::Volatile(Box::new(inner))
            }
            gimli::DW_TAG_typedef => {
                let name = die_name_string(dwarf, unit, &die);
                let target = self.resolve_referenced_type(dwarf, unit, &die);
                if !name.is_empty() {
                    self.compound_types.push(CompoundType::Typedef {
                        name: name.clone(),
                        target: target.clone(),
                    });
                    TypeRef::Named(name)
                } else {
                    target
                }
            }
            gimli::DW_TAG_structure_type => self.resolve_struct_type(dwarf, unit, &die, false),
            gimli::DW_TAG_union_type => self.resolve_struct_type(dwarf, unit, &die, true),
            gimli::DW_TAG_enumeration_type => self.resolve_enum_type(dwarf, unit, &die),
            gimli::DW_TAG_array_type => self.resolve_array_type(dwarf, unit, &die),
            gimli::DW_TAG_subroutine_type => self.resolve_subroutine_type(dwarf, unit, &die),
            gimli::DW_TAG_restrict_type => self.resolve_referenced_type(dwarf, unit, &die),
            _ => TypeRef::Primitive(PrimitiveType::Void),
        }
    }

    fn resolve_base_type(&self, die: &DebuggingInformationEntry<'_, '_, R>) -> TypeRef {
        let encoding = die
            .attr_value(gimli::DW_AT_encoding)
            .ok()
            .flatten()
            .and_then(|v| match v {
                AttributeValue::Encoding(e) => Some(e),
                _ => None,
            });
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        let prim = match encoding {
            Some(gimli::DW_ATE_boolean) => PrimitiveType::Bool,
            Some(gimli::DW_ATE_signed_char) | Some(gimli::DW_ATE_unsigned_char) => {
                if byte_size <= 1 {
                    PrimitiveType::Char
                } else {
                    PrimitiveType::WChar
                }
            }
            Some(gimli::DW_ATE_signed) => match byte_size {
                1 => PrimitiveType::I8,
                2 => PrimitiveType::I16,
                4 => PrimitiveType::I32,
                8 => PrimitiveType::I64,
                s if s == self.arch.pointer_size() as u64 => PrimitiveType::ISize,
                _ => PrimitiveType::I32,
            },
            Some(gimli::DW_ATE_unsigned) => match byte_size {
                1 => PrimitiveType::U8,
                2 => PrimitiveType::U16,
                4 => PrimitiveType::U32,
                8 => PrimitiveType::U64,
                s if s == self.arch.pointer_size() as u64 => PrimitiveType::USize,
                _ => PrimitiveType::U32,
            },
            Some(gimli::DW_ATE_float) => match byte_size {
                4 => PrimitiveType::F32,
                8 => PrimitiveType::F64,
                _ => PrimitiveType::F64,
            },
            _ => {
                if byte_size == self.arch.pointer_size() as u64 {
                    PrimitiveType::Pointer
                } else {
                    PrimitiveType::Void
                }
            }
        };

        TypeRef::Primitive(prim)
    }

    fn resolve_referenced_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> TypeRef {
        if let Ok(Some(attr)) = die.attr_value(gimli::DW_AT_type)
            && let Some(offset) = attr_to_unit_offset(&attr, unit)
        {
            return self.resolve_type(dwarf, unit, offset);
        }
        TypeRef::Primitive(PrimitiveType::Void)
    }

    fn resolve_struct_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
        is_union: bool,
    ) -> TypeRef {
        let name = die_name_string(dwarf, unit, die);
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0) as usize;

        let type_name = if name.is_empty() {
            format!(
                "anon_{}_{}",
                if is_union { "union" } else { "struct" },
                self.compound_types.len()
            )
        } else {
            name
        };

        let fields = self.parse_struct_fields(dwarf, unit, die);

        if is_union {
            self.compound_types.push(CompoundType::Union {
                name: type_name.clone(),
                fields,
                size: byte_size,
            });
        } else {
            self.compound_types.push(CompoundType::Struct {
                name: type_name.clone(),
                fields,
                size: byte_size,
            });
        }

        TypeRef::Named(type_name)
    }

    fn parse_struct_fields(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> Vec<StructField> {
        let mut fields = Vec::new();
        let Ok(mut tree) = unit.entries_tree(Some(die.offset())) else {
            return fields;
        };
        let Ok(root) = tree.root() else {
            return fields;
        };

        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            let entry = child.entry();
            if entry.tag() != gimli::DW_TAG_member {
                continue;
            }

            let fname = die_name_string(dwarf, unit, entry);
            let ftype = self.resolve_referenced_type(dwarf, unit, entry);
            let offset = entry
                .attr_value(gimli::DW_AT_data_member_location)
                .ok()
                .flatten()
                .and_then(|v| v.udata_value())
                .unwrap_or(0) as usize;

            let bit_offset = entry
                .attr_value(gimli::DW_AT_bit_offset)
                .ok()
                .flatten()
                .and_then(|v| v.udata_value())
                .map(|v| v as u8);
            let bit_size = entry
                .attr_value(gimli::DW_AT_bit_size)
                .ok()
                .flatten()
                .and_then(|v| v.udata_value())
                .map(|v| v as u8);

            fields.push(StructField {
                name: fname,
                type_ref: ftype,
                offset,
                bit_offset,
                bit_size,
            });
        }

        fields
    }

    fn resolve_enum_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> TypeRef {
        let name = die_name_string(dwarf, unit, die);
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(4) as usize;

        let type_name = if name.is_empty() {
            format!("anon_enum_{}", self.compound_types.len())
        } else {
            name
        };

        let mut variants = Vec::new();
        if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
            && let Ok(root) = tree.root()
        {
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let entry = child.entry();
                if entry.tag() != gimli::DW_TAG_enumerator {
                    continue;
                }
                let vname = die_name_string(dwarf, unit, entry);
                let value = entry
                    .attr_value(gimli::DW_AT_const_value)
                    .ok()
                    .flatten()
                    .and_then(|v| {
                        v.sdata_value()
                            .or_else(|| v.udata_value().map(|u| u as i64))
                    })
                    .unwrap_or(0);
                variants.push((vname, value));
            }
        }

        self.compound_types.push(CompoundType::Enum {
            name: type_name.clone(),
            variants,
            size: byte_size,
        });

        TypeRef::Named(type_name)
    }

    fn resolve_array_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> TypeRef {
        let element = self.resolve_referenced_type(dwarf, unit, die);
        let mut count = 0usize;

        if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
            && let Ok(root) = tree.root()
        {
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let entry = child.entry();
                if entry.tag() == gimli::DW_TAG_subrange_type {
                    if let Ok(Some(attr)) = entry.attr_value(gimli::DW_AT_count) {
                        count = attr.udata_value().unwrap_or(0) as usize;
                    } else if let Ok(Some(attr)) = entry.attr_value(gimli::DW_AT_upper_bound) {
                        count = attr.udata_value().map(|v| v as usize + 1).unwrap_or(0);
                    }
                }
            }
        }

        TypeRef::Array {
            element: Box::new(element),
            count,
        }
    }

    fn resolve_subroutine_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> TypeRef {
        let return_type = self.resolve_referenced_type(dwarf, unit, die);
        let mut params = Vec::new();
        let mut is_variadic = false;

        if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
            && let Ok(root) = tree.root()
        {
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let entry = child.entry();
                match entry.tag() {
                    gimli::DW_TAG_formal_parameter => {
                        let ptype = self.resolve_referenced_type(dwarf, unit, entry);
                        params.push(ptype);
                    }
                    gimli::DW_TAG_unspecified_parameters => {
                        is_variadic = true;
                    }
                    _ => {}
                }
            }
        }

        TypeRef::FunctionPointer {
            return_type: Box::new(return_type),
            params,
            is_variadic,
        }
    }

    /// Resolve a type attr into a FunctionParameter.
    pub fn resolve_parameter(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<'_, '_, R>,
    ) -> FunctionParameter {
        let name = die_name_string(dwarf, unit, die);
        let type_ref = self.resolve_referenced_type(dwarf, unit, die);
        FunctionParameter { name, type_ref }
    }
}

/// Convert a DW_AT_type attribute value to a UnitOffset.
pub fn attr_to_unit_offset<R: Reader<Offset = usize>>(
    attr: &AttributeValue<R>,
    unit: &Unit<R>,
) -> Option<UnitOffset<R::Offset>> {
    match *attr {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(di_offset) => {
            // Convert DebugInfoRef to UnitOffset by subtracting unit header offset + size
            let unit_offset = match unit.header.offset() {
                gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0,
                gimli::UnitSectionOffset::DebugTypesOffset(o) => o.0,
            };
            let header_size = unit.header.size_of_header();
            let offset_val = di_offset.0;
            // The UnitOffset is relative to the start of the unit's data (after header)
            if offset_val >= unit_offset + header_size {
                Some(UnitOffset(offset_val - unit_offset))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the DW_AT_name of a DIE as a String.
pub fn die_name_string<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    die: &DebuggingInformationEntry<'_, '_, R>,
) -> String {
    die.attr_value(gimli::DW_AT_name)
        .ok()
        .flatten()
        .and_then(|v| {
            let attr_str = dwarf.attr_string(unit, v).ok()?;
            let s = attr_str.to_string().ok()?;
            Some(s.to_string())
        })
        .unwrap_or_default()
}
