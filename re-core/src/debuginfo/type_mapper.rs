use crate::types::{
    ClassInfo, CompoundType, FunctionParameter, PrimitiveType, StructField, TypeRef,
};
use gimli::{AttributeValue, DebuggingInformationEntry, Dwarf, Reader, Unit, UnitOffset};
use std::collections::HashMap;

/// Maps DWARF type offsets to our TypeRef system.
///
/// The key is `(unit header offset in .debug_info, die offset within unit)`.
pub struct TypeContext<R: Reader> {
    cache: HashMap<(usize, usize), TypeRef>,
    /// Types that have been fully resolved into CompoundTypes
    pub compound_types: Vec<CompoundType>,
    /// C++ class metadata (base-class edges) keyed by qualified class name.
    pub classes: HashMap<String, ClassInfo>,
    /// Namespace/class qualification prefix (e.g. `ns::Outer::`) for DIEs
    /// nested inside named scopes, keyed like `cache`. Populated by the scope
    /// prepass in `dwarf.rs` before any type resolution happens.
    pub scope_prefixes: HashMap<(usize, usize), String>,
    pub arch: crate::arch::Architecture,
    /// Current nesting depth of in-flight `resolve_type` calls. The cache's
    /// placeholder protects against *cyclic* type graphs but not against a
    /// crafted multi-thousand-link acyclic chain of pointer/const/typedef
    /// DIEs, which would overflow the stack (debug info is untrusted input).
    depth: u32,
    _phantom: std::marker::PhantomData<R>,
}

/// Deepest legitimate type nesting we expect; beyond this the chain is
/// treated as hostile and resolves to `void`.
const MAX_TYPE_DEPTH: u32 = 64;

/// Upper bound on emitted compound types — a crafted unit cannot balloon the
/// type list without bound.
const MAX_TOTAL_TYPES: usize = 200_000;

/// Upper bound on fields parsed for one struct/union.
const MAX_STRUCT_FIELDS: usize = 10_000;

/// Upper bound on variants parsed for one enum.
const MAX_ENUM_VARIANTS: usize = 10_000;

impl<R: Reader<Offset = usize>> TypeContext<R> {
    pub fn new(arch: crate::arch::Architecture) -> Self {
        Self {
            cache: HashMap::new(),
            compound_types: Vec::new(),
            classes: HashMap::new(),
            scope_prefixes: HashMap::new(),
            arch,
            depth: 0,
            _phantom: std::marker::PhantomData,
        }
    }

    /// The qualification prefix recorded for a DIE, or `""` for global scope.
    pub fn scope_prefix(&self, unit: &Unit<R>, offset: UnitOffset<R::Offset>) -> &str {
        self.scope_prefixes
            .get(&(unit.header.offset().0, offset.0))
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Whether the emitted-type cap has been reached.
    fn types_full(&self) -> bool {
        self.compound_types.len() >= MAX_TOTAL_TYPES
    }

    /// Resolve a DWARF type DIE reference to our TypeRef.
    pub fn resolve_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        type_offset: UnitOffset<R::Offset>,
    ) -> TypeRef {
        let unit_header_offset = unit.header.offset().0;
        let key = (unit_header_offset, type_offset.0);

        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }
        if self.depth >= MAX_TYPE_DEPTH {
            return TypeRef::Primitive(PrimitiveType::Void);
        }

        // Insert a placeholder to handle recursive types
        self.cache
            .insert(key, TypeRef::Named("<resolving>".to_string()));

        self.depth += 1;
        let resolved = self.resolve_type_inner(dwarf, unit, type_offset);
        self.depth -= 1;
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
            // References and pointers-to-member have no dedicated TypeRef —
            // a pointer is the closest model (same size and indirection).
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_ptr_to_member_type => {
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
                    let name = format!("{}{}", self.scope_prefix(unit, die.offset()), name);
                    if !self.types_full() {
                        self.compound_types.push(CompoundType::Typedef {
                            name: name.clone(),
                            target: target.clone(),
                        });
                    }
                    TypeRef::Named(name)
                } else {
                    target
                }
            }
            // C++ classes are structs with methods; the field layout is what
            // matters for analysis.
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                self.resolve_struct_type(dwarf, unit, &die, false)
            }
            gimli::DW_TAG_union_type => self.resolve_struct_type(dwarf, unit, &die, true),
            gimli::DW_TAG_enumeration_type => self.resolve_enum_type(dwarf, unit, &die),
            gimli::DW_TAG_array_type => self.resolve_array_type(dwarf, unit, &die),
            gimli::DW_TAG_subroutine_type => self.resolve_subroutine_type(dwarf, unit, &die),
            gimli::DW_TAG_restrict_type => self.resolve_referenced_type(dwarf, unit, &die),
            _ => TypeRef::Primitive(PrimitiveType::Void),
        }
    }

    fn resolve_base_type(&self, die: &DebuggingInformationEntry<R>) -> TypeRef {
        let encoding = die.attr_value(gimli::DW_AT_encoding).and_then(|v| match v {
            AttributeValue::Encoding(e) => Some(e),
            _ => None,
        });
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
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
        die: &DebuggingInformationEntry<R>,
    ) -> TypeRef {
        if let Some(attr) = die.attr_value(gimli::DW_AT_type)
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
        die: &DebuggingInformationEntry<R>,
        is_union: bool,
    ) -> TypeRef {
        let name = die_name_string(dwarf, unit, die);
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
            .and_then(|v| v.udata_value())
            .unwrap_or(0) as usize;

        let type_name = if name.is_empty() {
            // Derived from section offsets so the name is stable across runs
            // (a counter-based name shifts whenever resolution order does).
            format!(
                "anon_{}_{:x}_{:x}",
                if is_union { "union" } else { "struct" },
                unit.header.offset().0,
                die.offset().0
            )
        } else {
            format!("{}{}", self.scope_prefix(unit, die.offset()), name)
        };

        let (fields, base) = self.parse_struct_fields(dwarf, unit, die);

        if let Some(base_name) = base {
            self.classes
                .entry(type_name.clone())
                .or_default()
                .base
                .get_or_insert(base_name);
        }

        if !self.types_full() {
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
        }

        TypeRef::Named(type_name)
    }

    /// Parse the members of a struct/class/union DIE. Returns the fields and
    /// the name of the first `DW_TAG_inheritance` base class, if any.
    fn parse_struct_fields(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<R>,
    ) -> (Vec<StructField>, Option<String>) {
        let mut fields = Vec::new();
        let mut base: Option<String> = None;
        let Ok(mut tree) = unit.entries_tree(Some(die.offset())) else {
            return (fields, base);
        };
        let Ok(root) = tree.root() else {
            return (fields, base);
        };

        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            let entry = child.entry();
            if entry.tag() == gimli::DW_TAG_inheritance {
                if base.is_none()
                    && let TypeRef::Named(base_name) =
                        self.resolve_referenced_type(dwarf, unit, entry)
                {
                    base = Some(base_name);
                }
                continue;
            }
            if entry.tag() != gimli::DW_TAG_member {
                continue;
            }
            if fields.len() >= MAX_STRUCT_FIELDS {
                break;
            }

            let fname = die_name_string(dwarf, unit, entry);
            let ftype = self.resolve_referenced_type(dwarf, unit, entry);
            let mut offset = entry
                .attr_value(gimli::DW_AT_data_member_location)
                .and_then(|v| member_location_value(&v))
                .unwrap_or(0);

            let mut bit_offset = entry
                .attr_value(gimli::DW_AT_bit_offset)
                .and_then(|v| v.udata_value())
                .map(|v| v as u8);
            let bit_size = entry
                .attr_value(gimli::DW_AT_bit_size)
                .and_then(|v| v.udata_value())
                .map(|v| v as u8);

            // DWARF 5 bitfields: DW_AT_data_bit_offset is the bit distance
            // from the start of the containing struct.
            if let Some(dbo) = entry
                .attr_value(gimli::DW_AT_data_bit_offset)
                .and_then(|v| v.udata_value())
            {
                offset = (dbo / 8) as usize;
                bit_offset = Some((dbo % 8) as u8);
            }

            fields.push(StructField {
                name: fname,
                type_ref: ftype,
                offset,
                bit_offset,
                bit_size,
            });
        }

        (fields, base)
    }

    fn resolve_enum_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<R>,
    ) -> TypeRef {
        let name = die_name_string(dwarf, unit, die);
        let byte_size = die
            .attr_value(gimli::DW_AT_byte_size)
            .and_then(|v| v.udata_value())
            .unwrap_or(4) as usize;

        let type_name = if name.is_empty() {
            // Offset-derived so the name is stable across runs.
            format!(
                "anon_enum_{:x}_{:x}",
                unit.header.offset().0,
                die.offset().0
            )
        } else {
            format!("{}{}", self.scope_prefix(unit, die.offset()), name)
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
                if variants.len() >= MAX_ENUM_VARIANTS {
                    break;
                }
                let vname = die_name_string(dwarf, unit, entry);
                let value = entry
                    .attr_value(gimli::DW_AT_const_value)
                    .and_then(|v| {
                        v.sdata_value()
                            .or_else(|| v.udata_value().map(|u| u as i64))
                    })
                    .unwrap_or(0);
                variants.push((vname, value));
            }
        }

        if !self.types_full() {
            self.compound_types.push(CompoundType::Enum {
                name: type_name.clone(),
                variants,
                size: byte_size,
            });
        }

        TypeRef::Named(type_name)
    }

    fn resolve_array_type(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        die: &DebuggingInformationEntry<R>,
    ) -> TypeRef {
        let element = self.resolve_referenced_type(dwarf, unit, die);
        // Fold every DW_TAG_subrange_type — a multidimensional array carries
        // one subrange per dimension, and the total element count is their
        // product (saturating: dimensions come from untrusted input).
        let mut count = 1usize;
        let mut seen_dimension = false;

        if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
            && let Ok(root) = tree.root()
        {
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let entry = child.entry();
                if entry.tag() != gimli::DW_TAG_subrange_type {
                    continue;
                }
                let dim = if let Some(attr) = entry.attr_value(gimli::DW_AT_count) {
                    attr.udata_value().unwrap_or(0) as usize
                } else if let Some(attr) = entry.attr_value(gimli::DW_AT_upper_bound) {
                    attr.udata_value()
                        .map(|v| (v as usize).saturating_add(1))
                        .unwrap_or(0)
                } else {
                    // Unbounded dimension (e.g. `int[]`) — size unknown
                    0
                };
                seen_dimension = true;
                count = count.saturating_mul(dim);
            }
        }

        if !seen_dimension {
            count = 0;
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
        die: &DebuggingInformationEntry<R>,
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
        die: &DebuggingInformationEntry<R>,
    ) -> FunctionParameter {
        let name = die_name_string(dwarf, unit, die);
        let type_ref = self.resolve_referenced_type(dwarf, unit, die);
        FunctionParameter { name, type_ref }
    }
}

/// Extract a member offset from `DW_AT_data_member_location`, which is either
/// a plain constant or (older producers) a `DW_OP_plus_uconst` expression.
fn member_location_value<R: Reader>(attr: &AttributeValue<R>) -> Option<usize> {
    if let Some(v) = attr.udata_value() {
        return Some(v as usize);
    }
    if let AttributeValue::Exprloc(ref expr) = *attr {
        let mut bytes = expr.0.clone();
        // DW_OP_plus_uconst <uleb offset>
        if bytes.read_u8().ok()? == 0x23 {
            return bytes.read_uleb128().ok().map(|v| v as usize);
        }
    }
    None
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
            let unit_offset = unit.header.offset().0;
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
    die: &DebuggingInformationEntry<R>,
) -> String {
    die.attr_value(gimli::DW_AT_name)
        .and_then(|v| {
            let attr_str = dwarf.attr_string(unit, v).ok()?;
            let s = attr_str.to_string().ok()?;
            Some(s.to_string())
        })
        .unwrap_or_default()
}
