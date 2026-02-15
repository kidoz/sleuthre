use crate::debuginfo::DebugInfo;
use crate::debuginfo::source_map::parse_source_lines;
use crate::debuginfo::type_mapper::{TypeContext, attr_to_unit_offset, die_name_string};
use crate::types::{FunctionSignature, PrimitiveType, TypeRef, VariableInfo, VariableLocation};
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};

type SliceReader<'a> = EndianSlice<'a, RunTimeEndian>;

/// Extract DWARF debug info from raw binary bytes.
///
/// If the binary has no DWARF sections, returns an empty `DebugInfo`.
pub fn extract_dwarf_info(bytes: &[u8]) -> crate::Result<DebugInfo> {
    let obj = match object::File::parse(bytes) {
        Ok(o) => o,
        Err(_) => return Ok(DebugInfo::default()),
    };

    // Check if we even have debug info
    if obj.section_by_name(".debug_info").is_none() {
        return Ok(DebugInfo::default());
    }

    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<SliceReader<'_>, gimli::Error> {
        let data = obj
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, endian))
    };

    let dwarf = Dwarf::load(&load_section)
        .map_err(|e| crate::error::Error::DebugInfo(format!("DWARF load error: {}", e)))?;

    parse_dwarf(&dwarf)
}

fn parse_dwarf<'a>(dwarf: &'a Dwarf<SliceReader<'a>>) -> crate::Result<DebugInfo> {
    let mut info = DebugInfo::default();
    let mut type_ctx: TypeContext<SliceReader<'a>> = TypeContext::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };

        // Parse source lines for this compilation unit
        let source_lines = parse_source_lines(dwarf, &unit);
        info.source_lines.extend(source_lines);

        // Walk DIEs in this unit
        let mut entries = unit.entries();
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    parse_subprogram(dwarf, &unit, entry, &mut type_ctx, &mut info);
                }
                gimli::DW_TAG_variable => {
                    if let Some(var) = parse_variable(dwarf, &unit, entry, &mut type_ctx)
                        && let VariableLocation::Address(addr) = var.location
                        && addr != 0
                    {
                        info.global_variables.insert(addr, var);
                    }
                }
                gimli::DW_TAG_structure_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_enumeration_type
                | gimli::DW_TAG_typedef => {
                    type_ctx.resolve_type(dwarf, &unit, entry.offset());
                }
                _ => {}
            }
        }
    }

    info.types = type_ctx.compound_types;
    Ok(info)
}

fn parse_subprogram<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<'_, '_, SliceReader<'a>>,
    type_ctx: &mut TypeContext<SliceReader<'a>>,
    info: &mut DebugInfo,
) {
    // Get low_pc (function address)
    let low_pc = die
        .attr_value(gimli::DW_AT_low_pc)
        .ok()
        .flatten()
        .and_then(|v| match v {
            gimli::AttributeValue::Addr(a) => Some(a),
            _ => None,
        });

    let addr = match low_pc {
        Some(a) if a != 0 => a,
        _ => return,
    };

    let name = die_name_string(dwarf, unit, die);
    let name = if name.is_empty() {
        format!("sub_{:x}", addr)
    } else {
        name
    };

    // Return type
    let return_type = if let Ok(Some(attr)) = die.attr_value(gimli::DW_AT_type) {
        if let Some(offset) = attr_to_unit_offset(&attr, unit) {
            type_ctx.resolve_type(dwarf, unit, offset)
        } else {
            TypeRef::Primitive(PrimitiveType::Void)
        }
    } else {
        TypeRef::Primitive(PrimitiveType::Void)
    };

    // Parse parameters and local variables from children
    let mut parameters = Vec::new();
    let mut locals = Vec::new();
    let mut is_variadic = false;

    if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
        && let Ok(root) = tree.root()
    {
        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            let child_entry = child.entry();
            match child_entry.tag() {
                gimli::DW_TAG_formal_parameter => {
                    let param = type_ctx.resolve_parameter(dwarf, unit, child_entry);
                    parameters.push(param);
                }
                gimli::DW_TAG_unspecified_parameters => {
                    is_variadic = true;
                }
                gimli::DW_TAG_variable => {
                    if let Some(var) = parse_variable(dwarf, unit, child_entry, type_ctx) {
                        locals.push(var);
                    }
                }
                _ => {}
            }
        }
    }

    let sig = FunctionSignature {
        name,
        return_type,
        parameters,
        calling_convention: String::new(),
        is_variadic,
    };

    info.function_signatures.insert(addr, sig);

    if !locals.is_empty() {
        info.local_variables.insert(addr, locals);
    }
}

fn parse_variable<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<'_, '_, SliceReader<'a>>,
    type_ctx: &mut TypeContext<SliceReader<'a>>,
) -> Option<VariableInfo> {
    let name = die_name_string(dwarf, unit, die);
    if name.is_empty() {
        return None;
    }

    let type_ref = if let Ok(Some(attr)) = die.attr_value(gimli::DW_AT_type) {
        if let Some(offset) = attr_to_unit_offset(&attr, unit) {
            type_ctx.resolve_type(dwarf, unit, offset)
        } else {
            TypeRef::Primitive(PrimitiveType::Void)
        }
    } else {
        TypeRef::Primitive(PrimitiveType::Void)
    };

    let location = parse_location(die);

    Some(VariableInfo {
        name,
        type_ref,
        location,
    })
}

fn parse_location(
    die: &gimli::DebuggingInformationEntry<'_, '_, SliceReader<'_>>,
) -> VariableLocation {
    if let Ok(Some(attr)) = die.attr_value(gimli::DW_AT_location) {
        match attr {
            gimli::AttributeValue::Exprloc(expr) => {
                let bytes = expr.0.slice();
                if !bytes.is_empty() {
                    match bytes[0] {
                        0x91 => {
                            // DW_OP_fbreg — SLEB128 offset from frame base
                            if let Some(offset) = read_sleb128(&bytes[1..]) {
                                return VariableLocation::Stack(offset);
                            }
                        }
                        0x03 => {
                            // DW_OP_addr
                            if bytes.len() >= 9 {
                                let addr = u64::from_le_bytes([
                                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                                    bytes[7], bytes[8],
                                ]);
                                return VariableLocation::Address(addr);
                            } else if bytes.len() >= 5 {
                                let addr =
                                    u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
                                        as u64;
                                return VariableLocation::Address(addr);
                            }
                        }
                        op if (0x50..=0x6f).contains(&op) => {
                            // DW_OP_reg0..DW_OP_reg31
                            let reg_num = op - 0x50;
                            return VariableLocation::Register(format!("reg{}", reg_num));
                        }
                        _ => {}
                    }
                }
            }
            gimli::AttributeValue::Addr(addr) => {
                return VariableLocation::Address(addr);
            }
            _ => {}
        }
    }

    VariableLocation::Stack(0)
}

fn read_sleb128(bytes: &[u8]) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    for &byte in bytes {
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            return Some(result);
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}
