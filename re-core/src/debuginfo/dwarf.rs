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
pub fn extract_dwarf_info(
    bytes: &[u8],
    arch: crate::arch::Architecture,
) -> crate::Result<DebugInfo> {
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

    parse_dwarf(&dwarf, arch)
}

fn parse_dwarf<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    arch: crate::arch::Architecture,
) -> crate::Result<DebugInfo> {
    let mut info = DebugInfo::default();
    let mut type_ctx: TypeContext<SliceReader<'a>> = TypeContext::new(arch);

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
        while let Ok(Some(entry)) = entries.next_dfs() {
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

/// How many `DW_AT_specification`/`DW_AT_abstract_origin` links to follow
/// before treating the chain as hostile (debug info is untrusted input).
const MAX_SPEC_CHAIN_DEPTH: u32 = 8;

/// Look up an attribute on a DIE, following its
/// `DW_AT_specification`/`DW_AT_abstract_origin` chain when the DIE itself
/// lacks the attribute. C++ out-of-line definitions carry only a reference to
/// their in-class declaration, which holds the name and type.
fn chained_attr<'a>(
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
    attr: gimli::DwAt,
) -> Option<gimli::AttributeValue<SliceReader<'a>>> {
    if let Some(v) = die.attr_value(attr) {
        return Some(v);
    }
    let mut link = die
        .attr_value(gimli::DW_AT_specification)
        .or_else(|| die.attr_value(gimli::DW_AT_abstract_origin))?;
    for _ in 0..MAX_SPEC_CHAIN_DEPTH {
        let offset = attr_to_unit_offset(&link, unit)?;
        let entry = unit.entry(offset).ok()?;
        if let Some(v) = entry.attr_value(attr) {
            return Some(v);
        }
        link = entry
            .attr_value(gimli::DW_AT_specification)
            .or_else(|| entry.attr_value(gimli::DW_AT_abstract_origin))?;
    }
    None
}

/// Resolve a subprogram's display name: `DW_AT_name` on the DIE or its
/// specification chain, falling back to the linkage (mangled) name when no
/// source-level name exists.
fn subprogram_name<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
) -> String {
    for attr in [gimli::DW_AT_name, gimli::DW_AT_linkage_name] {
        if let Some(v) = chained_attr(unit, die, attr)
            && let Ok(s) = dwarf.attr_string(unit, v)
            && let Ok(s) = s.to_string()
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// Map `DW_AT_calling_convention` to a descriptive string. `DW_CC_normal` maps
/// to the empty string (the default convention needs no annotation).
fn map_dwarf_calling_convention(cc: gimli::DwCc) -> String {
    match cc.0 {
        0x01 => String::new(),         // DW_CC_normal
        0x02 => "program".to_string(), // DW_CC_program
        0x03 => "nocall".to_string(),  // DW_CC_nocall
        0x04 => "pass_by_reference".to_string(),
        0x05 => "pass_by_value".to_string(),
        0x41 | 0xb3 | 0xb6 => "fastcall".to_string(), // GNU/Borland fastcall
        0xb1 => "stdcall".to_string(),
        0xb2 => "pascal".to_string(),
        0xb5 => "thiscall".to_string(),
        0xc0 => "vectorcall".to_string(), // DW_CC_LLVM_vectorcall
        0xc1 => "win64".to_string(),      // DW_CC_LLVM_Win64
        0xc2 => "sysv64".to_string(),     // DW_CC_LLVM_X86_64SysV
        other => format!("cc_{:#x}", other),
    }
}

fn parse_subprogram<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
    type_ctx: &mut TypeContext<SliceReader<'a>>,
    info: &mut DebugInfo,
) {
    // Get low_pc (function address). `attr_address` also resolves DWARF-5
    // `DW_FORM_addrx` indices through `.debug_addr` (clang's default form).
    let low_pc = die
        .attr_value(gimli::DW_AT_low_pc)
        .and_then(|v| dwarf.attr_address(unit, v).ok().flatten());

    let addr = match low_pc {
        Some(a) if a != 0 => a,
        _ => return,
    };

    let name = subprogram_name(dwarf, unit, die);
    let name = if name.is_empty() {
        format!("sub_{:x}", addr)
    } else {
        name
    };

    // Return type (also found via the specification chain for out-of-line
    // C++ method definitions).
    let return_type = if let Some(attr) = chained_attr(unit, die, gimli::DW_AT_type) {
        if let Some(offset) = attr_to_unit_offset(&attr, unit) {
            type_ctx.resolve_type(dwarf, unit, offset)
        } else {
            TypeRef::Primitive(PrimitiveType::Void)
        }
    } else {
        TypeRef::Primitive(PrimitiveType::Void)
    };

    let calling_convention = chained_attr(unit, die, gimli::DW_AT_calling_convention)
        .and_then(|v| match v {
            gimli::AttributeValue::CallingConvention(cc) => Some(cc),
            _ => None,
        })
        .map(map_dwarf_calling_convention)
        .unwrap_or_default();

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
        calling_convention,
        is_variadic,
        source: crate::types::SignatureSource::DebugInfo,
    };

    info.function_signatures.insert(addr, sig);

    if !locals.is_empty() {
        info.local_variables.insert(addr, locals);
    }
}

fn parse_variable<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
    type_ctx: &mut TypeContext<SliceReader<'a>>,
) -> Option<VariableInfo> {
    let name = die_name_string(dwarf, unit, die);
    if name.is_empty() {
        return None;
    }

    let type_ref = if let Some(attr) = die.attr_value(gimli::DW_AT_type) {
        if let Some(offset) = attr_to_unit_offset(&attr, unit) {
            type_ctx.resolve_type(dwarf, unit, offset)
        } else {
            TypeRef::Primitive(PrimitiveType::Void)
        }
    } else {
        TypeRef::Primitive(PrimitiveType::Void)
    };

    let location = parse_location(dwarf, unit, die);

    Some(VariableInfo {
        name,
        type_ref,
        location,
    })
}

fn parse_location<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
) -> VariableLocation {
    if let Some(attr) = die.attr_value(gimli::DW_AT_location) {
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
                        0xa1 => {
                            // DW_OP_addrx — ULEB128 index into .debug_addr
                            if let Some(index) = read_uleb128(&bytes[1..])
                                && let Ok(addr) =
                                    dwarf.address(unit, gimli::DebugAddrIndex(index as usize))
                            {
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

fn read_uleb128(bytes: &[u8]) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for &byte in bytes {
        // Bits past 64 in a crafted over-long ULEB128 are rejected rather
        // than silently truncated.
        if shift >= 64 {
            return None;
        }
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

fn read_sleb128(bytes: &[u8]) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    for &byte in bytes {
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                // Sign-extend. `(-1) << shift` (not `-(1 << shift)`) — the
                // latter overflows at shift 63, which a crafted 9-byte
                // SLEB128 in an exprloc reaches (panic in debug builds).
                result |= (-1i64) << shift;
            }
            return Some(result);
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calling_convention_mapping() {
        assert_eq!(map_dwarf_calling_convention(gimli::DW_CC_normal), "");
        assert_eq!(map_dwarf_calling_convention(gimli::DW_CC_nocall), "nocall");
        assert_eq!(
            map_dwarf_calling_convention(gimli::DW_CC_pass_by_value),
            "pass_by_value"
        );
        assert_eq!(map_dwarf_calling_convention(gimli::DwCc(0xb1)), "stdcall");
        assert_eq!(map_dwarf_calling_convention(gimli::DwCc(0xb5)), "thiscall");
        assert_eq!(
            map_dwarf_calling_convention(gimli::DwCc(0xc0)),
            "vectorcall"
        );
        // Unknown conventions keep the raw value visible instead of vanishing
        assert_eq!(map_dwarf_calling_convention(gimli::DwCc(0x99)), "cc_0x99");
    }

    #[test]
    fn uleb128_decoding() {
        assert_eq!(read_uleb128(&[0x00]), Some(0));
        assert_eq!(read_uleb128(&[0x7f]), Some(127));
        assert_eq!(read_uleb128(&[0x80, 0x01]), Some(128));
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26]), Some(624485));
        // Truncated (continuation bit set on last byte)
        assert_eq!(read_uleb128(&[0x80]), None);
        assert_eq!(read_uleb128(&[]), None);
        // Over-long hostile encoding must not panic
        assert_eq!(read_uleb128(&[0xff; 16]), None);
    }

    #[test]
    fn sleb128_decoding() {
        assert_eq!(read_sleb128(&[0x00]), Some(0));
        assert_eq!(read_sleb128(&[0x7f]), Some(-1));
        assert_eq!(read_sleb128(&[0x78]), Some(-8));
        assert_eq!(read_sleb128(&[0x80, 0x7f]), Some(-128));
        assert_eq!(read_sleb128(&[0x80]), None);
    }
}
