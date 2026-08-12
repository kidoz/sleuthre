use crate::debuginfo::DebugInfo;
use crate::debuginfo::source_map::parse_source_lines;
use crate::debuginfo::type_mapper::{TypeContext, attr_to_unit_offset, die_name_string};
use crate::types::{
    FunctionParameter, FunctionSignature, PrimitiveType, TypeRef, VariableInfo, VariableLocation,
};
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

    // Parse parameters and local variables from children, descending into
    // nested lexical blocks (block-scoped locals would otherwise be lost).
    let mut scope = CollectedScope::default();
    if let Ok(mut tree) = unit.entries_tree(Some(die.offset()))
        && let Ok(root) = tree.root()
    {
        collect_scope(dwarf, unit, root, type_ctx, &mut scope, 0);
    }

    let sig = FunctionSignature {
        name,
        return_type,
        parameters: scope.parameters,
        calling_convention,
        is_variadic: scope.is_variadic,
        source: crate::types::SignatureSource::DebugInfo,
    };

    info.function_signatures.insert(addr, sig);

    if !scope.locals.is_empty() {
        info.local_variables.insert(addr, scope.locals);
    }
}

/// Parameters and locals collected from a subprogram subtree.
#[derive(Default)]
struct CollectedScope {
    parameters: Vec<FunctionParameter>,
    locals: Vec<VariableInfo>,
    is_variadic: bool,
}

/// Deepest lexical-block nesting we follow inside a subprogram; beyond this
/// the tree is treated as hostile (recursion depth is bounded by it).
const MAX_LEXICAL_BLOCK_DEPTH: u32 = 32;

/// Upper bound on variables collected for one function, so a crafted DIE tree
/// cannot balloon memory.
const MAX_LOCALS_PER_FUNCTION: usize = 10_000;

fn collect_scope<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    node: gimli::EntriesTreeNode<'_, '_, SliceReader<'a>>,
    type_ctx: &mut TypeContext<SliceReader<'a>>,
    out: &mut CollectedScope,
    depth: u32,
) {
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        let tag = child.entry().tag();
        match tag {
            gimli::DW_TAG_formal_parameter => {
                if depth == 0 {
                    let param = type_ctx.resolve_parameter(dwarf, unit, child.entry());
                    out.parameters.push(param);
                } else if out.locals.len() < MAX_LOCALS_PER_FUNCTION
                    && let Some(var) = parse_variable(dwarf, unit, child.entry(), type_ctx)
                {
                    // A parameter re-homed into a nested scope (e.g. by an
                    // inlined instance) is surfaced as a local.
                    out.locals.push(var);
                }
            }
            gimli::DW_TAG_unspecified_parameters => {
                if depth == 0 {
                    out.is_variadic = true;
                }
            }
            gimli::DW_TAG_variable => {
                if out.locals.len() < MAX_LOCALS_PER_FUNCTION
                    && let Some(var) = parse_variable(dwarf, unit, child.entry(), type_ctx)
                {
                    out.locals.push(var);
                }
            }
            gimli::DW_TAG_lexical_block if depth < MAX_LEXICAL_BLOCK_DEPTH => {
                collect_scope(dwarf, unit, child, type_ctx, out, depth + 1);
            }
            _ => {}
        }
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

    // A variable whose location is absent or undecodable is skipped rather
    // than fabricated at stack offset 0 (indistinguishable from a real local).
    let location = parse_location(dwarf, unit, die, type_ctx.arch)?;

    Some(VariableInfo {
        name,
        type_ref,
        location,
    })
}

/// Map a DWARF register number to a display name for the architecture.
fn dwarf_register_name(arch: crate::arch::Architecture, reg: u8) -> String {
    use crate::arch::Architecture;
    match arch {
        Architecture::X86_64 => match reg {
            0 => "rax".to_string(),
            1 => "rdx".to_string(),
            2 => "rcx".to_string(),
            3 => "rbx".to_string(),
            4 => "rsi".to_string(),
            5 => "rdi".to_string(),
            6 => "rbp".to_string(),
            7 => "rsp".to_string(),
            8..=15 => format!("r{}", reg),
            _ => format!("reg{}", reg),
        },
        Architecture::X86 => match reg {
            0 => "eax".to_string(),
            1 => "ecx".to_string(),
            2 => "edx".to_string(),
            3 => "ebx".to_string(),
            4 => "esp".to_string(),
            5 => "ebp".to_string(),
            6 => "esi".to_string(),
            7 => "edi".to_string(),
            _ => format!("reg{}", reg),
        },
        Architecture::Arm64 => match reg {
            0..=28 => format!("x{}", reg),
            29 => "fp".to_string(),
            30 => "lr".to_string(),
            31 => "sp".to_string(),
            _ => format!("reg{}", reg),
        },
        Architecture::Arm => match reg {
            0..=10 => format!("r{}", reg),
            11 => "fp".to_string(),
            12 => "ip".to_string(),
            13 => "sp".to_string(),
            14 => "lr".to_string(),
            15 => "pc".to_string(),
            _ => format!("reg{}", reg),
        },
        _ => format!("reg{}", reg),
    }
}

/// Whether a DWARF register number is the frame or stack pointer for the
/// architecture — `DW_OP_breg` off these registers is a stack slot.
fn is_frame_or_stack_register(arch: crate::arch::Architecture, reg: u8) -> bool {
    use crate::arch::Architecture;
    matches!(
        (arch, reg),
        (Architecture::X86_64, 6 | 7)
            | (Architecture::X86, 4 | 5)
            | (Architecture::Arm64, 29 | 31)
            | (Architecture::Arm, 11 | 13)
            | (Architecture::Mips | Architecture::Mips64, 29 | 30)
            | (Architecture::RiscV32 | Architecture::RiscV64, 2 | 8)
    )
}

fn parse_location<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    die: &gimli::DebuggingInformationEntry<SliceReader<'a>>,
    arch: crate::arch::Architecture,
) -> Option<VariableLocation> {
    match die.attr_value(gimli::DW_AT_location)? {
        gimli::AttributeValue::Exprloc(expr) => {
            decode_location_expr(dwarf, unit, expr.0.slice(), arch)
        }
        gimli::AttributeValue::Addr(addr) => Some(VariableLocation::Address(addr)),
        // Location lists (variables that move between locations) and any
        // other form are not modelled — skip the variable.
        _ => None,
    }
}

/// Decode the leading operation of a DWARF location expression. Unknown or
/// truncated expressions yield `None` so the caller drops the variable.
fn decode_location_expr<'a>(
    dwarf: &'a Dwarf<SliceReader<'a>>,
    unit: &gimli::Unit<SliceReader<'a>>,
    bytes: &[u8],
    arch: crate::arch::Architecture,
) -> Option<VariableLocation> {
    let (&op, rest) = bytes.split_first()?;
    match op {
        // DW_OP_fbreg — SLEB128 offset from frame base
        0x91 => read_sleb128(rest).map(VariableLocation::Stack),
        // DW_OP_addr
        0x03 => {
            if rest.len() >= 8 {
                let addr = u64::from_le_bytes([
                    rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
                ]);
                Some(VariableLocation::Address(addr))
            } else if rest.len() >= 4 {
                let addr = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64;
                Some(VariableLocation::Address(addr))
            } else {
                None
            }
        }
        // DW_OP_addrx — ULEB128 index into .debug_addr
        0xa1 => {
            let index = read_uleb128(rest)?;
            dwarf
                .address(unit, gimli::DebugAddrIndex(index as usize))
                .ok()
                .map(VariableLocation::Address)
        }
        // DW_OP_reg0..DW_OP_reg31
        0x50..=0x6f => {
            let reg = op - 0x50;
            Some(VariableLocation::Register(dwarf_register_name(arch, reg)))
        }
        // DW_OP_breg0..DW_OP_breg31 — base register + SLEB128 offset. Off the
        // frame/stack pointer this is a stack slot; off any other register the
        // variable lives relative to that register.
        0x70..=0x8f => {
            let reg = op - 0x70;
            let offset = read_sleb128(rest)?;
            if is_frame_or_stack_register(arch, reg) {
                Some(VariableLocation::Stack(offset))
            } else {
                Some(VariableLocation::Register(dwarf_register_name(arch, reg)))
            }
        }
        _ => None,
    }
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
    fn register_naming_and_frame_detection() {
        use crate::arch::Architecture;
        assert_eq!(dwarf_register_name(Architecture::X86_64, 6), "rbp");
        assert_eq!(dwarf_register_name(Architecture::X86_64, 7), "rsp");
        assert_eq!(dwarf_register_name(Architecture::X86_64, 12), "r12");
        assert_eq!(dwarf_register_name(Architecture::X86, 5), "ebp");
        assert_eq!(dwarf_register_name(Architecture::Arm64, 29), "fp");
        assert_eq!(dwarf_register_name(Architecture::Arm64, 3), "x3");
        assert_eq!(dwarf_register_name(Architecture::Mips, 29), "reg29");

        assert!(is_frame_or_stack_register(Architecture::X86_64, 6));
        assert!(is_frame_or_stack_register(Architecture::X86_64, 7));
        assert!(!is_frame_or_stack_register(Architecture::X86_64, 0));
        assert!(is_frame_or_stack_register(Architecture::X86, 5));
        assert!(is_frame_or_stack_register(Architecture::Arm64, 31));
        assert!(is_frame_or_stack_register(Architecture::RiscV64, 2));
        assert!(!is_frame_or_stack_register(Architecture::Arm, 0));
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
