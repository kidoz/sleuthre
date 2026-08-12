//! Stack frame analysis and local variable recovery.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A recovered stack variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackVariable {
    /// Offset from the base register (negative = below it).
    pub offset: i64,
    /// Inferred size in bytes (from access width).
    pub size: u64,
    /// Auto-generated or user-assigned name.
    pub name: String,
    /// Inferred type hint.
    pub type_hint: StackVarType,
    /// Register class the slot is addressed from.
    #[serde(default)]
    pub base: StackBase,
}

/// The register class a stack slot is addressed from.
///
/// The distinction drives classification: only frame-pointer-relative slots
/// above the saved frame pointer / return address are incoming stack
/// arguments. Stack-pointer-relative slots are always locals — in
/// frame-pointer-omitted code positive `sp` offsets are plain locals, not
/// arguments.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum StackBase {
    /// `rbp`/`ebp`/`x29`-relative.
    #[default]
    FramePointer,
    /// `rsp`/`esp`/`sp`-relative.
    StackPointer,
}

/// What a stack slot holds, derived purely from its location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotKind {
    /// A local variable (or an outgoing-call staging slot).
    Local,
    /// The saved frame pointer (`fp+0`) or return address (`fp+word`) region.
    SavedRegister,
    /// An incoming stack-passed argument (`fp + 2*word` and above).
    Argument,
}

/// Classify a slot from its base and offset alone. `word` is the target
/// pointer width: on entry `[fp+0]` holds the caller's saved frame pointer
/// and `[fp+word]` the return address (saved `lr` on ARM64), so incoming
/// stack arguments start at `fp + 2*word`.
fn classify_slot(base: StackBase, offset: i64, word: i64) -> SlotKind {
    match base {
        StackBase::StackPointer => SlotKind::Local,
        StackBase::FramePointer => {
            if offset < 0 {
                SlotKind::Local
            } else if offset < 2 * word {
                SlotKind::SavedRegister
            } else {
                SlotKind::Argument
            }
        }
    }
}

/// Rough type classification from access patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackVarType {
    Unknown,
    Int8,
    Int16,
    Int32,
    Int64,
    Pointer,
    Buffer,
    Float32,
    Float64,
}

impl StackVarType {
    pub fn from_access_size(size: u8) -> Self {
        match size {
            1 => StackVarType::Int8,
            2 => StackVarType::Int16,
            4 => StackVarType::Int32,
            8 => StackVarType::Int64,
            _ => StackVarType::Unknown,
        }
    }
}

impl std::fmt::Display for StackVarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StackVarType::Unknown => "unknown",
            StackVarType::Int8 => "int8_t",
            StackVarType::Int16 => "int16_t",
            StackVarType::Int32 => "int32_t",
            StackVarType::Int64 => "int64_t",
            StackVarType::Pointer => "void*",
            StackVarType::Buffer => "char[]",
            StackVarType::Float32 => "float",
            StackVarType::Float64 => "double",
        };
        write!(f, "{}", s)
    }
}

/// Analyze disassembled instructions to recover stack variables.
/// Looks for patterns like `[rbp - 0x8]`, `[rsp + 0x10]`, `[sp, #-16]`, etc.
///
/// `arch` sets the default access width for size-prefix-free operands so a slot
/// touched only by, e.g., a push on a 32-bit target is sized as a word (4 bytes)
/// rather than always 8.
pub fn recover_stack_variables(
    instructions: &[crate::disasm::Instruction],
    arch: crate::arch::Architecture,
) -> Vec<StackVariable> {
    let mut vars: BTreeMap<(StackBase, i64), StackVariable> = BTreeMap::new();
    let word = arch.pointer_size() as u8;

    for insn in instructions {
        let op = &insn.op_str;

        // x86/x86_64: [rbp - 0xNN] or [ebp - 0xNN]
        extract_frame_accesses(op, "rbp", word, &mut vars);
        extract_frame_accesses(op, "ebp", word, &mut vars);

        // Also handle [rsp + 0xNN] (frame-pointer-omitted functions)
        extract_stack_accesses(op, "rsp", word, &mut vars);
        extract_stack_accesses(op, "esp", word, &mut vars);

        // ARM64: [x29, #-NN] is frame-relative, [sp, #NN] stack-relative.
        extract_arm_frame_accesses(
            op,
            &insn.mnemonic,
            "x29",
            StackBase::FramePointer,
            &mut vars,
        );
        extract_arm_frame_accesses(op, &insn.mnemonic, "sp", StackBase::StackPointer, &mut vars);
    }

    // Assign names and detect buffers
    let mut result: Vec<StackVariable> = vars.into_values().collect();
    detect_buffers(&mut result);
    assign_names(&mut result, word as i64);
    result
}

fn extract_frame_accesses(
    op: &str,
    reg: &str,
    word: u8,
    vars: &mut BTreeMap<(StackBase, i64), StackVariable>,
) {
    // Pattern: [rbp - 0xNN] or [rbp + 0xNN]
    if let Some(bracket_start) = op.find('[')
        && let Some(bracket_end) = op[bracket_start..].find(']')
    {
        let inner = &op[bracket_start + 1..bracket_start + bracket_end];
        if !inner.contains(reg) {
            return;
        }

        let base = StackBase::FramePointer;
        if let Some(minus) = inner.find(" - ") {
            let offset_str = inner[minus + 3..].trim().trim_start_matches("0x");
            if let Ok(offset) = i64::from_str_radix(offset_str, 16) {
                let size = infer_access_size(op, word);
                let entry = vars.entry((base, -offset)).or_insert(StackVariable {
                    offset: -offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                    base,
                });
                if (size as u64) > entry.size {
                    entry.size = size as u64;
                    entry.type_hint = StackVarType::from_access_size(size);
                }
            }
        } else if let Some(plus) = inner.find(" + ") {
            let offset_str = inner[plus + 3..].trim().trim_start_matches("0x");
            if let Ok(offset) = i64::from_str_radix(offset_str, 16) {
                let size = infer_access_size(op, word);
                vars.entry((base, offset)).or_insert(StackVariable {
                    offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                    base,
                });
            }
        }
    }
}

fn extract_stack_accesses(
    op: &str,
    reg: &str,
    word: u8,
    vars: &mut BTreeMap<(StackBase, i64), StackVariable>,
) {
    // Same as frame but for stack pointer
    if let Some(bracket_start) = op.find('[')
        && let Some(bracket_end) = op[bracket_start..].find(']')
    {
        let inner = &op[bracket_start + 1..bracket_start + bracket_end];
        if !inner.contains(reg) {
            return;
        }

        if let Some(plus) = inner.find(" + ") {
            let offset_str = inner[plus + 3..].trim().trim_start_matches("0x");
            if let Ok(offset) = i64::from_str_radix(offset_str, 16) {
                let size = infer_access_size(op, word);
                let base = StackBase::StackPointer;
                vars.entry((base, offset)).or_insert(StackVariable {
                    offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                    base,
                });
            }
        }
    }
}

fn extract_arm_frame_accesses(
    op: &str,
    mnemonic: &str,
    reg: &str,
    base: StackBase,
    vars: &mut BTreeMap<(StackBase, i64), StackVariable>,
) {
    // ARM64 pattern: [x29, #-16] or [sp, #0x20] or [sp]
    if let Some(bracket_start) = op.find('[')
        && let Some(bracket_end) = op[bracket_start..].find(']')
    {
        let inner = &op[bracket_start + 1..bracket_start + bracket_end];
        if !inner.contains(reg) {
            return;
        }

        let mut offset = 0i64;
        let mut found_offset = false;

        if let Some(hash) = inner.find('#') {
            let after_hash = inner[hash + 1..].trim();
            let is_negative = after_hash.starts_with('-');
            let abs_str = after_hash.trim_start_matches('-');
            // ARM immediates: #0x10 is hex, #16 is decimal
            let parsed = if let Some(hex) = abs_str.strip_prefix("0x") {
                i64::from_str_radix(hex, 16)
            } else {
                abs_str.parse::<i64>()
            };
            if let Ok(val) = parsed {
                offset = if is_negative { -val } else { val };
                found_offset = true;
            }
        } else {
            // [sp] implies offset 0
            if inner.trim() == reg {
                found_offset = true;
            }
        }

        if found_offset {
            let size: u64 = if op.contains('w') { 4 } else { 8 };

            // Add first variable
            vars.entry((base, offset)).or_insert(StackVariable {
                offset,
                size,
                name: String::new(),
                type_hint: StackVarType::from_access_size(size as u8),
                base,
            });

            // Handle Pair Load/Store (ldp/stp) - implies second variable at offset + size
            if mnemonic == "ldp" || mnemonic == "stp" {
                let offset2 = offset + size as i64;
                vars.entry((base, offset2)).or_insert(StackVariable {
                    offset: offset2,
                    size,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size as u8),
                    base,
                });
            }
        }
    }
}

fn infer_access_size(op: &str, word: u8) -> u8 {
    if op.contains("byte ptr") || op.contains("BYTE") {
        1
    } else if op.contains("qword ptr") || op.contains("QWORD") {
        // Check qword before word to avoid substring match ("qword ptr" contains "word ptr")
        8
    } else if op.contains("dword ptr") || op.contains("DWORD") {
        4
    } else if op.contains("word ptr") || op.contains("WORD") {
        2
    } else {
        word // default to the target word size
    }
}

fn detect_buffers(vars: &mut [StackVariable]) {
    // If consecutive variables have small sizes (1 byte each), mark as buffer.
    // Simple heuristic: variables with size 1 that are at negative offsets.
    for var in vars.iter_mut() {
        if var.size == 1 && var.offset < 0 {
            var.type_hint = StackVarType::Buffer;
        }
    }
}

/// Assign deterministic, location-derived names.
///
/// Every name encodes the slot's base and offset — `var_18` is `fp-0x18`,
/// `var_s10` is `sp+0x10`, `arg_0` is the first stack argument at
/// `fp + 2*word` — so touching an unrelated slot never renames existing
/// variables, unlike counter-based schemes where every later variable shifts.
/// The saved frame pointer / return address slots are named `saved_<off>`
/// and are never presented as arguments.
fn assign_names(vars: &mut [StackVariable], word: i64) {
    for var in vars.iter_mut() {
        var.name = match classify_slot(var.base, var.offset, word) {
            SlotKind::SavedRegister => format!("saved_{:x}", var.offset),
            SlotKind::Argument => format!("arg_{:x}", var.offset - 2 * word),
            SlotKind::Local => match var.base {
                // Pre-indexed ARM64 pushes (`[sp, #-0x10]!`) sit below the
                // stack pointer; keep them distinct from positive offsets.
                StackBase::StackPointer if var.offset < 0 => format!("var_sm{:x}", -var.offset),
                StackBase::StackPointer => format!("var_s{:x}", var.offset),
                StackBase::FramePointer => match var.type_hint {
                    StackVarType::Buffer => format!("buf_{:x}", -var.offset),
                    StackVarType::Pointer => format!("ptr_{:x}", -var.offset),
                    _ => format!("var_{:x}", -var.offset),
                },
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::Instruction;

    fn make_insn(mnemonic: &str, op_str: &str) -> Instruction {
        Instruction {
            address: 0x1000,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_string(),
            op_str: op_str.to_string(),
            groups: vec![],
        }
    }

    #[test]
    fn recover_x86_64_rbp_locals() {
        let insns = vec![
            make_insn("mov", "qword ptr [rbp - 0x8], rdi"),
            make_insn("mov", "dword ptr [rbp - 0x10], esi"),
            make_insn("mov", "qword ptr [rbp - 0x18], rdx"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 3);

        // Variables should be sorted by offset (BTreeMap order: -0x18, -0x10, -0x8)
        // and named from their location, not a running counter.
        assert_eq!(vars[0].offset, -0x18);
        assert_eq!(vars[0].size, 8);
        assert_eq!(vars[0].name, "var_18");
        assert_eq!(vars[0].base, StackBase::FramePointer);

        assert_eq!(vars[1].offset, -0x10);
        assert_eq!(vars[1].size, 4);
        assert_eq!(vars[1].type_hint, StackVarType::Int32);
        assert_eq!(vars[1].name, "var_10");

        assert_eq!(vars[2].offset, -0x8);
        assert_eq!(vars[2].size, 8);
        assert_eq!(vars[2].name, "var_8");
    }

    #[test]
    fn names_are_stable_when_unrelated_slot_is_added() {
        // Adding an access to a new slot must not rename existing variables.
        let base = vec![
            make_insn("mov", "qword ptr [rbp - 0x8], rdi"),
            make_insn("mov", "qword ptr [rbp - 0x18], rdx"),
        ];
        let mut extended = base.clone();
        extended.insert(1, make_insn("mov", "dword ptr [rbp - 0x10], esi"));

        let name_of = |vars: &[StackVariable], off: i64| {
            vars.iter().find(|v| v.offset == off).unwrap().name.clone()
        };
        let before = recover_stack_variables(&base, crate::arch::Architecture::X86_64);
        let after = recover_stack_variables(&extended, crate::arch::Architecture::X86_64);
        assert_eq!(name_of(&before, -0x8), name_of(&after, -0x8));
        assert_eq!(name_of(&before, -0x18), name_of(&after, -0x18));
    }

    #[test]
    fn recover_x86_64_rsp_accesses() {
        let insns = vec![
            make_insn("mov", "qword ptr [rsp + 0x8], rax"),
            make_insn("mov", "dword ptr [rsp + 0x10], ecx"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 2);
        // sp-relative positive offsets are locals (frame-pointer-omitted
        // code), never arguments.
        assert_eq!(vars[0].offset, 0x8);
        assert_eq!(vars[0].base, StackBase::StackPointer);
        assert_eq!(vars[0].name, "var_s8");
        assert_eq!(vars[1].offset, 0x10);
        assert_eq!(vars[1].name, "var_s10");
    }

    #[test]
    fn recover_rbp_positive_args() {
        let insns = vec![
            make_insn("mov", "qword ptr [rbp + 0x10], rdi"),
            make_insn("mov", "qword ptr [rbp + 0x18], rsi"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 2);
        // Stack args are rebased so the first one is arg_0: on x86-64 the
        // first incoming stack argument lives at rbp+0x10 (above the saved
        // rbp at +0 and return address at +8).
        assert_eq!(vars[0].name, "arg_0");
        assert_eq!(vars[1].name, "arg_8");
    }

    #[test]
    fn saved_frame_slots_are_not_arguments() {
        // rbp+0 (saved rbp) and rbp+8 (return address) are bookkeeping
        // slots, not incoming arguments.
        let insns = vec![
            make_insn("mov", "rax, qword ptr [rbp + 0x8]"),
            make_insn("mov", "rcx, qword ptr [rbp + 0x0]"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 2);
        assert!(vars.iter().all(|v| !v.name.starts_with("arg_")));
        assert_eq!(vars[0].name, "saved_0");
        assert_eq!(vars[1].name, "saved_8");
    }

    #[test]
    fn x86_stack_args_start_at_ebp_8() {
        // 32-bit frames: saved ebp at +0, return address at +4, so the first
        // stack argument is [ebp + 8].
        let insns = vec![
            make_insn("mov", "eax, dword ptr [ebp + 0x8]"),
            make_insn("mov", "ecx, dword ptr [ebp + 0xc]"),
            make_insn("mov", "edx, dword ptr [ebp + 0x4]"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86);
        let name_of = |off: i64| vars.iter().find(|v| v.offset == off).unwrap().name.clone();
        assert_eq!(name_of(0x8), "arg_0");
        assert_eq!(name_of(0xc), "arg_4");
        assert_eq!(name_of(0x4), "saved_4");
    }

    #[test]
    fn recover_arm64_frame_accesses() {
        let insns = vec![
            make_insn("str", "x0, [x29, #-8]"),
            make_insn("ldr", "x1, [x29, #-16]"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::Arm64);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].offset, -16);
        assert_eq!(vars[0].name, "var_10");
        assert_eq!(vars[1].offset, -8);
        assert_eq!(vars[1].name, "var_8");
    }

    #[test]
    fn arm64_frame_slots_classified_by_location() {
        let insns = vec![
            // [x29] = saved fp, [x29, #8] = saved lr.
            make_insn("ldr", "x0, [x29]"),
            make_insn("ldr", "x1, [x29, #8]"),
            // First stack argument at [x29, #0x10].
            make_insn("ldr", "x2, [x29, #0x10]"),
            // Below-frame local.
            make_insn("str", "x3, [x29, #-24]"),
            // sp-relative slots are locals, not arguments.
            make_insn("str", "x4, [sp, #0x20]"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::Arm64);
        let name_of = |base: StackBase, off: i64| {
            vars.iter()
                .find(|v| v.base == base && v.offset == off)
                .unwrap()
                .name
                .clone()
        };
        assert_eq!(name_of(StackBase::FramePointer, 0), "saved_0");
        assert_eq!(name_of(StackBase::FramePointer, 8), "saved_8");
        assert_eq!(name_of(StackBase::FramePointer, 0x10), "arg_0");
        assert_eq!(name_of(StackBase::FramePointer, -24), "var_18");
        assert_eq!(name_of(StackBase::StackPointer, 0x20), "var_s20");
    }

    #[test]
    fn same_offset_on_frame_and_stack_bases_stays_distinct() {
        // fp+0x10 is the first stack argument; sp+0x10 is an unrelated
        // local. They must not merge into one variable.
        let insns = vec![
            make_insn("mov", "rax, qword ptr [rbp + 0x10]"),
            make_insn("mov", "qword ptr [rsp + 0x10], rcx"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 2);
        let names: Vec<&str> = vars.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"arg_0"));
        assert!(names.contains(&"var_s10"));
    }

    #[test]
    fn size_upgrade_on_wider_access() {
        let insns = vec![
            make_insn("mov", "dword ptr [rbp - 0x8], eax"),
            make_insn("mov", "qword ptr [rbp - 0x8], rax"),
        ];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 1);
        // Should be upgraded to 8 bytes (qword)
        assert_eq!(vars[0].size, 8);
    }

    #[test]
    fn size_prefixless_access_defaults_to_word_size() {
        // No `dword/qword ptr` prefix: the slot is sized by the target word.
        let insns = vec![make_insn("mov", "[ebp - 0x8], eax")];

        let x86 = recover_stack_variables(&insns, crate::arch::Architecture::X86);
        assert_eq!(x86[0].size, 4);
        assert_eq!(x86[0].type_hint, StackVarType::Int32);

        let x64 = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(x64[0].size, 8);
        assert_eq!(x64[0].type_hint, StackVarType::Int64);
    }

    #[test]
    fn byte_locals_detected_as_buffer() {
        let insns = vec![make_insn("mov", "byte ptr [rbp - 0x20], al")];
        let vars = recover_stack_variables(&insns, crate::arch::Architecture::X86_64);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].type_hint, StackVarType::Buffer);
        assert_eq!(vars[0].name, "buf_20");
    }

    #[test]
    fn empty_instructions_yields_no_vars() {
        let vars = recover_stack_variables(&[], crate::arch::Architecture::X86_64);
        assert!(vars.is_empty());
    }

    #[test]
    fn display_stack_var_type() {
        assert_eq!(format!("{}", StackVarType::Int32), "int32_t");
        assert_eq!(format!("{}", StackVarType::Pointer), "void*");
        assert_eq!(format!("{}", StackVarType::Buffer), "char[]");
        assert_eq!(format!("{}", StackVarType::Unknown), "unknown");
        assert_eq!(format!("{}", StackVarType::Float64), "double");
    }

    #[test]
    fn from_access_size_coverage() {
        assert_eq!(StackVarType::from_access_size(1), StackVarType::Int8);
        assert_eq!(StackVarType::from_access_size(2), StackVarType::Int16);
        assert_eq!(StackVarType::from_access_size(4), StackVarType::Int32);
        assert_eq!(StackVarType::from_access_size(8), StackVarType::Int64);
        assert_eq!(StackVarType::from_access_size(16), StackVarType::Unknown);
    }
}
