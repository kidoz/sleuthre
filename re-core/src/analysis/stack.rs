//! Stack frame analysis and local variable recovery.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A recovered stack variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackVariable {
    /// Offset from frame pointer (negative = locals, positive = args on some ABIs).
    pub offset: i64,
    /// Inferred size in bytes (from access width).
    pub size: u64,
    /// Auto-generated or user-assigned name.
    pub name: String,
    /// Inferred type hint.
    pub type_hint: StackVarType,
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
pub fn recover_stack_variables(instructions: &[crate::disasm::Instruction]) -> Vec<StackVariable> {
    let mut vars: BTreeMap<i64, StackVariable> = BTreeMap::new();

    for insn in instructions {
        let op = &insn.op_str;

        // x86/x86_64: [rbp - 0xNN] or [ebp - 0xNN]
        extract_frame_accesses(op, "rbp", &mut vars);
        extract_frame_accesses(op, "ebp", &mut vars);

        // Also handle [rsp + 0xNN] (frame-pointer-omitted functions)
        extract_stack_accesses(op, "rsp", &mut vars);
        extract_stack_accesses(op, "esp", &mut vars);

        // ARM64: [sp, #-NN] or [x29, #-NN]
        extract_arm_frame_accesses(op, "x29", &mut vars);
        extract_arm_frame_accesses(op, "sp", &mut vars);
    }

    // Assign names and detect buffers
    let mut result: Vec<StackVariable> = vars.into_values().collect();
    detect_buffers(&mut result);
    assign_names(&mut result);
    result
}

fn extract_frame_accesses(op: &str, reg: &str, vars: &mut BTreeMap<i64, StackVariable>) {
    // Pattern: [rbp - 0xNN] or [rbp + 0xNN]
    if let Some(bracket_start) = op.find('[')
        && let Some(bracket_end) = op[bracket_start..].find(']')
    {
        let inner = &op[bracket_start + 1..bracket_start + bracket_end];
        if !inner.contains(reg) {
            return;
        }

        if let Some(minus) = inner.find(" - ") {
            let offset_str = inner[minus + 3..].trim().trim_start_matches("0x");
            if let Ok(offset) = i64::from_str_radix(offset_str, 16) {
                let size = infer_access_size(op);
                let entry = vars.entry(-offset).or_insert(StackVariable {
                    offset: -offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                });
                if (size as u64) > entry.size {
                    entry.size = size as u64;
                    entry.type_hint = StackVarType::from_access_size(size);
                }
            }
        } else if let Some(plus) = inner.find(" + ") {
            let offset_str = inner[plus + 3..].trim().trim_start_matches("0x");
            if let Ok(offset) = i64::from_str_radix(offset_str, 16) {
                let size = infer_access_size(op);
                vars.entry(offset).or_insert(StackVariable {
                    offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                });
            }
        }
    }
}

fn extract_stack_accesses(op: &str, reg: &str, vars: &mut BTreeMap<i64, StackVariable>) {
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
                let size = infer_access_size(op);
                vars.entry(offset).or_insert(StackVariable {
                    offset,
                    size: size as u64,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size),
                });
            }
        }
    }
}

fn extract_arm_frame_accesses(op: &str, reg: &str, vars: &mut BTreeMap<i64, StackVariable>) {
    // ARM64 pattern: [x29, #-16] or [sp, #0x20]
    if let Some(bracket_start) = op.find('[')
        && let Some(bracket_end) = op[bracket_start..].find(']')
    {
        let inner = &op[bracket_start + 1..bracket_start + bracket_end];
        if !inner.contains(reg) {
            return;
        }

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
            if let Ok(offset) = parsed {
                let actual_offset = if is_negative { -offset } else { offset };
                let size: u64 = if op.contains('w') { 4 } else { 8 };
                vars.entry(actual_offset).or_insert(StackVariable {
                    offset: actual_offset,
                    size,
                    name: String::new(),
                    type_hint: StackVarType::from_access_size(size as u8),
                });
            }
        }
    }
}

fn infer_access_size(op: &str) -> u8 {
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
        8 // default to 64-bit
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

fn assign_names(vars: &mut [StackVariable]) {
    let mut local_count = 0u32;
    let mut arg_count = 0u32;
    for var in vars.iter_mut() {
        if var.offset < 0 {
            // Local variable (below frame pointer)
            local_count += 1;
            var.name = match var.type_hint {
                StackVarType::Buffer => format!("buf_{:x}", (-var.offset) as u64),
                StackVarType::Pointer => format!("ptr_{local_count}"),
                _ => format!("var_{local_count}"),
            };
        } else if var.offset > 0 {
            // Could be saved register or argument
            arg_count += 1;
            var.name = format!("arg_{arg_count}");
        }
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
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 3);

        // Variables should be sorted by offset (BTreeMap order: -0x18, -0x10, -0x8)
        assert_eq!(vars[0].offset, -0x18);
        assert_eq!(vars[0].size, 8);
        assert!(vars[0].name.starts_with("var_"));

        assert_eq!(vars[1].offset, -0x10);
        assert_eq!(vars[1].size, 4);
        assert_eq!(vars[1].type_hint, StackVarType::Int32);

        assert_eq!(vars[2].offset, -0x8);
        assert_eq!(vars[2].size, 8);
    }

    #[test]
    fn recover_x86_64_rsp_accesses() {
        let insns = vec![
            make_insn("mov", "qword ptr [rsp + 0x8], rax"),
            make_insn("mov", "dword ptr [rsp + 0x10], ecx"),
        ];
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 2);
        // Both are positive offsets (args or rsp-relative locals)
        assert_eq!(vars[0].offset, 0x8);
        assert_eq!(vars[1].offset, 0x10);
    }

    #[test]
    fn recover_rbp_positive_args() {
        let insns = vec![
            make_insn("mov", "qword ptr [rbp + 0x10], rdi"),
            make_insn("mov", "qword ptr [rbp + 0x18], rsi"),
        ];
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 2);
        assert!(vars[0].name.starts_with("arg_"));
        assert!(vars[1].name.starts_with("arg_"));
    }

    #[test]
    fn recover_arm64_frame_accesses() {
        let insns = vec![
            make_insn("str", "x0, [x29, #-8]"),
            make_insn("ldr", "x1, [x29, #-16]"),
        ];
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].offset, -16);
        assert_eq!(vars[1].offset, -8);
    }

    #[test]
    fn size_upgrade_on_wider_access() {
        let insns = vec![
            make_insn("mov", "dword ptr [rbp - 0x8], eax"),
            make_insn("mov", "qword ptr [rbp - 0x8], rax"),
        ];
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 1);
        // Should be upgraded to 8 bytes (qword)
        assert_eq!(vars[0].size, 8);
    }

    #[test]
    fn byte_locals_detected_as_buffer() {
        let insns = vec![make_insn("mov", "byte ptr [rbp - 0x20], al")];
        let vars = recover_stack_variables(&insns);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].type_hint, StackVarType::Buffer);
        assert!(vars[0].name.starts_with("buf_"));
    }

    #[test]
    fn empty_instructions_yields_no_vars() {
        let vars = recover_stack_variables(&[]);
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
