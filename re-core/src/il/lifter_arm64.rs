//! ARM64 (AArch64) lifter: converts native instructions to LLIL.

use crate::disasm::Instruction;
use crate::il::llil::*;

/// Lift a sequence of native ARM64 instructions into an `LlilFunction`.
pub fn lift_function(name: &str, entry: u64, instructions: &[Instruction]) -> LlilFunction {
    let mut func = LlilFunction::new(name.to_string(), entry);

    for insn in instructions {
        let stmts = lift_instruction(&mut func, insn);
        func.add_inst(LlilInst {
            address: insn.address,
            stmts,
        });
    }

    func
}

/// Lift a single native ARM64 instruction into one or more LLIL statements.
fn lift_instruction(func: &mut LlilFunction, insn: &Instruction) -> Vec<LlilStmt> {
    let mn = insn.mnemonic.to_lowercase();
    let ops_raw: Vec<&str> = if insn.op_str.is_empty() {
        vec![]
    } else {
        split_arm64_operands(&insn.op_str)
    };

    // Check for conditional branches: b.eq, b.ne, b.lt, etc.
    if let Some(cond_str) = mn.strip_prefix("b.")
        && let Some(cond) = parse_condition(cond_str)
    {
        return lift_branch_cond(func, cond, &ops_raw);
    }

    // Try NEON SIMD instructions first. For mnemonics shared with scalar
    // ARM64 (add, sub, mul, etc.), check if the operands contain NEON
    // arrangement specifiers (e.g. ".4s", ".16b").
    if let Some(stmts) = lift_neon_instruction(func, &mn, &ops_raw, insn.address) {
        return stmts;
    }

    match mn.as_str() {
        "nop" => vec![LlilStmt::Nop],

        // --- Data movement ---
        "mov" | "movz" => lift_mov(func, &ops_raw),
        "movk" => lift_movk(func, &ops_raw),
        "movn" => lift_movn(func, &ops_raw),

        // --- Arithmetic ---
        "add" | "adds" => lift_alu3(func, BinOp::Add, &ops_raw),
        "sub" | "subs" => lift_alu3(func, BinOp::Sub, &ops_raw),
        "mul" => lift_alu3(func, BinOp::Mul, &ops_raw),

        // --- Bitwise ---
        "and" | "ands" => lift_alu3(func, BinOp::And, &ops_raw),
        "orr" => lift_alu3(func, BinOp::Or, &ops_raw),
        "eor" => lift_alu3(func, BinOp::Xor, &ops_raw),
        "lsl" => lift_alu3(func, BinOp::Shl, &ops_raw),
        "lsr" => lift_alu3(func, BinOp::Shr, &ops_raw),
        "asr" => lift_alu3(func, BinOp::Sar, &ops_raw),

        // --- Unary ---
        "neg" | "negs" => lift_unary(func, UnaryOp::Neg, &ops_raw),
        "mvn" => lift_unary(func, UnaryOp::Not, &ops_raw),

        // --- Comparison / test ---
        "cmp" => lift_cmp(func, &ops_raw),
        "tst" => lift_tst(func, &ops_raw),

        // --- Loads / stores ---
        "ldr" | "ldrb" | "ldrh" | "ldrsw" => lift_ldr(func, &mn, &ops_raw),
        "str" | "strb" | "strh" => lift_str(func, &mn, &ops_raw),
        "ldp" => lift_ldp(func, &ops_raw),
        "stp" => lift_stp(func, &ops_raw),

        // --- Branches ---
        "b" => lift_branch(func, &ops_raw),
        "bl" | "blr" => lift_call(func, &ops_raw),
        "br" => lift_branch(func, &ops_raw),
        "ret" => vec![LlilStmt::Return],

        // --- Compare-and-branch ---
        "cbz" => lift_cbz(func, &ops_raw, FlagCondition::E),
        "cbnz" => lift_cbz(func, &ops_raw, FlagCondition::Ne),

        // --- Address computation ---
        "adr" | "adrp" => lift_adr(func, &ops_raw),

        // --- System ---
        "svc" => vec![LlilStmt::Unimplemented {
            mnemonic: insn.mnemonic.clone(),
            op_str: insn.op_str.clone(),
        }],

        // --- Everything else ---
        _ => vec![LlilStmt::Unimplemented {
            mnemonic: insn.mnemonic.clone(),
            op_str: insn.op_str.clone(),
        }],
    }
}

/// Split ARM64 operands, respecting brackets.
/// E.g. "x0, [x1, #16]" => ["x0", "[x1, #16]"]
fn split_arm64_operands(op_str: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = op_str.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            b',' if depth == 0 => {
                let token = op_str[start..i].trim();
                if !token.is_empty() {
                    result.push(token);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = op_str[start..].trim();
    if !tail.is_empty() {
        result.push(tail);
    }
    result
}

/// Parse an ARM64 operand into an LLIL expression.
fn parse_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    let op = op.trim();

    // Memory operand: [x1], [x1, #16], [x1, #16]!, etc.
    if op.starts_with('[') {
        let (addr, size) = parse_mem_operand(func, op);
        return func.load(addr, size);
    }

    // Immediate: #0x42 or #42 or #-5
    if let Some(val) = parse_arm64_immediate(op) {
        return func.const_val(val);
    }

    // Bare hex constant (used for branch targets): 0x1234
    if let Some(hex) = op.strip_prefix("0x").or_else(|| op.strip_prefix("0X"))
        && let Ok(v) = u64::from_str_radix(hex, 16)
    {
        return func.const_val(v);
    }

    // Bare decimal
    if let Ok(v) = op.parse::<u64>() {
        return func.const_val(v);
    }

    // Zero registers
    if op == "xzr" || op == "wzr" {
        return func.const_val(0);
    }

    // Register
    func.reg(op)
}

/// Parse an ARM64 immediate value. Strips the leading '#'.
fn parse_arm64_immediate(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix('#')?;
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(neg_hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        let val = i64::from_str_radix(neg_hex, 16).ok()?;
        Some((-val) as u64)
    } else if s.starts_with('-') {
        s.parse::<i64>().ok().map(|v| v as u64)
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse a memory operand like `[x1]`, `[x1, #16]`, `[x1, x2]`, `[x1, #16]!`, `[x1], #16`.
/// Returns (address_expr_id, access_size_in_bytes).
/// Size is inferred from the instruction mnemonic context (caller decides), here we default to 8.
fn parse_mem_operand(func: &mut LlilFunction, op: &str) -> (ExprId, u8) {
    let op = op.trim();

    // Check for post-index: [x1], #16
    // The bracket part and the offset after the bracket
    let bracket_end = op.find(']').unwrap_or(op.len());
    let inner = &op[1..bracket_end];

    // Parse the inner part (base and optional offset)
    let addr = parse_mem_inner(func, inner);

    // Check for post-index offset after the bracket
    let after_bracket = &op[bracket_end + 1..];
    let after_bracket = after_bracket.trim().trim_start_matches('!').trim();

    if let Some(stripped) = after_bracket.strip_prefix(',') {
        let stripped = stripped.trim();
        if let Some(imm) = parse_arm64_immediate(stripped) {
            // Post-index: we still use the base address for the access
            // The base update is handled separately in the caller
            let _ = imm; // post-index offset is for the base update, not the access address
        }
    }

    (addr, 8) // default size; caller overrides
}

/// Parse the inner content of a memory bracket: "x1", "x1, #16", "x1, x2", "sp, #-16"
fn parse_mem_inner(func: &mut LlilFunction, inner: &str) -> ExprId {
    let parts: Vec<&str> = inner.splitn(2, ',').collect();
    let base_str = parts[0].trim();

    // Handle zero register as base
    let base = if base_str == "xzr" || base_str == "wzr" {
        func.const_val(0)
    } else {
        func.reg(base_str)
    };

    if parts.len() == 1 {
        return base;
    }

    let offset_str = parts[1].trim();

    // Immediate offset: #16 or #-8
    if let Some(imm) = parse_arm64_immediate(offset_str) {
        let offset = func.const_val(imm);
        return func.binop(BinOp::Add, base, offset);
    }

    // Register offset: x2
    let offset_reg = if offset_str == "xzr" || offset_str == "wzr" {
        func.const_val(0)
    } else {
        func.reg(offset_str)
    };
    func.binop(BinOp::Add, base, offset_reg)
}

/// Determine the memory access size from the load/store mnemonic.
fn mem_size_from_mnemonic(mn: &str) -> u8 {
    match mn {
        "ldrb" | "strb" => 1,
        "ldrh" | "strh" => 2,
        "ldrsw" => 4,
        "ldr" | "str" => 8, // default; caller may override based on register width
        _ => 8,
    }
}

/// Determine register width (4 for w-registers, 8 for x-registers).
fn reg_size(name: &str) -> u8 {
    let name = name.trim();
    if name.starts_with('w') || name == "wzr" {
        4
    } else {
        8
    }
}

/// Parse an ARM64 condition code string into a FlagCondition.
fn parse_condition(cond: &str) -> Option<FlagCondition> {
    match cond {
        "eq" => Some(FlagCondition::E),
        "ne" => Some(FlagCondition::Ne),
        "lt" => Some(FlagCondition::Slt),
        "le" => Some(FlagCondition::Sle),
        "gt" => Some(FlagCondition::Sgt),
        "ge" => Some(FlagCondition::Sge),
        "hi" => Some(FlagCondition::Ugt),
        "hs" | "cs" => Some(FlagCondition::Uge),
        "lo" | "cc" => Some(FlagCondition::Ult),
        "ls" => Some(FlagCondition::Ule),
        "mi" => Some(FlagCondition::Neg),
        "vs" => Some(FlagCondition::Overflow),
        _ => None,
    }
}

// --- NEON SIMD helpers ---

/// NEON arrangement specifier patterns. Presence of any of these in an operand
/// indicates a NEON vector instruction rather than a scalar one.
const NEON_ARRANGEMENTS: &[&str] = &[".16b", ".8b", ".8h", ".4h", ".4s", ".2s", ".2d", ".1d"];

/// Check whether any of the operands contain a NEON arrangement specifier.
fn has_neon_arrangement(ops: &[&str]) -> bool {
    ops.iter()
        .any(|op| NEON_ARRANGEMENTS.iter().any(|arr| op.contains(arr)))
}

/// Parse NEON arrangement specifier from an operand like `"v0.4s"` or `"v1.16b"`.
/// Returns `(element_type, width_bits)`.
fn parse_neon_arrangement(op: &str) -> (VectorElementType, u16) {
    if op.contains(".16b") {
        (VectorElementType::Int8, 128)
    } else if op.contains(".8b") {
        (VectorElementType::Int8, 64)
    } else if op.contains(".8h") {
        (VectorElementType::Int16, 128)
    } else if op.contains(".4h") {
        (VectorElementType::Int16, 64)
    } else if op.contains(".4s") {
        (VectorElementType::Int32, 128)
    } else if op.contains(".2s") {
        (VectorElementType::Int32, 64)
    } else if op.contains(".2d") {
        (VectorElementType::Int64, 128)
    } else if op.contains(".1d") {
        (VectorElementType::Int64, 64)
    } else {
        // Default fallback
        (VectorElementType::Int32, 128)
    }
}

/// Extract the register name from a NEON operand like `"v0.4s"` -> `"v0"`.
fn extract_neon_reg(op: &str) -> &str {
    op.split('.').next().unwrap_or(op).trim()
}

/// Parse a NEON element-index operand like `"v0.s[2]"`.
/// Returns `(register_name, index)` or `None` if not an indexed operand.
fn parse_neon_index(op: &str) -> Option<(&str, u8)> {
    let op = op.trim();
    // Look for pattern like "v0.s[2]"
    let bracket_start = op.find('[')?;
    let bracket_end = op.find(']')?;
    if bracket_end <= bracket_start + 1 {
        return None;
    }
    let index_str = &op[bracket_start + 1..bracket_end];
    let index: u8 = index_str.parse().ok()?;
    // Register name is everything before the dot
    let reg = op.split('.').next().unwrap_or(op).trim();
    Some((reg, index))
}

/// Try to extract element type and width from operands with element-index
/// notation like `"v0.s[2]"` or `"v0.b[3]"`. Returns `Some((elem_ty, 128))`
/// if found.
fn parse_element_index_type(ops: &[&str]) -> Option<(VectorElementType, u16)> {
    for op in ops {
        let op = op.trim();
        // Look for pattern: vN.X[N] where X is b/h/s/d
        if let Some(dot_pos) = op.find('.') {
            let after_dot = &op[dot_pos + 1..];
            let elem_ty = match after_dot.chars().next()? {
                'b' => VectorElementType::Int8,
                'h' => VectorElementType::Int16,
                's' => VectorElementType::Int32,
                'd' => VectorElementType::Int64,
                _ => continue,
            };
            if after_dot.contains('[') {
                return Some((elem_ty, 128));
            }
        }
    }
    None
}

/// Parse a NEON operand: if it contains an arrangement specifier, extract
/// the register name; otherwise fall back to the general `parse_operand`
/// (handles immediates, scalar registers, etc.).
fn parse_neon_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    let op = op.trim();
    if NEON_ARRANGEMENTS.iter().any(|arr| op.contains(arr)) {
        func.reg(extract_neon_reg(op))
    } else {
        parse_operand(func, op)
    }
}

/// Attempt to lift a NEON SIMD instruction. Returns `Some(stmts)` if the
/// instruction was recognized as NEON, or `None` to fall through to scalar
/// handling.
fn lift_neon_instruction(
    func: &mut LlilFunction,
    mnemonic: &str,
    ops: &[&str],
    _addr: u64,
) -> Option<Vec<LlilStmt>> {
    // Instructions that are always NEON regardless of arrangement specifiers
    let always_neon = matches!(
        mnemonic,
        "fadd"
            | "fsub"
            | "fmul"
            | "fdiv"
            | "fsqrt"
            | "fabs"
            | "fneg"
            | "fmin"
            | "fmax"
            | "fmla"
            | "fmls"
            | "sqadd"
            | "uqadd"
            | "sqsub"
            | "uqsub"
            | "abs"
            | "shl"
            | "ushr"
            | "sshr"
            | "cmeq"
            | "cmgt"
            | "cmge"
            | "cmlt"
            | "cmle"
            | "smin"
            | "umin"
            | "smax"
            | "umax"
            | "dup"
            | "movi"
            | "ins"
            | "umov"
            | "sxtl"
            | "uxtl"
            | "xtn"
            | "addp"
            | "tbl"
            | "bic"
            | "not"
            | "scvtf"
            | "ucvtf"
            | "fcvtzs"
            | "fcvtzu"
    );

    // For shared mnemonics (add, sub, mul, mov, and, orr, eor, neg, mvn),
    // only treat as NEON if operands have arrangement specifiers.
    let shared_with_scalar = matches!(
        mnemonic,
        "add"
            | "adds"
            | "sub"
            | "subs"
            | "mul"
            | "and"
            | "ands"
            | "orr"
            | "eor"
            | "mov"
            | "neg"
            | "negs"
            | "mvn"
    );

    if !always_neon {
        if shared_with_scalar {
            if !has_neon_arrangement(ops) {
                return None; // fall through to scalar
            }
        } else {
            return None; // not a recognized NEON mnemonic
        }
    }

    // For instructions that are always-NEON but may not have arrangement
    // specifiers in the operands (e.g. scalar float), check if we have
    // enough operands.
    if ops.is_empty() {
        return None;
    }

    // Determine element type and width from the first operand that has an
    // arrangement specifier, from element-index notation (ins/umov), or
    // from float mnemonic prefix.
    let (elem_ty, width) = if has_neon_arrangement(ops) {
        // Use the first operand with an arrangement specifier
        ops.iter()
            .find(|op| NEON_ARRANGEMENTS.iter().any(|arr| op.contains(arr)))
            .map(|op| parse_neon_arrangement(op))
            .unwrap_or((VectorElementType::Int32, 128))
    } else if let Some(et_w) = parse_element_index_type(ops) {
        // Element-index notation: v0.s[2], v0.b[3], etc.
        et_w
    } else {
        // For always-NEON instructions without arrangement or index, return
        // None to let them fall through to Unimplemented.
        return None;
    };

    match mnemonic {
        // --- Integer arithmetic (element-wise) ---
        "add" | "adds" => lift_neon_binop(func, VectorOpKind::Add, elem_ty, width, ops),
        "sub" | "subs" => lift_neon_binop(func, VectorOpKind::Sub, elem_ty, width, ops),
        "mul" => lift_neon_binop(func, VectorOpKind::Mul, elem_ty, width, ops),
        "neg" | "negs" => lift_neon_unaryop(
            func,
            VectorOpKind::Intrinsic("vneg".into()),
            elem_ty,
            width,
            ops,
        ),
        "abs" => lift_neon_unaryop(func, VectorOpKind::Abs, elem_ty, width, ops),

        // --- Saturating arithmetic ---
        "sqadd" | "uqadd" => lift_neon_binop(func, VectorOpKind::AddSaturate, elem_ty, width, ops),
        "sqsub" | "uqsub" => lift_neon_binop(func, VectorOpKind::SubSaturate, elem_ty, width, ops),

        // --- Bitwise ---
        "and" | "ands" => lift_neon_binop(func, VectorOpKind::And, elem_ty, width, ops),
        "orr" => lift_neon_binop(func, VectorOpKind::Or, elem_ty, width, ops),
        "eor" => lift_neon_binop(func, VectorOpKind::Xor, elem_ty, width, ops),
        "bic" => lift_neon_binop(func, VectorOpKind::AndNot, elem_ty, width, ops),
        "not" | "mvn" => lift_neon_unaryop(
            func,
            VectorOpKind::Intrinsic("vnot".into()),
            elem_ty,
            width,
            ops,
        ),

        // --- Shifts ---
        "shl" => lift_neon_binop(func, VectorOpKind::ShiftLeft, elem_ty, width, ops),
        "ushr" => lift_neon_binop(func, VectorOpKind::ShiftRight, elem_ty, width, ops),
        "sshr" => lift_neon_binop(func, VectorOpKind::ShiftRightArith, elem_ty, width, ops),

        // --- Compare ---
        "cmeq" => lift_neon_binop(func, VectorOpKind::CompareEq, elem_ty, width, ops),
        "cmgt" | "cmge" => lift_neon_binop(func, VectorOpKind::CompareGt, elem_ty, width, ops),
        "cmlt" | "cmle" => lift_neon_binop(func, VectorOpKind::CompareLt, elem_ty, width, ops),

        // --- Float arithmetic ---
        "fadd" => lift_neon_float_binop(func, VectorOpKind::Add, elem_ty, width, ops),
        "fsub" => lift_neon_float_binop(func, VectorOpKind::Sub, elem_ty, width, ops),
        "fmul" => lift_neon_float_binop(func, VectorOpKind::Mul, elem_ty, width, ops),
        "fdiv" => lift_neon_float_binop(func, VectorOpKind::Div, elem_ty, width, ops),
        "fsqrt" => lift_neon_float_unaryop(func, VectorOpKind::Sqrt, elem_ty, width, ops),
        "fabs" => lift_neon_float_unaryop(func, VectorOpKind::Abs, elem_ty, width, ops),
        "fneg" => lift_neon_float_unaryop(
            func,
            VectorOpKind::Intrinsic("fneg".into()),
            elem_ty,
            width,
            ops,
        ),
        "fmin" => lift_neon_float_binop(func, VectorOpKind::Min, elem_ty, width, ops),
        "fmax" => lift_neon_float_binop(func, VectorOpKind::Max, elem_ty, width, ops),

        // --- FMA ---
        "fmla" => lift_neon_ternaryop(func, VectorOpKind::FusedMulAdd, elem_ty, width, ops),
        "fmls" => lift_neon_ternaryop(func, VectorOpKind::FusedMulSub, elem_ty, width, ops),

        // --- Min / Max ---
        "smin" | "umin" => lift_neon_binop(func, VectorOpKind::Min, elem_ty, width, ops),
        "smax" | "umax" => lift_neon_binop(func, VectorOpKind::Max, elem_ty, width, ops),

        // --- Move / Load / Store ---
        "mov" => lift_neon_move(func, elem_ty, width, ops),
        "dup" => lift_neon_broadcast(func, elem_ty, width, ops),
        "movi" => lift_neon_movi(func, elem_ty, width, ops),

        // --- Insert / Extract ---
        "ins" => lift_neon_insert(func, elem_ty, width, ops),
        "umov" => lift_neon_extract(func, elem_ty, width, ops),

        // --- Widen / Narrow ---
        "sxtl" | "uxtl" => lift_neon_unaryop(func, VectorOpKind::ConvertWiden, elem_ty, width, ops),
        "xtn" => lift_neon_unaryop(func, VectorOpKind::ConvertNarrow, elem_ty, width, ops),

        // --- Horizontal ---
        "addp" => lift_neon_binop(func, VectorOpKind::HorizontalAdd, elem_ty, width, ops),

        // --- Table lookup ---
        "tbl" => lift_neon_binop(func, VectorOpKind::ShuffleBytes, elem_ty, width, ops),

        // --- Convert ---
        "scvtf" | "ucvtf" => {
            lift_neon_unaryop(func, VectorOpKind::ConvertIntToFloat, elem_ty, width, ops)
        }
        "fcvtzs" | "fcvtzu" => {
            lift_neon_unaryop(func, VectorOpKind::ConvertFloatToInt, elem_ty, width, ops)
        }

        _ => None,
    }
}

/// Lift a NEON binary (two-source) instruction: `dest = op(src1, src2)`.
fn lift_neon_binop(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 3 {
        return None;
    }
    let dest = extract_neon_reg(ops[0]);
    let src1 = func.reg(extract_neon_reg(ops[1]));
    let src2 = parse_neon_operand(func, ops[2]);
    let expr = func.vector_op(kind, elem_ty, width, vec![src1, src2]);
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Lift a NEON unary (one-source) instruction: `dest = op(src)`.
fn lift_neon_unaryop(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let dest = extract_neon_reg(ops[0]);
    let src = func.reg(extract_neon_reg(ops[1]));
    let expr = func.vector_op(kind, elem_ty, width, vec![src]);
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Lift a NEON float binary instruction, converting integer element types
/// to their float equivalents based on element bit width.
fn lift_neon_float_binop(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    let float_ty = int_to_float_element(elem_ty);
    lift_neon_binop(func, kind, float_ty, width, ops)
}

/// Lift a NEON float unary instruction.
fn lift_neon_float_unaryop(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    let float_ty = int_to_float_element(elem_ty);
    lift_neon_unaryop(func, kind, float_ty, width, ops)
}

/// Lift a NEON ternary (accumulating) instruction: `dest = op(dest, src1, src2)`.
/// Used for fmla/fmls where the destination is also an input.
fn lift_neon_ternaryop(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 3 {
        return None;
    }
    let float_ty = int_to_float_element(elem_ty);
    let dest = extract_neon_reg(ops[0]);
    let acc = func.reg(dest);
    let src1 = func.reg(extract_neon_reg(ops[1]));
    let src2 = func.reg(extract_neon_reg(ops[2]));
    let expr = func.vector_op(kind, float_ty, width, vec![acc, src1, src2]);
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Lift NEON `mov v0.16b, v1.16b`.
fn lift_neon_move(
    func: &mut LlilFunction,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let dest = extract_neon_reg(ops[0]);
    let src = func.reg(extract_neon_reg(ops[1]));
    let expr = func.vector_op(VectorOpKind::Move, elem_ty, width, vec![src]);
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Lift NEON `dup v0.4s, w1` (broadcast scalar to all lanes).
fn lift_neon_broadcast(
    func: &mut LlilFunction,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let dest = extract_neon_reg(ops[0]);
    let src = parse_operand(func, ops[1].trim());
    let expr = func.vector_op(VectorOpKind::Broadcast, elem_ty, width, vec![src]);
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Lift NEON `movi v0.4s, #imm`.
/// When the immediate is 0, emit `VectorOpKind::Zero`; otherwise `Broadcast`.
fn lift_neon_movi(
    func: &mut LlilFunction,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let dest = extract_neon_reg(ops[0]);
    let imm_val = parse_arm64_immediate(ops[1].trim());
    let kind = if imm_val == Some(0) {
        VectorOpKind::Zero
    } else {
        VectorOpKind::Broadcast
    };
    if kind == VectorOpKind::Zero {
        let expr = func.vector_op(kind, elem_ty, width, vec![]);
        Some(vec![LlilStmt::SetReg {
            dest: dest.to_string(),
            src: expr,
        }])
    } else {
        let src = parse_operand(func, ops[1].trim());
        let expr = func.vector_op(kind, elem_ty, width, vec![src]);
        Some(vec![LlilStmt::SetReg {
            dest: dest.to_string(),
            src: expr,
        }])
    }
}

/// Lift NEON `ins v0.s[2], w1` (insert scalar into lane).
fn lift_neon_insert(
    func: &mut LlilFunction,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let (dest_reg, index) = parse_neon_index(ops[0])?;
    let src = parse_operand(func, ops[1].trim());
    let dest_expr = func.reg(dest_reg);
    let expr = func.vector_op(
        VectorOpKind::Insert { index },
        elem_ty,
        width,
        vec![dest_expr, src],
    );
    Some(vec![LlilStmt::SetReg {
        dest: dest_reg.to_string(),
        src: expr,
    }])
}

/// Lift NEON `umov w1, v0.s[2]` (extract lane to scalar).
fn lift_neon_extract(
    func: &mut LlilFunction,
    elem_ty: VectorElementType,
    width: u16,
    ops: &[&str],
) -> Option<Vec<LlilStmt>> {
    if ops.len() < 2 {
        return None;
    }
    let dest = ops[0].trim();
    let (src_reg, index) = parse_neon_index(ops[1])?;
    let src_expr = func.reg(src_reg);
    let expr = func.vector_op(
        VectorOpKind::Extract { index },
        elem_ty,
        width,
        vec![src_expr],
    );
    Some(vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
    }])
}

/// Convert an integer element type to its float equivalent of the same width.
/// `Int32` -> `Float32`, `Int64` -> `Float64`. Other types map to `Float32`
/// as a reasonable default.
fn int_to_float_element(ty: VectorElementType) -> VectorElementType {
    match ty {
        VectorElementType::Int64 => VectorElementType::Float64,
        VectorElementType::Float32 | VectorElementType::Float64 => ty,
        _ => VectorElementType::Float32,
    }
}

// --- Lifting helpers ---

fn lift_mov(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let src = parse_operand(func, ops[1]);
    vec![LlilStmt::SetReg {
        dest: ops[0].trim().to_string(),
        src,
    }]
}

fn lift_movk(_func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // MOVK inserts a 16-bit value at a shifted position.
    // For simplicity, we model it as an Unimplemented that preserves context,
    // since proper lifting needs shift info from Capstone detail.
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    vec![LlilStmt::Unimplemented {
        mnemonic: "movk".to_string(),
        op_str: ops.join(", "),
    }]
}

fn lift_movn(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let src = parse_operand(func, ops[1]);
    let result = func.add_expr(LlilExpr::UnaryOp {
        op: UnaryOp::Not,
        operand: src,
    });
    vec![LlilStmt::SetReg {
        dest: ops[0].trim().to_string(),
        src: result,
    }]
}

fn lift_alu3(func: &mut LlilFunction, op: BinOp, ops: &[&str]) -> Vec<LlilStmt> {
    // ARM64 3-operand: dest, src1, src2
    // Also handles 2-operand form (e.g. add x0, x0, #1 sometimes printed as add x0, #1 in aliases)
    if ops.len() == 3 {
        let left = parse_operand(func, ops[1]);
        let right = parse_operand(func, ops[2]);
        let result = func.binop(op, left, right);
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else if ops.len() == 2 {
        // 2-operand alias: dest = dest OP src
        let left = parse_operand(func, ops[0]);
        let right = parse_operand(func, ops[1]);
        let result = func.binop(op, left, right);
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else {
        vec![LlilStmt::Nop]
    }
}

fn lift_unary(func: &mut LlilFunction, op: UnaryOp, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let src = parse_operand(func, ops[1]);
    let result = func.add_expr(LlilExpr::UnaryOp { op, operand: src });
    vec![LlilStmt::SetReg {
        dest: ops[0].trim().to_string(),
        src: result,
    }]
}

fn lift_cmp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let left = parse_operand(func, ops[0]);
    let right = parse_operand(func, ops[1]);
    let result = func.binop(BinOp::Sub, left, right);
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: result,
    }]
}

fn lift_tst(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let left = parse_operand(func, ops[0]);
    let right = parse_operand(func, ops[1]);
    let result = func.binop(BinOp::And, left, right);
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: result,
    }]
}

fn lift_ldr(func: &mut LlilFunction, mn: &str, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let dest = ops[0].trim();
    let mem_str = ops[1].trim();

    // Determine size from mnemonic, or from register width
    let mut size = mem_size_from_mnemonic(mn);
    if mn == "ldr" {
        size = reg_size(dest);
    }

    // Parse memory operand
    if mem_str.starts_with('[') {
        // Reconstruct the full memory string including possible post-index parts
        let full_mem = if ops.len() > 2 {
            // Post-index: e.g. [x1], #16 was split as "[x1]", "#16"
            format!("{}, {}", mem_str, ops[2])
        } else {
            mem_str.to_string()
        };
        let (addr, _default_size) = parse_mem_operand(func, &full_mem);
        let loaded = func.load(addr, size);
        vec![LlilStmt::SetReg {
            dest: dest.to_string(),
            src: loaded,
        }]
    } else {
        // Literal load: ldr x0, =label or ldr x0, #imm
        let src = parse_operand(func, mem_str);
        vec![LlilStmt::SetReg {
            dest: dest.to_string(),
            src,
        }]
    }
}

fn lift_str(func: &mut LlilFunction, mn: &str, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let src_reg = ops[0].trim();
    let mem_str = ops[1].trim();

    let mut size = mem_size_from_mnemonic(mn);
    if mn == "str" {
        size = reg_size(src_reg);
    }

    if mem_str.starts_with('[') {
        let full_mem = if ops.len() > 2 {
            format!("{}, {}", mem_str, ops[2])
        } else {
            mem_str.to_string()
        };
        let (addr, _) = parse_mem_operand(func, &full_mem);
        let value = parse_operand(func, src_reg);
        vec![LlilStmt::Store { addr, value, size }]
    } else {
        vec![LlilStmt::Nop]
    }
}

fn lift_ldp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // ldp x29, x30, [sp], #16  or  ldp x29, x30, [sp, #offset]
    if ops.len() < 3 {
        return vec![LlilStmt::Nop];
    }
    let dest1 = ops[0].trim();
    let dest2 = ops[1].trim();
    let mem_str = ops[2].trim();
    let size = reg_size(dest1);

    if mem_str.starts_with('[') {
        let full_mem = if ops.len() > 3 {
            format!("{}, {}", mem_str, ops[3])
        } else {
            mem_str.to_string()
        };
        let (addr, _) = parse_mem_operand(func, &full_mem);

        // First load at addr
        let load1 = func.load(addr, size);

        // Second load at addr + size
        let offset = func.const_val(size as u64);
        let addr2 = func.binop(BinOp::Add, addr, offset);
        let load2 = func.load(addr2, size);

        vec![
            LlilStmt::SetReg {
                dest: dest1.to_string(),
                src: load1,
            },
            LlilStmt::SetReg {
                dest: dest2.to_string(),
                src: load2,
            },
        ]
    } else {
        vec![LlilStmt::Nop]
    }
}

fn lift_stp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // stp x29, x30, [sp, #-16]!  or  stp x29, x30, [sp, #offset]
    if ops.len() < 3 {
        return vec![LlilStmt::Nop];
    }
    let src1 = ops[0].trim();
    let src2 = ops[1].trim();
    let mem_str = ops[2].trim();
    let size = reg_size(src1);

    if mem_str.starts_with('[') {
        let full_mem = if ops.len() > 3 {
            format!("{}, {}", mem_str, ops[3])
        } else {
            mem_str.to_string()
        };
        let (addr, _) = parse_mem_operand(func, &full_mem);

        let val1 = parse_operand(func, src1);
        let val2 = parse_operand(func, src2);

        // Second store at addr + size
        let offset = func.const_val(size as u64);
        let addr2 = func.binop(BinOp::Add, addr, offset);

        vec![
            LlilStmt::Store {
                addr,
                value: val1,
                size,
            },
            LlilStmt::Store {
                addr: addr2,
                value: val2,
                size,
            },
        ]
    } else {
        vec![LlilStmt::Nop]
    }
}

fn lift_branch(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Jump { target }]
}

fn lift_branch_cond(func: &mut LlilFunction, cond: FlagCondition, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let target = parse_operand(func, ops[0]);
    let flag = func.add_expr(LlilExpr::Flag(cond));
    vec![LlilStmt::BranchIf { cond: flag, target }]
}

fn lift_call(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Call { target }]
}

fn lift_cbz(func: &mut LlilFunction, ops: &[&str], cond: FlagCondition) -> Vec<LlilStmt> {
    // cbz x0, #0x1234
    // First set flags by comparing the register with zero, then branch.
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let reg = parse_operand(func, ops[0]);
    let zero = func.const_val(0);
    let cmp_result = func.binop(BinOp::Sub, reg, zero);
    let target = parse_operand(func, ops[1]);
    let flag = func.add_expr(LlilExpr::Flag(cond));
    vec![
        LlilStmt::SetReg {
            dest: "__flags".into(),
            src: cmp_result,
        },
        LlilStmt::BranchIf { cond: flag, target },
    ]
}

fn lift_adr(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let dest = ops[0].trim();
    let addr = parse_operand(func, ops[1]);
    vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: addr,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insn(addr: u64, mn: &str, op: &str) -> Instruction {
        Instruction {
            address: addr,
            bytes: vec![],
            mnemonic: mn.to_string(),
            op_str: op.to_string(),
            groups: vec![],
        }
    }

    #[test]
    fn lift_mov_reg_reg() {
        let insns = [make_insn(0x1000, "mov", "x0, x1")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert_eq!(func.exprs[*src], LlilExpr::Reg("x1".into()));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_mov_reg_imm() {
        let insns = [make_insn(0x1000, "mov", "x0, #0x42")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert_eq!(func.exprs[*src], LlilExpr::Const(0x42));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_add_three_reg() {
        let insns = [make_insn(0x1000, "add", "x0, x1, x2")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                match &func.exprs[*src] {
                    LlilExpr::BinOp { op, left, right } => {
                        assert_eq!(*op, BinOp::Add);
                        assert_eq!(func.exprs[*left], LlilExpr::Reg("x1".into()));
                        assert_eq!(func.exprs[*right], LlilExpr::Reg("x2".into()));
                    }
                    other => panic!("Expected BinOp, got {:?}", other),
                }
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_add_reg_imm() {
        let insns = [make_insn(0x1000, "add", "x0, x1, #0x10")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                match &func.exprs[*src] {
                    LlilExpr::BinOp { op, left, right } => {
                        assert_eq!(*op, BinOp::Add);
                        assert_eq!(func.exprs[*left], LlilExpr::Reg("x1".into()));
                        assert_eq!(func.exprs[*right], LlilExpr::Const(0x10));
                    }
                    other => panic!("Expected BinOp, got {:?}", other),
                }
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_sub() {
        let insns = [make_insn(0x1000, "sub", "x0, x1, x2")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Sub, .. }
                ));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_ldr_simple() {
        let insns = [make_insn(0x1000, "ldr", "x0, [x1]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 8, .. }));
            }
            other => panic!("Expected SetReg with Load, got {:?}", other),
        }
    }

    #[test]
    fn lift_ldr_w_register() {
        let insns = [make_insn(0x1000, "ldr", "w0, [x1]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "w0");
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 4, .. }));
            }
            other => panic!("Expected SetReg with Load(4), got {:?}", other),
        }
    }

    #[test]
    fn lift_str_simple() {
        let insns = [make_insn(0x1000, "str", "x0, [x1]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::Store { size, .. } => {
                assert_eq!(*size, 8);
            }
            other => panic!("Expected Store, got {:?}", other),
        }
    }

    #[test]
    fn lift_stp_pair() {
        let insns = [make_insn(0x1000, "stp", "x29, x30, [sp, #-16]")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions[0].stmts.len(), 2);
        assert!(matches!(
            func.instructions[0].stmts[0],
            LlilStmt::Store { size: 8, .. }
        ));
        assert!(matches!(
            func.instructions[0].stmts[1],
            LlilStmt::Store { size: 8, .. }
        ));
    }

    #[test]
    fn lift_ldp_pair() {
        let insns = [make_insn(0x1000, "ldp", "x29, x30, [sp, #16]")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions[0].stmts.len(), 2);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x29");
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 8, .. }));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
        match &func.instructions[0].stmts[1] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x30");
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 8, .. }));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_bl() {
        let insns = [make_insn(0x1000, "bl", "#0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::Call { target } => {
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected Call, got {:?}", other),
        }
    }

    #[test]
    fn lift_b_unconditional() {
        let insns = [make_insn(0x1000, "b", "#0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::Jump { target } => {
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn lift_b_eq() {
        let insns = [make_insn(0x1000, "b.eq", "#0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::BranchIf { cond, target } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::E));
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn lift_b_ne() {
        let insns = [make_insn(0x1000, "b.ne", "#0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::BranchIf { cond, target } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::Ne));
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn lift_b_lt() {
        let insns = [make_insn(0x1000, "b.lt", "#0x2000")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::BranchIf { cond, .. } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::Slt));
            }
            other => panic!("Expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn lift_ret() {
        let insns = [make_insn(0x1000, "ret", "")];
        let func = lift_function("test", 0x1000, &insns);
        assert!(matches!(func.instructions[0].stmts[0], LlilStmt::Return));
    }

    #[test]
    fn lift_cmp_regs() {
        let insns = [make_insn(0x1000, "cmp", "x0, x1")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "__flags");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Sub, .. }
                ));
            }
            other => panic!("Expected SetReg __flags, got {:?}", other),
        }
    }

    #[test]
    fn lift_cbz() {
        let insns = [make_insn(0x1000, "cbz", "x0, #0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions[0].stmts.len(), 2);
        // First: set flags
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::SetReg { dest, .. } if dest == "__flags"
        ));
        // Second: branch if equal
        match &func.instructions[0].stmts[1] {
            LlilStmt::BranchIf { cond, target } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::E));
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn lift_cbnz() {
        let insns = [make_insn(0x1000, "cbnz", "x0, #0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions[0].stmts.len(), 2);
        match &func.instructions[0].stmts[1] {
            LlilStmt::BranchIf { cond, .. } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::Ne));
            }
            other => panic!("Expected BranchIf with Ne, got {:?}", other),
        }
    }

    #[test]
    fn lift_and_orr_eor() {
        let insns = [
            make_insn(0x1000, "and", "x0, x1, x2"),
            make_insn(0x1004, "orr", "x0, x1, x2"),
            make_insn(0x1008, "eor", "x0, x1, x2"),
        ];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::And, .. }
                ));
            }
            other => panic!("Expected SetReg with And, got {:?}", other),
        }
        match &func.instructions[1].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Or, .. }
                ));
            }
            other => panic!("Expected SetReg with Or, got {:?}", other),
        }
        match &func.instructions[2].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Xor, .. }
                ));
            }
            other => panic!("Expected SetReg with Xor, got {:?}", other),
        }
    }

    #[test]
    fn lift_shifts() {
        let insns = [
            make_insn(0x1000, "lsl", "x0, x1, #3"),
            make_insn(0x1004, "lsr", "x0, x1, #3"),
            make_insn(0x1008, "asr", "x0, x1, #3"),
        ];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Shl, .. }
                ));
            }
            _ => panic!("Expected Shl"),
        }
        match &func.instructions[1].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Shr, .. }
                ));
            }
            _ => panic!("Expected Shr"),
        }
        match &func.instructions[2].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Sar, .. }
                ));
            }
            _ => panic!("Expected Sar"),
        }
    }

    #[test]
    fn lift_mul() {
        let insns = [make_insn(0x1000, "mul", "x0, x1, x2")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { src, .. } => {
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Mul, .. }
                ));
            }
            other => panic!("Expected SetReg with Mul, got {:?}", other),
        }
    }

    #[test]
    fn lift_neg_mvn() {
        let insns = [
            make_insn(0x1000, "neg", "x0, x1"),
            make_insn(0x1004, "mvn", "x0, x1"),
        ];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::UnaryOp {
                        op: UnaryOp::Neg,
                        ..
                    }
                ));
            }
            other => panic!("Expected SetReg with Neg, got {:?}", other),
        }
        match &func.instructions[1].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::UnaryOp {
                        op: UnaryOp::Not,
                        ..
                    }
                ));
            }
            other => panic!("Expected SetReg with Not, got {:?}", other),
        }
    }

    #[test]
    fn lift_nop() {
        let insns = [make_insn(0x1000, "nop", "")];
        let func = lift_function("test", 0x1000, &insns);
        assert!(matches!(func.instructions[0].stmts[0], LlilStmt::Nop));
    }

    #[test]
    fn lift_adr() {
        let insns = [make_insn(0x1000, "adr", "x0, #0x1234")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert_eq!(func.exprs[*src], LlilExpr::Const(0x1234));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_adrp() {
        let insns = [make_insn(0x1000, "adrp", "x0, #0x1000")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert_eq!(func.exprs[*src], LlilExpr::Const(0x1000));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_zero_register() {
        let insns = [make_insn(0x1000, "mov", "x0, xzr")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert_eq!(func.exprs[*src], LlilExpr::Const(0));
            }
            other => panic!("Expected SetReg with Const(0), got {:?}", other),
        }
    }

    #[test]
    fn lift_tst() {
        let insns = [make_insn(0x1000, "tst", "x0, x1")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "__flags");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::And, .. }
                ));
            }
            other => panic!("Expected SetReg __flags, got {:?}", other),
        }
    }

    #[test]
    fn lift_unimplemented_passes_through() {
        let insns = [make_insn(0x1000, "mrs", "x0, sctlr_el1")];
        let func = lift_function("test", 0x1000, &insns);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::Unimplemented { mnemonic, .. } if mnemonic == "mrs"
        ));
    }

    #[test]
    fn lift_ldr_with_offset() {
        let insns = [make_insn(0x1000, "ldr", "x0, [x1, #16]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                // Should be Load { addr: BinOp(Add, Reg("x1"), Const(16)), size: 8 }
                match &func.exprs[*src] {
                    LlilExpr::Load { addr, size } => {
                        assert_eq!(*size, 8);
                        assert!(matches!(func.exprs[*addr], LlilExpr::BinOp { .. }));
                    }
                    other => panic!("Expected Load, got {:?}", other),
                }
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_full_function() {
        // A typical ARM64 function prologue/epilogue
        let insns = [
            make_insn(0x1000, "stp", "x29, x30, [sp, #-16]"),
            make_insn(0x1004, "mov", "x29, sp"),
            make_insn(0x1008, "mov", "x0, #0"),
            make_insn(0x100c, "ldp", "x29, x30, [sp, #16]"),
            make_insn(0x1010, "ret", ""),
        ];
        let func = lift_function("test_func", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 5);
        assert_eq!(func.entry, 0x1000);
        assert_eq!(func.name, "test_func");
        // Last instruction should be Return
        assert!(matches!(func.instructions[4].stmts[0], LlilStmt::Return));
    }

    #[test]
    fn lift_movn() {
        let insns = [make_insn(0x1000, "movn", "x0, #0")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::UnaryOp {
                        op: UnaryOp::Not,
                        ..
                    }
                ));
            }
            other => panic!("Expected SetReg with Not, got {:?}", other),
        }
    }

    #[test]
    fn lift_blr() {
        let insns = [make_insn(0x1000, "blr", "x8")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::Call { target } => {
                assert_eq!(func.exprs[*target], LlilExpr::Reg("x8".into()));
            }
            other => panic!("Expected Call, got {:?}", other),
        }
    }

    #[test]
    fn lift_ldrb() {
        let insns = [make_insn(0x1000, "ldrb", "w0, [x1]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "w0");
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 1, .. }));
            }
            other => panic!("Expected SetReg with Load(1), got {:?}", other),
        }
    }

    #[test]
    fn lift_strb() {
        let insns = [make_insn(0x1000, "strb", "w0, [x1]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::Store { size, .. } => {
                assert_eq!(*size, 1);
            }
            other => panic!("Expected Store(1), got {:?}", other),
        }
    }

    // ========================= NEON SIMD tests =========================

    #[test]
    fn lift_neon_add_4s() {
        let insns = [make_insn(0x1000, "add", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Int32);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fadd() {
        let insns = [make_insn(0x1000, "fadd", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Float32);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_eor() {
        let insns = [make_insn(0x1000, "eor", "v0.16b, v1.16b, v2.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Xor);
            } else {
                panic!("expected VectorOp::Xor");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fmla() {
        let insns = [make_insn(0x1000, "fmla", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::FusedMulAdd);
            } else {
                panic!("expected VectorOp::FusedMulAdd");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_cmeq() {
        let insns = [make_insn(0x1000, "cmeq", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::CompareEq);
            } else {
                panic!("expected VectorOp::CompareEq");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_sub_8h() {
        let insns = [make_insn(0x1000, "sub", "v3.8h, v4.8h, v5.8h")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v3");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Sub);
                assert_eq!(*element_type, VectorElementType::Int16);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp::Sub");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_mul_4s() {
        let insns = [make_insn(0x1000, "mul", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Mul);
            } else {
                panic!("expected VectorOp::Mul");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_and_16b() {
        let insns = [make_insn(0x1000, "and", "v0.16b, v1.16b, v2.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::And);
                assert_eq!(*element_type, VectorElementType::Int8);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp::And");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_orr_16b() {
        let insns = [make_insn(0x1000, "orr", "v0.16b, v1.16b, v2.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Or);
            } else {
                panic!("expected VectorOp::Or");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_bic() {
        let insns = [make_insn(0x1000, "bic", "v0.16b, v1.16b, v2.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::AndNot);
            } else {
                panic!("expected VectorOp::AndNot");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_shl() {
        let insns = [make_insn(0x1000, "shl", "v0.4s, v1.4s, #3")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ShiftLeft);
            } else {
                panic!("expected VectorOp::ShiftLeft");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_ushr() {
        let insns = [make_insn(0x1000, "ushr", "v0.4s, v1.4s, #3")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ShiftRight);
            } else {
                panic!("expected VectorOp::ShiftRight");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_sshr() {
        let insns = [make_insn(0x1000, "sshr", "v0.4s, v1.4s, #3")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ShiftRightArith);
            } else {
                panic!("expected VectorOp::ShiftRightArith");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_cmgt() {
        let insns = [make_insn(0x1000, "cmgt", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::CompareGt);
            } else {
                panic!("expected VectorOp::CompareGt");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_cmlt() {
        let insns = [make_insn(0x1000, "cmlt", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::CompareLt);
            } else {
                panic!("expected VectorOp::CompareLt");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fsub() {
        let insns = [make_insn(0x1000, "fsub", "v0.2d, v1.2d, v2.2d")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Sub);
                assert_eq!(*element_type, VectorElementType::Float64);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp::Sub with Float64");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fmul() {
        let insns = [make_insn(0x1000, "fmul", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Mul);
                assert_eq!(*element_type, VectorElementType::Float32);
            } else {
                panic!("expected VectorOp::Mul");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fdiv() {
        let insns = [make_insn(0x1000, "fdiv", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Div);
            } else {
                panic!("expected VectorOp::Div");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fsqrt() {
        let insns = [make_insn(0x1000, "fsqrt", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Sqrt);
            } else {
                panic!("expected VectorOp::Sqrt");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fabs() {
        let insns = [make_insn(0x1000, "fabs", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Abs);
            } else {
                panic!("expected VectorOp::Abs");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fmin_fmax() {
        let insns = [
            make_insn(0x1000, "fmin", "v0.4s, v1.4s, v2.4s"),
            make_insn(0x1004, "fmax", "v3.4s, v4.4s, v5.4s"),
        ];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[match &llil.instructions[0].stmts[0] {
            LlilStmt::SetReg { src, .. } => *src,
            _ => panic!("expected SetReg"),
        }] {
            assert_eq!(*kind, VectorOpKind::Min);
        } else {
            panic!("expected VectorOp::Min");
        }
        if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[match &llil.instructions[1].stmts[0] {
            LlilStmt::SetReg { src, .. } => *src,
            _ => panic!("expected SetReg"),
        }] {
            assert_eq!(*kind, VectorOpKind::Max);
        } else {
            panic!("expected VectorOp::Max");
        }
    }

    #[test]
    fn lift_neon_fmls() {
        let insns = [make_insn(0x1000, "fmls", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::FusedMulSub);
            } else {
                panic!("expected VectorOp::FusedMulSub");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_sqadd() {
        let insns = [make_insn(0x1000, "sqadd", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::AddSaturate);
            } else {
                panic!("expected VectorOp::AddSaturate");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_sqsub() {
        let insns = [make_insn(0x1000, "sqsub", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::SubSaturate);
            } else {
                panic!("expected VectorOp::SubSaturate");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_smin_smax() {
        let insns = [
            make_insn(0x1000, "smin", "v0.4s, v1.4s, v2.4s"),
            make_insn(0x1004, "smax", "v3.4s, v4.4s, v5.4s"),
        ];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[match &llil.instructions[0].stmts[0] {
            LlilStmt::SetReg { src, .. } => *src,
            _ => panic!("expected SetReg"),
        }] {
            assert_eq!(*kind, VectorOpKind::Min);
        } else {
            panic!("expected VectorOp::Min");
        }
        if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[match &llil.instructions[1].stmts[0] {
            LlilStmt::SetReg { src, .. } => *src,
            _ => panic!("expected SetReg"),
        }] {
            assert_eq!(*kind, VectorOpKind::Max);
        } else {
            panic!("expected VectorOp::Max");
        }
    }

    #[test]
    fn lift_neon_mov_16b() {
        let insns = [make_insn(0x1000, "mov", "v0.16b, v1.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Move);
            } else {
                panic!("expected VectorOp::Move");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_dup() {
        let insns = [make_insn(0x1000, "dup", "v0.4s, w1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Broadcast);
                assert_eq!(*element_type, VectorElementType::Int32);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp::Broadcast");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_movi_zero() {
        let insns = [make_insn(0x1000, "movi", "v0.4s, #0")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Zero);
            } else {
                panic!("expected VectorOp::Zero");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_movi_nonzero() {
        let insns = [make_insn(0x1000, "movi", "v0.4s, #1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Broadcast);
            } else {
                panic!("expected VectorOp::Broadcast");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_ins() {
        let insns = [make_insn(0x1000, "ins", "v0.s[2], w1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Insert { index: 2 });
            } else {
                panic!("expected VectorOp::Insert");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_umov() {
        let insns = [make_insn(0x1000, "umov", "w1, v0.s[2]")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "w1");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Extract { index: 2 });
            } else {
                panic!("expected VectorOp::Extract");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_sxtl() {
        let insns = [make_insn(0x1000, "sxtl", "v0.4s, v1.4h")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ConvertWiden);
            } else {
                panic!("expected VectorOp::ConvertWiden");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_xtn() {
        let insns = [make_insn(0x1000, "xtn", "v0.4h, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ConvertNarrow);
            } else {
                panic!("expected VectorOp::ConvertNarrow");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_addp() {
        let insns = [make_insn(0x1000, "addp", "v0.4s, v1.4s, v2.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::HorizontalAdd);
            } else {
                panic!("expected VectorOp::HorizontalAdd");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_tbl() {
        let insns = [make_insn(0x1000, "tbl", "v0.16b, v1.16b, v2.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ShuffleBytes);
            } else {
                panic!("expected VectorOp::ShuffleBytes");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_scvtf() {
        let insns = [make_insn(0x1000, "scvtf", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ConvertIntToFloat);
            } else {
                panic!("expected VectorOp::ConvertIntToFloat");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fcvtzs() {
        let insns = [make_insn(0x1000, "fcvtzs", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::ConvertFloatToInt);
            } else {
                panic!("expected VectorOp::ConvertFloatToInt");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_neg_4s() {
        let insns = [make_insn(0x1000, "neg", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Intrinsic("vneg".into()));
            } else {
                panic!("expected VectorOp::Intrinsic(vneg)");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_not_16b() {
        let insns = [make_insn(0x1000, "not", "v0.16b, v1.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Intrinsic("vnot".into()));
            } else {
                panic!("expected VectorOp::Intrinsic(vnot)");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_mvn_16b() {
        // mvn is alias for not in NEON context
        let insns = [make_insn(0x1000, "mvn", "v0.16b, v1.16b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Intrinsic("vnot".into()));
            } else {
                panic!("expected VectorOp::Intrinsic(vnot)");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_fneg() {
        let insns = [make_insn(0x1000, "fneg", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Intrinsic("fneg".into()));
            } else {
                panic!("expected VectorOp::Intrinsic(fneg)");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_abs_4s() {
        let insns = [make_insn(0x1000, "abs", "v0.4s, v1.4s")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::Abs);
            } else {
                panic!("expected VectorOp::Abs");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_neon_64bit_width() {
        // Test 64-bit vector width (8b arrangement)
        let insns = [make_insn(0x1000, "add", "v0.8b, v1.8b, v2.8b")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "v0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Int8);
                assert_eq!(*width, 64);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn scalar_add_still_works() {
        // Ensure scalar add is not broken by NEON detection
        let insns = [make_insn(0x1000, "add", "x0, x1, x2")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Add, .. }
                ));
            }
            other => panic!("Expected scalar BinOp::Add, got {:?}", other),
        }
    }

    #[test]
    fn scalar_sub_still_works() {
        let insns = [make_insn(0x1000, "sub", "x0, x1, x2")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::BinOp { op: BinOp::Sub, .. }
                ));
            }
            other => panic!("Expected scalar BinOp::Sub, got {:?}", other),
        }
    }

    #[test]
    fn scalar_neg_still_works() {
        let insns = [make_insn(0x1000, "neg", "x0, x1")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::UnaryOp {
                        op: UnaryOp::Neg,
                        ..
                    }
                ));
            }
            other => panic!("Expected scalar UnaryOp::Neg, got {:?}", other),
        }
    }

    #[test]
    fn scalar_mvn_still_works() {
        let insns = [make_insn(0x1000, "mvn", "x0, x1")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "x0");
                assert!(matches!(
                    func.exprs[*src],
                    LlilExpr::UnaryOp {
                        op: UnaryOp::Not,
                        ..
                    }
                ));
            }
            other => panic!("Expected scalar UnaryOp::Not, got {:?}", other),
        }
    }
}
