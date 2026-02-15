//! x86/x86_64 lifter: converts native instructions to LLIL.

use crate::disasm::Instruction;
use crate::il::llil::*;

// ---------------------------------------------------------------------------
// SIMD helpers
// ---------------------------------------------------------------------------

/// Detect vector width from operand register names.
fn detect_vector_width(ops: &str) -> u16 {
    if ops.contains("zmm") {
        512
    } else if ops.contains("ymm") {
        256
    } else if ops.contains("xmm") {
        128
    } else if ops.contains("mm") {
        64
    } else {
        128 // default
    }
}

/// Extract the destination register name (first operand).
fn extract_dest_reg(ops: &str) -> &str {
    ops.split(',').next().unwrap_or("").trim()
}

/// Extract source operands (everything after the first comma), split by comma.
fn extract_source_parts(ops: &str) -> Vec<&str> {
    let mut parts = ops.split(',');
    parts.next(); // skip dest
    parts.map(|s| s.trim()).collect()
}

/// Extract immediate value from the last operand.
fn extract_imm8(ops: &str) -> u8 {
    let last = ops.split(',').next_back().unwrap_or("").trim();
    if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        last.parse::<u8>().unwrap_or(0)
    }
}

/// Check if two register-name operands are the same (zero-idiom detection).
fn is_same_reg_pair(ops: &str) -> bool {
    let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
    match parts.len() {
        2 => !parts[0].is_empty() && parts[0] == parts[1],
        3 => !parts[0].is_empty() && parts[0] == parts[1] && parts[1] == parts[2],
        _ => false,
    }
}

/// Build source operand `ExprId`s from the operand string, skipping the
/// destination (first) operand.
fn build_source_operands(func: &mut LlilFunction, ops: &str) -> Vec<ExprId> {
    extract_source_parts(ops)
        .iter()
        .map(|s| parse_operand(func, s))
        .collect()
}

/// Lift a sequence of native x86 instructions into an `LlilFunction`.
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

/// Lift a single native instruction into one or more LLIL statements.
fn lift_instruction(func: &mut LlilFunction, insn: &Instruction) -> Vec<LlilStmt> {
    let mn = insn.mnemonic.to_lowercase();
    let ops: Vec<&str> = if insn.op_str.is_empty() {
        vec![]
    } else {
        insn.op_str.split(',').map(|s| s.trim()).collect()
    };

    match mn.as_str() {
        "nop" | "endbr64" | "endbr32" => vec![LlilStmt::Nop],

        // --- Data movement ---
        "mov" | "movabs" | "movzx" | "movsx" | "movsxd" => lift_mov(func, &ops),
        "lea" => lift_lea(func, &ops),
        "push" => lift_push(func, &ops),
        "pop" => lift_pop(func, &ops),
        "xchg" => lift_xchg(func, &ops),

        // --- Arithmetic ---
        "add" => lift_binop(func, BinOp::Add, &ops),
        "sub" => lift_binop(func, BinOp::Sub, &ops),
        "imul" => lift_imul(func, &ops),
        "inc" => lift_inc_dec(func, BinOp::Add, &ops),
        "dec" => lift_inc_dec(func, BinOp::Sub, &ops),
        "neg" => lift_neg(func, &ops),

        // --- Bitwise ---
        "and" => lift_binop(func, BinOp::And, &ops),
        "or" => lift_binop(func, BinOp::Or, &ops),
        "xor" => lift_xor(func, &ops),
        "not" => lift_not(func, &ops),
        "shl" | "sal" => lift_binop(func, BinOp::Shl, &ops),
        "shr" => lift_binop(func, BinOp::Shr, &ops),
        "sar" => lift_binop(func, BinOp::Sar, &ops),

        // --- Comparison / test ---
        "cmp" => lift_cmp(func, &ops),
        "test" => lift_test(func, &ops),

        // --- Control flow ---
        "jmp" => lift_jmp(func, &ops),
        "je" | "jz" => lift_jcc(func, FlagCondition::E, &ops),
        "jne" | "jnz" => lift_jcc(func, FlagCondition::Ne, &ops),
        "jb" | "jc" | "jnae" => lift_jcc(func, FlagCondition::Ult, &ops),
        "jbe" | "jna" => lift_jcc(func, FlagCondition::Ule, &ops),
        "ja" | "jnbe" => lift_jcc(func, FlagCondition::Ugt, &ops),
        "jae" | "jnb" | "jnc" => lift_jcc(func, FlagCondition::Uge, &ops),
        "jl" | "jnge" => lift_jcc(func, FlagCondition::Slt, &ops),
        "jle" | "jng" => lift_jcc(func, FlagCondition::Sle, &ops),
        "jg" | "jnle" => lift_jcc(func, FlagCondition::Sgt, &ops),
        "jge" | "jnl" => lift_jcc(func, FlagCondition::Sge, &ops),
        "js" => lift_jcc(func, FlagCondition::Neg, &ops),
        "jo" => lift_jcc(func, FlagCondition::Overflow, &ops),
        "call" => lift_call(func, &ops),
        "ret" | "retn" => vec![LlilStmt::Return],

        // --- SIMD / Vector ---
        _ => {
            if let Some(stmts) = lift_simd_instruction(func, &mn, &insn.op_str) {
                stmts
            } else {
                vec![LlilStmt::Unimplemented {
                    mnemonic: insn.mnemonic.clone(),
                    op_str: insn.op_str.clone(),
                }]
            }
        }
    }
}

/// Parse an operand string into an LLIL expression.
fn parse_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    let op = op.trim();

    // Memory operand: e.g. "qword ptr [rbp - 8]" or "[rax + rcx*4]"
    if let Some(inner) = extract_mem_operand(op) {
        let addr = parse_address_expr(func, inner);
        let size = mem_size_prefix(op);
        return func.load(addr, size);
    }

    // Immediate
    if let Some(val) = parse_immediate(op) {
        return func.const_val(val);
    }

    // Register
    func.reg(op)
}

/// Extract content between [ and ] from a memory operand.
fn extract_mem_operand(op: &str) -> Option<&str> {
    let start = op.find('[')?;
    let end = op.find(']')?;
    Some(op[start + 1..end].trim())
}

/// Parse an address expression inside brackets like "rbp - 8" or "rax + rcx*4 + 0x10".
fn parse_address_expr(func: &mut LlilFunction, expr: &str) -> ExprId {
    let expr = expr.trim();

    // Try splitting on " + " and " - " for compound expressions
    // Handle subtraction: "rbp - 8"
    if let Some(pos) = expr.rfind(" - ") {
        let left = parse_address_expr(func, &expr[..pos]);
        let right = parse_address_expr(func, &expr[pos + 3..]);
        return func.binop(BinOp::Sub, left, right);
    }

    // Handle addition: "rax + rcx*4"
    if let Some(pos) = expr.rfind(" + ") {
        let left = parse_address_expr(func, &expr[..pos]);
        let right = parse_address_expr(func, &expr[pos + 3..]);
        return func.binop(BinOp::Add, left, right);
    }

    // Handle scale: "rcx*4"
    if let Some(pos) = expr.find('*') {
        let reg_part = expr[..pos].trim();
        let scale_part = expr[pos + 1..].trim();
        let reg = func.reg(reg_part);
        if let Some(scale) = parse_immediate(scale_part) {
            let s = func.const_val(scale);
            return func.binop(BinOp::Mul, reg, s);
        }
    }

    // Immediate
    if let Some(val) = parse_immediate(expr) {
        return func.const_val(val);
    }

    // Register
    func.reg(expr)
}

/// Determine memory access size from prefix (qword=8, dword=4, word=2, byte=1).
fn mem_size_prefix(op: &str) -> u8 {
    let lower = op.to_lowercase();
    if lower.starts_with("qword") {
        8
    } else if lower.starts_with("dword") {
        4
    } else if lower.starts_with("word") {
        2
    } else if lower.starts_with("byte") {
        1
    } else {
        // Default to pointer size
        8
    }
}

/// Parse an immediate value (hex or decimal).
fn parse_immediate(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.starts_with('-') {
        s.parse::<i64>().ok().map(|v| v as u64)
    } else {
        s.parse::<u64>().ok()
    }
}

/// Check if an operand is a memory reference.
fn is_mem_operand(op: &str) -> bool {
    op.contains('[')
}

/// Determine if a destination operand is a register (not memory).
fn dest_is_reg(op: &str) -> bool {
    !is_mem_operand(op)
}

// --- Lifting helpers ---

fn lift_mov(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    let src = parse_operand(func, ops[1]);
    if dest_is_reg(ops[0]) {
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src,
        }]
    } else {
        // Store to memory
        let addr_inner = extract_mem_operand(ops[0]).unwrap_or(ops[0]);
        let addr = parse_address_expr(func, addr_inner);
        let size = mem_size_prefix(ops[0]);
        vec![LlilStmt::Store {
            addr,
            value: src,
            size,
        }]
    }
}

fn lift_lea(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    // LEA loads the effective address, not the memory contents
    let addr_inner = extract_mem_operand(ops[1]).unwrap_or(ops[1]);
    let addr = parse_address_expr(func, addr_inner);
    vec![LlilStmt::SetReg {
        dest: ops[0].trim().to_string(),
        src: addr,
    }]
}

fn lift_push(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let val = parse_operand(func, ops[0]);
    let rsp = func.reg("rsp");
    let eight = func.const_val(8);
    let new_rsp = func.binop(BinOp::Sub, rsp, eight);
    vec![
        LlilStmt::SetReg {
            dest: "rsp".into(),
            src: new_rsp,
        },
        LlilStmt::Store {
            addr: new_rsp,
            value: val,
            size: 8,
        },
    ]
}

fn lift_pop(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let rsp = func.reg("rsp");
    let loaded = func.load(rsp, 8);
    let eight = func.const_val(8);
    let new_rsp = func.binop(BinOp::Add, rsp, eight);
    vec![
        LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: loaded,
        },
        LlilStmt::SetReg {
            dest: "rsp".into(),
            src: new_rsp,
        },
    ]
}

fn lift_xchg(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    let a = parse_operand(func, ops[0]);
    let b = parse_operand(func, ops[1]);
    vec![
        LlilStmt::SetReg {
            dest: "__tmp".into(),
            src: a,
        },
        LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: b,
        },
        LlilStmt::SetReg {
            dest: ops[1].trim().to_string(),
            src: func.reg("__tmp"),
        },
    ]
}

fn lift_binop(func: &mut LlilFunction, op: BinOp, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    let left = parse_operand(func, ops[0]);
    let right = parse_operand(func, ops[1]);
    let result = func.binop(op, left, right);

    if dest_is_reg(ops[0]) {
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else {
        let addr_inner = extract_mem_operand(ops[0]).unwrap_or(ops[0]);
        let addr = parse_address_expr(func, addr_inner);
        let size = mem_size_prefix(ops[0]);
        vec![LlilStmt::Store {
            addr,
            value: result,
            size,
        }]
    }
}

fn lift_imul(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    match ops.len() {
        2 => lift_binop(func, BinOp::Mul, ops),
        3 => {
            // imul dest, src, imm
            let src = parse_operand(func, ops[1]);
            let imm = parse_operand(func, ops[2]);
            let result = func.binop(BinOp::Mul, src, imm);
            vec![LlilStmt::SetReg {
                dest: ops[0].trim().to_string(),
                src: result,
            }]
        }
        _ => vec![LlilStmt::Nop],
    }
}

fn lift_inc_dec(func: &mut LlilFunction, op: BinOp, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let val = parse_operand(func, ops[0]);
    let one = func.const_val(1);
    let result = func.binop(op, val, one);
    if dest_is_reg(ops[0]) {
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else {
        let addr_inner = extract_mem_operand(ops[0]).unwrap_or(ops[0]);
        let addr = parse_address_expr(func, addr_inner);
        let size = mem_size_prefix(ops[0]);
        vec![LlilStmt::Store {
            addr,
            value: result,
            size,
        }]
    }
}

fn lift_neg(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let val = parse_operand(func, ops[0]);
    let result = func.add_expr(LlilExpr::UnaryOp {
        op: UnaryOp::Neg,
        operand: val,
    });
    if dest_is_reg(ops[0]) {
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else {
        let addr_inner = extract_mem_operand(ops[0]).unwrap_or(ops[0]);
        let addr = parse_address_expr(func, addr_inner);
        let size = mem_size_prefix(ops[0]);
        vec![LlilStmt::Store {
            addr,
            value: result,
            size,
        }]
    }
}

fn lift_xor(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    // xor reg, reg => zero idiom
    if ops[0].trim() == ops[1].trim() && dest_is_reg(ops[0]) {
        let zero = func.const_val(0);
        return vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: zero,
        }];
    }
    lift_binop(func, BinOp::Xor, ops)
}

fn lift_not(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let val = parse_operand(func, ops[0]);
    let result = func.add_expr(LlilExpr::UnaryOp {
        op: UnaryOp::Not,
        operand: val,
    });
    if dest_is_reg(ops[0]) {
        vec![LlilStmt::SetReg {
            dest: ops[0].trim().to_string(),
            src: result,
        }]
    } else {
        let addr_inner = extract_mem_operand(ops[0]).unwrap_or(ops[0]);
        let addr = parse_address_expr(func, addr_inner);
        let size = mem_size_prefix(ops[0]);
        vec![LlilStmt::Store {
            addr,
            value: result,
            size,
        }]
    }
}

fn lift_cmp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![LlilStmt::Nop];
    }
    // CMP sets flags based on left - right (result discarded).
    // We represent this as setting a virtual "flags" register.
    let left = parse_operand(func, ops[0]);
    let right = parse_operand(func, ops[1]);
    let result = func.binop(BinOp::Sub, left, right);
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: result,
    }]
}

fn lift_test(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
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

fn lift_jmp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Jump { target }]
}

fn lift_jcc(func: &mut LlilFunction, cond: FlagCondition, ops: &[&str]) -> Vec<LlilStmt> {
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

// ---------------------------------------------------------------------------
// SIMD instruction lifter
// ---------------------------------------------------------------------------

/// Attempt to lift a SIMD instruction. Returns `None` if the mnemonic is not
/// a recognised SIMD instruction so the caller can fall back to `Unimplemented`.
fn lift_simd_instruction(
    func: &mut LlilFunction,
    mnemonic: &str,
    ops_raw: &str,
) -> Option<Vec<LlilStmt>> {
    let width = detect_vector_width(ops_raw);

    // --- Zero idioms --------------------------------------------------------
    // pxor xmm0, xmm0 / xorps xmm0, xmm0 / vpxor xmm0, xmm0, xmm0 etc.
    if matches!(
        mnemonic,
        "pxor" | "vpxor" | "xorps" | "vxorps" | "xorpd" | "vxorpd"
    ) && is_same_reg_pair(ops_raw)
    {
        let dest = extract_dest_reg(ops_raw).to_string();
        let elem = if mnemonic.contains("ps") {
            VectorElementType::Float32
        } else if mnemonic.contains("pd") {
            VectorElementType::Float64
        } else {
            VectorElementType::Int8
        };
        let expr = func.vector_op(VectorOpKind::Zero, elem, width, vec![]);
        return Some(vec![LlilStmt::SetReg { dest, src: expr }]);
    }

    // --- Determine if this is an AVX (v-prefix) instruction -----------------
    let (is_avx, base_mnemonic) = if mnemonic.starts_with('v') && mnemonic.len() > 1 {
        // FMA instructions have their own prefix patterns; handle separately
        if mnemonic.starts_with("vfmadd") || mnemonic.starts_with("vfmsub") {
            (true, mnemonic.to_string())
        } else {
            (true, mnemonic[1..].to_string())
        }
    } else {
        (false, mnemonic.to_string())
    };

    // For AVX 3-operand form the destination is operand 0, src1 is operand 1,
    // src2 is operand 2. For legacy SSE the destination is operand 0 and it is
    // also the first source (destructive form with 2 operands).
    let dest = extract_dest_reg(ops_raw).to_string();

    // Match the base mnemonic to a (VectorOpKind, VectorElementType) pair.
    let result: Option<(VectorOpKind, VectorElementType)> = match base_mnemonic.as_str() {
        // ---- MMX / SSE2 integer packed add ---------------------------------
        "paddb" => Some((VectorOpKind::Add, VectorElementType::Int8)),
        "paddw" => Some((VectorOpKind::Add, VectorElementType::Int16)),
        "paddd" => Some((VectorOpKind::Add, VectorElementType::Int32)),
        "paddq" => Some((VectorOpKind::Add, VectorElementType::Int64)),

        // ---- MMX / SSE2 integer packed sub ---------------------------------
        "psubb" => Some((VectorOpKind::Sub, VectorElementType::Int8)),
        "psubw" => Some((VectorOpKind::Sub, VectorElementType::Int16)),
        "psubd" => Some((VectorOpKind::Sub, VectorElementType::Int32)),
        "psubq" => Some((VectorOpKind::Sub, VectorElementType::Int64)),

        // ---- Multiply ------------------------------------------------------
        "pmullw" => Some((VectorOpKind::Mul, VectorElementType::Int16)),
        "pmulld" => Some((VectorOpKind::Mul, VectorElementType::Int32)),
        "pmuludq" => Some((VectorOpKind::Mul, VectorElementType::Int64)),

        // ---- Bitwise -------------------------------------------------------
        "pand" | "andps" | "andpd" => {
            let elem = float_elem_from_suffix(&base_mnemonic);
            Some((VectorOpKind::And, elem))
        }
        "por" | "orps" | "orpd" => {
            let elem = float_elem_from_suffix(&base_mnemonic);
            Some((VectorOpKind::Or, elem))
        }
        "pxor" | "xorps" | "xorpd" => {
            // non-zero-idiom case (zero idiom handled above)
            let elem = float_elem_from_suffix(&base_mnemonic);
            Some((VectorOpKind::Xor, elem))
        }
        "pandn" | "andnps" | "andnpd" => {
            let elem = float_elem_from_suffix(&base_mnemonic);
            Some((VectorOpKind::AndNot, elem))
        }

        // ---- Compare -------------------------------------------------------
        "pcmpeqb" => Some((VectorOpKind::CompareEq, VectorElementType::Int8)),
        "pcmpeqw" => Some((VectorOpKind::CompareEq, VectorElementType::Int16)),
        "pcmpeqd" => Some((VectorOpKind::CompareEq, VectorElementType::Int32)),
        "pcmpgtb" => Some((VectorOpKind::CompareGt, VectorElementType::Int8)),
        "pcmpgtw" => Some((VectorOpKind::CompareGt, VectorElementType::Int16)),
        "pcmpgtd" => Some((VectorOpKind::CompareGt, VectorElementType::Int32)),

        // ---- Saturating arithmetic -----------------------------------------
        "paddsb" => Some((VectorOpKind::AddSaturate, VectorElementType::Int8)),
        "paddsw" => Some((VectorOpKind::AddSaturate, VectorElementType::Int16)),
        "psubsb" => Some((VectorOpKind::SubSaturate, VectorElementType::Int8)),
        "psubsw" => Some((VectorOpKind::SubSaturate, VectorElementType::Int16)),

        // ---- Pack ----------------------------------------------------------
        "packuswb" => Some((VectorOpKind::PackUnsigned, VectorElementType::Int8)),
        "packsswb" => Some((VectorOpKind::PackSigned, VectorElementType::Int8)),
        "packssdw" => Some((VectorOpKind::PackSigned, VectorElementType::Int16)),

        // ---- Unpack --------------------------------------------------------
        "punpcklbw" => Some((VectorOpKind::UnpackLow, VectorElementType::Int8)),
        "punpcklwd" => Some((VectorOpKind::UnpackLow, VectorElementType::Int16)),
        "punpckldq" => Some((VectorOpKind::UnpackLow, VectorElementType::Int32)),
        "punpckhbw" => Some((VectorOpKind::UnpackHigh, VectorElementType::Int8)),
        "punpckhwd" => Some((VectorOpKind::UnpackHigh, VectorElementType::Int16)),
        "punpckhdq" => Some((VectorOpKind::UnpackHigh, VectorElementType::Int32)),

        // ---- SSE float arithmetic ------------------------------------------
        "addps" | "addss" => Some((VectorOpKind::Add, VectorElementType::Float32)),
        "subps" | "subss" => Some((VectorOpKind::Sub, VectorElementType::Float32)),
        "mulps" | "mulss" => Some((VectorOpKind::Mul, VectorElementType::Float32)),
        "divps" | "divss" => Some((VectorOpKind::Div, VectorElementType::Float32)),
        "sqrtps" | "sqrtss" => Some((VectorOpKind::Sqrt, VectorElementType::Float32)),
        "rcpps" | "rcpss" => Some((VectorOpKind::Reciprocal, VectorElementType::Float32)),
        "rsqrtps" | "rsqrtss" => Some((VectorOpKind::ReciprocalSqrt, VectorElementType::Float32)),
        "maxps" | "maxss" => Some((VectorOpKind::Max, VectorElementType::Float32)),
        "minps" | "minss" => Some((VectorOpKind::Min, VectorElementType::Float32)),

        // ---- SSE float move ------------------------------------------------
        "movaps" => Some((VectorOpKind::MoveAligned, VectorElementType::Float32)),
        "movups" => Some((VectorOpKind::MoveUnaligned, VectorElementType::Float32)),
        "movss" => Some((VectorOpKind::Move, VectorElementType::Float32)),

        // ---- SSE float shuffle ---------------------------------------------
        "shufps" => {
            let mask = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Shuffle { mask },
                VectorElementType::Float32,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }

        // ---- SSE2 double ---------------------------------------------------
        "addpd" | "addsd" => Some((VectorOpKind::Add, VectorElementType::Float64)),
        "subpd" | "subsd" => Some((VectorOpKind::Sub, VectorElementType::Float64)),
        "mulpd" | "mulsd" => Some((VectorOpKind::Mul, VectorElementType::Float64)),
        "divpd" | "divsd" => Some((VectorOpKind::Div, VectorElementType::Float64)),
        "sqrtpd" | "sqrtsd" => Some((VectorOpKind::Sqrt, VectorElementType::Float64)),

        // ---- SSE2 move -----------------------------------------------------
        "movdqa" => Some((VectorOpKind::MoveAligned, VectorElementType::Int8)),
        "movdqu" => Some((VectorOpKind::MoveUnaligned, VectorElementType::Int8)),
        "movapd" => Some((VectorOpKind::MoveAligned, VectorElementType::Float64)),
        "movupd" => Some((VectorOpKind::MoveUnaligned, VectorElementType::Float64)),

        // ---- SSE2 shuffle / shift ------------------------------------------
        "pshufd" => {
            let mask = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Shuffle { mask },
                VectorElementType::Int32,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "psllw" => Some((VectorOpKind::ShiftLeft, VectorElementType::Int16)),
        "pslld" => Some((VectorOpKind::ShiftLeft, VectorElementType::Int32)),
        "psllq" => Some((VectorOpKind::ShiftLeft, VectorElementType::Int64)),
        "psrlw" => Some((VectorOpKind::ShiftRight, VectorElementType::Int16)),
        "psrld" => Some((VectorOpKind::ShiftRight, VectorElementType::Int32)),
        "psrlq" => Some((VectorOpKind::ShiftRight, VectorElementType::Int64)),
        "psraw" => Some((VectorOpKind::ShiftRightArith, VectorElementType::Int16)),
        "psrad" => Some((VectorOpKind::ShiftRightArith, VectorElementType::Int32)),

        // ---- SSE2 intrinsic ------------------------------------------------
        "pmaddwd" => Some((
            VectorOpKind::Intrinsic("pmaddwd".to_string()),
            VectorElementType::Int16,
        )),

        // ---- SSE3 / SSSE3 -------------------------------------------------
        "haddps" => Some((VectorOpKind::HorizontalAdd, VectorElementType::Float32)),
        "haddpd" => Some((VectorOpKind::HorizontalAdd, VectorElementType::Float64)),
        "hsubps" => Some((VectorOpKind::HorizontalSub, VectorElementType::Float32)),
        "hsubpd" => Some((VectorOpKind::HorizontalSub, VectorElementType::Float64)),
        "pshufb" => Some((VectorOpKind::ShuffleBytes, VectorElementType::Int8)),
        "pabsb" => Some((VectorOpKind::Abs, VectorElementType::Int8)),
        "pabsw" => Some((VectorOpKind::Abs, VectorElementType::Int16)),
        "pabsd" => Some((VectorOpKind::Abs, VectorElementType::Int32)),
        "phaddw" => Some((VectorOpKind::HorizontalAdd, VectorElementType::Int16)),
        "phaddd" => Some((VectorOpKind::HorizontalAdd, VectorElementType::Int32)),
        "phsubw" => Some((VectorOpKind::HorizontalSub, VectorElementType::Int16)),
        "phsubd" => Some((VectorOpKind::HorizontalSub, VectorElementType::Int32)),
        "pavgb" => Some((VectorOpKind::Avg, VectorElementType::Int8)),
        "pavgw" => Some((VectorOpKind::Avg, VectorElementType::Int16)),

        // ---- SSE4.1 blend --------------------------------------------------
        "pblendvb" => Some((VectorOpKind::BlendVar, VectorElementType::Int8)),
        "blendps" => {
            let mask = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Blend { mask },
                VectorElementType::Float32,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "blendpd" => {
            let mask = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Blend { mask },
                VectorElementType::Float64,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }

        // ---- SSE4.1 round --------------------------------------------------
        "roundps" | "roundss" => Some((VectorOpKind::Round, VectorElementType::Float32)),
        "roundpd" | "roundsd" => Some((VectorOpKind::Round, VectorElementType::Float64)),

        // ---- SSE4.1 insert / extract ---------------------------------------
        "pinsrb" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Insert { index: idx },
                VectorElementType::Int8,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pinsrw" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Insert { index: idx },
                VectorElementType::Int16,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pinsrd" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Insert { index: idx },
                VectorElementType::Int32,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pinsrq" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Insert { index: idx },
                VectorElementType::Int64,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pextrb" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Extract { index: idx },
                VectorElementType::Int8,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pextrw" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Extract { index: idx },
                VectorElementType::Int16,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pextrd" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Extract { index: idx },
                VectorElementType::Int32,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }
        "pextrq" => {
            let idx = extract_imm8(ops_raw);
            return Some(lift_simd_simple(
                func,
                VectorOpKind::Extract { index: idx },
                VectorElementType::Int64,
                width,
                &dest,
                ops_raw,
                is_avx,
            ));
        }

        // ---- SSE4.1 widen (zero-extend / sign-extend) ----------------------
        "pmovzxbw" | "pmovsxbw" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int16)),
        "pmovzxbd" | "pmovsxbd" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int32)),
        "pmovzxbq" | "pmovsxbq" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int64)),
        "pmovzxwd" | "pmovsxwd" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int32)),
        "pmovzxwq" | "pmovsxwq" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int64)),
        "pmovzxdq" | "pmovsxdq" => Some((VectorOpKind::ConvertWiden, VectorElementType::Int64)),

        // ---- SSE4.2 string compare -----------------------------------------
        "pcmpistri" | "pcmpistrm" => Some((VectorOpKind::StringCompare, VectorElementType::Int8)),

        // ---- SSE4.1 min / max ----------------------------------------------
        "pminub" => Some((VectorOpKind::Min, VectorElementType::Int8)),
        "pminsb" => Some((VectorOpKind::Min, VectorElementType::Int8)),
        "pminuw" => Some((VectorOpKind::Min, VectorElementType::Int16)),
        "pminsw" => Some((VectorOpKind::Min, VectorElementType::Int16)),
        "pminud" => Some((VectorOpKind::Min, VectorElementType::Int32)),
        "pminsd" => Some((VectorOpKind::Min, VectorElementType::Int32)),
        "pmaxub" => Some((VectorOpKind::Max, VectorElementType::Int8)),
        "pmaxsb" => Some((VectorOpKind::Max, VectorElementType::Int8)),
        "pmaxuw" => Some((VectorOpKind::Max, VectorElementType::Int16)),
        "pmaxsw" => Some((VectorOpKind::Max, VectorElementType::Int16)),
        "pmaxud" => Some((VectorOpKind::Max, VectorElementType::Int32)),
        "pmaxsd" => Some((VectorOpKind::Max, VectorElementType::Int32)),

        // ---- SSE4.1 ptest --------------------------------------------------
        "ptest" => Some((VectorOpKind::TestAllZeros, VectorElementType::Int8)),

        // ---- SSE2 / SSE4.1 conversions ------------------------------------
        "cvtdq2ps" => Some((VectorOpKind::ConvertIntToFloat, VectorElementType::Float32)),
        "cvtps2dq" | "cvttps2dq" => {
            Some((VectorOpKind::ConvertFloatToInt, VectorElementType::Int32))
        }

        // ---- AVX broadcast -------------------------------------------------
        "broadcastss" => Some((VectorOpKind::Broadcast, VectorElementType::Float32)),
        "broadcastsd" => Some((VectorOpKind::Broadcast, VectorElementType::Float64)),

        // ---- AVX vperm2f128 ------------------------------------------------
        "perm2f128" => Some((
            VectorOpKind::Intrinsic("vperm2f128".to_string()),
            VectorElementType::Float32,
        )),

        // ---- FMA -----------------------------------------------------------
        _ if base_mnemonic.starts_with("vfmadd") => {
            let elem = if base_mnemonic.ends_with("ps") {
                VectorElementType::Float32
            } else {
                VectorElementType::Float64
            };
            Some((VectorOpKind::FusedMulAdd, elem))
        }
        _ if base_mnemonic.starts_with("vfmsub") => {
            let elem = if base_mnemonic.ends_with("ps") {
                VectorElementType::Float32
            } else {
                VectorElementType::Float64
            };
            Some((VectorOpKind::FusedMulSub, elem))
        }

        _ => None,
    };

    let (kind, elem) = result?;

    Some(lift_simd_simple(
        func, kind, elem, width, &dest, ops_raw, is_avx,
    ))
}

/// Determine float element type from mnemonic suffix.
fn float_elem_from_suffix(mn: &str) -> VectorElementType {
    if mn.ends_with("ps") {
        VectorElementType::Float32
    } else if mn.ends_with("pd") {
        VectorElementType::Float64
    } else {
        VectorElementType::Int8
    }
}

/// Emit a `SetReg { dest, VectorOp { ... } }` statement for a typical SIMD
/// instruction. For AVX 3-operand form all source parts are used; for legacy
/// SSE the destination doubles as the first source.
fn lift_simd_simple(
    func: &mut LlilFunction,
    kind: VectorOpKind,
    elem: VectorElementType,
    width: u16,
    dest: &str,
    ops_raw: &str,
    is_avx: bool,
) -> Vec<LlilStmt> {
    let operands = if is_avx {
        // AVX: all operands after dest are sources
        build_source_operands(func, ops_raw)
    } else {
        // Legacy SSE: dest is also first source, second operand is the other
        let mut v = vec![parse_operand(func, dest)];
        v.extend(build_source_operands(func, ops_raw));
        v
    };
    let expr = func.vector_op(kind, elem, width, operands);
    vec![LlilStmt::SetReg {
        dest: dest.to_string(),
        src: expr,
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
        let insns = [make_insn(0x1000, "mov", "rax, rbx")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "rax");
                // src should be a Reg("rbx")
                assert_eq!(func.exprs[*src], LlilExpr::Reg("rbx".into()));
            }
            other => panic!("Expected SetReg, got {:?}", other),
        }
    }

    #[test]
    fn lift_xor_zero_idiom() {
        let insns = [make_insn(0x1000, "xor", "eax, eax")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "eax");
                assert_eq!(func.exprs[*src], LlilExpr::Const(0));
            }
            other => panic!("Expected SetReg(0), got {:?}", other),
        }
    }

    #[test]
    fn lift_push_pop() {
        let insns = [
            make_insn(0x1000, "push", "rbp"),
            make_insn(0x1001, "pop", "rbp"),
        ];
        let func = lift_function("test", 0x1000, &insns);
        // push generates 2 stmts (rsp -= 8, store)
        assert_eq!(func.instructions[0].stmts.len(), 2);
        // pop generates 2 stmts (load, rsp += 8)
        assert_eq!(func.instructions[1].stmts.len(), 2);
    }

    #[test]
    fn lift_conditional_branch() {
        let insns = [make_insn(0x1000, "je", "0x1020")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::BranchIf { cond, target } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::E));
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1020));
            }
            other => panic!("Expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn lift_call_and_ret() {
        let insns = [
            make_insn(0x1000, "call", "0x2000"),
            make_insn(0x1005, "ret", ""),
        ];
        let func = lift_function("test", 0x1000, &insns);
        assert!(matches!(
            func.instructions[0].stmts[0],
            LlilStmt::Call { .. }
        ));
        assert!(matches!(func.instructions[1].stmts[0], LlilStmt::Return));
    }

    #[test]
    fn lift_memory_operand() {
        let insns = [make_insn(0x1000, "mov", "rax, qword ptr [rbp - 8]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "rax");
                // src should be a Load
                assert!(matches!(func.exprs[*src], LlilExpr::Load { size: 8, .. }));
            }
            other => panic!("Expected SetReg with Load, got {:?}", other),
        }
    }

    #[test]
    fn lift_lea() {
        let insns = [make_insn(0x1000, "lea", "rax, [rbp - 0x10]")];
        let func = lift_function("test", 0x1000, &insns);
        match &func.instructions[0].stmts[0] {
            LlilStmt::SetReg { dest, src } => {
                assert_eq!(dest, "rax");
                // LEA should produce address computation, NOT a load
                assert!(matches!(func.exprs[*src], LlilExpr::BinOp { .. }));
            }
            other => panic!("Expected SetReg with BinOp, got {:?}", other),
        }
    }

    #[test]
    fn lift_unimplemented_passes_through() {
        let insns = [make_insn(0x1000, "cpuid", "")];
        let func = lift_function("test", 0x1000, &insns);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::Unimplemented { mnemonic, .. } if mnemonic == "cpuid"
        ));
    }

    // ---- SIMD tests --------------------------------------------------------

    #[test]
    fn lift_paddw() {
        let insns = [make_insn(0x1000, "paddw", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        assert_eq!(llil.instructions.len(), 1);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Int16);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_xorps_zero() {
        let insns = [make_insn(0x1000, "xorps", "xmm0, xmm0")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
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
    fn lift_movaps() {
        let insns = [make_insn(0x1000, "movaps", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::MoveAligned);
            } else {
                panic!("expected VectorOp::MoveAligned");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_pshufd() {
        let insns = [make_insn(0x1000, "pshufd", "xmm0, xmm1, 0xe4")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert!(matches!(kind, VectorOpKind::Shuffle { mask: 0xe4 }));
            } else {
                panic!("expected VectorOp::Shuffle");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_haddps() {
        let insns = [make_insn(0x1000, "haddps", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::HorizontalAdd);
                assert_eq!(*element_type, VectorElementType::Float32);
            } else {
                panic!("expected VectorOp::HorizontalAdd");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_avx_vaddps() {
        let insns = [make_insn(0x1000, "vaddps", "ymm0, ymm1, ymm2")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "ymm0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Float32);
                assert_eq!(*width, 256);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_pxor_zero_idiom() {
        let insns = [make_insn(0x1000, "pxor", "xmm0, xmm0")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
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
    fn lift_vpxor_zero_idiom() {
        let insns = [make_insn(0x1000, "vpxor", "xmm0, xmm0, xmm0")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
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
    fn lift_mmx_paddb() {
        let insns = [make_insn(0x1000, "paddb", "mm0, mm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "mm0");
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
    fn lift_addps() {
        let insns = [make_insn(0x1000, "addps", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Add);
                assert_eq!(*element_type, VectorElementType::Float32);
                assert_eq!(*width, 128);
            } else {
                panic!("expected VectorOp");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_movdqa() {
        let insns = [make_insn(0x1000, "movdqa", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::MoveAligned);
                assert_eq!(*element_type, VectorElementType::Int8);
            } else {
                panic!("expected VectorOp::MoveAligned");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_pabsd() {
        let insns = [make_insn(0x1000, "pabsd", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Abs);
                assert_eq!(*element_type, VectorElementType::Int32);
            } else {
                panic!("expected VectorOp::Abs");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_pinsrd() {
        let insns = [make_insn(0x1000, "pinsrd", "xmm0, eax, 2")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert!(matches!(kind, VectorOpKind::Insert { index: 2 }));
            } else {
                panic!("expected VectorOp::Insert");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_vfmadd231ps() {
        let insns = [make_insn(0x1000, "vfmadd231ps", "xmm0, xmm1, xmm2")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::FusedMulAdd);
                assert_eq!(*element_type, VectorElementType::Float32);
            } else {
                panic!("expected VectorOp::FusedMulAdd");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_vbroadcastss() {
        let insns = [make_insn(0x1000, "vbroadcastss", "ymm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "ymm0");
            if let LlilExpr::VectorOp {
                kind,
                element_type,
                width,
                ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::Broadcast);
                assert_eq!(*element_type, VectorElementType::Float32);
                assert_eq!(*width, 256);
            } else {
                panic!("expected VectorOp::Broadcast");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_cvtdq2ps() {
        let insns = [make_insn(0x1000, "cvtdq2ps", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp {
                kind, element_type, ..
            } = &llil.exprs[*src]
            {
                assert_eq!(*kind, VectorOpKind::ConvertIntToFloat);
                assert_eq!(*element_type, VectorElementType::Float32);
            } else {
                panic!("expected VectorOp::ConvertIntToFloat");
            }
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn lift_ptest() {
        let insns = [make_insn(0x1000, "ptest", "xmm0, xmm1")];
        let llil = lift_function("test", 0x1000, &insns);
        if let LlilStmt::SetReg { dest, src } = &llil.instructions[0].stmts[0] {
            assert_eq!(dest, "xmm0");
            if let LlilExpr::VectorOp { kind, .. } = &llil.exprs[*src] {
                assert_eq!(*kind, VectorOpKind::TestAllZeros);
            } else {
                panic!("expected VectorOp::TestAllZeros");
            }
        } else {
            panic!("expected SetReg");
        }
    }
}
