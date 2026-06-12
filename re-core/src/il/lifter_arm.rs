//! ARM32 / Thumb-2 lifter: converts native 32-bit ARM or Thumb instructions
//! (as decoded by Capstone) into LLIL.
//!
//! This is a **minimum viable** lifter: it covers the most common data movement,
//! arithmetic, logical, memory, and branch instructions so that decompilation
//! of routine ARM code succeeds. Coprocessor, NEON, and VFP instructions fall
//! through to `Intrinsic` and can be refined later.

use crate::disasm::Instruction;
use crate::il::llil::*;

/// Lift a sequence of native ARM32/Thumb instructions into an `LlilFunction`.
pub fn lift_function(name: &str, entry: u64, instructions: &[Instruction]) -> LlilFunction {
    let mut func = LlilFunction::new(name.to_string(), entry);
    for insn in instructions {
        let mut stmts = lift_instruction(&mut func, insn);
        if stmts.is_empty() {
            // A helper bailed on malformed/unexpected operands: record the
            // original text as an explicit barrier instead of silently
            // dropping the instruction (a zero-statement lift corrupts the
            // dataflow passes downstream exactly like a Nop would).
            stmts.push(LlilStmt::Unimplemented {
                mnemonic: insn.mnemonic.clone(),
                op_str: insn.op_str.clone(),
            });
        }
        func.add_inst(LlilInst {
            address: insn.address,
            stmts,
        });
    }
    func
}

/// Lift a single ARM or Thumb instruction.
///
/// ARM mnemonics may carry a condition-code suffix (e.g. `addeq`, `bne`). Any
/// conditional variant is treated as if it were the unconditional form wrapped
/// in a `BranchIf`/`If` upstream — for MVP we drop the condition and emit the
/// core data effect, then rely on later passes/CFG to re-attach control flow.
fn lift_instruction(func: &mut LlilFunction, insn: &Instruction) -> Vec<LlilStmt> {
    let raw = insn.mnemonic.to_lowercase();
    let ops: Vec<&str> = if insn.op_str.is_empty() {
        Vec::new()
    } else {
        insn.op_str.split(',').map(|s| s.trim()).collect()
    };

    // Try the full mnemonic first: flag-setting forms like `movs`/`muls`/`bics`/
    // `lsls` end in characters that look like condition codes, so stripping a
    // condition suffix up front would mangle them. Only on a miss do we strip a
    // genuine condition suffix and retry (e.g. `addeq` -> `add`).
    if let Some(stmts) = lift_mnemonic(func, &raw, &ops) {
        return stmts;
    }
    let (base, cond) = strip_condition_suffix(&raw);
    // Conditional branch: `b<cond>` must keep its condition — flattening it
    // to an unconditional jump corrupts every if/loop in the function. Other
    // conditional forms (e.g. `addeq`) still drop the predicate (MVP).
    if base == "b"
        && let Some(c) = cond
        && c != "al"
    {
        return lift_bcc(func, c, &ops);
    }
    if base != raw
        && let Some(stmts) = lift_mnemonic(func, base, &ops)
    {
        return stmts;
    }

    vec![LlilStmt::Unimplemented {
        mnemonic: insn.mnemonic.clone(),
        op_str: insn.op_str.clone(),
    }]
}

/// Lift a single (already lower-cased, condition-free) ARM mnemonic, or `None`
/// if it isn't recognised.
fn lift_mnemonic(func: &mut LlilFunction, mn: &str, ops: &[&str]) -> Option<Vec<LlilStmt>> {
    Some(match mn {
        "nop" => vec![LlilStmt::Nop],

        // --- Data movement ---
        "mov" | "movs" | "mvn" | "mvns" => lift_mov(func, mn, ops),
        "movw" => lift_movw(func, ops),
        "movt" => lift_movt(func, ops),

        // --- Arithmetic (Rd, Rn, op2 form) ---
        "add" | "adds" => lift_alu3(func, BinOp::Add, ops),
        "sub" | "subs" => lift_alu3(func, BinOp::Sub, ops),
        "rsb" | "rsbs" => lift_alu3_reversed(func, BinOp::Sub, ops),
        "mul" | "muls" => lift_alu3(func, BinOp::Mul, ops),

        // --- Bitwise ---
        "and" | "ands" => lift_alu3(func, BinOp::And, ops),
        "orr" | "orrs" => lift_alu3(func, BinOp::Or, ops),
        "eor" | "eors" => lift_alu3(func, BinOp::Xor, ops),
        "bic" | "bics" => lift_bic(func, ops),
        "lsl" | "lsls" => lift_alu3(func, BinOp::Shl, ops),
        "lsr" | "lsrs" => lift_alu3(func, BinOp::Shr, ops),
        "asr" | "asrs" => lift_alu3(func, BinOp::Sar, ops),

        // --- Comparison ---
        "cmp" => lift_cmp(func, ops),
        "cmn" => lift_cmn(func, ops),
        "tst" => lift_tst(func, ops),

        // --- Loads / stores ---
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" => lift_ldr(func, mn, ops),
        "str" | "strb" | "strh" => lift_str(func, mn, ops),

        // --- Stack ---
        "push" => lift_push(func, ops),
        "pop" => lift_pop(func, ops),

        // --- Branches ---
        "b" => lift_branch(func, ops),
        "bl" | "blx" => lift_call(func, ops),
        "bx" => lift_return_or_call(func, ops),

        // --- Thumb IT block: treat as NOP (conditions handled via CFG later) ---
        "it" | "itt" | "ite" | "itte" | "itee" | "iteee" => vec![LlilStmt::Nop],

        _ => return None,
    })
}

/// Strip an ARM condition-code suffix from a mnemonic (`addeq` → (`add`, `eq`)).
fn strip_condition_suffix(mn: &str) -> (&str, Option<&str>) {
    const CONDS: &[&str] = &[
        "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
        "le", "al",
    ];
    for cond in CONDS {
        if let Some(base) = mn.strip_suffix(cond) {
            // Allow a trailing `s` flag-setting variant before the condition.
            if !base.is_empty() {
                return (base, Some(cond));
            }
        }
    }
    (mn, None)
}

fn reg(func: &mut LlilFunction, name: &str) -> ExprId {
    func.add_expr(LlilExpr::Reg(name.to_string()))
}

fn imm(func: &mut LlilFunction, v: u64) -> ExprId {
    func.add_expr(LlilExpr::Const(v))
}

fn parse_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    let op = op
        .trim()
        .trim_matches(|c| c == '[' || c == ']' || c == '{' || c == '}');
    if let Some(rest) = op.strip_prefix('#')
        && let Ok(v) = parse_number(rest)
    {
        return imm(func, v);
    }
    if let Ok(v) = parse_number(op) {
        return imm(func, v);
    }
    reg(func, op)
}

fn parse_number(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).map_err(|_| ())
    } else if let Some(rest) = s.strip_prefix('-') {
        rest.parse::<i64>().map(|v| (-v) as u64).map_err(|_| ())
    } else {
        s.parse().map_err(|_| ())
    }
}

fn lift_mov(func: &mut LlilFunction, base: &str, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(dst) = ops.first() else {
        return vec![LlilStmt::Nop];
    };
    let src = ops.get(1).copied().unwrap_or("#0");
    let mut src_expr = parse_operand(func, src);
    if base.starts_with("mvn") {
        src_expr = func.add_expr(LlilExpr::UnaryOp {
            op: UnaryOp::Not,
            operand: src_expr,
        });
    }
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: src_expr,
    }]
}

fn lift_movw(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(dst) = ops.first() else {
        return vec![LlilStmt::Nop];
    };
    let imm_val = ops
        .get(1)
        .and_then(|s| parse_number(s.trim_start_matches('#')).ok())
        .unwrap_or(0);
    let src_val = imm(func, imm_val & 0xFFFF);
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: src_val,
    }]
}

fn lift_movt(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(dst) = ops.first() else {
        return vec![LlilStmt::Nop];
    };
    // `movt Rd, #imm16` loads the top 16 bits of Rd without touching the
    // bottom 16. Encode that as Rd = (Rd & 0xFFFF) | (imm16 << 16).
    let imm_val = ops
        .get(1)
        .and_then(|s| parse_number(s.trim_start_matches('#')).ok())
        .unwrap_or(0);
    let reg_read = reg(func, dst);
    let mask = imm(func, 0xFFFF);
    let low = func.add_expr(LlilExpr::BinOp {
        op: BinOp::And,
        left: reg_read,
        right: mask,
    });
    let high = imm(func, (imm_val & 0xFFFF) << 16);
    let combined = func.add_expr(LlilExpr::BinOp {
        op: BinOp::Or,
        left: low,
        right: high,
    });
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: combined,
    }]
}

fn lift_alu3(func: &mut LlilFunction, op: BinOp, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(dst) = ops.first() else {
        return vec![LlilStmt::Nop];
    };
    let (lhs_str, rhs_str) = if ops.len() >= 3 {
        (ops[1], ops[2])
    } else if ops.len() == 2 {
        (ops[0], ops[1])
    } else {
        return vec![LlilStmt::Nop];
    };
    let lhs = parse_operand(func, lhs_str);
    let rhs = parse_operand(func, rhs_str);
    let value = func.add_expr(LlilExpr::BinOp {
        op,
        left: lhs,
        right: rhs,
    });
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: value,
    }]
}

/// `rsb Rd, Rn, op2` computes `op2 - Rn` — inverse operand order of `sub`.
fn lift_alu3_reversed(func: &mut LlilFunction, op: BinOp, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 3 {
        return vec![LlilStmt::Nop];
    }
    let dst = ops[0];
    let rhs = parse_operand(func, ops[1]);
    let lhs = parse_operand(func, ops[2]);
    let value = func.add_expr(LlilExpr::BinOp {
        op,
        left: lhs,
        right: rhs,
    });
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: value,
    }]
}

/// `bic Rd, Rn, op2` clears bits: `Rn & !op2`.
fn lift_bic(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 3 {
        return vec![LlilStmt::Nop];
    }
    let dst = ops[0];
    let lhs = parse_operand(func, ops[1]);
    let rhs = parse_operand(func, ops[2]);
    let not_rhs = func.add_expr(LlilExpr::UnaryOp {
        op: UnaryOp::Not,
        operand: rhs,
    });
    let value = func.add_expr(LlilExpr::BinOp {
        op: BinOp::And,
        left: lhs,
        right: not_rhs,
    });
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: value,
    }]
}

fn lift_cmp(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let lhs = parse_operand(func, ops[0]);
    let rhs = parse_operand(func, ops[1]);
    let sub = func.add_expr(LlilExpr::BinOp {
        op: BinOp::Sub,
        left: lhs,
        right: rhs,
    });
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: sub,
    }]
}

fn lift_cmn(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let lhs = parse_operand(func, ops[0]);
    let rhs = parse_operand(func, ops[1]);
    let add = func.add_expr(LlilExpr::BinOp {
        op: BinOp::Add,
        left: lhs,
        right: rhs,
    });
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: add,
    }]
}

fn lift_tst(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![LlilStmt::Nop];
    }
    let lhs = parse_operand(func, ops[0]);
    let rhs = parse_operand(func, ops[1]);
    let and = func.add_expr(LlilExpr::BinOp {
        op: BinOp::And,
        left: lhs,
        right: rhs,
    });
    vec![LlilStmt::SetReg {
        dest: "__flags".into(),
        src: and,
    }]
}

fn lift_ldr(func: &mut LlilFunction, base: &str, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(dst) = ops.first() else {
        return vec![LlilStmt::Nop];
    };
    let size: u8 = match base {
        "ldrb" | "ldrsb" => 1,
        "ldrh" | "ldrsh" => 2,
        _ => 4,
    };
    // Compute the effective address from everything after the destination.
    let addr = parse_memory_addr(func, &ops[1..]);
    let value = func.add_expr(LlilExpr::Load { addr, size });
    vec![LlilStmt::SetReg {
        dest: dst.to_string(),
        src: value,
    }]
}

fn lift_str(func: &mut LlilFunction, base: &str, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![LlilStmt::Nop];
    }
    let size: u8 = match base {
        "strb" => 1,
        "strh" => 2,
        _ => 4,
    };
    let src = parse_operand(func, ops[0]);
    let addr = parse_memory_addr(func, &ops[1..]);
    vec![LlilStmt::Store {
        addr,
        value: src,
        size,
    }]
}

fn parse_memory_addr(func: &mut LlilFunction, ops: &[&str]) -> ExprId {
    // Flatten and strip the enclosing brackets.
    let joined = ops.join(",");
    let inner = joined.trim();
    let stripped = inner
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('!');
    let parts: Vec<&str> = stripped.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return imm(func, 0);
    }
    let base = reg(func, parts[0]);
    if parts.len() == 1 {
        return base;
    }
    let off_str = parts[1];
    let off = if let Some(rest) = off_str.strip_prefix('#') {
        parse_number(rest).ok().map(|v| imm(func, v))
    } else {
        Some(parse_operand(func, off_str))
    };
    if let Some(off_expr) = off {
        return func.add_expr(LlilExpr::BinOp {
            op: BinOp::Add,
            left: base,
            right: off_expr,
        });
    }
    base
}

fn lift_push(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // Multi-register push: `push {r4, r5, lr}` stores the registers to
    // descending stack slots. Model each as `sp = sp - 4; *(sp) = reg` —
    // distinct addresses (the old single-`[sp]` model aliased every slot)
    // and an sp the stack-tracking passes can follow. The list's first
    // register lands at the lowest address, so iterate in reverse.
    let mut stmts = Vec::new();
    for op in ops.iter().rev() {
        let name = op.trim().trim_matches(|c| c == '{' || c == '}');
        if name.is_empty() {
            continue;
        }
        let sp = reg(func, "sp");
        let four = imm(func, 4);
        let dec = func.add_expr(LlilExpr::BinOp {
            op: BinOp::Sub,
            left: sp,
            right: four,
        });
        stmts.push(LlilStmt::SetReg {
            dest: "sp".to_string(),
            src: dec,
        });
        let slot = reg(func, "sp");
        let value = reg(func, name);
        stmts.push(LlilStmt::Store {
            addr: slot,
            value,
            size: 4,
        });
    }
    stmts
}

fn lift_pop(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // Mirror of `lift_push`: `reg = *(sp); sp = sp + 4` per register, first
    // register from the lowest address. `pop {.., pc}` is a function return.
    let mut stmts = Vec::new();
    for op in ops {
        let name = op.trim().trim_matches(|c| c == '{' || c == '}');
        if name.is_empty() {
            continue;
        }
        let slot = reg(func, "sp");
        let load = func.add_expr(LlilExpr::Load {
            addr: slot,
            size: 4,
        });
        if name.eq_ignore_ascii_case("pc") {
            let sp = reg(func, "sp");
            let four = imm(func, 4);
            let inc = func.add_expr(LlilExpr::BinOp {
                op: BinOp::Add,
                left: sp,
                right: four,
            });
            stmts.push(LlilStmt::SetReg {
                dest: "sp".to_string(),
                src: inc,
            });
            stmts.push(LlilStmt::Return);
            continue;
        }
        stmts.push(LlilStmt::SetReg {
            dest: name.to_string(),
            src: load,
        });
        let sp = reg(func, "sp");
        let four = imm(func, 4);
        let inc = func.add_expr(LlilExpr::BinOp {
            op: BinOp::Add,
            left: sp,
            right: four,
        });
        stmts.push(LlilStmt::SetReg {
            dest: "sp".to_string(),
            src: inc,
        });
    }
    stmts
}

fn lift_branch(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // Capstone prints ARM branch targets with a `#` prefix (`b #0x1c`);
    // parse_operand strips it (a bare parse_number would fail and produce
    // a bogus jump to 0).
    let target = ops
        .first()
        .map(|s| parse_operand(func, s))
        .unwrap_or_else(|| imm(func, 0));
    vec![LlilStmt::Jump { target }]
}

/// Conditional direct branch: `b<cond> #target` becomes a `BranchIf` on the
/// flag condition so MLIL can fold the preceding cmp/tst into a relational
/// expression, exactly as on x86.
fn lift_bcc(func: &mut LlilFunction, cond: &str, ops: &[&str]) -> Vec<LlilStmt> {
    let Some(flag_cond) = arm_cond_to_flag(cond) else {
        // pl/vc have no FlagCondition mapping yet — stay honest rather than
        // emitting a wrong branch shape.
        return vec![LlilStmt::Unimplemented {
            mnemonic: format!("b{}", cond),
            op_str: ops.join(", "),
        }];
    };
    let target = ops
        .first()
        .map(|s| parse_operand(func, s))
        .unwrap_or_else(|| imm(func, 0));
    let flag = func.add_expr(LlilExpr::Flag(flag_cond));
    vec![LlilStmt::BranchIf { cond: flag, target }]
}

/// Map an ARM condition code to the shared [`FlagCondition`] vocabulary.
fn arm_cond_to_flag(cond: &str) -> Option<FlagCondition> {
    Some(match cond {
        "eq" => FlagCondition::E,
        "ne" => FlagCondition::Ne,
        "cs" | "hs" => FlagCondition::Uge,
        "cc" | "lo" => FlagCondition::Ult,
        "mi" => FlagCondition::Neg,
        "vs" => FlagCondition::Overflow,
        "hi" => FlagCondition::Ugt,
        "ls" => FlagCondition::Ule,
        "ge" => FlagCondition::Sge,
        "lt" => FlagCondition::Slt,
        "gt" => FlagCondition::Sgt,
        "le" => FlagCondition::Sle,
        _ => return None,
    })
}

fn lift_call(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    let target = ops
        .first()
        .map(|s| parse_operand(func, s))
        .unwrap_or_else(|| imm(func, 0));
    vec![LlilStmt::Call { target }]
}

/// `bx lr` is a return; any other `bx Rn` is an indirect call.
fn lift_return_or_call(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops
        .first()
        .map(|s| s.trim().eq_ignore_ascii_case("lr"))
        .unwrap_or(false)
    {
        return vec![LlilStmt::Return];
    }
    let target = ops
        .first()
        .map(|s| parse_operand(func, s))
        .unwrap_or_else(|| imm(func, 0));
    vec![LlilStmt::Jump { target }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::Instruction;

    fn mk(addr: u64, mn: &str, ops: &str) -> Instruction {
        Instruction {
            address: addr,
            mnemonic: mn.into(),
            op_str: ops.into(),
            bytes: vec![],
            groups: vec![],
        }
    }

    #[test]
    fn lift_mov_imm_sets_register() {
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "mov", "r0, #0x1234"));
        assert_eq!(stmts.len(), 1);
        assert!(matches!(&stmts[0], LlilStmt::SetReg { dest, .. } if dest == "r0"));
    }

    #[test]
    fn lift_add_three_regs() {
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "add", "r0, r1, r2"));
        assert!(matches!(&stmts[0], LlilStmt::SetReg { dest, .. } if dest == "r0"));
    }

    #[test]
    fn flag_setting_forms_lift_not_dropped() {
        // These mnemonics end in characters that look like condition codes
        // (movs→"vs", muls→"ls", bics→"cs", lsls→"ls"); they must lift rather
        // than be mangled by condition-suffix stripping into Unimplemented.
        for (mn, ops) in [
            ("movs", "r0, #1"),
            ("muls", "r0, r1, r2"),
            ("bics", "r0, r1, r2"),
            ("lsls", "r0, r1, #2"),
        ] {
            let mut func = LlilFunction::new("t".into(), 0);
            let stmts = lift_instruction(&mut func, &mk(0, mn, ops));
            assert!(
                !matches!(stmts.as_slice(), [LlilStmt::Unimplemented { .. }]),
                "{mn} was dropped to Unimplemented"
            );
        }
    }

    #[test]
    fn conditional_suffix_still_strips_on_miss() {
        // `addeq` isn't a known mnemonic; the condition suffix is stripped and
        // it lifts as `add`.
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "addeq", "r0, r1, r2"));
        assert!(matches!(&stmts[0], LlilStmt::SetReg { dest, .. } if dest == "r0"));
    }

    #[test]
    fn lift_push_pop_adjust_sp_per_slot() {
        let mut func = LlilFunction::new("t".into(), 0);
        // Each pushed register gets its own `sp -= 4; *(sp) = reg` pair, so
        // the slots no longer alias a single address.
        let push = lift_instruction(&mut func, &mk(0, "push", "{r4, lr}"));
        assert_eq!(push.len(), 4);
        assert!(matches!(&push[0], LlilStmt::SetReg { dest, .. } if dest == "sp"));
        assert!(matches!(push[1], LlilStmt::Store { .. }));
        // `pop {.., pc}` restores then returns.
        let pop = lift_instruction(&mut func, &mk(4, "pop", "{r4, pc}"));
        assert!(matches!(&pop[0], LlilStmt::SetReg { dest, .. } if dest == "r4"));
        assert_eq!(pop.last(), Some(&LlilStmt::Return));
    }

    #[test]
    fn direct_branch_parses_hash_prefixed_target() {
        // Capstone prints `b #0x1c`; the target must parse, not collapse to 0.
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "b", "#0x1c"));
        match &stmts[0] {
            LlilStmt::Jump { target } => {
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x1c));
            }
            other => panic!("expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn conditional_branch_keeps_its_condition() {
        // `bne #0x2000` must lift to a BranchIf on Ne — flattening it to an
        // unconditional Jump corrupts every if/loop.
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "bne", "#0x2000"));
        match &stmts[0] {
            LlilStmt::BranchIf { cond, target } => {
                assert_eq!(func.exprs[*cond], LlilExpr::Flag(FlagCondition::Ne));
                assert_eq!(func.exprs[*target], LlilExpr::Const(0x2000));
            }
            other => panic!("expected BranchIf, got {:?}", other),
        }
    }

    #[test]
    fn cmp_defines_the_shared_flags_register() {
        // MLIL's condition folding and DSE only recognize `__flags`; the old
        // bare `flags` name was both unfoldable and DSE-deletable.
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "cmp", "r0, r1"));
        assert!(matches!(&stmts[0], LlilStmt::SetReg { dest, .. } if dest == "__flags"));
    }

    #[test]
    fn bx_lr_is_return() {
        let mut func = LlilFunction::new("t".into(), 0);
        let stmts = lift_instruction(&mut func, &mk(0, "bx", "lr"));
        assert_eq!(stmts, vec![LlilStmt::Return]);
    }

    #[test]
    fn strip_suffix_recognizes_eq() {
        let (base, cond) = strip_condition_suffix("addeq");
        assert_eq!(base, "add");
        assert_eq!(cond, Some("eq"));
    }
}
