//! RISC-V lifter: converts native RISC-V instructions to LLIL.

use crate::disasm::Instruction;
use crate::il::llil::*;

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

fn lift_instruction(func: &mut LlilFunction, insn: &Instruction) -> Vec<LlilStmt> {
    let mn = insn.mnemonic.to_lowercase();
    let ops: Vec<&str> = if insn.op_str.is_empty() {
        vec![]
    } else {
        insn.op_str.split(',').map(|s| s.trim()).collect()
    };

    match mn.as_str() {
        "nop" | "c.nop" => vec![LlilStmt::Nop],

        // Arithmetic
        "add" | "addw" | "c.add" | "c.addw" => lift_binary_op(func, &ops, BinOp::Add),
        "addi" | "addiw" | "c.addi" | "c.addiw" | "c.addi16sp" | "c.addi4spn" => {
            lift_binary_op_imm(func, &ops, BinOp::Add)
        }
        "sub" | "subw" | "c.sub" | "c.subw" => lift_binary_op(func, &ops, BinOp::Sub),
        "mul" | "mulw" => lift_binary_op(func, &ops, BinOp::Mul),
        "div" | "divw" => lift_binary_op(func, &ops, BinOp::SDiv),
        "divu" | "divuw" => lift_binary_op(func, &ops, BinOp::UDiv),
        "rem" | "remw" => lift_binary_op(func, &ops, BinOp::SMod),
        "remu" | "remuw" => lift_binary_op(func, &ops, BinOp::UMod),

        // Logic
        "and" | "c.and" => lift_binary_op(func, &ops, BinOp::And),
        "andi" | "c.andi" => lift_binary_op_imm(func, &ops, BinOp::And),
        "or" | "c.or" => lift_binary_op(func, &ops, BinOp::Or),
        "ori" => lift_binary_op_imm(func, &ops, BinOp::Or),
        "xor" | "c.xor" => lift_binary_op(func, &ops, BinOp::Xor),
        "xori" => lift_binary_op_imm(func, &ops, BinOp::Xor),

        // Shifts
        "sll" | "sllw" => lift_binary_op(func, &ops, BinOp::Shl),
        "slli" | "slliw" | "c.slli" => lift_binary_op_imm(func, &ops, BinOp::Shl),
        "srl" | "srlw" => lift_binary_op(func, &ops, BinOp::Shr),
        "srli" | "srliw" | "c.srli" => lift_binary_op_imm(func, &ops, BinOp::Shr),
        "sra" | "sraw" => lift_binary_op(func, &ops, BinOp::Sar),
        "srai" | "sraiw" | "c.srai" => lift_binary_op_imm(func, &ops, BinOp::Sar),

        // Comparisons (set less-than)
        "slt" => lift_binary_op(func, &ops, BinOp::CmpLt),
        "sltu" => lift_binary_op(func, &ops, BinOp::CmpUlt),
        "slti" => lift_binary_op_imm(func, &ops, BinOp::CmpLt),
        "sltiu" => lift_binary_op_imm(func, &ops, BinOp::CmpUlt),

        // Moves / load-immediate
        "mv" | "c.mv" => lift_move(func, &ops),
        "li" | "c.li" => lift_load_immediate(func, &ops),
        "lui" | "c.lui" => lift_lui(func, &ops),
        "auipc" => lift_auipc(func, insn.address, &ops),

        // Loads
        "lb" => lift_load(func, &ops, 1),
        "lbu" => lift_load(func, &ops, 1),
        "lh" => lift_load(func, &ops, 2),
        "lhu" => lift_load(func, &ops, 2),
        "lw" | "c.lw" | "c.lwsp" => lift_load(func, &ops, 4),
        "lwu" => lift_load(func, &ops, 4),
        "ld" | "c.ld" | "c.ldsp" => lift_load(func, &ops, 8),

        // Stores
        "sb" => lift_store(func, &ops, 1),
        "sh" => lift_store(func, &ops, 2),
        "sw" | "c.sw" | "c.swsp" => lift_store(func, &ops, 4),
        "sd" | "c.sd" | "c.sdsp" => lift_store(func, &ops, 8),

        // Jumps
        "j" | "c.j" => lift_jump(func, &ops),
        "jr" | "c.jr" => lift_jump_reg(func, &ops),
        "jal" | "c.jal" => lift_call(func, &ops),
        "jalr" | "c.jalr" => lift_jalr(func, &ops),
        "ret" => vec![LlilStmt::Return],

        // Branches
        "beq" | "c.beqz" => lift_branch(func, &ops, BinOp::CmpEq),
        "bne" | "c.bnez" => lift_branch(func, &ops, BinOp::CmpNe),
        "blt" => lift_branch(func, &ops, BinOp::CmpLt),
        "bge" => lift_branch(func, &ops, BinOp::CmpGe),
        "bltu" => lift_branch(func, &ops, BinOp::CmpUlt),
        "bgeu" => lift_branch(func, &ops, BinOp::CmpUge),

        // Pseudo-instructions
        "neg" => {
            // neg rd, rs = sub rd, x0, rs
            if ops.len() == 2 {
                let dest = ops[0].to_string();
                let zero = func.add_expr(LlilExpr::Const(0));
                let src = parse_operand(func, ops[1]);
                let expr = func.add_expr(LlilExpr::BinOp {
                    op: BinOp::Sub,
                    left: zero,
                    right: src,
                });
                vec![LlilStmt::SetReg { dest, src: expr }]
            } else {
                vec![]
            }
        }
        "not" => {
            // not rd, rs = xori rd, rs, -1
            if ops.len() == 2 {
                let dest = ops[0].to_string();
                let src = parse_operand(func, ops[1]);
                let expr = func.add_expr(LlilExpr::UnaryOp {
                    op: UnaryOp::Not,
                    operand: src,
                });
                vec![LlilStmt::SetReg { dest, src: expr }]
            } else {
                vec![]
            }
        }
        "seqz" => {
            // seqz rd, rs = sltiu rd, rs, 1
            if ops.len() == 2 {
                let dest = ops[0].to_string();
                let src = parse_operand(func, ops[1]);
                let one = func.add_expr(LlilExpr::Const(1));
                let expr = func.add_expr(LlilExpr::BinOp {
                    op: BinOp::CmpUlt,
                    left: src,
                    right: one,
                });
                vec![LlilStmt::SetReg { dest, src: expr }]
            } else {
                vec![]
            }
        }
        "snez" => {
            // snez rd, rs = sltu rd, x0, rs
            if ops.len() == 2 {
                let dest = ops[0].to_string();
                let zero = func.add_expr(LlilExpr::Const(0));
                let src = parse_operand(func, ops[1]);
                let expr = func.add_expr(LlilExpr::BinOp {
                    op: BinOp::CmpUlt,
                    left: zero,
                    right: src,
                });
                vec![LlilStmt::SetReg { dest, src: expr }]
            } else {
                vec![]
            }
        }

        // Call pseudo (tail call)
        "tail" => lift_jump(func, &ops),
        "call" => lift_call(func, &ops),

        // Anything else: unimplemented
        _ => vec![],
    }
}

fn parse_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    let op = op.trim();
    if let Ok(val) = op.parse::<i64>() {
        func.add_expr(LlilExpr::Const(val as u64))
    } else if let Some(hex) = op.strip_prefix("0x").or_else(|| op.strip_prefix("0X")) {
        let val = u64::from_str_radix(hex, 16).unwrap_or(0);
        func.add_expr(LlilExpr::Const(val))
    } else if let Some(neg) = op.strip_prefix('-') {
        if let Ok(val) = neg.parse::<i64>() {
            func.add_expr(LlilExpr::Const((-val) as u64))
        } else {
            func.add_expr(LlilExpr::Reg(op.to_string()))
        }
    } else {
        func.add_expr(LlilExpr::Reg(op.to_string()))
    }
}

/// Parse a memory operand like "offset(base)" into an address expression.
fn parse_mem_operand(func: &mut LlilFunction, ops: &[&str]) -> Option<(String, ExprId)> {
    // RISC-V memory operands come as: "rd, offset(base)" → ops = ["rd", "offset(base)"]
    if ops.len() < 2 {
        return None;
    }
    let dest = ops[0].to_string();
    let mem_op = ops[1].trim();

    let addr_expr = if let Some(start) = mem_op.find('(') {
        let offset_str = &mem_op[..start];
        let base_str = &mem_op[start + 1..mem_op.len().saturating_sub(1)];
        let base = parse_operand(func, base_str);
        if offset_str.is_empty() || offset_str == "0" {
            base
        } else {
            let offset = parse_operand(func, offset_str);
            func.add_expr(LlilExpr::BinOp {
                op: BinOp::Add,
                left: base,
                right: offset,
            })
        }
    } else {
        parse_operand(func, mem_op)
    };

    Some((dest, addr_expr))
}

fn lift_binary_op(func: &mut LlilFunction, ops: &[&str], op: BinOp) -> Vec<LlilStmt> {
    if ops.len() != 3 {
        return vec![];
    }
    let dest = ops[0].to_string();
    let src1 = parse_operand(func, ops[1]);
    let src2 = parse_operand(func, ops[2]);
    let expr = func.add_expr(LlilExpr::BinOp {
        op,
        left: src1,
        right: src2,
    });
    vec![LlilStmt::SetReg { dest, src: expr }]
}

fn lift_binary_op_imm(func: &mut LlilFunction, ops: &[&str], op: BinOp) -> Vec<LlilStmt> {
    if ops.len() == 3 {
        lift_binary_op(func, ops, op)
    } else if ops.len() == 2 {
        // Compressed form: c.addi rd, imm → rd = rd + imm
        let dest = ops[0].to_string();
        let src1 = parse_operand(func, ops[0]);
        let src2 = parse_operand(func, ops[1]);
        let expr = func.add_expr(LlilExpr::BinOp {
            op,
            left: src1,
            right: src2,
        });
        vec![LlilStmt::SetReg { dest, src: expr }]
    } else {
        vec![]
    }
}

fn lift_move(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let dest = ops[0].to_string();
    let src = parse_operand(func, ops[1]);
    vec![LlilStmt::SetReg { dest, src }]
}

fn lift_load_immediate(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let dest = ops[0].to_string();
    let val = parse_operand(func, ops[1]);
    vec![LlilStmt::SetReg { dest, src: val }]
}

fn lift_lui(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let dest = ops[0].to_string();
    // LUI loads a 20-bit immediate into bits [31:12]
    if let Ok(val) = ops[1].trim().parse::<i64>() {
        let shifted = (val << 12) as u64;
        let expr = func.add_expr(LlilExpr::Const(shifted));
        vec![LlilStmt::SetReg { dest, src: expr }]
    } else {
        let val = parse_operand(func, ops[1]);
        vec![LlilStmt::SetReg { dest, src: val }]
    }
}

fn lift_auipc(func: &mut LlilFunction, pc: u64, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let dest = ops[0].to_string();
    if let Ok(val) = ops[1].trim().parse::<i64>() {
        let result = pc.wrapping_add((val << 12) as u64);
        let expr = func.add_expr(LlilExpr::Const(result));
        vec![LlilStmt::SetReg { dest, src: expr }]
    } else {
        let val = parse_operand(func, ops[1]);
        vec![LlilStmt::SetReg { dest, src: val }]
    }
}

fn lift_load(func: &mut LlilFunction, ops: &[&str], size: u8) -> Vec<LlilStmt> {
    if let Some((dest, addr_expr)) = parse_mem_operand(func, ops) {
        let load_expr = func.add_expr(LlilExpr::Load {
            addr: addr_expr,
            size,
        });
        vec![LlilStmt::SetReg {
            dest,
            src: load_expr,
        }]
    } else {
        vec![]
    }
}

fn lift_store(func: &mut LlilFunction, ops: &[&str], size: u8) -> Vec<LlilStmt> {
    if ops.len() < 2 {
        return vec![];
    }
    let val = parse_operand(func, ops[0]);
    let mem_op = ops[1].trim();

    let addr_expr = if let Some(start) = mem_op.find('(') {
        let offset_str = &mem_op[..start];
        let base_str = &mem_op[start + 1..mem_op.len().saturating_sub(1)];
        let base = parse_operand(func, base_str);
        if offset_str.is_empty() || offset_str == "0" {
            base
        } else {
            let offset = parse_operand(func, offset_str);
            func.add_expr(LlilExpr::BinOp {
                op: BinOp::Add,
                left: base,
                right: offset,
            })
        }
    } else {
        parse_operand(func, mem_op)
    };

    vec![LlilStmt::Store {
        addr: addr_expr,
        value: val,
        size,
    }]
}

fn lift_jump(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Jump { target }]
}

fn lift_jump_reg(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![];
    }
    let reg = ops[0].trim();
    if reg == "ra" {
        return vec![LlilStmt::Return];
    }
    let target = parse_operand(func, reg);
    vec![LlilStmt::Jump { target }]
}

fn lift_call(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Call { target }]
}

fn lift_jalr(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    // jalr rd, rs, offset — if rd is ra or x1, it's a call; if rd is zero, it's a jump
    // jalr rs — compressed, equivalent to jalr ra, rs, 0 (call)
    if ops.is_empty() {
        return vec![];
    }
    if ops.len() == 1 {
        // c.jalr rs — call through register
        let reg = ops[0].trim();
        if reg == "ra" {
            return vec![LlilStmt::Return];
        }
        let target = parse_operand(func, reg);
        return vec![LlilStmt::Call { target }];
    }
    // jalr rd, offset(rs) or jalr rd, rs, offset
    let rd = ops[0].trim();
    if rd == "zero" || rd == "x0" {
        // Jump (tail call / computed goto)
        if ops.len() >= 2 {
            let target = parse_operand(func, ops[1]);
            return vec![LlilStmt::Jump { target }];
        }
    }
    // Otherwise it's a call
    if ops.len() >= 2 {
        let target = parse_operand(func, ops[1]);
        return vec![LlilStmt::Call { target }];
    }
    vec![]
}

fn lift_branch(func: &mut LlilFunction, ops: &[&str], cmp: BinOp) -> Vec<LlilStmt> {
    // beq rs1, rs2, target  OR  c.beqz rs, target
    if ops.len() == 3 {
        let left = parse_operand(func, ops[0]);
        let right = parse_operand(func, ops[1]);
        let target = parse_operand(func, ops[2]);
        let cond = func.add_expr(LlilExpr::BinOp {
            op: cmp,
            left,
            right,
        });
        vec![LlilStmt::BranchIf { cond, target }]
    } else if ops.len() == 2 {
        // Compressed: c.beqz rs, target → beq rs, zero, target
        let left = parse_operand(func, ops[0]);
        let right = func.add_expr(LlilExpr::Const(0));
        let target = parse_operand(func, ops[1]);
        let cond = func.add_expr(LlilExpr::BinOp {
            op: cmp,
            left,
            right,
        });
        vec![LlilStmt::BranchIf { cond, target }]
    } else {
        vec![]
    }
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
    fn lift_add_reg() {
        let insns = [make_insn(0x1000, "add", "a0, a1, a2")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(
            matches!(&func.instructions[0].stmts[0], LlilStmt::SetReg { dest, .. } if dest == "a0")
        );
    }

    #[test]
    fn lift_addi() {
        let insns = [make_insn(0x1000, "addi", "sp, sp, -16")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(
            matches!(&func.instructions[0].stmts[0], LlilStmt::SetReg { dest, .. } if dest == "sp")
        );
    }

    #[test]
    fn lift_load_word() {
        let insns = [make_insn(0x1000, "lw", "a0, 8(sp)")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(
            matches!(&func.instructions[0].stmts[0], LlilStmt::SetReg { dest, .. } if dest == "a0")
        );
    }

    #[test]
    fn lift_store_word() {
        let insns = [make_insn(0x1000, "sw", "a0, 8(sp)")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::Store { size: 4, .. }
        ));
    }

    #[test]
    fn lift_branch_eq() {
        let insns = [make_insn(0x1000, "beq", "a0, a1, 0x1020")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::BranchIf { .. }
        ));
    }

    #[test]
    fn lift_ret() {
        let insns = [make_insn(0x1000, "ret", "")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(matches!(&func.instructions[0].stmts[0], LlilStmt::Return));
    }

    #[test]
    fn lift_jal_call() {
        let insns = [make_insn(0x1000, "jal", "0x2000")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::Call { .. }
        ));
    }

    #[test]
    fn lift_full_function() {
        let insns = [
            make_insn(0x1000, "addi", "sp, sp, -16"),
            make_insn(0x1004, "sd", "ra, 8(sp)"),
            make_insn(0x1008, "add", "a0, a0, a1"),
            make_insn(0x100c, "ld", "ra, 8(sp)"),
            make_insn(0x1010, "addi", "sp, sp, 16"),
            make_insn(0x1014, "ret", ""),
        ];
        let func = lift_function("test_func", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 6);
        assert!(matches!(
            func.instructions.last().unwrap().stmts[0],
            LlilStmt::Return
        ));
    }

    #[test]
    fn lift_compressed_beqz() {
        let insns = [make_insn(0x1000, "c.beqz", "a0, 0x1020")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        assert!(matches!(
            &func.instructions[0].stmts[0],
            LlilStmt::BranchIf { .. }
        ));
    }

    #[test]
    fn lift_lui() {
        let insns = [make_insn(0x1000, "lui", "a0, 1")];
        let func = lift_function("test", 0x1000, &insns);
        assert_eq!(func.instructions.len(), 1);
        // lui a0, 1 → a0 = 1 << 12 = 0x1000
        if let LlilStmt::SetReg { src, .. } = &func.instructions[0].stmts[0] {
            assert!(matches!(&func.exprs[*src], LlilExpr::Const(0x1000)));
        } else {
            panic!("expected SetReg");
        }
    }
}
