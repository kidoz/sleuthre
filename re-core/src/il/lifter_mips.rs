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
        "nop" => vec![LlilStmt::Nop],
        "add" | "addu" => lift_binary_op(func, &ops, BinOp::Add),
        "sub" | "subu" => lift_binary_op(func, &ops, BinOp::Sub),
        "and" | "andi" => lift_binary_op(func, &ops, BinOp::And),
        "or" | "ori" => lift_binary_op(func, &ops, BinOp::Or),
        "xor" | "xori" => lift_binary_op(func, &ops, BinOp::Xor),
        "move" => lift_move(func, &ops),
        "lw" => lift_load(func, &ops, 4),
        "sw" => lift_store(func, &ops, 4),
        "lb" => lift_load(func, &ops, 1),
        "sb" => lift_store(func, &ops, 1),
        "li" | "la" => lift_load_immediate(func, &ops),
        "j" | "b" => lift_jump(func, &ops),
        "jr" => lift_jump_reg(func, &ops),
        "jal" | "jalr" => lift_call(func, &ops),
        "beq" => lift_branch(func, &ops, "=="),
        "bne" => lift_branch(func, &ops, "!="),
        _ => vec![], // Unimplemented
    }
}

fn parse_operand(func: &mut LlilFunction, op: &str) -> ExprId {
    if let Ok(val) = op.parse::<u64>() {
        func.add_expr(LlilExpr::Const(val))
    } else if let Some(hex) = op.strip_prefix("0x") {
        let val = u64::from_str_radix(hex, 16).unwrap_or(0);
        func.add_expr(LlilExpr::Const(val))
    } else {
        func.add_expr(LlilExpr::Reg(op.to_string()))
    }
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

fn lift_load(func: &mut LlilFunction, ops: &[&str], size: u8) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let dest = ops[0].to_string();
    let mem_op = ops[1];

    let addr_expr = if let Some(start) = mem_op.find('(') {
        let offset_str = &mem_op[..start];
        let base_str = &mem_op[start + 1..mem_op.len() - 1];
        let base = parse_operand(func, base_str);
        if offset_str.is_empty() {
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

    let load_expr = func.add_expr(LlilExpr::Load {
        addr: addr_expr,
        size,
    });
    vec![LlilStmt::SetReg {
        dest,
        src: load_expr,
    }]
}

fn lift_store(func: &mut LlilFunction, ops: &[&str], size: u8) -> Vec<LlilStmt> {
    if ops.len() != 2 {
        return vec![];
    }
    let val = parse_operand(func, ops[0]);
    let mem_op = ops[1];

    let addr_expr = if let Some(start) = mem_op.find('(') {
        let offset_str = &mem_op[..start];
        let base_str = &mem_op[start + 1..mem_op.len() - 1];
        let base = parse_operand(func, base_str);
        if offset_str.is_empty() {
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
    if ops[0] == "$ra" {
        return vec![LlilStmt::Return];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Jump { target }]
}

fn lift_call(func: &mut LlilFunction, ops: &[&str]) -> Vec<LlilStmt> {
    if ops.is_empty() {
        return vec![];
    }
    let target = parse_operand(func, ops[0]);
    vec![LlilStmt::Call { target }]
}

fn lift_branch(func: &mut LlilFunction, ops: &[&str], cmp: &str) -> Vec<LlilStmt> {
    if ops.len() != 3 {
        return vec![];
    }
    let left = parse_operand(func, ops[0]);
    let right = parse_operand(func, ops[1]);
    let target = parse_operand(func, ops[2]);

    let cond_op = match cmp {
        "==" => BinOp::CmpEq,
        "!=" => BinOp::CmpNe,
        _ => BinOp::CmpEq,
    };

    let cond = func.add_expr(LlilExpr::BinOp {
        op: cond_op,
        left,
        right,
    });
    vec![LlilStmt::BranchIf { cond, target }]
}
