//! Medium-Level Intermediate Language (MLIL)
//!
//! Simplifies LLIL by: folding constants, building expression trees,
//! eliminating dead stores, and constructing SSA form.

use std::collections::HashMap;
use std::fmt;

use crate::il::llil::{
    self, BinOp, ExprId, LlilFunction, LlilStmt, UnaryOp, VectorElementType, VectorOpKind,
};

/// An SSA variable: a register name with a version number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.version)
    }
}

/// MLIL expression — higher-level than LLIL, uses SSA variables.
#[derive(Debug, Clone, PartialEq)]
pub enum MlilExpr {
    Var(SsaVar),
    Const(u64),
    Load {
        addr: Box<MlilExpr>,
        size: u8,
    },
    BinOp {
        op: BinOp,
        left: Box<MlilExpr>,
        right: Box<MlilExpr>,
    },
    UnaryOp {
        op: UnaryOp,
        operand: Box<MlilExpr>,
    },
    Phi(Vec<SsaVar>),
    Call {
        target: Box<MlilExpr>,
        args: Vec<MlilExpr>,
    },
    /// SIMD vector operation.
    VectorOp {
        kind: VectorOpKind,
        element_type: VectorElementType,
        width: u16,
        operands: Vec<MlilExpr>,
    },
}

/// MLIL statement.
#[derive(Debug, Clone, PartialEq)]
pub enum MlilStmt {
    Assign {
        dest: SsaVar,
        src: MlilExpr,
    },
    Store {
        addr: MlilExpr,
        value: MlilExpr,
        size: u8,
    },
    Jump {
        target: MlilExpr,
    },
    BranchIf {
        cond: MlilExpr,
        target: MlilExpr,
    },
    Call {
        target: MlilExpr,
    },
    Return,
    Nop,
}

/// An MLIL instruction with source address.
#[derive(Debug, Clone)]
pub struct MlilInst {
    pub address: u64,
    pub stmts: Vec<MlilStmt>,
}

/// An MLIL function in SSA form.
#[derive(Debug, Clone)]
pub struct MlilFunction {
    pub name: String,
    pub entry: u64,
    pub instructions: Vec<MlilInst>,
}

/// Convert LLIL expression index into an MLIL expression tree.
fn lower_expr(llil_func: &LlilFunction, id: ExprId) -> MlilExpr {
    match &llil_func.exprs[id] {
        llil::LlilExpr::Reg(name) => MlilExpr::Var(SsaVar {
            name: name.clone(),
            version: 0,
        }),
        llil::LlilExpr::Const(v) => MlilExpr::Const(*v),
        llil::LlilExpr::Load { addr, size } => MlilExpr::Load {
            addr: Box::new(lower_expr(llil_func, *addr)),
            size: *size,
        },
        llil::LlilExpr::BinOp { op, left, right } => MlilExpr::BinOp {
            op: *op,
            left: Box::new(lower_expr(llil_func, *left)),
            right: Box::new(lower_expr(llil_func, *right)),
        },
        llil::LlilExpr::UnaryOp { op, operand } => MlilExpr::UnaryOp {
            op: *op,
            operand: Box::new(lower_expr(llil_func, *operand)),
        },
        llil::LlilExpr::Zx { operand, .. } | llil::LlilExpr::Sx { operand, .. } => {
            lower_expr(llil_func, *operand)
        }
        llil::LlilExpr::Flag(cond) => {
            // Represent as a named flag variable
            MlilExpr::Var(SsaVar {
                name: format!("flag_{}", cond),
                version: 0,
            })
        }
        llil::LlilExpr::VectorOp {
            kind,
            element_type,
            width,
            operands,
        } => MlilExpr::VectorOp {
            kind: kind.clone(),
            element_type: *element_type,
            width: *width,
            operands: operands
                .iter()
                .map(|id| lower_expr(llil_func, *id))
                .collect(),
        },
    }
}

/// Lower an LLIL function to MLIL (pre-SSA: all versions are 0).
pub fn lower_to_mlil(llil_func: &LlilFunction) -> MlilFunction {
    let mut instructions = Vec::new();

    for inst in &llil_func.instructions {
        let mut stmts = Vec::new();
        for stmt in &inst.stmts {
            match stmt {
                LlilStmt::SetReg { dest, src } => {
                    stmts.push(MlilStmt::Assign {
                        dest: SsaVar {
                            name: dest.clone(),
                            version: 0,
                        },
                        src: lower_expr(llil_func, *src),
                    });
                }
                LlilStmt::Store { addr, value, size } => {
                    stmts.push(MlilStmt::Store {
                        addr: lower_expr(llil_func, *addr),
                        value: lower_expr(llil_func, *value),
                        size: *size,
                    });
                }
                LlilStmt::Jump { target } => {
                    stmts.push(MlilStmt::Jump {
                        target: lower_expr(llil_func, *target),
                    });
                }
                LlilStmt::BranchIf { cond, target } => {
                    stmts.push(MlilStmt::BranchIf {
                        cond: lower_expr(llil_func, *cond),
                        target: lower_expr(llil_func, *target),
                    });
                }
                LlilStmt::Call { target } => {
                    stmts.push(MlilStmt::Call {
                        target: lower_expr(llil_func, *target),
                    });
                }
                LlilStmt::Return => stmts.push(MlilStmt::Return),
                LlilStmt::Nop | LlilStmt::Unimplemented { .. } => stmts.push(MlilStmt::Nop),
            }
        }
        instructions.push(MlilInst {
            address: inst.address,
            stmts,
        });
    }

    MlilFunction {
        name: llil_func.name.clone(),
        entry: llil_func.entry,
        instructions,
    }
}

/// Apply SSA renaming: assign unique version numbers to each register definition.
pub fn apply_ssa(func: &mut MlilFunction) {
    let mut counters: HashMap<String, u32> = HashMap::new();

    for inst in &mut func.instructions {
        for stmt in &mut inst.stmts {
            if let MlilStmt::Assign { dest, .. } = stmt {
                let counter = counters.entry(dest.name.clone()).or_insert(0);
                *counter += 1;
                dest.version = *counter;
            }
        }
    }
}

/// Constant folding: simplify expressions with known constant operands.
pub fn fold_constants(expr: &MlilExpr) -> MlilExpr {
    match expr {
        MlilExpr::BinOp { op, left, right } => {
            let left = fold_constants(left);
            let right = fold_constants(right);
            if let (MlilExpr::Const(l), MlilExpr::Const(r)) = (&left, &right) {
                let result = match op {
                    BinOp::Add => l.wrapping_add(*r),
                    BinOp::Sub => l.wrapping_sub(*r),
                    BinOp::Mul => l.wrapping_mul(*r),
                    BinOp::And => l & r,
                    BinOp::Or => l | r,
                    BinOp::Xor => l ^ r,
                    BinOp::Shl => l.wrapping_shl(*r as u32),
                    BinOp::Shr => l.wrapping_shr(*r as u32),
                    _ => {
                        return MlilExpr::BinOp {
                            op: *op,
                            left: Box::new(left),
                            right: Box::new(right),
                        };
                    }
                };
                return MlilExpr::Const(result);
            }
            // Identity simplifications
            match op {
                BinOp::Add if right == MlilExpr::Const(0) => return left,
                BinOp::Add if left == MlilExpr::Const(0) => return right,
                BinOp::Sub if right == MlilExpr::Const(0) => return left,
                BinOp::Mul if right == MlilExpr::Const(1) => return left,
                BinOp::Mul if left == MlilExpr::Const(1) => return right,
                BinOp::Mul if right == MlilExpr::Const(0) || left == MlilExpr::Const(0) => {
                    return MlilExpr::Const(0);
                }
                _ => {}
            }
            MlilExpr::BinOp {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
        MlilExpr::UnaryOp { op, operand } => {
            let operand = fold_constants(operand);
            if let MlilExpr::Const(v) = &operand {
                let result = match op {
                    UnaryOp::Not => !v,
                    UnaryOp::Neg => (-((*v) as i64)) as u64,
                };
                return MlilExpr::Const(result);
            }
            MlilExpr::UnaryOp {
                op: *op,
                operand: Box::new(operand),
            }
        }
        other => other.clone(),
    }
}

/// Eliminate dead stores: remove assignments to SSA variables that are never read.
pub fn eliminate_dead_stores(func: &mut MlilFunction) {
    use std::collections::HashSet;

    // Phase 1: Collect all SSA vars that are READ
    let mut used: HashSet<(String, u32)> = HashSet::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            collect_used_vars_stmt(stmt, &mut used);
        }
    }

    // Phase 2: Remove assignments to unused vars (but keep side-effectful ones)
    for inst in &mut func.instructions {
        inst.stmts.retain(|stmt| {
            if let MlilStmt::Assign { dest, .. } = stmt {
                // Keep if the dest is used somewhere, or if dest is a "return" register
                // (rax, eax, x0) since those may be the return value
                if dest.name == "rax" || dest.name == "eax" || dest.name == "x0" {
                    return true;
                }
                // Keep flag assignments (they affect control flow)
                if dest.name.starts_with("flag_") || dest.name.starts_with("__") {
                    return true;
                }
                used.contains(&(dest.name.clone(), dest.version))
            } else {
                true // keep all non-Assign statements
            }
        });
    }
}

fn collect_used_vars_expr(expr: &MlilExpr, used: &mut std::collections::HashSet<(String, u32)>) {
    match expr {
        MlilExpr::Var(ssa) => {
            used.insert((ssa.name.clone(), ssa.version));
        }
        MlilExpr::Load { addr, .. } => collect_used_vars_expr(addr, used),
        MlilExpr::BinOp { left, right, .. } => {
            collect_used_vars_expr(left, used);
            collect_used_vars_expr(right, used);
        }
        MlilExpr::UnaryOp { operand, .. } => collect_used_vars_expr(operand, used),
        MlilExpr::Phi(vars) => {
            for v in vars {
                used.insert((v.name.clone(), v.version));
            }
        }
        MlilExpr::Call { target, args } => {
            collect_used_vars_expr(target, used);
            for a in args {
                collect_used_vars_expr(a, used);
            }
        }
        MlilExpr::VectorOp { operands, .. } => {
            for op in operands {
                collect_used_vars_expr(op, used);
            }
        }
        MlilExpr::Const(_) => {}
    }
}

fn collect_used_vars_stmt(stmt: &MlilStmt, used: &mut std::collections::HashSet<(String, u32)>) {
    match stmt {
        MlilStmt::Assign { src, .. } => collect_used_vars_expr(src, used),
        MlilStmt::Store { addr, value, .. } => {
            collect_used_vars_expr(addr, used);
            collect_used_vars_expr(value, used);
        }
        MlilStmt::Jump { target } => collect_used_vars_expr(target, used),
        MlilStmt::BranchIf { cond, target } => {
            collect_used_vars_expr(cond, used);
            collect_used_vars_expr(target, used);
        }
        MlilStmt::Call { target } => collect_used_vars_expr(target, used),
        MlilStmt::Return | MlilStmt::Nop => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::lifter_x86::lift_function;

    fn make_insn(addr: u64, mn: &str, op: &str) -> crate::disasm::Instruction {
        crate::disasm::Instruction {
            address: addr,
            bytes: vec![],
            mnemonic: mn.to_string(),
            op_str: op.to_string(),
            groups: vec![],
        }
    }

    #[test]
    fn llil_to_mlil_lowering() {
        let insns = [
            make_insn(0x1000, "mov", "rax, 42"),
            make_insn(0x1004, "add", "rax, rbx"),
            make_insn(0x1008, "ret", ""),
        ];
        let llil = lift_function("test", 0x1000, &insns);
        let mlil = lower_to_mlil(&llil);
        assert_eq!(mlil.instructions.len(), 3);
    }

    #[test]
    fn ssa_versioning() {
        let insns = [
            make_insn(0x1000, "mov", "rax, 1"),
            make_insn(0x1004, "mov", "rax, 2"),
            make_insn(0x1008, "mov", "rbx, rax"),
        ];
        let llil = lift_function("test", 0x1000, &insns);
        let mut mlil = lower_to_mlil(&llil);
        apply_ssa(&mut mlil);

        // rax should have versions 1 and 2
        if let MlilStmt::Assign { dest, .. } = &mlil.instructions[0].stmts[0] {
            assert_eq!(dest.name, "rax");
            assert_eq!(dest.version, 1);
        }
        if let MlilStmt::Assign { dest, .. } = &mlil.instructions[1].stmts[0] {
            assert_eq!(dest.name, "rax");
            assert_eq!(dest.version, 2);
        }
    }

    #[test]
    fn constant_folding() {
        let expr = MlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(MlilExpr::Const(10)),
            right: Box::new(MlilExpr::Const(32)),
        };
        assert_eq!(fold_constants(&expr), MlilExpr::Const(42));
    }

    #[test]
    fn identity_folding() {
        let var = MlilExpr::Var(SsaVar {
            name: "rax".into(),
            version: 1,
        });
        let expr = MlilExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(var.clone()),
            right: Box::new(MlilExpr::Const(0)),
        };
        assert_eq!(fold_constants(&expr), var);
    }

    #[test]
    fn dead_store_elimination_removes_unused() {
        // rbx#1 = 42    (dead — never read)
        // rax#1 = 10    (rax is a return register — kept)
        // return
        let mut func = MlilFunction {
            name: "test".to_string(),
            entry: 0x1000,
            instructions: vec![
                MlilInst {
                    address: 0x1000,
                    stmts: vec![
                        MlilStmt::Assign {
                            dest: SsaVar {
                                name: "rbx".into(),
                                version: 1,
                            },
                            src: MlilExpr::Const(42),
                        },
                        MlilStmt::Assign {
                            dest: SsaVar {
                                name: "rax".into(),
                                version: 1,
                            },
                            src: MlilExpr::Const(10),
                        },
                    ],
                },
                MlilInst {
                    address: 0x1004,
                    stmts: vec![MlilStmt::Return],
                },
            ],
        };

        eliminate_dead_stores(&mut func);

        // rbx#1 should be removed (dead store), rax#1 kept (return register)
        assert_eq!(func.instructions[0].stmts.len(), 1);
        if let MlilStmt::Assign { dest, .. } = &func.instructions[0].stmts[0] {
            assert_eq!(dest.name, "rax");
        } else {
            panic!("expected Assign to rax");
        }
    }

    #[test]
    fn dead_store_elimination_keeps_used() {
        // rcx#1 = 42
        // rax#1 = rcx#1 + 1   (rcx#1 is used here — keep it)
        // return
        let mut func = MlilFunction {
            name: "test".to_string(),
            entry: 0x1000,
            instructions: vec![
                MlilInst {
                    address: 0x1000,
                    stmts: vec![
                        MlilStmt::Assign {
                            dest: SsaVar {
                                name: "rcx".into(),
                                version: 1,
                            },
                            src: MlilExpr::Const(42),
                        },
                        MlilStmt::Assign {
                            dest: SsaVar {
                                name: "rax".into(),
                                version: 1,
                            },
                            src: MlilExpr::BinOp {
                                op: BinOp::Add,
                                left: Box::new(MlilExpr::Var(SsaVar {
                                    name: "rcx".into(),
                                    version: 1,
                                })),
                                right: Box::new(MlilExpr::Const(1)),
                            },
                        },
                    ],
                },
                MlilInst {
                    address: 0x1004,
                    stmts: vec![MlilStmt::Return],
                },
            ],
        };

        eliminate_dead_stores(&mut func);

        // Both assignments should be kept: rcx#1 is used by rax#1's source
        assert_eq!(func.instructions[0].stmts.len(), 2);
    }
}
