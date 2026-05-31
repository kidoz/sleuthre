//! Medium-Level Intermediate Language (MLIL)
//!
//! Simplifies LLIL by: folding constants, building expression trees,
//! eliminating dead stores, and constructing SSA form.

use std::collections::HashMap;
use std::fmt;

use crate::il::llil::{
    self, BinOp, ExprId, FlagCondition, LlilFunction, LlilStmt, UnaryOp, VectorElementType,
    VectorOpKind,
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

/// Map a CPU [`FlagCondition`] to the relational [`BinOp`] that recovers it.
///
/// Returns `None` for conditions that don't correspond to a simple two-operand
/// relational comparison (`Neg`/`Overflow`), so the caller falls back to the
/// opaque `flag_*` variable rather than synthesizing a misleading expression.
fn flag_condition_to_binop(cond: FlagCondition) -> Option<BinOp> {
    Some(match cond {
        FlagCondition::E => BinOp::CmpEq,
        FlagCondition::Ne => BinOp::CmpNe,
        FlagCondition::Slt => BinOp::CmpLt,
        FlagCondition::Sle => BinOp::CmpLe,
        FlagCondition::Sgt => BinOp::CmpGt,
        FlagCondition::Sge => BinOp::CmpGe,
        FlagCondition::Ult => BinOp::CmpUlt,
        FlagCondition::Ule => BinOp::CmpUle,
        FlagCondition::Ugt => BinOp::CmpUgt,
        FlagCondition::Uge => BinOp::CmpUge,
        FlagCondition::Neg | FlagCondition::Overflow => return None,
    })
}

/// Reconstruct a relational condition from the most recent flag-setting
/// expression and the branch's [`FlagCondition`].
///
/// The x86 lifter models `cmp a, b` as `__flags = a - b` and `test a, b` as
/// `__flags = a & b` (see `lifter_x86::lift_cmp`/`lift_test`), then emits the
/// branch as an opaque `Flag(cond)`. This folds the two back together:
/// - `cmp a, b` + `jl`  → `a < b`
/// - `test eax, eax` + `je` → `eax == 0`
/// - `test a, b` + `jne` → `(a & b) != 0`
///
/// Returns `None` (caller falls back to the `flag_*` variable) when the flag
/// source isn't a recognized `cmp`/`test` shape or the condition isn't
/// relational.
fn synthesize_condition(cond: FlagCondition, flag_src: &MlilExpr) -> Option<MlilExpr> {
    let op = flag_condition_to_binop(cond)?;
    match flag_src {
        // `cmp a, b` → compare a against b directly.
        MlilExpr::BinOp {
            op: BinOp::Sub,
            left,
            right,
        } => Some(MlilExpr::BinOp {
            op,
            left: left.clone(),
            right: right.clone(),
        }),
        // `test a, b` → compare the bitwise-and against zero. The common
        // self-test `test eax, eax` collapses to `eax <op> 0`.
        MlilExpr::BinOp {
            op: BinOp::And,
            left,
            right,
        } => {
            let lhs = if left == right {
                left.clone()
            } else {
                Box::new(MlilExpr::BinOp {
                    op: BinOp::And,
                    left: left.clone(),
                    right: right.clone(),
                })
            };
            Some(MlilExpr::BinOp {
                op,
                left: lhs,
                right: Box::new(MlilExpr::Const(0)),
            })
        }
        _ => None,
    }
}

/// Lower an LLIL function to MLIL (pre-SSA: all versions are 0).
pub fn lower_to_mlil(llil_func: &LlilFunction) -> MlilFunction {
    let mut instructions = Vec::new();

    // Tracks the source expression of the most recent `__flags` assignment so a
    // following conditional branch can be folded into a relational expression.
    // This is a straight-line approximation: the lifter only sets `__flags` for
    // `cmp`/`test`, which compilers place immediately before the branch.
    let mut last_flag: Option<MlilExpr> = None;

    for inst in &llil_func.instructions {
        let mut stmts = Vec::new();
        for stmt in &inst.stmts {
            match stmt {
                LlilStmt::SetReg { dest, src } => {
                    let src = lower_expr(llil_func, *src);
                    if dest == "__flags" {
                        last_flag = Some(src.clone());
                    }
                    stmts.push(MlilStmt::Assign {
                        dest: SsaVar {
                            name: dest.clone(),
                            version: 0,
                        },
                        src,
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
                    // Fold `cmp/test` + `Jcc` into a relational expression when
                    // possible; otherwise keep the opaque `flag_*` variable.
                    let cond = match &llil_func.exprs[*cond] {
                        llil::LlilExpr::Flag(fc) => last_flag
                            .as_ref()
                            .and_then(|src| synthesize_condition(*fc, src))
                            .unwrap_or_else(|| lower_expr(llil_func, *cond)),
                        _ => lower_expr(llil_func, *cond),
                    };
                    stmts.push(MlilStmt::BranchIf {
                        cond,
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
                BinOp::Add | BinOp::FAdd if right == MlilExpr::Const(0) => return left,
                BinOp::Add | BinOp::FAdd if left == MlilExpr::Const(0) => return right,
                BinOp::Sub | BinOp::FSub if right == MlilExpr::Const(0) => return left,
                BinOp::Mul | BinOp::FMul if right == MlilExpr::Const(1) => return left,
                BinOp::Mul | BinOp::FMul if left == MlilExpr::Const(1) => return right,
                BinOp::Mul | BinOp::FMul
                    if right == MlilExpr::Const(0) || left == MlilExpr::Const(0) =>
                {
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

/// Eliminate dead stores: remove assignments to registers that are never read.
///
/// Liveness is keyed by register **name**, not by SSA version, because
/// [`apply_ssa`] versions definitions but does not rename uses (so a use would
/// never match its versioned definition). Name-keying makes this conservative —
/// an assignment is removed only when its destination register is read *nowhere*
/// in the function — which guarantees live code is never deleted (it may retain
/// some genuinely-dead stores; correctness over aggressiveness).
pub fn eliminate_dead_stores(func: &mut MlilFunction) {
    use std::collections::HashSet;

    // Phase 1: collect the names of every register that is read.
    let mut used: HashSet<String> = HashSet::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            collect_used_vars_stmt(stmt, &mut used);
        }
    }

    // Phase 2: drop assignments to never-read registers (keep side-effectful ones).
    for inst in &mut func.instructions {
        inst.stmts.retain(|stmt| {
            if let MlilStmt::Assign { dest, .. } = stmt {
                // Keep return registers (may hold the function's return value)…
                if dest.name == "rax" || dest.name == "eax" || dest.name == "x0" {
                    return true;
                }
                // …and flag/synthetic registers (affect control flow).
                if dest.name.starts_with("flag_") || dest.name.starts_with("__") {
                    return true;
                }
                used.contains(&dest.name)
            } else {
                true // keep all non-Assign statements
            }
        });
    }
}

fn collect_used_vars_expr(expr: &MlilExpr, used: &mut std::collections::HashSet<String>) {
    match expr {
        MlilExpr::Var(ssa) => {
            used.insert(ssa.name.clone());
        }
        MlilExpr::Load { addr, .. } => collect_used_vars_expr(addr, used),
        MlilExpr::BinOp { left, right, .. } => {
            collect_used_vars_expr(left, used);
            collect_used_vars_expr(right, used);
        }
        MlilExpr::UnaryOp { operand, .. } => collect_used_vars_expr(operand, used),
        MlilExpr::Phi(vars) => {
            for v in vars {
                used.insert(v.name.clone());
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

fn collect_used_vars_stmt(stmt: &MlilStmt, used: &mut std::collections::HashSet<String>) {
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

    /// Return the condition of the first `BranchIf` in the lowered function.
    fn first_branch_cond(insns: &[crate::disasm::Instruction]) -> MlilExpr {
        let llil = lift_function("test", 0x1000, insns);
        let mlil = lower_to_mlil(&llil);
        mlil.instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .find_map(|s| match s {
                MlilStmt::BranchIf { cond, .. } => Some(cond.clone()),
                _ => None,
            })
            .expect("expected a BranchIf statement")
    }

    fn var(name: &str) -> MlilExpr {
        MlilExpr::Var(SsaVar {
            name: name.into(),
            version: 0,
        })
    }

    #[test]
    fn cmp_jl_synthesizes_signed_less_than() {
        let cond = first_branch_cond(&[
            make_insn(0x1000, "cmp", "eax, ebx"),
            make_insn(0x1002, "jl", "0x1010"),
        ]);
        assert_eq!(
            cond,
            MlilExpr::BinOp {
                op: BinOp::CmpLt,
                left: Box::new(var("eax")),
                right: Box::new(var("ebx")),
            }
        );
    }

    #[test]
    fn cmp_jb_synthesizes_unsigned_less_than() {
        let cond = first_branch_cond(&[
            make_insn(0x1000, "cmp", "eax, ebx"),
            make_insn(0x1002, "jb", "0x1010"),
        ]);
        assert!(matches!(
            cond,
            MlilExpr::BinOp {
                op: BinOp::CmpUlt,
                ..
            }
        ));
    }

    #[test]
    fn self_test_collapses_to_compare_against_zero() {
        // `test eax, eax; je` is the canonical "is eax zero?" idiom.
        let cond = first_branch_cond(&[
            make_insn(0x1000, "test", "eax, eax"),
            make_insn(0x1002, "je", "0x1010"),
        ]);
        assert_eq!(
            cond,
            MlilExpr::BinOp {
                op: BinOp::CmpEq,
                left: Box::new(var("eax")),
                right: Box::new(MlilExpr::Const(0)),
            }
        );
    }

    #[test]
    fn test_with_mask_compares_bitand_against_zero() {
        // `test al, 1; jne` → `(al & 1) != 0`.
        let cond = first_branch_cond(&[
            make_insn(0x1000, "test", "al, 1"),
            make_insn(0x1002, "jne", "0x1010"),
        ]);
        assert_eq!(
            cond,
            MlilExpr::BinOp {
                op: BinOp::CmpNe,
                left: Box::new(MlilExpr::BinOp {
                    op: BinOp::And,
                    left: Box::new(var("al")),
                    right: Box::new(MlilExpr::Const(1)),
                }),
                right: Box::new(MlilExpr::Const(0)),
            }
        );
    }

    #[test]
    fn no_flag_var_leaks_into_output() {
        // Whatever the synthesized shape, it must not be an opaque `flag_*` var.
        let cond = first_branch_cond(&[
            make_insn(0x1000, "cmp", "eax, ebx"),
            make_insn(0x1002, "jne", "0x1010"),
        ]);
        let mut names = std::collections::HashSet::new();
        collect_used_vars_expr(&cond, &mut names);
        assert!(
            !names.iter().any(|n| n.starts_with("flag_")),
            "condition still references a flag pseudo-variable: {cond:?}"
        );
    }

    #[test]
    fn unrecoverable_condition_falls_back_to_flag_var() {
        // `js` (sign flag) has no two-operand relational form here, and there is
        // no preceding `cmp`/`test`, so we keep the opaque flag variable.
        let cond = first_branch_cond(&[make_insn(0x1000, "js", "0x1010")]);
        match cond {
            MlilExpr::Var(v) => assert!(v.name.starts_with("flag_"), "got {}", v.name),
            other => panic!("expected fallback flag var, got {other:?}"),
        }
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

    #[test]
    fn dead_store_elimination_survives_real_ssa_pipeline() {
        // Regression: `apply_ssa` versions definitions but not uses, so the old
        // version-keyed liveness deleted live code once run on real lifted IL.
        // Run the actual pipeline and confirm a live def-use chain through
        // non-return registers survives.
        let insns = [
            make_insn(0x1000, "mov", "rcx, 5"),
            make_insn(0x1004, "add", "rdx, rcx"), // reads rcx
            make_insn(0x1008, "mov", "rax, rdx"), // reads rdx (rax is the return reg)
        ];
        let llil = lift_function("test", 0x1000, &insns);
        let mut mlil = lower_to_mlil(&llil);
        apply_ssa(&mut mlil);
        eliminate_dead_stores(&mut mlil);

        let assigned: Vec<&str> = mlil
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter_map(|s| match s {
                MlilStmt::Assign { dest, .. } => Some(dest.name.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            assigned.contains(&"rcx"),
            "live rcx assignment was deleted: {assigned:?}"
        );
        assert!(
            assigned.contains(&"rdx"),
            "live rdx assignment was deleted: {assigned:?}"
        );
    }
}
