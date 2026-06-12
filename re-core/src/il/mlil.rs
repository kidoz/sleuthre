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

/// Version assigned to a use with no known reaching definition: before any
/// def of the name, after a join point, or after an instruction with unknown
/// effects. It is distinct from every version a definition can carry (defs
/// get 0 or 1..), which is what makes the optimization passes sound: value
/// propagation never substitutes into such a use, and dead-store elimination
/// treats it as keeping *every* definition of the name alive.
pub const VER_UNKNOWN: u32 = u32::MAX;

/// An SSA variable: a register name with a version number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.version == VER_UNKNOWN {
            write!(f, "{}#?", self.name)
        } else {
            write!(f, "{}#{}", self.name, self.version)
        }
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
        /// Reconstructed call arguments in left-to-right source order. Empty
        /// until [`reconstruct_stack_operations`] runs (e.g. stack-passed cdecl
        /// arguments recovered from the preceding `push` sequence).
        args: Vec<MlilExpr>,
    },
    Return,
    Nop,
    /// An instruction the lifter could not translate (original text kept).
    /// It may read or write anything, so the dataflow passes must treat it
    /// as a barrier — erasing it to `Nop` would let dead-store elimination
    /// delete the live definitions it consumes.
    Unimplemented {
        text: String,
    },
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

/// Canonicalize a register name to its widest architectural alias (`eax` →
/// `rax`, `cl` → `rcx`, `w3` → `x3`) at MLIL lowering time. Sub-registers
/// were previously unrelated variables to every dataflow pass: DSE deleted
/// the `mov ecx, 5` feeding a `shl eax, cl`, and the ABI tables (keyed on
/// the wide names) missed `mov edi, …` argument setup entirely. Width
/// semantics (zero/sign extension of the narrow write) are intentionally not
/// modeled, matching MLIL's existing width handling, and the pseudocode
/// renderer already maps each alias family to one display name, so output
/// naming is unchanged. `sp` and `ip` are deliberately NOT mapped — as
/// operand text those names are ARM's stack pointer and r12, not the 16-bit
/// x86 aliases.
fn canonical_register(name: &str) -> String {
    // ARM64: w-registers are the 32-bit views of the x-registers.
    if let Some(num) = name.strip_prefix('w')
        && !num.is_empty()
        && num.len() <= 2
        && num.chars().all(|c| c.is_ascii_digit())
    {
        return format!("x{}", num);
    }
    match name {
        "wzr" => "xzr",
        "eax" | "ax" | "al" | "ah" => "rax",
        "ebx" | "bx" | "bl" | "bh" => "rbx",
        "ecx" | "cx" | "cl" | "ch" => "rcx",
        "edx" | "dx" | "dl" | "dh" => "rdx",
        "esi" | "si" | "sil" => "rsi",
        "edi" | "di" | "dil" => "rdi",
        "ebp" | "bp" | "bpl" => "rbp",
        "esp" | "spl" => "rsp",
        "eip" => "rip",
        "r8d" | "r8w" | "r8b" => "r8",
        "r9d" | "r9w" | "r9b" => "r9",
        "r10d" | "r10w" | "r10b" => "r10",
        "r11d" | "r11w" | "r11b" => "r11",
        "r12d" | "r12w" | "r12b" => "r12",
        "r13d" | "r13w" | "r13b" => "r13",
        "r14d" | "r14w" | "r14b" => "r14",
        "r15d" | "r15w" | "r15b" => "r15",
        other => other,
    }
    .to_string()
}

/// Convert LLIL expression index into an MLIL expression tree.
fn lower_expr(llil_func: &LlilFunction, id: ExprId) -> MlilExpr {
    match &llil_func.exprs[id] {
        llil::LlilExpr::Reg(name) => MlilExpr::Var(SsaVar {
            name: canonical_register(name),
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
                            name: canonical_register(dest),
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
                        args: Vec::new(),
                    });
                }
                LlilStmt::Return => stmts.push(MlilStmt::Return),
                LlilStmt::Nop => stmts.push(MlilStmt::Nop),
                LlilStmt::Unimplemented { mnemonic, op_str } => {
                    stmts.push(MlilStmt::Unimplemented {
                        text: format!("{} {}", mnemonic, op_str).trim().to_string(),
                    });
                }
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

/// Version both definitions *and* uses so each use names its reaching definition.
///
/// [`apply_ssa`] versions only definitions, leaving every use at version 0 — so
/// a register read after a redefinition rendered as the (stale) incoming value.
/// This walks the function in program order tracking the current version of each
/// register and rewrites each use to it, while assigning definitions the same
/// monotonic versions `apply_ssa` would.
///
/// Without a full CFG this is sound only within straight-line code, so the
/// reaching map is reset at branch targets (join points): uses there fall back
/// to version 0 (the merged/incoming value) rather than a possibly-wrong guess.
pub fn version_defs_and_uses(func: &mut MlilFunction) {
    // Addresses that are jump/branch targets begin a new block (possible join).
    let mut targets: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            match stmt {
                MlilStmt::Jump { target } | MlilStmt::BranchIf { target, .. } => {
                    if let MlilExpr::Const(a) = target {
                        targets.insert(*a);
                    }
                }
                _ => {}
            }
        }
    }

    // Count definitions per register so single-assignment registers keep their
    // bare name (no `_1` suffix) — versioning only earns its keep when a register
    // is actually reassigned.
    let mut def_counts: HashMap<String, u32> = HashMap::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            if let MlilStmt::Assign { dest, .. } = stmt {
                *def_counts.entry(dest.name.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut counters: HashMap<String, u32> = HashMap::new();
    let mut current: HashMap<String, u32> = HashMap::new();
    for inst in &mut func.instructions {
        if targets.contains(&inst.address) {
            current.clear();
        }
        for stmt in &mut inst.stmts {
            match stmt {
                MlilStmt::Assign { dest, src } => {
                    rename_uses(src, &current);
                    // Stack/frame pointers and single-def registers stay at
                    // version 0: the former are elided pseudo-registers, the
                    // latter need no disambiguation.
                    if is_stack_or_frame_pointer(&dest.name)
                        || def_counts.get(dest.name.as_str()).copied().unwrap_or(0) <= 1
                    {
                        dest.version = 0;
                        current.insert(dest.name.clone(), 0);
                        continue;
                    }
                    let c = counters.entry(dest.name.clone()).or_insert(0);
                    *c += 1;
                    dest.version = *c;
                    current.insert(dest.name.clone(), *c);
                }
                MlilStmt::Store { addr, value, .. } => {
                    rename_uses(addr, &current);
                    rename_uses(value, &current);
                }
                MlilStmt::Jump { target } => rename_uses(target, &current),
                MlilStmt::BranchIf { cond, target } => {
                    rename_uses(cond, &current);
                    rename_uses(target, &current);
                }
                MlilStmt::Call { target, args } => {
                    rename_uses(target, &current);
                    for a in args {
                        rename_uses(a, &current);
                    }
                }
                // Unknown effects: every register may have been redefined, so
                // later uses must not be linked to definitions above it.
                MlilStmt::Unimplemented { .. } => current.clear(),
                MlilStmt::Return | MlilStmt::Nop => {}
            }
        }
    }
}

/// Point every variable in `expr` at its current reaching-definition version.
fn rename_uses(expr: &mut MlilExpr, current: &HashMap<String, u32>) {
    match expr {
        // No reaching definition known (use-before-def, post-join, or past an
        // unimplemented instruction): the sentinel keeps this use from ever
        // matching a definition's version in the optimization passes.
        MlilExpr::Var(v) => v.version = current.get(&v.name).copied().unwrap_or(VER_UNKNOWN),
        MlilExpr::Load { addr, .. } => rename_uses(addr, current),
        MlilExpr::BinOp { left, right, .. } => {
            rename_uses(left, current);
            rename_uses(right, current);
        }
        MlilExpr::UnaryOp { operand, .. } => rename_uses(operand, current),
        MlilExpr::Call { target, args } => {
            rename_uses(target, current);
            for a in args {
                rename_uses(a, current);
            }
        }
        MlilExpr::VectorOp { operands, .. } => {
            for o in operands {
                rename_uses(o, current);
            }
        }
        MlilExpr::Phi(_) | MlilExpr::Const(_) => {}
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
                // `x | 0`, `x ^ 0`, `x << 0`, `x >> 0` → x
                BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr | BinOp::Sar
                    if right == MlilExpr::Const(0) =>
                {
                    return left;
                }
                // `0 | x`, `0 ^ x` → x
                BinOp::Or | BinOp::Xor if left == MlilExpr::Const(0) => return right,
                // `x & 0`, `0 & x` → 0
                BinOp::And if right == MlilExpr::Const(0) || left == MlilExpr::Const(0) => {
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
            // Involution: `-(-x)` → x and `~(~x)` → x.
            if let MlilExpr::UnaryOp {
                op: inner_op,
                operand: inner,
            } = &operand
                && inner_op == op
            {
                return (**inner).clone();
            }
            MlilExpr::UnaryOp {
                op: *op,
                operand: Box::new(operand),
            }
        }
        other => other.clone(),
    }
}

/// Collect every SSA variable read in an expression (uses, by name+version).
fn collect_ssavars_in_expr(expr: &MlilExpr, used: &mut std::collections::HashSet<SsaVar>) {
    match expr {
        MlilExpr::Var(v) => {
            used.insert(v.clone());
        }
        MlilExpr::Load { addr, .. } => collect_ssavars_in_expr(addr, used),
        MlilExpr::BinOp { left, right, .. } => {
            collect_ssavars_in_expr(left, used);
            collect_ssavars_in_expr(right, used);
        }
        MlilExpr::UnaryOp { operand, .. } => collect_ssavars_in_expr(operand, used),
        MlilExpr::Call { target, args } => {
            collect_ssavars_in_expr(target, used);
            for a in args {
                collect_ssavars_in_expr(a, used);
            }
        }
        MlilExpr::VectorOp { operands, .. } => {
            for o in operands {
                collect_ssavars_in_expr(o, used);
            }
        }
        MlilExpr::Phi(vars) => {
            for v in vars {
                used.insert(v.clone());
            }
        }
        MlilExpr::Const(_) => {}
    }
}

/// Version-aware dead-store elimination: drop an assignment whose exact SSA
/// variable (name + version) is never read.
///
/// Unlike [`eliminate_dead_stores`] (conservative, name-keyed), this requires
/// uses to have been versioned by [`version_defs_and_uses`] — it is sound only
/// then, because the decompiler renders each `(name, version)` as a distinct
/// variable. Return registers and synthetic registers are always kept (the
/// return value is consumed implicitly, not by a statement).
pub fn eliminate_dead_stores_ssa(func: &mut MlilFunction) {
    use std::collections::HashSet;

    // An unimplemented instruction reads an unknown set of registers (e.g.
    // `div ecx` implicitly reads eax/edx): any definition feeding it would
    // look dead. No elimination is sound in that case.
    let has_unknown_effects = func.instructions.iter().any(|i| {
        i.stmts
            .iter()
            .any(|s| matches!(s, MlilStmt::Unimplemented { .. }))
    });
    if has_unknown_effects {
        return;
    }

    let mut used: HashSet<SsaVar> = HashSet::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            match stmt {
                MlilStmt::Assign { src, .. } => collect_ssavars_in_expr(src, &mut used),
                MlilStmt::Store { addr, value, .. } => {
                    collect_ssavars_in_expr(addr, &mut used);
                    collect_ssavars_in_expr(value, &mut used);
                }
                MlilStmt::Jump { target } => collect_ssavars_in_expr(target, &mut used),
                MlilStmt::BranchIf { cond, target } => {
                    collect_ssavars_in_expr(cond, &mut used);
                    collect_ssavars_in_expr(target, &mut used);
                }
                MlilStmt::Call { target, args } => {
                    collect_ssavars_in_expr(target, &mut used);
                    for a in args {
                        collect_ssavars_in_expr(a, &mut used);
                    }
                }
                MlilStmt::Return | MlilStmt::Nop | MlilStmt::Unimplemented { .. } => {}
            }
        }
    }

    // A use whose reaching definition is unknown (post-join / use-before-def)
    // may read *any* definition of that name — every def of the name must
    // survive, or branch-side assignments feeding a join get deleted.
    let used_any_version: HashSet<&str> = used
        .iter()
        .filter(|v| v.version == VER_UNKNOWN)
        .map(|v| v.name.as_str())
        .collect();

    for inst in &mut func.instructions {
        inst.stmts.retain(|stmt| match stmt {
            MlilStmt::Assign { dest, .. } => {
                // Return registers (value consumed by the implicit return) and
                // synthetic/flag registers are always kept. The return-register
                // list covers every lifted architecture: x86 (rax/eax), ARM64
                // (x0/w0), ARM32 (r0), MIPS (v0/v1), RISC-V (a0/a1).
                matches!(
                    dest.name.as_str(),
                    "rax" | "eax" | "x0" | "w0" | "r0" | "v0" | "v1" | "a0" | "a1"
                ) || dest.name.starts_with("flag_")
                    || dest.name.starts_with("__")
                    || used.contains(dest)
                    || used_any_version.contains(dest.name.as_str())
            }
            _ => true,
        });
    }
}

/// Apply `f` to every *use*-position expression of a statement (i.e. not the
/// destination of an assignment).
fn for_each_use_expr_mut(stmt: &mut MlilStmt, mut f: impl FnMut(&mut MlilExpr)) {
    match stmt {
        MlilStmt::Assign { src, .. } => f(src),
        MlilStmt::Store { addr, value, .. } => {
            f(addr);
            f(value);
        }
        MlilStmt::Jump { target } => f(target),
        MlilStmt::BranchIf { cond, target } => {
            f(cond);
            f(target);
        }
        MlilStmt::Call { target, args } => {
            f(target);
            for a in args {
                f(a);
            }
        }
        MlilStmt::Return | MlilStmt::Nop | MlilStmt::Unimplemented { .. } => {}
    }
}

/// Resolve a variable through chains of constant/copy definitions, e.g. given
/// `a = 0; b = a`, `resolve(b)` yields `0`. Returns `None` if `v` has no tracked
/// constant/copy definition.
fn resolve_value(v: &SsaVar, values: &HashMap<SsaVar, MlilExpr>, depth: u32) -> Option<MlilExpr> {
    if depth > 32 {
        return None;
    }
    match values.get(v)? {
        MlilExpr::Const(c) => Some(MlilExpr::Const(*c)),
        MlilExpr::Var(w) => {
            Some(resolve_value(w, values, depth + 1).unwrap_or(MlilExpr::Var(w.clone())))
        }
        other => Some(other.clone()),
    }
}

/// Substitute resolved constant/copy values into every variable leaf of `expr`.
fn substitute_values(expr: &mut MlilExpr, values: &HashMap<SsaVar, MlilExpr>, changed: &mut bool) {
    match expr {
        MlilExpr::Var(v) => {
            if let Some(resolved) = resolve_value(v, values, 0)
                && resolved != *expr
            {
                *expr = resolved;
                *changed = true;
            }
        }
        MlilExpr::Load { addr, .. } => substitute_values(addr, values, changed),
        MlilExpr::BinOp { left, right, .. } => {
            substitute_values(left, values, changed);
            substitute_values(right, values, changed);
        }
        MlilExpr::UnaryOp { operand, .. } => substitute_values(operand, values, changed),
        MlilExpr::Call { target, args } => {
            substitute_values(target, values, changed);
            for a in args {
                substitute_values(a, values, changed);
            }
        }
        MlilExpr::VectorOp { operands, .. } => {
            for o in operands {
                substitute_values(o, values, changed);
            }
        }
        MlilExpr::Phi(_) | MlilExpr::Const(_) => {}
    }
}

/// Constant- and copy-propagation with constant folding, to a fixpoint.
///
/// Replaces uses of a register whose reaching definition is a constant or a
/// plain copy with that value, then folds. Keyed on the exact SSA variable
/// (name + version), this is sound given [`version_defs_and_uses`]: only a
/// register's unique reaching definition is propagated. Iterates so chains like
/// `a = 0; b = a | c; d = b | e` collapse. The now-dead definitions are cleaned
/// up by [`eliminate_dead_stores`].
pub fn propagate_values(func: &mut MlilFunction) {
    const MAX_ROUNDS: usize = 16;
    for _ in 0..MAX_ROUNDS {
        // Fold first so freshly-simplified constants become propagatable.
        for inst in &mut func.instructions {
            for stmt in &mut inst.stmts {
                for_each_use_expr_mut(stmt, |e| *e = fold_constants(e));
            }
        }

        // Collect constant/copy definitions.
        let mut values: HashMap<SsaVar, MlilExpr> = HashMap::new();
        for inst in &func.instructions {
            for stmt in &inst.stmts {
                if let MlilStmt::Assign { dest, src } = stmt
                    && matches!(src, MlilExpr::Const(_) | MlilExpr::Var(_))
                    && !matches!(src, MlilExpr::Var(v) if v == dest)
                {
                    values.insert(dest.clone(), src.clone());
                }
            }
        }
        if values.is_empty() {
            break;
        }

        let mut changed = false;
        for inst in &mut func.instructions {
            for stmt in &mut inst.stmts {
                for_each_use_expr_mut(stmt, |e| substitute_values(e, &values, &mut changed));
            }
        }
        if !changed {
            break;
        }
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
        MlilStmt::Call { target, args } => {
            collect_used_vars_expr(target, used);
            for a in args {
                collect_used_vars_expr(a, used);
            }
        }
        MlilStmt::Return | MlilStmt::Nop | MlilStmt::Unimplemented { .. } => {}
    }
}

/// Names of the stack and frame pointer registers across the x86 family. Used
/// for *addressing* (`[ebp - 8]` is stack-relative).
fn is_stack_or_frame_pointer(name: &str) -> bool {
    matches!(name, "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp")
}

/// The actual stack pointer (never the frame pointer). `push`/`pop` adjust this,
/// so detecting their mechanics — and distinguishing a `pop ebp` (ebp is a
/// general/frame register here) from a stack-pointer update — must use this.
fn is_stack_pointer(name: &str) -> bool {
    matches!(name, "rsp" | "esp" | "sp" | "spl")
}

/// Whether `name` is a callee-saved general-purpose register on the x86 family
/// (the set a function must preserve, so it spills them in the prologue and
/// restores them in the epilogue). Covers both x86-32 (ebx/esi/edi/ebp) and
/// x86-64 (rbx/rbp/r12–r15, plus rsi/rdi under Win64).
fn is_callee_saved_register(name: &str) -> bool {
    matches!(
        name,
        "rbx"
            | "ebx"
            | "rbp"
            | "ebp"
            | "rsi"
            | "esi"
            | "rdi"
            | "edi"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
    )
}

/// Whether `addr` is a stack-pointer-relative address: a bare `sp`/`bp` register
/// or `sp ± constant`. Matches the shape the lifter emits for `push` stores.
fn is_stack_relative_addr(addr: &MlilExpr) -> bool {
    match addr {
        MlilExpr::Var(v) => is_stack_or_frame_pointer(&v.name),
        MlilExpr::BinOp {
            op: BinOp::Add | BinOp::Sub,
            left,
            right,
        } => {
            (matches!(&**left, MlilExpr::Var(v) if is_stack_or_frame_pointer(&v.name))
                && matches!(&**right, MlilExpr::Const(_)))
                || (matches!(&**right, MlilExpr::Var(v) if is_stack_or_frame_pointer(&v.name))
                    && matches!(&**left, MlilExpr::Const(_)))
        }
        _ => false,
    }
}

/// Whether `src` is a bare `pop`-style load from the top of stack — `*(sp)` with
/// no offset, exactly what [`crate::il::lifter_x86`] emits for `pop reg`. This is
/// deliberately narrow so it never matches a real frame-relative local load.
fn is_pop_load(src: &MlilExpr) -> bool {
    matches!(src, MlilExpr::Load { addr, .. }
        if matches!(&**addr, MlilExpr::Var(v) if is_stack_pointer(&v.name)))
}

/// If `inst` is a `pop reg` — a load of the top-of-stack into `reg` paired with
/// a stack-pointer increment — return the destination register name.
fn pop_target(inst: &MlilInst) -> Option<String> {
    let mut dest_reg: Option<String> = None;
    let mut increments_sp = false;
    for stmt in &inst.stmts {
        match stmt {
            MlilStmt::Assign { dest, src } if is_pop_load(src) && !is_stack_pointer(&dest.name) => {
                dest_reg = Some(dest.name.clone());
            }
            MlilStmt::Assign {
                dest,
                src:
                    MlilExpr::BinOp {
                        op: BinOp::Add,
                        left,
                        ..
                    },
            } if is_stack_pointer(&dest.name) && is_stack_pointer_var(left) => {
                increments_sp = true;
            }
            _ => {}
        }
    }
    if increments_sp { dest_reg } else { None }
}

/// Whether `expr` is a bare stack-pointer register read (for `sp ± k` detection).
fn is_stack_pointer_var(expr: &MlilExpr) -> bool {
    matches!(expr, MlilExpr::Var(v) if is_stack_pointer(&v.name))
}

/// If `inst` is a `push` — a stack-pointer decrement paired with a store to the
/// decremented slot — return the pushed value. The decrement gate distinguishes
/// a real push from an ordinary frame-relative store (`mov [ebp-8], eax`).
fn push_value(inst: &MlilInst) -> Option<MlilExpr> {
    let mut decrements_sp = false;
    let mut stored: Option<MlilExpr> = None;
    for stmt in &inst.stmts {
        match stmt {
            MlilStmt::Assign {
                dest,
                src:
                    MlilExpr::BinOp {
                        op: BinOp::Sub,
                        left,
                        ..
                    },
            } if is_stack_pointer(&dest.name) && is_stack_pointer_var(left) => {
                decrements_sp = true;
            }
            MlilStmt::Store { addr, value, .. } if is_stack_relative_addr(addr) => {
                stored = Some(value.clone());
            }
            _ => {}
        }
    }
    if decrements_sp { stored } else { None }
}

/// Whether `inst` is a caller-side stack cleanup (`add esp, N`) — a stack
/// pointer increment by a constant, emitted after a cdecl call to pop arguments.
fn is_sp_cleanup(inst: &MlilInst) -> bool {
    inst.stmts.iter().all(|stmt| {
        matches!(stmt, MlilStmt::Assign { dest, src: MlilExpr::BinOp { op: BinOp::Add, left, right } }
            if is_stack_pointer(&dest.name)
                && is_stack_pointer_var(left)
                && matches!(&**right, MlilExpr::Const(_)))
    }) && !inst.stmts.is_empty()
}

/// Index of the first `Call` statement in `inst`, if any.
fn call_stmt_index(inst: &MlilInst) -> Option<usize> {
    inst.stmts
        .iter()
        .position(|s| matches!(s, MlilStmt::Call { .. }))
}

/// A pending `push` during the stack simulation.
struct PushedItem {
    /// Instruction index of the push.
    inst: usize,
    /// The value pushed.
    value: MlilExpr,
    /// `Some(reg)` if this is a prologue save of callee-saved register `reg`'s
    /// incoming value (eligible to be elided against a matching restore).
    save_reg: Option<String>,
}

/// Reconstruct x86 stack operations by simulating the push/pop stack, turning
/// the implicit stack discipline into explicit data flow. In one LIFO pass this:
///
/// - **elides callee-saved save/restore pairs** — a prologue `push reg` of the
///   register's incoming value balanced by an epilogue `pop reg` (preserving
///   caller registers is an ABI obligation, not part of the function's logic);
/// - **folds `push x; pop reg` into `reg = x`** — the constant/value
///   materialization idiom (e.g. `push 3; pop ebp`);
/// - **recovers stack-passed call arguments** — cdecl/stdcall arguments pushed
///   right-to-left before a `call` become its argument list (left-to-right),
///   and the caller-side `add esp, N` cleanup is dropped.
///
/// Register-passed conventions (x86-64) push nothing, so their calls keep empty
/// argument lists — unchanged. The simulation is per-basic-block: control-flow
/// statements reset the pending stack so nothing is paired across a branch.
pub fn reconstruct_stack_operations(func: &mut MlilFunction) {
    use std::collections::HashSet;

    let n = func.instructions.len();
    let mut remove = vec![false; n];
    let mut rewrite: Vec<Option<MlilStmt>> = (0..n).map(|_| None).collect();
    let mut stack: Vec<PushedItem> = Vec::new();
    let mut defined: HashSet<String> = HashSet::new();
    let mut expect_cleanup = false;

    for i in 0..n {
        // A cdecl caller pops arguments with `add esp, N` right after the call.
        if expect_cleanup {
            expect_cleanup = false;
            if is_sp_cleanup(&func.instructions[i]) {
                remove[i] = true;
                continue;
            }
        }

        if let Some(value) = push_value(&func.instructions[i]) {
            let save_reg = match &value {
                MlilExpr::Var(v)
                    if is_callee_saved_register(&v.name) && !defined.contains(&v.name) =>
                {
                    Some(v.name.clone())
                }
                _ => None,
            };
            stack.push(PushedItem {
                inst: i,
                value,
                save_reg,
            });
            continue;
        }

        if let Some(reg) = pop_target(&func.instructions[i]) {
            match stack.pop() {
                Some(item) => {
                    remove[item.inst] = true; // the matching push is consumed
                    match &item.save_reg {
                        // Balanced save/restore of the same register: pure ABI churn.
                        Some(saved) if *saved == reg => remove[i] = true,
                        // Otherwise the pop materializes the pushed value: `reg = x`.
                        _ => {
                            rewrite[i] = Some(MlilStmt::Assign {
                                dest: SsaVar {
                                    name: reg.clone(),
                                    version: 0,
                                },
                                src: item.value,
                            });
                            defined.insert(reg);
                        }
                    }
                }
                // No matching push in view (the prologue save is out of the
                // decoded window): a `pop` of a callee-saved register is an
                // epilogue restore — drop it as boilerplate.
                None if is_callee_saved_register(&reg) => remove[i] = true,
                None => {}
            }
            continue;
        }

        if let Some(sidx) = call_stmt_index(&func.instructions[i]) {
            // Consume the trailing run of non-save pushes as arguments. Stack top
            // is the last value pushed = the leftmost (first) cdecl argument, so
            // popping yields left-to-right order directly.
            let mut args = Vec::new();
            while let Some(top) = stack.last() {
                if top.save_reg.is_some() {
                    break;
                }
                let item = stack.pop().unwrap();
                remove[item.inst] = true;
                args.push(item.value);
            }
            if let MlilStmt::Call { args: slot, .. } = &mut func.instructions[i].stmts[sidx] {
                *slot = args;
            }
            expect_cleanup = true;
            continue;
        }

        // Track definitions for the incoming-value gate. At a basic-block
        // boundary, drop pending *data* pushes (args/temporaries are consumed
        // within a block) but keep prologue register saves — they legitimately
        // span the whole function and are matched against the epilogue pops.
        let mut control_flow = false;
        for stmt in &func.instructions[i].stmts {
            match stmt {
                MlilStmt::Assign { dest, .. } => {
                    defined.insert(dest.name.clone());
                }
                MlilStmt::Jump { .. }
                | MlilStmt::BranchIf { .. }
                | MlilStmt::Return
                // Unknown effects may include stack adjustment — drop any
                // tracked data pushes rather than misattribute them.
                | MlilStmt::Unimplemented { .. } => control_flow = true,
                _ => {}
            }
        }
        if control_flow {
            stack.retain(|item| item.save_reg.is_some());
        }
    }

    // Any prologue saves never matched by a restore — because the epilogue pop is
    // outside the decoded window — are still ABI boilerplate; elide their stores.
    for item in &stack {
        if item.save_reg.is_some() {
            remove[item.inst] = true;
        }
    }

    for (i, stmt) in rewrite.into_iter().enumerate() {
        if let Some(stmt) = stmt {
            func.instructions[i].stmts = vec![stmt];
        }
    }

    let mut idx = 0;
    func.instructions.retain(|_| {
        let keep = !remove[idx];
        idx += 1;
        keep
    });
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
                left: Box::new(var("rax")),
                right: Box::new(var("rbx")),
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
                left: Box::new(var("rax")),
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
                    left: Box::new(var("rax")),
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

    fn count_stores(f: &MlilFunction) -> usize {
        f.instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter(|s| matches!(s, MlilStmt::Store { .. }))
            .count()
    }

    fn lowered(insns: &[crate::disasm::Instruction]) -> MlilFunction {
        let mut m = lower_to_mlil(&lift_function("test", 0x1000, insns));
        reconstruct_stack_operations(&mut m);
        m
    }

    fn first_call_args(f: &MlilFunction) -> Vec<MlilExpr> {
        f.instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .find_map(|s| match s {
                MlilStmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("expected a Call statement")
    }

    #[test]
    fn elides_callee_saved_save_and_restore() {
        // `push ebx … pop ebx` is pure save/restore churn.
        let m = lowered(&[
            make_insn(0x1000, "push", "ebx"),
            make_insn(0x1001, "pop", "ebx"),
            make_insn(0x1002, "ret", ""),
        ]);
        assert_eq!(count_stores(&m), 0, "prologue save store should be removed");
        let restores = m
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter(|s| {
                matches!(s, MlilStmt::Assign { dest, src }
                if dest.name == "ebx" && matches!(src, MlilExpr::Load { .. }))
            })
            .count();
        assert_eq!(restores, 0, "epilogue pop restore should be removed");
    }

    #[test]
    fn keeps_spill_of_computed_value() {
        // `mov ebx, eax; push ebx` spills a *computed* value — not boilerplate.
        let m = lowered(&[
            make_insn(0x1000, "mov", "ebx, eax"),
            make_insn(0x1004, "push", "ebx"),
        ]);
        assert_eq!(count_stores(&m), 1, "computed spill must be preserved");
    }

    #[test]
    fn keeps_unconsumed_constant_push() {
        // A `push 3` with no matching pop or call stays as-is.
        let m = lowered(&[make_insn(0x1000, "push", "3")]);
        assert_eq!(count_stores(&m), 1);
    }

    #[test]
    fn folds_push_immediate_pop_into_assignment() {
        // `push 3; pop ebp` materializes a constant: `ebp = 3` (no stack store).
        // This pop must NOT be mistaken for a callee-saved restore.
        let m = lowered(&[
            make_insn(0x1000, "push", "3"),
            make_insn(0x1002, "pop", "ebp"),
        ]);
        assert_eq!(count_stores(&m), 0, "the push store should be consumed");
        let assigns: Vec<_> = m
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter_map(|s| match s {
                MlilStmt::Assign { dest, src } if dest.name == "rbp" => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(assigns, vec![MlilExpr::Const(3)], "expected ebp = 3");
    }

    #[test]
    fn reconstructs_cdecl_call_arguments() {
        // cdecl pushes right-to-left: `push 2; push 1; call f` → f(1, 2).
        let m = lowered(&[
            make_insn(0x1000, "push", "2"),
            make_insn(0x1002, "push", "1"),
            make_insn(0x1004, "call", "0x2000"),
        ]);
        assert_eq!(count_stores(&m), 0, "argument pushes should be consumed");
        assert_eq!(
            first_call_args(&m),
            vec![MlilExpr::Const(1), MlilExpr::Const(2)]
        );
    }

    #[test]
    fn drops_caller_side_argument_cleanup() {
        // `add esp, 4` after a call pops the pushed argument — pure bookkeeping.
        let m = lowered(&[
            make_insn(0x1000, "push", "1"),
            make_insn(0x1002, "call", "0x2000"),
            make_insn(0x1007, "add", "esp, 4"),
        ]);
        let has_esp_add = m.instructions.iter().flat_map(|i| &i.stmts).any(
            |s| matches!(s, MlilStmt::Assign { dest, .. } if is_stack_or_frame_pointer(&dest.name)),
        );
        assert!(!has_esp_add, "the add esp, 4 cleanup should be removed");
    }

    /// Version of the source variable of the `idx`-th `Assign` statement.
    fn src_var_version(f: &MlilFunction, idx: usize) -> u32 {
        let assigns: Vec<_> = f
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter_map(|s| match s {
                MlilStmt::Assign {
                    src: MlilExpr::Var(v),
                    ..
                } => Some(v.version),
                _ => None,
            })
            .collect();
        assigns[idx]
    }

    #[test]
    fn uses_name_their_reaching_definition() {
        // mov eax, 1 ; mov ebx, eax ; mov eax, 2 ; mov ecx, eax
        // The two reads of eax must resolve to versions 1 and 2 respectively.
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "eax, 1"),
                make_insn(0x1005, "mov", "ebx, eax"),
                make_insn(0x1007, "mov", "eax, 2"),
                make_insn(0x100c, "mov", "ecx, eax"),
            ],
        ));
        version_defs_and_uses(&mut m);
        assert_eq!(src_var_version(&m, 0), 1, "first `ebx = eax` reads eax#1");
        assert_eq!(src_var_version(&m, 1), 2, "later `ecx = eax` reads eax#2");
    }

    #[test]
    fn reaching_defs_reset_at_branch_targets() {
        // eax is reassigned (so it *would* be versioned), then a jump lands on a
        // block whose first instruction reads eax: the reaching map resets at the
        // join, so the use gets the unknown-definition sentinel rather than a
        // wrong guess (and rather than version 0, which would alias a
        // single-def register's version and let propagation rewrite it).
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "eax, 1"),
                make_insn(0x1005, "mov", "eax, 2"),
                make_insn(0x100a, "jmp", "0x1010"),
                make_insn(0x1010, "mov", "ebx, eax"),
            ],
        ));
        version_defs_and_uses(&mut m);
        assert_eq!(
            src_var_version(&m, 0),
            VER_UNKNOWN,
            "use at a branch target resets to the unknown sentinel"
        );
    }

    /// Both sides of a diamond assign the same register and a use follows the
    /// join: dead-store elimination must keep *both* definitions (the join use
    /// carries the unknown sentinel, which keeps every version of the name).
    #[test]
    fn dse_keeps_both_branch_definitions_feeding_a_join() {
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "test", "ecx, ecx"),
                make_insn(0x1002, "je", "0x1010"),
                make_insn(0x1004, "mov", "ebx, 1"),
                make_insn(0x1009, "jmp", "0x1015"),
                make_insn(0x1010, "mov", "ebx, 2"),
                make_insn(0x1015, "mov", "eax, ebx"),
            ],
        ));
        version_defs_and_uses(&mut m);
        eliminate_dead_stores_ssa(&mut m);
        let ebx_defs = m
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter(|s| matches!(s, MlilStmt::Assign { dest, .. } if dest.name == "rbx"))
            .count();
        assert_eq!(ebx_defs, 2, "both branch-side ebx defs must survive DSE");
    }

    /// A register is read first and reassigned later: propagation must not
    /// rewrite the earlier read with the later value (use-before-def shares
    /// no version with the definition).
    #[test]
    fn propagation_never_rewrites_a_use_before_its_def() {
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "eax, edi"), // reads incoming edi
                make_insn(0x1005, "mov", "edi, 5"),   // single def of edi
            ],
        ));
        version_defs_and_uses(&mut m);
        propagate_values(&mut m);
        match &m.instructions[0].stmts[0] {
            MlilStmt::Assign { src, .. } => assert!(
                matches!(src, MlilExpr::Var(v) if v.name == "rdi"),
                "eax must read the incoming edi (canonical rdi), not the later constant; got {:?}",
                src
            ),
            other => panic!("expected assign, got {:?}", other),
        }
    }

    /// An unlifted instruction has unknown reads: it must survive lowering as
    /// a barrier (not a Nop), and DSE must not delete definitions that may
    /// feed it (`div ecx` implicitly reads eax/edx and ecx).
    #[test]
    fn unimplemented_blocks_dead_store_elimination() {
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "ecx, 10"),
                make_insn(0x1005, "div", "ecx"),
            ],
        ));
        assert!(
            m.instructions
                .iter()
                .flat_map(|i| &i.stmts)
                .any(|s| matches!(s, MlilStmt::Unimplemented { text } if text.contains("div"))),
            "unlifted div must lower to an Unimplemented barrier"
        );
        version_defs_and_uses(&mut m);
        eliminate_dead_stores_ssa(&mut m);
        assert!(
            m.instructions
                .iter()
                .flat_map(|i| &i.stmts)
                .any(|s| matches!(s, MlilStmt::Assign { dest, .. } if dest.name == "rcx")),
            "the ecx def feeding the unlifted div must survive DSE"
        );
    }

    /// `mov ecx, 5; shl eax, cl` — the cl read is the same register as the
    /// ecx write (canonical rcx); DSE must not delete the shift amount.
    #[test]
    fn dse_keeps_def_read_through_a_subregister() {
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "ecx, 5"),
                make_insn(0x1005, "shl", "eax, cl"),
            ],
        ));
        version_defs_and_uses(&mut m);
        eliminate_dead_stores_ssa(&mut m);
        assert!(
            m.instructions
                .iter()
                .flat_map(|i| &i.stmts)
                .any(|s| matches!(
                    s,
                    MlilStmt::Assign { dest, src } if dest.name == "rcx"
                        && matches!(src, MlilExpr::Const(5))
                )),
            "the shift-amount def must survive DSE"
        );
    }

    #[test]
    fn single_def_registers_stay_unversioned() {
        // ecx is assigned once; its use keeps the bare name (version 0).
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "ecx, 7"),
                make_insn(0x1005, "mov", "ebx, ecx"),
            ],
        ));
        version_defs_and_uses(&mut m);
        // The `ecx = 7` def is version 0, and `ebx = ecx` reads ecx#0.
        assert_eq!(src_var_version(&m, 0), 0);
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
    fn bitwise_identity_folding() {
        let x = MlilExpr::Var(SsaVar {
            name: "eax".into(),
            version: 0,
        });
        // x | 0 → x
        let or0 = MlilExpr::BinOp {
            op: BinOp::Or,
            left: Box::new(x.clone()),
            right: Box::new(MlilExpr::Const(0)),
        };
        assert_eq!(fold_constants(&or0), x);
        // -(-x) → x
        let double_neg = MlilExpr::UnaryOp {
            op: UnaryOp::Neg,
            operand: Box::new(MlilExpr::UnaryOp {
                op: UnaryOp::Neg,
                operand: Box::new(x.clone()),
            }),
        };
        assert_eq!(fold_constants(&double_neg), x);
    }

    #[test]
    fn propagates_constant_through_copy() {
        // mov eax, 5 ; mov ebx, eax  →  ebx = 5
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "eax, 5"),
                make_insn(0x1005, "mov", "ebx, eax"),
            ],
        ));
        version_defs_and_uses(&mut m);
        propagate_values(&mut m);
        let ebx_src = m
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .find_map(|s| match s {
                MlilStmt::Assign { dest, src } if dest.name == "rbx" => Some(src.clone()),
                _ => None,
            })
            .expect("ebx assignment");
        assert_eq!(ebx_src, MlilExpr::Const(5));
    }

    #[test]
    fn version_aware_dse_drops_dead_versioned_def() {
        // mov ecx, 1 ; mov ecx, 2 ; mov ebx, ecx — ecx#1 is dead (ebx reads ecx#2).
        let mut m = lower_to_mlil(&lift_function(
            "test",
            0x1000,
            &[
                make_insn(0x1000, "mov", "ecx, 1"),
                make_insn(0x1005, "mov", "ecx, 2"),
                make_insn(0x100a, "mov", "ebx, ecx"),
            ],
        ));
        version_defs_and_uses(&mut m);
        eliminate_dead_stores_ssa(&mut m);
        let ecx_defs = m
            .instructions
            .iter()
            .flat_map(|i| &i.stmts)
            .filter(|s| matches!(s, MlilStmt::Assign { dest, .. } if dest.name == "rcx"))
            .count();
        assert_eq!(ecx_defs, 1, "the dead ecx#1 store should be removed");
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
