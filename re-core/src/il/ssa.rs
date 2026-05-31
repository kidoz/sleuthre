//! Def-use index over an MLIL function.
//!
//! Records, per register, where it is defined (assignment destinations) and
//! where it is used (variable occurrences in expressions), plus a linear
//! reaching-definition query. This is the backbone for interprocedural type
//! inference: at a call site it lets us find the definition feeding an argument
//! register and the uses consuming the return register.
//!
//! The index is keyed by register **name**, not by `SsaVar` version. The
//! current MLIL SSA pass ([`crate::il::mlil::apply_ssa`]) versions definitions
//! but does not rename uses or insert phi nodes, so name-keyed lookups are the
//! reliable interface. [`DefUse::reaching_def`] consequently walks linearly and
//! ignores branch merges — callers must treat it as a single-path approximation
//! and bail when that is not sound.

use crate::il::mlil::{MlilExpr, MlilFunction, MlilStmt};
use std::collections::HashMap;

/// A position within an [`MlilFunction`]: which instruction, which statement,
/// and the source address of that instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    pub inst_index: usize,
    pub stmt_index: usize,
    pub address: u64,
}

impl Site {
    /// Total order along the linear instruction/statement sequence.
    fn order(&self) -> (usize, usize) {
        (self.inst_index, self.stmt_index)
    }
}

/// Def-use information for the register variables of an MLIL function.
#[derive(Debug, Default)]
pub struct DefUse {
    defs: HashMap<String, Vec<Site>>,
    uses: HashMap<String, Vec<Site>>,
}

impl DefUse {
    /// Build the index by walking every statement in program order.
    pub fn build(func: &MlilFunction) -> Self {
        let mut idx = DefUse::default();
        for (inst_index, inst) in func.instructions.iter().enumerate() {
            for (stmt_index, stmt) in inst.stmts.iter().enumerate() {
                let site = Site {
                    inst_index,
                    stmt_index,
                    address: inst.address,
                };
                match stmt {
                    MlilStmt::Assign { dest, src } => {
                        idx.defs.entry(dest.name.clone()).or_default().push(site);
                        idx.collect_uses(src, site);
                    }
                    MlilStmt::Store { addr, value, .. } => {
                        idx.collect_uses(addr, site);
                        idx.collect_uses(value, site);
                    }
                    MlilStmt::Jump { target } => idx.collect_uses(target, site),
                    MlilStmt::BranchIf { cond, target } => {
                        idx.collect_uses(cond, site);
                        idx.collect_uses(target, site);
                    }
                    MlilStmt::Call { target } => idx.collect_uses(target, site),
                    MlilStmt::Return | MlilStmt::Nop => {}
                }
            }
        }
        idx
    }

    fn collect_uses(&mut self, expr: &MlilExpr, site: Site) {
        match expr {
            MlilExpr::Var(v) => self.uses.entry(v.name.clone()).or_default().push(site),
            MlilExpr::Const(_) => {}
            MlilExpr::Load { addr, .. } => self.collect_uses(addr, site),
            MlilExpr::BinOp { left, right, .. } => {
                self.collect_uses(left, site);
                self.collect_uses(right, site);
            }
            MlilExpr::UnaryOp { operand, .. } => self.collect_uses(operand, site),
            MlilExpr::Phi(vars) => {
                for v in vars {
                    self.uses.entry(v.name.clone()).or_default().push(site);
                }
            }
            MlilExpr::Call { target, args } => {
                self.collect_uses(target, site);
                for a in args {
                    self.collect_uses(a, site);
                }
            }
            MlilExpr::VectorOp { operands, .. } => {
                for o in operands {
                    self.collect_uses(o, site);
                }
            }
        }
    }

    /// All definition sites of register `name`, in program order.
    pub fn defs_of(&self, name: &str) -> &[Site] {
        self.defs.get(name).map_or(&[], Vec::as_slice)
    }

    /// All use sites of register `name`, in program order.
    pub fn uses_of(&self, name: &str) -> &[Site] {
        self.uses.get(name).map_or(&[], Vec::as_slice)
    }

    /// The definition of `name` reaching position `before` along a linear walk
    /// (the latest def strictly before it). Ignores branch merges — a
    /// single-path approximation; do not rely on it where control flow joins.
    pub fn reaching_def(&self, name: &str, before: Site) -> Option<Site> {
        self.defs
            .get(name)?
            .iter()
            .copied()
            .filter(|d| d.order() < before.order())
            .max_by_key(|d| d.order())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::mlil::{MlilInst, SsaVar};

    fn var(name: &str, version: u32) -> SsaVar {
        SsaVar {
            name: name.to_string(),
            version,
        }
    }

    /// Build:
    ///   0x1000  rax = 5
    ///   0x1004  rbx = rax
    ///   0x1008  rax = 9
    fn sample() -> MlilFunction {
        MlilFunction {
            name: "t".to_string(),
            entry: 0x1000,
            instructions: vec![
                MlilInst {
                    address: 0x1000,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax", 1),
                        src: MlilExpr::Const(5),
                    }],
                },
                MlilInst {
                    address: 0x1004,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rbx", 1),
                        src: MlilExpr::Var(var("rax", 0)),
                    }],
                },
                MlilInst {
                    address: 0x1008,
                    stmts: vec![MlilStmt::Assign {
                        dest: var("rax", 2),
                        src: MlilExpr::Const(9),
                    }],
                },
            ],
        }
    }

    #[test]
    fn records_defs_and_uses_by_name() {
        let du = DefUse::build(&sample());
        assert_eq!(du.defs_of("rax").len(), 2);
        assert_eq!(du.defs_of("rbx").len(), 1);
        assert_eq!(du.uses_of("rax").len(), 1);
        assert_eq!(du.uses_of("rax")[0].address, 0x1004);
        // A register never mentioned has no defs or uses.
        assert!(du.defs_of("rcx").is_empty());
        assert!(du.uses_of("rcx").is_empty());
    }

    #[test]
    fn reaching_def_picks_latest_prior_definition() {
        let du = DefUse::build(&sample());
        // The use of rax at 0x1004 is reached by the rax def at 0x1000.
        let use_site = du.uses_of("rax")[0];
        let reaching = du.reaching_def("rax", use_site).unwrap();
        assert_eq!(reaching.address, 0x1000);

        // After the redefinition at 0x1008, the reaching def is that one.
        let after = Site {
            inst_index: 3,
            stmt_index: 0,
            address: 0x100c,
        };
        assert_eq!(du.reaching_def("rax", after).unwrap().address, 0x1008);

        // Nothing defines rax before the very first instruction.
        let start = Site {
            inst_index: 0,
            stmt_index: 0,
            address: 0x1000,
        };
        assert!(du.reaching_def("rax", start).is_none());
    }
}
