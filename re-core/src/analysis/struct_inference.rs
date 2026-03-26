use crate::Result;
use crate::analysis::functions::FunctionManager;
use crate::analysis::strings::StringsManager;
use crate::analysis::xrefs::XrefManager;
use crate::arch::Architecture;
use crate::disasm::Disassembler;
use crate::il::llil::{BinOp, LlilExpr, LlilStmt};
use crate::memory::MemoryMap;
use crate::plugin::{AnalysisFinding, AnalysisPass, FindingCategory};
use std::collections::HashMap;

pub struct StructInferencePass {
    pub arch: Architecture,
}

impl StructInferencePass {
    pub fn new(arch: Architecture) -> Self {
        Self { arch }
    }
}

impl AnalysisPass for StructInferencePass {
    fn name(&self) -> &str {
        "Struct Inference"
    }

    fn run_analysis(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
        _xrefs: &XrefManager,
        _strings: &StringsManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();
        let Ok(disasm) = Disassembler::new(self.arch) else {
            return Ok(findings);
        };

        for func in functions.functions.values() {
            let end_addr = func.end_address.unwrap_or(func.start_address + 0x100); // Only small sample to avoid freezing
            let size = (end_addr.saturating_sub(func.start_address)) as usize;

            let Ok(insns) = disasm.disassemble_range(memory, func.start_address, size.min(0x1000))
            else {
                continue;
            };

            let llil = match self.arch {
                Architecture::Arm64 => {
                    crate::il::lifter_arm64::lift_function(&func.name, func.start_address, &insns)
                }
                Architecture::Mips | Architecture::Mips64 => {
                    crate::il::lifter_mips::lift_function(&func.name, func.start_address, &insns)
                }
                Architecture::RiscV32 | Architecture::RiscV64 => {
                    crate::il::lifter_riscv::lift_function(&func.name, func.start_address, &insns)
                }
                _ => crate::il::lifter_x86::lift_function(&func.name, func.start_address, &insns),
            };

            // Analyze LLIL for memory accesses: [reg + offset]
            let mut reg_max_offsets: HashMap<String, u64> = HashMap::new();

            for inst in &llil.instructions {
                for stmt in &inst.stmts {
                    match stmt {
                        LlilStmt::Store { addr, .. } => {
                            if let LlilExpr::BinOp {
                                op: BinOp::Add,
                                left,
                                right,
                            } = &llil.exprs[*addr]
                            {
                                if let (LlilExpr::Reg(r), LlilExpr::Const(c)) =
                                    (&llil.exprs[*left], &llil.exprs[*right])
                                {
                                    let entry = reg_max_offsets.entry(r.clone()).or_insert(0);
                                    if *c > *entry {
                                        *entry = *c;
                                    }
                                } else if let (LlilExpr::Const(c), LlilExpr::Reg(r)) =
                                    (&llil.exprs[*left], &llil.exprs[*right])
                                {
                                    let entry = reg_max_offsets.entry(r.clone()).or_insert(0);
                                    if *c > *entry {
                                        *entry = *c;
                                    }
                                }
                            }
                        }
                        LlilStmt::SetReg { src, .. } => {
                            if let LlilExpr::Load { addr, .. } = &llil.exprs[*src]
                                && let LlilExpr::BinOp {
                                    op: BinOp::Add,
                                    left,
                                    right,
                                } = &llil.exprs[*addr]
                            {
                                if let (LlilExpr::Reg(r), LlilExpr::Const(c)) =
                                    (&llil.exprs[*left], &llil.exprs[*right])
                                {
                                    let entry = reg_max_offsets.entry(r.clone()).or_insert(0);
                                    if *c > *entry {
                                        *entry = *c;
                                    }
                                } else if let (LlilExpr::Const(c), LlilExpr::Reg(r)) =
                                    (&llil.exprs[*left], &llil.exprs[*right])
                                {
                                    let entry = reg_max_offsets.entry(r.clone()).or_insert(0);
                                    if *c > *entry {
                                        *entry = *c;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            for (reg, max_offset) in reg_max_offsets {
                // Heuristic: If offset is >= 8 and we are not using rsp/rbp/esp/ebp (which are just locals)
                if (8..0x10000).contains(&max_offset)
                    && !reg.ends_with("sp")
                    && !reg.ends_with("bp")
                {
                    findings.push(AnalysisFinding::new(
                        func.start_address,
                        FindingCategory::Info,
                        format!(
                            "Likely struct pointer in '{}': max offset 0x{:x}",
                            reg, max_offset
                        ),
                        0.7,
                    ));
                }
            }
        }

        Ok(findings)
    }
}
