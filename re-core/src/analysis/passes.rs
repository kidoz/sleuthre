use crate::analysis::functions::FunctionManager;
use crate::memory::MemoryMap;
use crate::plugin::{AnalysisFinding, AnalysisPass, FindingCategory};
use crate::Result;

pub struct SuspiciousNamePass;

impl AnalysisPass for SuspiciousNamePass {
    fn name(&self) -> &str {
        "Suspicious Name Scanner"
    }

    fn run_analysis(
        &self,
        _memory: &MemoryMap,
        functions: &mut FunctionManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();
        let suspicious_terms = ["alloc", "system", "exec", "strcpy", "sprintf", "unsafe"];

        for func in functions.functions.values() {
            for term in suspicious_terms {
                if func.name.to_lowercase().contains(term) {
                    findings.push(AnalysisFinding::new(
                        func.start_address,
                        FindingCategory::Vulnerability,
                        format!("Function '{}' contains suspicious term '{}'", func.name, term),
                        0.5,
                    ));
                }
            }
        }
        Ok(findings)
    }
}
