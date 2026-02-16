use crate::Result;
use crate::analysis::functions::FunctionManager;
use crate::analysis::strings::StringsManager;
use crate::analysis::xrefs::XrefManager;
use crate::memory::MemoryMap;
use crate::plugin::{AnalysisFinding, AnalysisPass, FindingCategory};
use crate::signatures::SignatureDatabase;

pub struct SuspiciousNamePass;

impl AnalysisPass for SuspiciousNamePass {
    fn name(&self) -> &str {
        "Suspicious Name Scanner"
    }

    fn run_analysis(
        &self,
        _memory: &MemoryMap,
        functions: &mut FunctionManager,
        _xrefs: &XrefManager,
        _strings: &StringsManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();
        let suspicious_terms = ["alloc", "system", "exec", "strcpy", "sprintf", "unsafe"];

        for func in functions.functions.values() {
            for term in suspicious_terms {
                if func.name.to_lowercase().contains(term) {
                    findings.push(AnalysisFinding::new(
                        func.start_address,
                        FindingCategory::Vulnerability,
                        format!(
                            "Function '{}' contains suspicious term '{}'",
                            func.name, term
                        ),
                        0.5,
                    ));
                }
            }
        }
        Ok(findings)
    }
}

pub struct SignaturePass {
    db: SignatureDatabase,
}

impl SignaturePass {
    pub fn new(db: SignatureDatabase) -> Self {
        Self { db }
    }
}

impl AnalysisPass for SignaturePass {
    fn name(&self) -> &str {
        "Library Signature Matcher"
    }

    fn run_analysis(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
        _xrefs: &XrefManager,
        _strings: &StringsManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let matches = self.db.scan_and_apply(memory, functions);
        let findings = matches
            .into_iter()
            .map(|m| {
                AnalysisFinding::new(
                    m.address,
                    FindingCategory::Info,
                    format!("Identified as {} ({})", m.signature_name, m.library),
                    1.0,
                )
            })
            .collect();
        Ok(findings)
    }
}

pub struct HeuristicNamePass;

impl AnalysisPass for HeuristicNamePass {
    fn name(&self) -> &str {
        "Heuristic Name Recovery"
    }

    fn run_analysis(
        &self,
        _memory: &MemoryMap,
        functions: &mut FunctionManager,
        xrefs: &XrefManager,
        strings: &StringsManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();

        for s in &strings.strings {
            if let Some(refs) = xrefs.to_address_xrefs.get(&s.address) {
                for xref in refs {
                    if !matches!(
                        xref.xref_type,
                        crate::analysis::xrefs::XrefType::DataRead
                            | crate::analysis::xrefs::XrefType::StringRef
                    ) {
                        continue;
                    }
                    if let Some(func_addr) = functions.find_function_containing(xref.from_address)
                        && let Some(func) = functions.functions.get_mut(&func_addr)
                    {
                        if !func.name.starts_with("sub_") && !func.name.starts_with("fcn_") {
                            continue;
                        }

                        let mut new_name = None;
                        let val = s.value.to_lowercase();
                        if val.contains("assertion failed") {
                            new_name = Some(format!("assert_{:x}", func_addr));
                        } else if val.contains("panic") {
                            new_name = Some(format!("panic_{:x}", func_addr));
                        } else if val.contains("out of bounds") {
                            new_name = Some(format!("bounds_check_{:x}", func_addr));
                        } else if val.contains("not implemented") {
                            new_name = Some(format!("todo_{:x}", func_addr));
                        }

                        if let Some(name) = new_name {
                            func.name = name.clone();
                            findings.push(AnalysisFinding::new(
                                func_addr,
                                FindingCategory::Info,
                                format!("Renamed based on string: '{}'", s.value),
                                0.8,
                            ));
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
