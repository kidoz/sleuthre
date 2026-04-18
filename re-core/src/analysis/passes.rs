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

/// Detect common MSVC x86 prologue/code patterns: SEH frame setup, FPO
/// (frame-pointer omission), and inline memcpy/memset via `rep movs`/`rep stos`.
///
/// Operates on x86-32 code only. For other architectures it yields no findings.
pub struct MsvcPatternPass;

impl AnalysisPass for MsvcPatternPass {
    fn name(&self) -> &str {
        "MSVC Pattern Recognition"
    }

    fn run_analysis(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
        _xrefs: &XrefManager,
        _strings: &StringsManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();

        for func in functions.functions.values() {
            let addr = func.start_address;
            let Some(prologue) = memory.get_data(addr, 24) else {
                continue;
            };

            if let Some(kind) = detect_seh_frame(prologue) {
                findings.push(AnalysisFinding::new(
                    addr,
                    FindingCategory::Pattern,
                    format!("MSVC SEH frame setup ({})", kind),
                    0.85,
                ));
            }

            if detect_fpo_prologue(prologue) {
                findings.push(AnalysisFinding::new(
                    addr,
                    FindingCategory::Pattern,
                    "MSVC FPO (no frame pointer) prologue".to_string(),
                    0.6,
                ));
            }
        }

        // Scan function bodies for inline memcpy/memset.
        for func in functions.functions.values() {
            let addr = func.start_address;
            let end = func.end_address.unwrap_or(addr + 512);
            let size = (end.saturating_sub(addr)).min(4096) as usize;
            let Some(body) = memory.get_data(addr, size) else {
                continue;
            };
            for (i, window) in body.windows(2).enumerate() {
                match window {
                    // REP MOVSB / REP MOVSD — inline memcpy.
                    [0xF3, 0xA4] | [0xF3, 0xA5] => {
                        findings.push(AnalysisFinding::new(
                            addr + i as u64,
                            FindingCategory::Pattern,
                            "Inline memcpy (rep movs)".to_string(),
                            0.75,
                        ));
                    }
                    // REP STOSB / REP STOSD — inline memset.
                    [0xF3, 0xAA] | [0xF3, 0xAB] => {
                        findings.push(AnalysisFinding::new(
                            addr + i as u64,
                            FindingCategory::Pattern,
                            "Inline memset (rep stos)".to_string(),
                            0.75,
                        ));
                    }
                    _ => {}
                }
            }
        }

        Ok(findings)
    }
}

/// Classic MSVC SEH frame setup prologue (x86, Windows).
/// Returns a short classification if one of the well-known shapes is found.
fn detect_seh_frame(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 18 {
        return None;
    }
    // Shape A: push -1 (6A FF), push <handler> (68 xx xx xx xx),
    //          mov eax, fs:[0] (64 A1 00 00 00 00), push eax (50),
    //          mov fs:[0], esp (64 89 25 00 00 00 00)
    if bytes[0] == 0x6A
        && bytes[1] == 0xFF
        && bytes[2] == 0x68
        && bytes[7] == 0x64
        && bytes[8] == 0xA1
        && bytes[9..13] == [0x00, 0x00, 0x00, 0x00]
    {
        return Some("SEH __except_handler");
    }
    // Shape B: same but push -1 encoded as 68 FF FF FF FF.
    if bytes[0] == 0x68
        && bytes[1..5] == [0xFF, 0xFF, 0xFF, 0xFF]
        && bytes[5] == 0x68
        && bytes[10] == 0x64
        && bytes[11] == 0xA1
    {
        return Some("SEH __except_handler (long form)");
    }
    // Shape C: __SEH_prolog4 call (MSVC >= 2003): first instructions push some
    // scope table pointer then call __SEH_prolog4. Byte signature is loose,
    // so detect: push <imm32> / push <imm32> / call rel32.
    if bytes[0] == 0x68 && bytes[5] == 0x68 && bytes[10] == 0xE8 {
        return Some("SEH __SEH_prolog4-style");
    }
    None
}

/// Detect an FPO-style prologue: no `push ebp; mov ebp, esp`, function opens
/// directly with `sub esp, N` or `mov eax, <imm>` style.
fn detect_fpo_prologue(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }
    // Frame-pointer prologue to RULE OUT: 55 8B EC  (push ebp; mov ebp, esp).
    if bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC {
        return false;
    }
    // Positive signals: sub esp, imm8 (83 EC xx) or sub esp, imm32 (81 EC xx xx xx xx).
    if bytes[0] == 0x83 && bytes[1] == 0xEC {
        return true;
    }
    if bytes[0] == 0x81 && bytes[1] == 0xEC {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seh_shape_a_detected() {
        // 6A FF 68 AA BB CC DD 64 A1 00 00 00 00 50 64 89 25 00 00 00 00
        let bytes = [
            0x6A, 0xFF, 0x68, 0xAA, 0xBB, 0xCC, 0xDD, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50,
            0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(detect_seh_frame(&bytes), Some("SEH __except_handler"));
    }

    #[test]
    fn fpo_prologue_detected() {
        let fpo = [0x83, 0xEC, 0x10, 0x53, 0x56, 0x57];
        assert!(detect_fpo_prologue(&fpo));
        let fp = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        assert!(!detect_fpo_prologue(&fp));
    }
}
