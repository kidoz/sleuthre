//! Struct-pointer inference with recorded evidence.
//!
//! Walks each function's LLIL for `[reg + const]` memory accesses and gathers
//! per-offset evidence: every access site (address), its direction (read or
//! write), and its width. A register dereferenced at struct-like offsets
//! becomes a [`StructCandidate`] the analyst can review in the UI; accepting a
//! candidate materializes a concrete struct type whose `field_<offset>` names
//! line up with the decompiler's synthetic field rendering.

use crate::Result;
use crate::analysis::functions::FunctionManager;
use crate::analysis::strings::StringsManager;
use crate::analysis::xrefs::XrefManager;
use crate::arch::Architecture;
use crate::disasm::Disassembler;
use crate::il::llil::{BinOp, ExprId, LlilExpr, LlilFunction, LlilStmt};
use crate::memory::MemoryMap;
use crate::plugin::{AnalysisFinding, AnalysisPass, FindingCategory};
use crate::types::{CompoundType, PrimitiveType, StructField, TypeRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Offsets at or above this are treated as address-like constants, not fields.
const MAX_FIELD_OFFSET: u64 = 0x10000;

/// A register needs an access at or beyond this offset to become a candidate
/// (dereferences below it are just as likely plain pointer indirection).
const MIN_QUALIFYING_OFFSET: u64 = 8;

/// Whether a field access read or wrote memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    Read,
    Write,
}

/// One concrete `[base + offset]` access supporting a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSite {
    /// Address of the instruction performing the access.
    pub address: u64,
    pub kind: AccessKind,
    /// Access width in bytes.
    pub size: u8,
}

/// The evidence for one inferred field: every access observed at this offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEvidence {
    pub offset: u64,
    /// Widest access size seen at this offset (bytes).
    pub size: u8,
    pub accesses: Vec<AccessSite>,
}

/// Analyst review status of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EvidenceStatus {
    #[default]
    Proposed,
    Accepted,
    Rejected,
}

/// A register observed being dereferenced at struct-like offsets within one
/// function, with the full access evidence and a review status that survives
/// re-analysis and project save/load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructCandidate {
    /// Start address of the function the accesses occur in.
    pub function: u64,
    pub function_name: String,
    /// Base register holding the presumed struct pointer.
    pub base: String,
    /// Distinct accessed offsets, ascending.
    pub fields: Vec<FieldEvidence>,
    /// Heuristic confidence in `[0, 1]`; see [`candidate_confidence`].
    pub confidence: f32,
    #[serde(default)]
    pub status: EvidenceStatus,
    /// Name of the struct type materialized when the candidate was accepted.
    #[serde(default)]
    pub accepted_type: Option<String>,
}

impl StructCandidate {
    /// Deterministic default name for the type an acceptance materializes.
    pub fn suggested_type_name(&self) -> String {
        format!("struct_{:x}_{}", self.function, self.base)
    }

    /// Build a concrete struct type from the recorded evidence. Field names
    /// use the decompiler's `field_<offset>` scheme so accepted candidates
    /// render identically to the synthetic folding, but typed.
    pub fn materialize_type(&self, name: &str) -> CompoundType {
        let mut fields: Vec<StructField> = self
            .fields
            .iter()
            .map(|f| StructField {
                name: format!("field_{:x}", f.offset),
                type_ref: type_for_access_size(f.size),
                offset: f.offset as usize,
                bit_offset: None,
                bit_size: None,
            })
            .collect();
        fields.sort_by_key(|f| f.offset);
        let size = self
            .fields
            .iter()
            .map(|f| (f.offset + u64::from(f.size.max(1))) as usize)
            .max()
            .unwrap_or(0);
        CompoundType::Struct {
            name: name.to_string(),
            fields,
            size,
        }
    }
}

fn type_for_access_size(size: u8) -> TypeRef {
    match size {
        0 | 1 => TypeRef::Primitive(PrimitiveType::U8),
        2 => TypeRef::Primitive(PrimitiveType::U16),
        4 => TypeRef::Primitive(PrimitiveType::U32),
        8 => TypeRef::Primitive(PrimitiveType::U64),
        s => TypeRef::Array {
            element: Box::new(TypeRef::Primitive(PrimitiveType::U8)),
            count: s as usize,
        },
    }
}

/// Confidence heuristic: more distinct fields and more total accesses raise
/// it; observing both reads and writes raises it slightly. Deterministic and
/// clamped to `[0, 0.95]` — inference never claims certainty.
fn candidate_confidence(fields: &[FieldEvidence]) -> f32 {
    let distinct = fields.len().min(4) as f32;
    let total = fields
        .iter()
        .map(|f| f.accesses.len())
        .sum::<usize>()
        .min(8) as f32;
    let has_read = fields
        .iter()
        .any(|f| f.accesses.iter().any(|a| a.kind == AccessKind::Read));
    let has_write = fields
        .iter()
        .any(|f| f.accesses.iter().any(|a| a.kind == AccessKind::Write));
    let rw_bonus = if has_read && has_write { 0.05 } else { 0.0 };
    (0.35 + 0.12 * distinct + 0.03 * total + rw_bonus).clamp(0.0, 0.95)
}

/// If `addr` is `reg + const` (either operand order) with a field-sized
/// offset, return the base register and offset.
fn base_plus_offset(llil: &LlilFunction, addr: ExprId) -> Option<(&str, u64)> {
    let LlilExpr::BinOp {
        op: BinOp::Add,
        left,
        right,
    } = &llil.exprs[addr]
    else {
        return None;
    };
    let (reg, off) = match (&llil.exprs[*left], &llil.exprs[*right]) {
        (LlilExpr::Reg(r), LlilExpr::Const(c)) | (LlilExpr::Const(c), LlilExpr::Reg(r)) => (r, *c),
        _ => return None,
    };
    // Stack accesses are locals, not struct fields; huge offsets are
    // absolute-address arithmetic.
    if reg.ends_with("sp") || reg.ends_with("bp") || off >= MAX_FIELD_OFFSET {
        return None;
    }
    Some((reg.as_str(), off))
}

/// Record every `Load` reachable from `expr` as a read access.
fn collect_loads(
    llil: &LlilFunction,
    expr: ExprId,
    address: u64,
    out: &mut BTreeMap<String, BTreeMap<u64, FieldEvidence>>,
) {
    match &llil.exprs[expr] {
        LlilExpr::Load { addr, size } => {
            if let Some((reg, off)) = base_plus_offset(llil, *addr) {
                record_access(
                    out,
                    reg,
                    off,
                    AccessSite {
                        address,
                        kind: AccessKind::Read,
                        size: *size,
                    },
                );
            }
            collect_loads(llil, *addr, address, out);
        }
        LlilExpr::BinOp { left, right, .. } => {
            collect_loads(llil, *left, address, out);
            collect_loads(llil, *right, address, out);
        }
        LlilExpr::UnaryOp { operand, .. }
        | LlilExpr::Zx { operand, .. }
        | LlilExpr::Sx { operand, .. } => collect_loads(llil, *operand, address, out),
        _ => {}
    }
}

fn record_access(
    out: &mut BTreeMap<String, BTreeMap<u64, FieldEvidence>>,
    reg: &str,
    offset: u64,
    site: AccessSite,
) {
    let field = out
        .entry(reg.to_string())
        .or_default()
        .entry(offset)
        .or_insert_with(|| FieldEvidence {
            offset,
            size: 0,
            accesses: Vec::new(),
        });
    field.size = field.size.max(site.size);
    field.accesses.push(site);
}

/// Collect struct-pointer candidates from one lifted function.
fn candidates_for_llil(
    llil: &LlilFunction,
    function: u64,
    function_name: &str,
) -> Vec<StructCandidate> {
    let mut accesses: BTreeMap<String, BTreeMap<u64, FieldEvidence>> = BTreeMap::new();

    for inst in &llil.instructions {
        for stmt in &inst.stmts {
            match stmt {
                LlilStmt::Store { addr, value, size } => {
                    if let Some((reg, off)) = base_plus_offset(llil, *addr) {
                        record_access(
                            &mut accesses,
                            reg,
                            off,
                            AccessSite {
                                address: inst.address,
                                kind: AccessKind::Write,
                                size: *size,
                            },
                        );
                    }
                    collect_loads(llil, *addr, inst.address, &mut accesses);
                    collect_loads(llil, *value, inst.address, &mut accesses);
                }
                LlilStmt::SetReg { src, .. } => {
                    collect_loads(llil, *src, inst.address, &mut accesses);
                }
                LlilStmt::Jump { target } | LlilStmt::Call { target } => {
                    collect_loads(llil, *target, inst.address, &mut accesses);
                }
                LlilStmt::BranchIf { cond, target } => {
                    collect_loads(llil, *cond, inst.address, &mut accesses);
                    collect_loads(llil, *target, inst.address, &mut accesses);
                }
                LlilStmt::Return | LlilStmt::Nop | LlilStmt::Unimplemented { .. } => {}
            }
        }
    }

    let mut candidates = Vec::new();
    for (reg, fields) in accesses {
        let max_offset = fields.keys().next_back().copied().unwrap_or(0);
        if max_offset < MIN_QUALIFYING_OFFSET {
            continue;
        }
        let fields: Vec<FieldEvidence> = fields.into_values().collect();
        let confidence = candidate_confidence(&fields);
        candidates.push(StructCandidate {
            function,
            function_name: function_name.to_string(),
            base: reg,
            fields,
            confidence,
            status: EvidenceStatus::Proposed,
            accepted_type: None,
        });
    }
    candidates
}

/// Run struct-pointer inference over every function, returning the full
/// evidence. Deterministic: candidates are ordered by (function, base).
pub fn infer_struct_candidates(
    memory: &MemoryMap,
    functions: &FunctionManager,
    arch: Architecture,
) -> Vec<StructCandidate> {
    let mut candidates = Vec::new();
    let Ok(disasm) = Disassembler::new(arch) else {
        return candidates;
    };

    for func in functions.functions.values() {
        // Only a bounded window per function to avoid stalling on huge or
        // mis-bounded functions.
        let end_addr = func.end_address.unwrap_or(func.start_address + 0x100);
        let size = (end_addr.saturating_sub(func.start_address)) as usize;

        let Ok(insns) = disasm.disassemble_range(memory, func.start_address, size.min(0x1000))
        else {
            continue;
        };

        let llil = crate::il::lift_function(arch, &func.name, func.start_address, &insns);
        candidates.extend(candidates_for_llil(&llil, func.start_address, &func.name));
    }
    candidates
}

/// Carry analyst decisions (status + accepted type) from a previous run onto
/// freshly inferred candidates, matching by (function, base). Re-analysis must
/// not silently reset reviews.
pub fn merge_candidate_statuses(new: &mut [StructCandidate], old: &[StructCandidate]) {
    for cand in new.iter_mut() {
        if let Some(prev) = old
            .iter()
            .find(|o| o.function == cand.function && o.base == cand.base)
            && prev.status != EvidenceStatus::Proposed
        {
            cand.status = prev.status;
            cand.accepted_type.clone_from(&prev.accepted_type);
        }
    }
}

/// Derive the prose findings the pass has always reported, so existing finding
/// consumers keep working.
pub fn findings_from_candidates(candidates: &[StructCandidate]) -> Vec<AnalysisFinding> {
    candidates
        .iter()
        .map(|c| {
            let max_offset = c.fields.last().map(|f| f.offset).unwrap_or(0);
            AnalysisFinding::new(
                c.function,
                FindingCategory::Info,
                format!(
                    "Likely struct pointer in '{}': max offset 0x{:x}",
                    c.base, max_offset
                ),
                f64::from(c.confidence),
            )
        })
        .collect()
}

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
        let candidates = infer_struct_candidates(memory, functions, self.arch);
        Ok(findings_from_candidates(&candidates))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::llil::LlilInst;

    /// Build an LLIL function with `mov rax, [rdi+8]` at 0x1000 and
    /// `mov [rdi+0x10], rax` at 0x1004.
    fn sample_llil() -> LlilFunction {
        let mut f = LlilFunction::new("f".into(), 0x1000);
        // exprs: 0=rdi 1=8 2=rdi+8 3=load[2] 4=rdi 5=0x10 6=rdi+0x10 7=rax
        f.exprs = vec![
            LlilExpr::Reg("rdi".into()),
            LlilExpr::Const(8),
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 0,
                right: 1,
            },
            LlilExpr::Load { addr: 2, size: 8 },
            LlilExpr::Reg("rdi".into()),
            LlilExpr::Const(0x10),
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 4,
                right: 5,
            },
            LlilExpr::Reg("rax".into()),
        ];
        f.instructions = vec![
            LlilInst {
                address: 0x1000,
                stmts: vec![LlilStmt::SetReg {
                    dest: "rax".into(),
                    src: 3,
                }],
            },
            LlilInst {
                address: 0x1004,
                stmts: vec![LlilStmt::Store {
                    addr: 6,
                    value: 7,
                    size: 8,
                }],
            },
        ];
        f
    }

    #[test]
    fn records_read_and_write_access_sites() {
        let llil = sample_llil();
        let cands = candidates_for_llil(&llil, 0x1000, "f");
        assert_eq!(cands.len(), 1);
        let c = &cands[0];
        assert_eq!(c.base, "rdi");
        assert_eq!(c.function, 0x1000);
        assert_eq!(c.fields.len(), 2);
        assert_eq!(c.fields[0].offset, 8);
        assert_eq!(c.fields[0].accesses.len(), 1);
        assert_eq!(c.fields[0].accesses[0].address, 0x1000);
        assert_eq!(c.fields[0].accesses[0].kind, AccessKind::Read);
        assert_eq!(c.fields[0].accesses[0].size, 8);
        assert_eq!(c.fields[1].offset, 0x10);
        assert_eq!(c.fields[1].accesses[0].address, 0x1004);
        assert_eq!(c.fields[1].accesses[0].kind, AccessKind::Write);
        assert!(c.confidence > 0.0 && c.confidence <= 0.95);
        assert_eq!(c.status, EvidenceStatus::Proposed);
    }

    #[test]
    fn stack_registers_and_small_offsets_are_not_candidates() {
        let mut f = LlilFunction::new("f".into(), 0x2000);
        // [rbp+8] load and [rcx+4] load — rbp excluded, rcx max offset < 8.
        f.exprs = vec![
            LlilExpr::Reg("rbp".into()),
            LlilExpr::Const(8),
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 0,
                right: 1,
            },
            LlilExpr::Load { addr: 2, size: 8 },
            LlilExpr::Reg("rcx".into()),
            LlilExpr::Const(4),
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 4,
                right: 5,
            },
            LlilExpr::Load { addr: 6, size: 4 },
        ];
        f.instructions = vec![
            LlilInst {
                address: 0x2000,
                stmts: vec![LlilStmt::SetReg {
                    dest: "rax".into(),
                    src: 3,
                }],
            },
            LlilInst {
                address: 0x2004,
                stmts: vec![LlilStmt::SetReg {
                    dest: "rdx".into(),
                    src: 7,
                }],
            },
        ];
        assert!(candidates_for_llil(&f, 0x2000, "f").is_empty());
    }

    #[test]
    fn loads_inside_branch_conditions_are_recorded() {
        let mut f = LlilFunction::new("f".into(), 0x3000);
        // if ([rsi+0x20] == 0) goto 0x3010
        f.exprs = vec![
            LlilExpr::Reg("rsi".into()),
            LlilExpr::Const(0x20),
            LlilExpr::BinOp {
                op: BinOp::Add,
                left: 0,
                right: 1,
            },
            LlilExpr::Load { addr: 2, size: 4 },
            LlilExpr::Const(0),
            LlilExpr::BinOp {
                op: BinOp::CmpEq,
                left: 3,
                right: 4,
            },
            LlilExpr::Const(0x3010),
        ];
        f.instructions = vec![LlilInst {
            address: 0x3000,
            stmts: vec![LlilStmt::BranchIf { cond: 5, target: 6 }],
        }];
        let cands = candidates_for_llil(&f, 0x3000, "f");
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].base, "rsi");
        assert_eq!(cands[0].fields[0].offset, 0x20);
        assert_eq!(cands[0].fields[0].accesses[0].kind, AccessKind::Read);
    }

    #[test]
    fn merge_preserves_reviewed_statuses() {
        let llil = sample_llil();
        let mut new = candidates_for_llil(&llil, 0x1000, "f");
        let mut old = new.clone();
        old[0].status = EvidenceStatus::Accepted;
        old[0].accepted_type = Some("struct_1000_rdi".into());
        merge_candidate_statuses(&mut new, &old);
        assert_eq!(new[0].status, EvidenceStatus::Accepted);
        assert_eq!(new[0].accepted_type.as_deref(), Some("struct_1000_rdi"));
    }

    #[test]
    fn materialized_type_matches_evidence() {
        let llil = sample_llil();
        let cands = candidates_for_llil(&llil, 0x1000, "f");
        let ty = cands[0].materialize_type("struct_test");
        let CompoundType::Struct { name, fields, size } = ty else {
            panic!("expected struct");
        };
        assert_eq!(name, "struct_test");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "field_8");
        assert_eq!(fields[0].offset, 8);
        assert_eq!(fields[1].name, "field_10");
        assert_eq!(fields[1].offset, 0x10);
        assert_eq!(size, 0x18);
    }

    #[test]
    fn findings_match_legacy_message_format() {
        let llil = sample_llil();
        let cands = candidates_for_llil(&llil, 0x1000, "f");
        let findings = findings_from_candidates(&cands);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "Likely struct pointer in 'rdi': max offset 0x10"
        );
        assert_eq!(findings[0].address, 0x1000);
    }
}
