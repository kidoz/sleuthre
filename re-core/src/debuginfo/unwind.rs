//! DWARF-based stack unwinder.
//!
//! Walks `.eh_frame` (and `.debug_frame` as a fallback) using the existing
//! `gimli` dependency to recover return addresses without requiring frame
//! pointers. Works on optimized release builds where `frame_pointer_backtrace`
//! returns garbage past the first frame.
//!
//! The unwinder is intentionally architecture-aware but conservative: it
//! supports x86-64 / x86 / ARM64 / ARM (32-bit) — the same set the GDB-RSP
//! backend already speaks. Other architectures fall back to an empty result so
//! the caller can transparently degrade to the frame-pointer chain.

use gimli::{
    BaseAddresses, CfaRule, DebugFrame, EhFrame, EndianSlice, EvaluationResult, Expression,
    Location, RegisterRule, RunTimeEndian, UnwindContext, UnwindSection, UnwindTableRow, Value,
};
use object::{Object, ObjectSection};
use std::collections::HashMap;

/// Owned copy of the unwind sections for a binary, plus the resolved base
/// addresses gimli needs to interpret PC-relative pointer encodings.
///
/// `.eh_frame` is preferred (it's what runtime unwinders use, ships with
/// non-debug binaries on Linux/macOS). `.debug_frame` is a fallback for
/// embedded ELFs where only the debug variant is present.
pub struct StackUnwinder {
    eh_frame_data: Option<Vec<u8>>,
    debug_frame_data: Option<Vec<u8>>,
    bases: BaseAddresses,
    endian: RunTimeEndian,
}

impl StackUnwinder {
    /// Build an unwinder from raw binary bytes (ELF or Mach-O). Returns `None`
    /// when neither `.eh_frame` nor `.debug_frame` is present.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let obj = object::File::parse(bytes).ok()?;
        let endian = if obj.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let eh_frame_section = obj.section_by_name(".eh_frame");
        let debug_frame_section = obj.section_by_name(".debug_frame");
        if eh_frame_section.is_none() && debug_frame_section.is_none() {
            return None;
        }

        let mut bases = BaseAddresses::default();
        let eh_frame_data = eh_frame_section.and_then(|s| {
            bases = std::mem::take(&mut bases).set_eh_frame(s.address());
            s.data().ok().map(|d| d.to_vec())
        });
        let debug_frame_data = debug_frame_section.and_then(|s| s.data().ok().map(|d| d.to_vec()));
        if let Some(s) = obj.section_by_name(".text") {
            bases = bases.set_text(s.address());
        }
        if let Some(s) = obj.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(s.address());
        }

        Some(Self {
            eh_frame_data,
            debug_frame_data,
            bases,
            endian,
        })
    }

    /// Unwind the call stack starting from the supplied register snapshot.
    ///
    /// `read_memory` is invoked whenever the unwinder needs to fetch a saved
    /// register from memory. Returns the call chain — current PC first, then
    /// each caller's return address — capped at `max_depth`. Returns an empty
    /// vec if the very first PC has no FDE entry, which lets callers fall
    /// back to a frame-pointer walk.
    pub fn unwind<F>(
        &self,
        arch: crate::arch::Architecture,
        regs: &HashMap<String, u64>,
        max_depth: usize,
        mut read_memory: F,
    ) -> Vec<u64>
    where
        F: FnMut(u64, usize) -> Option<Vec<u8>>,
    {
        let layout = match RegisterLayout::for_arch(arch) {
            Some(l) => l,
            None => return Vec::new(),
        };
        let ptr_size = arch.pointer_size();

        let mut state: HashMap<u16, u64> = HashMap::new();
        for (name, dwarf_no) in layout.named_regs.iter() {
            if let Some(&v) = regs.get(*name) {
                state.insert(*dwarf_no, v);
            }
        }

        let pc_reg = layout.pc;

        let mut out = Vec::new();
        let Some(&start_pc) = state.get(&pc_reg) else {
            return out;
        };
        out.push(start_pc);

        // Try `.eh_frame` first; fall back to `.debug_frame` if it didn't
        // produce any extra frames (binary lacks .eh_frame for this PC).
        if let Some(ref eh_data) = self.eh_frame_data {
            let slice = EndianSlice::new(eh_data, self.endian);
            let section: EhFrame<_> = EhFrame::from(slice);
            let mut ctx: Box<UnwindContext<usize>> = Box::default();
            walk_unwind_loop(
                |pc, ctx| {
                    section
                        .unwind_info_for_address(&self.bases, ctx, pc, EhFrame::cie_from_offset)
                        .ok()
                        .cloned()
                },
                &mut ctx,
                &layout,
                &mut state,
                &mut out,
                max_depth,
                ptr_size,
                &mut read_memory,
            );
            if out.len() > 1 {
                return out;
            }
        }

        if let Some(ref dbg_data) = self.debug_frame_data {
            let slice = EndianSlice::new(dbg_data, self.endian);
            let section: DebugFrame<_> = DebugFrame::from(slice);
            let mut ctx: Box<UnwindContext<usize>> = Box::default();
            walk_unwind_loop(
                |pc, ctx| {
                    section
                        .unwind_info_for_address(&self.bases, ctx, pc, DebugFrame::cie_from_offset)
                        .ok()
                        .cloned()
                },
                &mut ctx,
                &layout,
                &mut state,
                &mut out,
                max_depth,
                ptr_size,
                &mut read_memory,
            );
        }

        out
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_unwind_loop<L, F>(
    mut lookup_row: L,
    ctx: &mut UnwindContext<usize>,
    layout: &RegisterLayout,
    state: &mut HashMap<u16, u64>,
    out: &mut Vec<u64>,
    max_depth: usize,
    ptr_size: usize,
    read_memory: &mut F,
) where
    L: FnMut(u64, &mut UnwindContext<usize>) -> Option<UnwindTableRow<usize>>,
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    let pc_reg = layout.pc;
    let cfa_seed_reg = layout.cfa_seed;
    let return_reg = layout.return_address;

    for _ in 0..max_depth {
        let Some(&pc) = state.get(&pc_reg) else {
            break;
        };
        let Some(row) = lookup_row(pc, ctx) else {
            break;
        };

        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                let Some(&base) = state.get(&register.0) else {
                    break;
                };
                (base as i64 + offset) as u64
            }
            // CfaRule::Expression references bytes via an UnwindExpression
            // handle that needs section-relative resolution; our evaluator
            // runs against concrete `Expression<R>` only. Rather than plumb
            // the section through, we bail and let the caller fall back to
            // the frame-pointer walker. This is a best-effort degradation:
            // most SysV CFI uses simple RegisterAndOffset rules.
            CfaRule::Expression(_) => break,
        };

        let ra_rule = row.register(gimli::Register(return_reg));
        let caller_ra = match resolve_register_rule(&ra_rule, cfa, state, ptr_size, read_memory) {
            Some(v) => v,
            None => break,
        };
        if caller_ra == 0 {
            break;
        }

        let mut next_state = state.clone();
        next_state.insert(pc_reg, caller_ra);
        let cfa_seed_rule = row.register(gimli::Register(cfa_seed_reg));
        let next_seed = match cfa_seed_rule {
            RegisterRule::Undefined => Some(cfa),
            _ => resolve_register_rule(&cfa_seed_rule, cfa, state, ptr_size, read_memory),
        };
        if let Some(seed) = next_seed {
            next_state.insert(cfa_seed_reg, seed);
        }
        for (_, dw_no) in layout.named_regs.iter() {
            if *dw_no == pc_reg || *dw_no == cfa_seed_reg {
                continue;
            }
            let rule = row.register(gimli::Register(*dw_no));
            if !matches!(rule, RegisterRule::Undefined)
                && let Some(v) = resolve_register_rule(&rule, cfa, state, ptr_size, read_memory)
            {
                next_state.insert(*dw_no, v);
            }
        }
        *state = next_state;
        out.push(caller_ra);
    }
}

/// Resolve a `RegisterRule` against the current CFA and register state.
/// `T` is the gimli offset type (the row's `Offset = R::Offset`); for our
/// `EndianSlice` reader it ends up as `usize`.
fn resolve_register_rule<T, F>(
    rule: &RegisterRule<T>,
    cfa: u64,
    state: &HashMap<u16, u64>,
    ptr_size: usize,
    read_memory: &mut F,
) -> Option<u64>
where
    T: gimli::ReaderOffset,
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    match rule {
        RegisterRule::Undefined | RegisterRule::SameValue => None,
        RegisterRule::Offset(off) => {
            let addr = cfa as i64 + off;
            let bytes = read_memory(addr as u64, ptr_size)?;
            Some(read_le_pointer(&bytes))
        }
        RegisterRule::ValOffset(off) => Some((cfa as i64 + off) as u64),
        RegisterRule::Register(other) => state.get(&other.0).copied(),
        // CFI expression rules reference the section via `UnwindExpression`
        // and need section-relative resolution before we can evaluate them.
        // For now fall through so the caller can walk the frame-pointer chain.
        _ => None,
    }
}

/// Run a DWARF expression to completion against the supplied register state
/// and memory reader. Returns the top of stack as a `u64`.
///
/// Handles the subset of operations exercised by typical `.eh_frame` /
/// `.debug_frame` CFI rules: register reads, constant pushes, `plus`/`minus`,
/// `deref`. Caller must already have a concrete `Expression<R>` — `.eh_frame`
/// unwind rules actually reference an `UnwindExpression` handle that needs
/// section-relative resolution first. This function is exposed primarily for
/// future `.debug_loc` / `.loclists` consumers (e.g. variable-location display).
pub fn eval_dwarf_expression<F>(
    expr: Expression<EndianSlice<RunTimeEndian>>,
    state: &HashMap<u16, u64>,
    initial_tos: u64,
    address_size: u8,
    read_memory: &mut F,
) -> Option<u64>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    eval_dwarf_expression_impl(expr, state, initial_tos, address_size, read_memory)
}

fn eval_dwarf_expression_impl<F>(
    expr: Expression<EndianSlice<RunTimeEndian>>,
    state: &HashMap<u16, u64>,
    initial_tos: u64,
    address_size: u8,
    read_memory: &mut F,
) -> Option<u64>
where
    F: FnMut(u64, usize) -> Option<Vec<u8>>,
{
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size,
    };
    let mut eval = expr.evaluation(encoding);
    // Many CFI expressions start by pushing the CFA — gimli models that as
    // `set_initial_value`.
    eval.set_initial_value(initial_tos);
    let mut result = eval.evaluate().ok()?;
    loop {
        match result {
            EvaluationResult::Complete => {
                let pieces = eval.result();
                let piece = pieces.first()?;
                return match piece.location {
                    Location::Address { address } => Some(address),
                    Location::Value { value } => match value {
                        Value::Generic(v) => Some(v),
                        Value::U8(v) => Some(v as u64),
                        Value::U16(v) => Some(v as u64),
                        Value::U32(v) => Some(v as u64),
                        Value::U64(v) => Some(v),
                        Value::I8(v) => Some(v as u64),
                        Value::I16(v) => Some(v as u64),
                        Value::I32(v) => Some(v as u64),
                        Value::I64(v) => Some(v as u64),
                        _ => None,
                    },
                    _ => None,
                };
            }
            EvaluationResult::RequiresRegister { register, .. } => {
                let v = *state.get(&register.0)?;
                result = eval.resume_with_register(Value::Generic(v)).ok()?;
            }
            EvaluationResult::RequiresMemory { address, size, .. } => {
                let bytes = read_memory(address, size as usize)?;
                let v = match size {
                    1 => bytes.first().copied().map(|b| b as u64),
                    2 => bytes
                        .get(..2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]) as u64),
                    4 => bytes
                        .get(..4)
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64),
                    8 => bytes.get(..8).map(|b| {
                        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                    }),
                    _ => None,
                }?;
                result = eval.resume_with_memory(Value::Generic(v)).ok()?;
            }
            EvaluationResult::RequiresFrameBase => {
                // CFI expressions shouldn't need a frame base — the CFA
                // itself is already seeded via set_initial_value.
                return None;
            }
            // Other resume kinds (relocation, CFA, TLS, etc.) aren't worth
            // pulling in extra state for; fall back to the FP walker.
            _ => return None,
        }
    }
}

fn read_le_pointer(bytes: &[u8]) -> u64 {
    match bytes.len() {
        4 => u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as u64,
        8 => u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

/// Maps named register strings (as the GDB-RSP backend reports them) to the
/// DWARF register numbers used by `.eh_frame`. Source for the numbers:
/// SysV ABI for x86-64, i386 ABI for x86, AArch64 ABI for ARM64, ARM 32 ABI.
struct RegisterLayout {
    pc: u16,
    /// Stack pointer (used both as a frame-base seed and the RSP-equivalent).
    cfa_seed: u16,
    /// DWARF register number that holds the return address per the ABI.
    return_address: u16,
    named_regs: &'static [(&'static str, u16)],
}

impl RegisterLayout {
    fn for_arch(arch: crate::arch::Architecture) -> Option<Self> {
        use crate::arch::Architecture::*;
        Some(match arch {
            X86_64 => Self {
                pc: 16,
                cfa_seed: 7,
                return_address: 16,
                named_regs: &[
                    ("rax", 0),
                    ("rdx", 1),
                    ("rcx", 2),
                    ("rbx", 3),
                    ("rsi", 4),
                    ("rdi", 5),
                    ("rbp", 6),
                    ("rsp", 7),
                    ("r8", 8),
                    ("r9", 9),
                    ("r10", 10),
                    ("r11", 11),
                    ("r12", 12),
                    ("r13", 13),
                    ("r14", 14),
                    ("r15", 15),
                    ("rip", 16),
                ],
            },
            X86 => Self {
                pc: 8,
                cfa_seed: 4,
                return_address: 8,
                named_regs: &[
                    ("eax", 0),
                    ("ecx", 1),
                    ("edx", 2),
                    ("ebx", 3),
                    ("esp", 4),
                    ("ebp", 5),
                    ("esi", 6),
                    ("edi", 7),
                    ("eip", 8),
                ],
            },
            Arm64 => Self {
                pc: 32,
                cfa_seed: 31,
                return_address: 30,
                named_regs: &[
                    ("x0", 0),
                    ("x1", 1),
                    ("x2", 2),
                    ("x3", 3),
                    ("x4", 4),
                    ("x5", 5),
                    ("x6", 6),
                    ("x7", 7),
                    ("x8", 8),
                    ("x9", 9),
                    ("x10", 10),
                    ("x11", 11),
                    ("x12", 12),
                    ("x13", 13),
                    ("x14", 14),
                    ("x15", 15),
                    ("x16", 16),
                    ("x17", 17),
                    ("x18", 18),
                    ("x19", 19),
                    ("x20", 20),
                    ("x21", 21),
                    ("x22", 22),
                    ("x23", 23),
                    ("x24", 24),
                    ("x25", 25),
                    ("x26", 26),
                    ("x27", 27),
                    ("x28", 28),
                    ("fp", 29),
                    ("lr", 30),
                    ("sp", 31),
                    ("pc", 32),
                ],
            },
            Arm => Self {
                pc: 15,
                cfa_seed: 13,
                return_address: 14,
                named_regs: &[
                    ("r0", 0),
                    ("r1", 1),
                    ("r2", 2),
                    ("r3", 3),
                    ("r4", 4),
                    ("r5", 5),
                    ("r6", 6),
                    ("r7", 7),
                    ("r8", 8),
                    ("r9", 9),
                    ("r10", 10),
                    ("r11", 11),
                    ("r12", 12),
                    ("sp", 13),
                    ("lr", 14),
                    ("pc", 15),
                ],
            },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_non_object_bytes() {
        assert!(StackUnwinder::from_bytes(b"not an elf").is_none());
    }

    #[test]
    fn read_le_pointer_handles_both_widths() {
        assert_eq!(read_le_pointer(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);
        assert_eq!(read_le_pointer(&[0x01, 0, 0, 0, 0, 0, 0, 0]), 1);
    }

    #[test]
    fn register_layout_returns_pc_for_supported_archs() {
        for arch in [
            crate::arch::Architecture::X86_64,
            crate::arch::Architecture::X86,
            crate::arch::Architecture::Arm64,
            crate::arch::Architecture::Arm,
        ] {
            let layout = RegisterLayout::for_arch(arch).expect("layout exists");
            assert!(layout.named_regs.iter().any(|(_, n)| *n == layout.pc));
        }
    }
}
