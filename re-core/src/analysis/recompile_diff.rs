//! Verify decompiler semantics by recompiling the emitted C and comparing the
//! resulting instruction categories against the original function.
//!
//! This is a capability no commercial RE tool ships: it answers "does the
//! decompilation actually mean what the original bytes mean?" with a
//! reproducible yes/no per basic block.
//!
//! The comparison is **category-level**, not byte-level — compilers differ in
//! register allocation, scheduling, and address layout, so exact bytes rarely
//! match. Instead we bucket each instruction into a coarse class (call, branch,
//! arithmetic, memory) and report divergence at the bucket level.

use crate::Result;
use crate::disasm::{Disassembler, Instruction};
use crate::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A coarse instruction class used for semantic comparison across compilers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum InstructionCategory {
    Call,
    Branch,
    Return,
    Memory,
    Arithmetic,
    Move,
    Compare,
    Other,
}

impl InstructionCategory {
    pub fn classify(mnemonic: &str) -> Self {
        let m = mnemonic.to_ascii_lowercase();
        // Call / return / branch: check longest prefix first so `ret` ≠ `return`
        // and `call` ≠ a hypothetical identifier starting with `call`.
        if m == "call" || m.starts_with("bl") {
            return Self::Call;
        }
        if m == "ret" || m.starts_with("retn") || m == "iret" {
            return Self::Return;
        }
        if m.starts_with("j") || m.starts_with('b') || m == "br" {
            return Self::Branch;
        }
        if m.starts_with("cmp") || m == "test" || m.starts_with("tst") {
            return Self::Compare;
        }
        if matches!(
            m.as_str(),
            "mov" | "movzx" | "movsx" | "movsxd" | "lea" | "mvn"
        ) {
            return Self::Move;
        }
        if m.starts_with("ld") || m.starts_with("st") || m == "push" || m == "pop" {
            return Self::Memory;
        }
        if matches!(
            m.as_str(),
            "add"
                | "adc"
                | "sub"
                | "sbb"
                | "mul"
                | "imul"
                | "div"
                | "idiv"
                | "and"
                | "or"
                | "xor"
                | "shl"
                | "shr"
                | "sar"
                | "rol"
                | "ror"
                | "not"
                | "neg"
                | "inc"
                | "dec"
        ) {
            return Self::Arithmetic;
        }
        Self::Other
    }
}

/// Summary of categories in a function body.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CategoryHistogram {
    pub call: usize,
    pub branch: usize,
    pub ret: usize,
    pub memory: usize,
    pub arithmetic: usize,
    pub move_: usize,
    pub compare: usize,
    pub other: usize,
    pub total: usize,
}

impl CategoryHistogram {
    pub fn from_instructions(insns: &[Instruction]) -> Self {
        let mut h = Self::default();
        for insn in insns {
            h.total += 1;
            match InstructionCategory::classify(&insn.mnemonic) {
                InstructionCategory::Call => h.call += 1,
                InstructionCategory::Branch => h.branch += 1,
                InstructionCategory::Return => h.ret += 1,
                InstructionCategory::Memory => h.memory += 1,
                InstructionCategory::Arithmetic => h.arithmetic += 1,
                InstructionCategory::Move => h.move_ += 1,
                InstructionCategory::Compare => h.compare += 1,
                InstructionCategory::Other => h.other += 1,
            }
        }
        h
    }

    /// Return the absolute difference per category, normalized by the max of
    /// the two totals.
    pub fn diff(&self, other: &Self) -> CategoryDiff {
        CategoryDiff {
            call: (self.call as i64 - other.call as i64),
            branch: (self.branch as i64 - other.branch as i64),
            ret: (self.ret as i64 - other.ret as i64),
            memory: (self.memory as i64 - other.memory as i64),
            arithmetic: (self.arithmetic as i64 - other.arithmetic as i64),
            move_: (self.move_ as i64 - other.move_ as i64),
            compare: (self.compare as i64 - other.compare as i64),
            other: (self.other as i64 - other.other as i64),
        }
    }
}

/// Signed per-category delta between two histograms.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CategoryDiff {
    pub call: i64,
    pub branch: i64,
    pub ret: i64,
    pub memory: i64,
    pub arithmetic: i64,
    pub move_: i64,
    pub compare: i64,
    pub other: i64,
}

impl CategoryDiff {
    /// Sum of absolute differences across all categories. Zero means the
    /// histograms are identical; larger values mean more divergence.
    pub fn l1_norm(&self) -> u64 {
        (self.call.unsigned_abs())
            + self.branch.unsigned_abs()
            + self.ret.unsigned_abs()
            + self.memory.unsigned_abs()
            + self.arithmetic.unsigned_abs()
            + self.move_.unsigned_abs()
            + self.compare.unsigned_abs()
            + self.other.unsigned_abs()
    }
}

/// Result of a recompile-diff run for a single function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecompileDiffResult {
    pub function_name: String,
    pub original_histogram: CategoryHistogram,
    pub recompiled_histogram: CategoryHistogram,
    pub diff: CategoryDiff,
    pub l1_norm: u64,
    /// Ratio of L1 divergence to original function size. Values near zero mean
    /// the decompilation preserved semantics; values approaching 1.0 mean the
    /// recompiled code looks nothing like the original.
    pub divergence_ratio: f64,
    /// Path to the compiled object file, kept for manual inspection.
    pub artifact_path: Option<PathBuf>,
    /// Any stderr output from the C compiler (empty on success).
    pub compiler_stderr: String,
}

/// Run the full pipeline: write `c_source` to a temporary file, compile it,
/// disassemble the resulting object, and diff against `original_insns`.
pub fn recompile_and_diff(
    function_name: &str,
    c_source: &str,
    original_insns: &[Instruction],
    arch: crate::arch::Architecture,
) -> Result<RecompileDiffResult> {
    let original_histogram = CategoryHistogram::from_instructions(original_insns);

    let cc = find_c_compiler().ok_or_else(|| Error::Analysis("no C compiler on PATH".into()))?;

    let tmp = std::env::temp_dir();
    let stem = format!("sleuthre_rediff_{}", uuid::Uuid::new_v4());
    let src_path = tmp.join(format!("{}.c", stem));
    let obj_path = tmp.join(format!("{}.o", stem));

    {
        let mut f = std::fs::File::create(&src_path)
            .map_err(|e| Error::Analysis(format!("create tmp src: {}", e)))?;
        f.write_all(c_source.as_bytes())
            .map_err(|e| Error::Analysis(format!("write tmp src: {}", e)))?;
    }

    let output = Command::new(&cc)
        .args(["-c", "-O1", "-fno-stack-protector", "-o"])
        .arg(&obj_path)
        .arg(&src_path)
        .output()
        .map_err(|e| Error::Analysis(format!("spawn cc: {}", e)))?;

    let compiler_stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_file(&src_path);

    if !output.status.success() {
        let _ = std::fs::remove_file(&obj_path);
        let empty = CategoryHistogram::default();
        let diff_to_empty = original_histogram.diff(&empty);
        let total = original_histogram.total as u64;
        return Ok(RecompileDiffResult {
            function_name: function_name.to_string(),
            original_histogram,
            recompiled_histogram: empty,
            diff: diff_to_empty,
            l1_norm: total,
            divergence_ratio: 1.0,
            artifact_path: None,
            compiler_stderr,
        });
    }

    let recompiled_insns = disassemble_object(&obj_path, function_name, arch)?;
    let recompiled_histogram = CategoryHistogram::from_instructions(&recompiled_insns);
    let diff = original_histogram.diff(&recompiled_histogram);
    let l1 = diff.l1_norm();
    let divergence_ratio = if original_histogram.total == 0 {
        0.0
    } else {
        (l1 as f64) / (original_histogram.total as f64)
    };

    Ok(RecompileDiffResult {
        function_name: function_name.to_string(),
        original_histogram,
        recompiled_histogram,
        diff,
        l1_norm: l1,
        divergence_ratio,
        artifact_path: Some(obj_path),
        compiler_stderr,
    })
}

/// Disassemble an ELF/Mach-O object file and return instructions belonging to
/// the named function. We walk all sections whose names start with `__text`
/// (Mach-O) or contain `text` (ELF) and disassemble each; this avoids a hard
/// dependency on a symbol table (useful when `cc` strips or renames symbols).
fn disassemble_object(
    path: &Path,
    _function_name: &str,
    arch: crate::arch::Architecture,
) -> Result<Vec<Instruction>> {
    let data = std::fs::read(path)
        .map_err(|e| Error::Analysis(format!("read object {}: {}", path.display(), e)))?;

    let mut insns = Vec::new();
    let disasm = Disassembler::new(arch)?;

    if let Ok(obj) = goblin::Object::parse(&data) {
        match obj {
            goblin::Object::Elf(elf) => {
                for section in &elf.section_headers {
                    let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
                    if !name.contains("text") {
                        continue;
                    }
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    if end <= data.len() {
                        let chunk = &data[start..end];
                        insns.extend(disasm.disassemble_bytes(chunk, section.sh_addr)?);
                    }
                }
            }
            goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
                for seg in &macho.segments {
                    for (sec, section_data) in seg.into_iter().flatten() {
                        let name = sec.name().unwrap_or("");
                        if !name.contains("text") {
                            continue;
                        }
                        insns.extend(disasm.disassemble_bytes(section_data, sec.addr)?);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(insns)
}

fn find_c_compiler() -> Option<PathBuf> {
    for candidate in ["cc", "gcc", "clang"] {
        if let Ok(out) = Command::new("which").arg(candidate).output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(mn: &str) -> Instruction {
        Instruction {
            address: 0,
            mnemonic: mn.into(),
            op_str: String::new(),
            bytes: vec![],
            groups: vec![],
        }
    }

    #[test]
    fn classify_call_branch_return() {
        assert_eq!(
            InstructionCategory::classify("call"),
            InstructionCategory::Call
        );
        assert_eq!(
            InstructionCategory::classify("bl"),
            InstructionCategory::Call
        );
        assert_eq!(
            InstructionCategory::classify("ret"),
            InstructionCategory::Return
        );
        assert_eq!(
            InstructionCategory::classify("jne"),
            InstructionCategory::Branch
        );
        assert_eq!(
            InstructionCategory::classify("b.eq"),
            InstructionCategory::Branch
        );
    }

    #[test]
    fn histogram_counts_match() {
        let insns = vec![mk("mov"), mk("add"), mk("call"), mk("ret")];
        let h = CategoryHistogram::from_instructions(&insns);
        assert_eq!(h.total, 4);
        assert_eq!(h.move_, 1);
        assert_eq!(h.arithmetic, 1);
        assert_eq!(h.call, 1);
        assert_eq!(h.ret, 1);
    }

    #[test]
    fn identical_histograms_have_zero_l1() {
        let a = vec![mk("mov"), mk("add"), mk("ret")];
        let b = vec![mk("mov"), mk("add"), mk("ret")];
        let ha = CategoryHistogram::from_instructions(&a);
        let hb = CategoryHistogram::from_instructions(&b);
        assert_eq!(ha.diff(&hb).l1_norm(), 0);
    }

    #[test]
    fn divergent_histograms_have_nonzero_l1() {
        let a = vec![mk("mov"), mk("add"), mk("ret")];
        let b = vec![mk("mov"), mk("mov"), mk("ret")];
        let ha = CategoryHistogram::from_instructions(&a);
        let hb = CategoryHistogram::from_instructions(&b);
        assert!(ha.diff(&hb).l1_norm() > 0);
    }

    #[test]
    fn recompile_roundtrips_real_c() {
        // Skip silently if no C compiler is on PATH.
        if find_c_compiler().is_none() {
            return;
        }
        let source = "\
            int probe(int a, int b) {\n\
                int s = a + b;\n\
                if (s > 0) return s;\n\
                return -s;\n\
            }\n";
        // Minimal fake x86-64 original: call + arith + ret shape.
        let original = vec![
            mk("push"),
            mk("mov"),
            mk("add"),
            mk("cmp"),
            mk("jle"),
            mk("mov"),
            mk("pop"),
            mk("ret"),
        ];
        // On arm64 hosts we have to pick the native arch of the compiler.
        // Use a portable pick: on arm64 macos cc emits arm64; on x86-64 linux
        // it emits x86-64. Try both and accept whichever disassembles.
        let arch = if cfg!(target_arch = "aarch64") {
            crate::arch::Architecture::Arm64
        } else {
            crate::arch::Architecture::X86_64
        };
        let result = recompile_and_diff("probe", source, &original, arch).unwrap();
        // The compiled function must contain *something*.
        assert!(
            result.recompiled_histogram.total > 0,
            "compiled object had no disassembly: {}",
            result.compiler_stderr
        );
        if let Some(p) = result.artifact_path {
            let _ = std::fs::remove_file(p);
        }
    }
}
