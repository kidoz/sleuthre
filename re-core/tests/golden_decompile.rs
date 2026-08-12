//! Golden-file regression tests over real decompiler output.
//!
//! Each case hand-assembles a small x86-64 function into a `MemoryMap`
//! segment, disassembles it with the real capstone-backed `Disassembler`,
//! runs the full `decompile()` pipeline, and compares the pseudocode
//! byte-for-byte against a committed golden file in `tests/golden/`.
//!
//! To update goldens after an intentional decompiler change:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test -p re-core --test golden_decompile
//! ```
//!
//! See `tests/golden/README.md` for the review policy on golden diffs.

use std::collections::HashMap;
use std::path::PathBuf;

use re_core::arch::Architecture;
use re_core::disasm::{Disassembler, Instruction};
use re_core::il::structuring::decompile;
use re_core::memory::{MemoryMap, MemorySegment, Permissions};
use re_core::types::TypeManager;

/// Load address for every case; matches a typical small-binary .text base.
const BASE: u64 = 0x40_1000;

/// Place `code` in a fresh `MemoryMap` at [`BASE`] and disassemble all of it.
///
/// Panics if capstone does not consume every byte — that means the
/// hand-written machine code drifted from the assembly documented next to it,
/// and the case must be fixed rather than silently truncated.
fn disassemble(code: &[u8]) -> (Vec<Instruction>, MemoryMap) {
    let mut mem = MemoryMap::default();
    mem.add_segment(MemorySegment {
        name: ".text".into(),
        start: BASE,
        size: code.len() as u64,
        data: code.to_vec(),
        permissions: Permissions::READ | Permissions::EXECUTE,
    })
    .expect("segment must be addable");
    let disasm = Disassembler::new(Architecture::X86_64).expect("x86-64 disassembler");
    let insns = disasm
        .disassemble_range(&mem, BASE, code.len())
        .expect("disassembly must succeed");
    let decoded: usize = insns.iter().map(|i| i.bytes.len()).sum();
    assert_eq!(
        decoded,
        code.len(),
        "capstone decoded {} of {} bytes; instruction stream: {}",
        decoded,
        code.len(),
        render_listing(&insns),
    );
    (insns, mem)
}

fn render_listing(insns: &[Instruction]) -> String {
    insns
        .iter()
        .map(|i| format!("{:#x}: {} {}", i.address, i.mnemonic, i.op_str))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Run the full decompilation pipeline over hand-assembled machine code.
fn decompile_case(name: &str, code: &[u8], symbols: &HashMap<u64, String>) -> String {
    let (insns, mem) = disassemble(code);
    decompile(
        name,
        &insns,
        Architecture::X86_64,
        symbols,
        None,
        &TypeManager::default(),
        &mem,
        &HashMap::new(),
    )
    .text
}

fn golden_path(case: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{case}.txt"))
}

/// Compare `actual` against the committed golden file, or rewrite the golden
/// when `UPDATE_GOLDEN` is set. Failure messages show the first differing
/// line with surrounding context so a regression is readable in CI logs.
fn check_golden(case: &str, actual: &str) {
    let path = golden_path(case);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap_or_else(|e| {
            panic!("failed to write golden file {}: {e}", path.display());
        });
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden file {} ({e}); run `UPDATE_GOLDEN=1 cargo test -p re-core \
             --test golden_decompile` to create it",
            path.display()
        );
    });
    if expected != actual {
        panic!(
            "decompiled output for `{case}` diverged from {}\n{}\n\
             If this change is intentional, regenerate with `UPDATE_GOLDEN=1 cargo test \
             -p re-core --test golden_decompile` and review the diff as a behavior change.",
            path.display(),
            first_difference(&expected, actual),
        );
    }
}

/// Render the first differing line between two texts with up to two lines of
/// context on each side, plus full texts for copy-paste comparison.
fn first_difference(expected: &str, actual: &str) -> String {
    let exp: Vec<&str> = expected.lines().collect();
    let act: Vec<&str> = actual.lines().collect();
    let diff_line = exp
        .iter()
        .zip(act.iter())
        .position(|(e, a)| e != a)
        .unwrap_or_else(|| exp.len().min(act.len()));
    let mut out = String::new();
    out.push_str(&format!("first difference at line {}:\n", diff_line + 1));
    let start = diff_line.saturating_sub(2);
    let end = (diff_line + 3).min(exp.len().max(act.len()));
    for i in start..end {
        let e = exp.get(i).copied();
        let a = act.get(i).copied();
        match (e, a) {
            (Some(e), Some(a)) if e == a => out.push_str(&format!("   {i:>4} | {e}\n")),
            _ => {
                if let Some(e) = e {
                    out.push_str(&format!("  -{i:>4} | {e}\n"));
                }
                if let Some(a) = a {
                    out.push_str(&format!("  +{i:>4} | {a}\n"));
                }
            }
        }
    }
    out.push_str(&format!(
        "--- expected ---\n{expected}\n--- actual ---\n{actual}\n"
    ));
    out
}

/// Case a: straight-line arithmetic on two register parameters + return.
///
/// ```text
/// 401000: mov eax, edi
/// 401002: add eax, esi
/// 401004: ret
/// ```
fn arith_return_code() -> Vec<u8> {
    vec![
        0x89, 0xf8, // mov eax, edi
        0x01, 0xf0, // add eax, esi
        0xc3, // ret
    ]
}

/// Case b: if/else picking a constant, driven by a relational comparison.
///
/// ```text
/// 401000: cmp edi, 5
/// 401003: jle 0x40100b
/// 401005: mov eax, 1
/// 40100a: ret
/// 40100b: mov eax, 2
/// 401010: ret
/// ```
fn branch_select_code() -> Vec<u8> {
    vec![
        0x83, 0xff, 0x05, // cmp edi, 5
        0x7e, 0x06, // jle 0x40100b
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xc3, // ret
        0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
        0xc3, // ret
    ]
}

/// Case c: a counted accumulation loop (back edge → loop structuring).
///
/// ```text
/// 401000: xor eax, eax
/// 401002: add eax, edi
/// 401004: sub edi, 1
/// 401007: cmp edi, 0
/// 40100a: jne 0x401002
/// 40100c: ret
/// ```
fn loop_sum_code() -> Vec<u8> {
    vec![
        0x31, 0xc0, // xor eax, eax
        0x01, 0xf8, // add eax, edi
        0x83, 0xef, 0x01, // sub edi, 1
        0x83, 0xff, 0x00, // cmp edi, 0
        0x75, 0xf6, // jne 0x401002
        0xc3, // ret
    ]
}

/// Case d: a call with register arguments (SysV: rdi, rsi), so argument
/// recovery has to bind the two constants to the callee's parameter list.
///
/// ```text
/// 401000: mov edi, 1
/// 401005: mov esi, 2
/// 40100a: call 0x401100   ; resolves to symbol `helper`
/// 40100f: ret
/// ```
fn call_args_code() -> Vec<u8> {
    vec![
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0xbe, 0x02, 0x00, 0x00, 0x00, // mov esi, 2
        0xe8, 0xf1, 0x00, 0x00, 0x00, // call 0x401100
        0xc3, // ret
    ]
}

/// Case e: two loads at distinct offsets off a non-stack register, which the
/// typeless struct-recovery pass must fold to `base->field_<offset>`.
///
/// ```text
/// 401000: mov eax, dword ptr [rdi + 8]
/// 401003: add eax, dword ptr [rdi + 0x10]
/// 401006: ret
/// ```
fn field_access_code() -> Vec<u8> {
    vec![
        0x8b, 0x47, 0x08, // mov eax, dword ptr [rdi + 8]
        0x03, 0x47, 0x10, // add eax, dword ptr [rdi + 0x10]
        0xc3, // ret
    ]
}

/// Case f: frame-pointer stack locals, so location-based local naming and
/// stack-slot lifting are covered too.
///
/// ```text
/// 401000: push rbp
/// 401001: mov rbp, rsp
/// 401004: mov dword ptr [rbp - 4], edi
/// 401007: mov dword ptr [rbp - 8], esi
/// 40100a: mov eax, dword ptr [rbp - 4]
/// 40100d: add eax, dword ptr [rbp - 8]
/// 401010: pop rbp
/// 401011: ret
/// ```
fn stack_locals_code() -> Vec<u8> {
    vec![
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x89, 0x7d, 0xfc, // mov dword ptr [rbp - 4], edi
        0x89, 0x75, 0xf8, // mov dword ptr [rbp - 8], esi
        0x8b, 0x45, 0xfc, // mov eax, dword ptr [rbp - 4]
        0x03, 0x45, 0xf8, // add eax, dword ptr [rbp - 8]
        0x5d, // pop rbp
        0xc3, // ret
    ]
}

fn no_symbols() -> HashMap<u64, String> {
    HashMap::new()
}

fn helper_symbols() -> HashMap<u64, String> {
    let mut symbols = HashMap::new();
    symbols.insert(0x40_1100, "helper".to_string());
    symbols
}

#[test]
fn golden_arith_return() {
    let text = decompile_case("arith_return", &arith_return_code(), &no_symbols());
    check_golden("arith_return", &text);
}

#[test]
fn golden_branch_select() {
    let text = decompile_case("branch_select", &branch_select_code(), &no_symbols());
    check_golden("branch_select", &text);
}

#[test]
fn golden_loop_sum() {
    let text = decompile_case("loop_sum", &loop_sum_code(), &no_symbols());
    check_golden("loop_sum", &text);
}

#[test]
fn golden_call_args() {
    let text = decompile_case("call_args", &call_args_code(), &helper_symbols());
    check_golden("call_args", &text);
}

#[test]
fn golden_field_access() {
    let text = decompile_case("field_access", &field_access_code(), &no_symbols());
    check_golden("field_access", &text);
}

#[test]
fn golden_stack_locals() {
    let text = decompile_case("stack_locals", &stack_locals_code(), &no_symbols());
    check_golden("stack_locals", &text);
}

/// Every golden case, as `(name, machine code, symbol table)`.
fn all_cases() -> Vec<(&'static str, Vec<u8>, HashMap<u64, String>)> {
    vec![
        ("arith_return", arith_return_code(), no_symbols()),
        ("branch_select", branch_select_code(), no_symbols()),
        ("loop_sum", loop_sum_code(), no_symbols()),
        ("call_args", call_args_code(), helper_symbols()),
        ("field_access", field_access_code(), no_symbols()),
        ("stack_locals", stack_locals_code(), no_symbols()),
    ]
}

/// Decompiling the same input repeatedly in one process must produce identical
/// bytes. Each `HashMap`/`HashSet` built during a run gets a different hash
/// seed, so repeats here exercise iteration-order sensitivity; cross-process
/// stability is what the committed goldens themselves check.
#[test]
fn decompile_is_deterministic_in_process() {
    for (name, code, symbols) in all_cases() {
        let first = decompile_case(name, &code, &symbols);
        for _ in 0..16 {
            let again = decompile_case(name, &code, &symbols);
            assert_eq!(
                first, again,
                "decompiling `{name}` repeatedly produced different text"
            );
        }
    }
}

/// The generated-C gate the roadmap asks for: real decompiler output (not a
/// synthetic HLIL tree) must survive a C compiler's syntax check.
///
/// Skips when no compiler is on PATH, unless `SLEUTHRE_REQUIRE_CC` is set (as
/// it is in CI), where a missing compiler is a hard failure so the gate cannot
/// silently go dark.
#[test]
fn golden_output_is_compilable_c() {
    let Some(cc) = find_c_compiler() else {
        assert!(
            std::env::var_os("SLEUTHRE_REQUIRE_CC").is_none(),
            "SLEUTHRE_REQUIRE_CC is set but no C compiler (cc/gcc/clang) is on PATH"
        );
        return;
    };

    // Prologue: a stub for the only callee any case references. The decompiler
    // knows just its symbol name, so it is declared without a prototype and
    // every recovered argument list is accepted.
    let mut source = String::from("long long helper();\n\n");
    for (name, code, symbols) in all_cases() {
        // `field_access` is excluded on purpose: synthetic
        // `base->field_<offset>` members stand in for an unrecovered struct
        // type, so that output is pseudocode rather than compilable C.
        if name == "field_access" {
            continue;
        }
        source.push_str(&decompile_case(name, &code, &symbols));
        source.push('\n');
    }

    let tmp = std::env::temp_dir().join(format!("sleuthre_golden_c_{}.c", std::process::id()));
    std::fs::write(&tmp, source.as_bytes()).expect("write temp C source");
    let output = std::process::Command::new(&cc)
        .args([
            "-std=c11",
            "-fsyntax-only",
            "-Werror=implicit-function-declaration",
        ])
        .arg(&tmp)
        .output()
        .expect("failed to spawn C compiler");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        output.status.success(),
        "decompiled C failed to compile:\n--- source ---\n{source}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Locate a C compiler for the generated-C gate, mirroring the lookup used by
/// the in-crate compiler tests.
fn find_c_compiler() -> Option<PathBuf> {
    for candidate in ["cc", "gcc", "clang"] {
        if let Ok(output) = std::process::Command::new("which").arg(candidate).output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}
