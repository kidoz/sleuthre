//! Microbenchmarks for the analysis hot paths.
//!
//! Run with `cargo bench -p re-core`. The fixtures are synthetic ELF/x86-64
//! byte sequences shaped like prologue/body patterns the disassembler and
//! signature engine would actually see, so the numbers track real-world
//! costs rather than empty-pipeline overhead.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use re_core::analysis::recompile_diff::{CategoryHistogram, InstructionCategory};
use re_core::arch::Architecture;
use re_core::disasm::{Disassembler, Instruction};
use re_core::memory::{MemoryMap, MemorySegment, Permissions};
use re_core::signatures::SignatureDatabase;

/// 64 KiB of repeated x86-64 function prologues with NOP padding so the
/// signature scanner has plenty of candidate match points.
fn synthetic_text() -> Vec<u8> {
    // `push rbp ; mov rbp, rsp ; sub rsp, 0x20 ; nop * N ; ret`
    let proto = [
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3,
    ];
    let mut data = Vec::with_capacity(64 * 1024);
    while data.len() < 64 * 1024 {
        data.extend_from_slice(&proto);
    }
    data
}

fn fixture_memory() -> MemoryMap {
    let mut mem = MemoryMap::default();
    mem.add_segment(MemorySegment {
        name: ".text".into(),
        start: 0x40_0000,
        size: 64 * 1024,
        data: synthetic_text(),
        permissions: Permissions::READ | Permissions::EXECUTE,
    })
    .unwrap();
    mem
}

fn bench_disassembly(c: &mut Criterion) {
    let mem = fixture_memory();
    let disasm = Disassembler::new(Architecture::X86_64).unwrap();
    c.bench_function("disasm_64k", |b| {
        b.iter(|| {
            let insns = disasm
                .disassemble_range(&mem, 0x40_0000, 64 * 1024)
                .unwrap();
            black_box(insns.len())
        })
    });
}

fn bench_signature_scan(c: &mut Criterion) {
    let mem = fixture_memory();
    let db = SignatureDatabase::builtin_x86_64();
    c.bench_function("signature_scan_64k", |b| {
        b.iter(|| {
            let matches = db.scan(&mem);
            black_box(matches.len())
        })
    });
}

fn bench_histogram(c: &mut Criterion) {
    // Build a representative instruction list to measure the recompile-diff
    // category bucketing without hitting Capstone every iteration.
    let names = [
        "mov", "add", "sub", "call", "ret", "jne", "test", "cmp", "lea", "push",
    ];
    let insns: Vec<Instruction> = (0..2048)
        .map(|i| Instruction {
            address: 0x401000 + i as u64,
            mnemonic: names[i % names.len()].to_string(),
            op_str: String::new(),
            bytes: vec![],
            groups: vec![],
        })
        .collect();
    c.bench_function("histogram_2k", |b| {
        b.iter(|| {
            let h = CategoryHistogram::from_instructions(&insns);
            black_box(h.total)
        })
    });

    c.bench_function("classify_1m", |b| {
        b.iter(|| {
            let mut hits = 0u64;
            for _ in 0..1_000_000 {
                if matches!(
                    InstructionCategory::classify("mov"),
                    InstructionCategory::Move
                ) {
                    hits += 1;
                }
            }
            black_box(hits)
        })
    });
}

criterion_group!(
    benches,
    bench_disassembly,
    bench_signature_scan,
    bench_histogram
);
criterion_main!(benches);
