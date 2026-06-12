//! Deterministic "fuzz-lite" smoke test for the untrusted-input parsers.
//!
//! The project's first rule is that malformed binary input must never panic.
//! This throws thousands of random and magic-seeded/mutated buffers at the
//! binary loader and the image/archive decoders and asserts none of them
//! panic (a panic aborts the test thread and fails the test). It is a
//! regression guard runnable under plain `cargo test`, not a replacement for
//! coverage-guided fuzzing (`cargo-fuzz`), which would be a good follow-up.

/// Tiny deterministic xorshift64 PRNG — fixed seed keeps the test reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
    /// A value in `0..n` (n must be > 0).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Feed one buffer through every untrusted-input entry point. The assertion is
/// implicit: if any of these panic, the test fails.
fn exercise(data: &[u8]) {
    let _ = re_core::loader::load_binary_from_bytes(data);

    // DWARF extraction runs on the raw bytes in the default analysis
    // pipeline, so it is just as reachable from a hostile binary as the
    // loader itself.
    let _ = re_core::debuginfo::extract_debug_info(data, re_core::arch::Architecture::X86_64);

    let images = re_core::formats::image::default_image_registry();
    for ext in ["x.bmp", "x.tga", "x.pcx"] {
        let _ = images.decode(data, ext);
    }

    let archives = re_core::formats::archive::default_registry();
    for ext in ["lod", "vid", "snd"] {
        let _ = archives.open(data, ext);
    }
}

#[test]
fn parsers_never_panic_on_random_or_mutated_input() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    // Real magic prefixes so mutation reaches deeper parser paths than pure
    // random noise usually would.
    let seeds: [&[u8]; 6] = [
        b"\x7fELF",                // ELF
        b"MZ",                     // PE/DOS
        &[0xCF, 0xFA, 0xED, 0xFE], // Mach-O 64-bit little-endian
        b"BM",                     // BMP
        &[0x0A, 0x05, 0x01, 0x08], // PCX (manufacturer/version/encoding/bpp)
        &[0x4C, 0x4F, 0x44, 0x00], // "LOD\0"
    ];

    for _ in 0..4000 {
        // (1) Pure random buffer of random length.
        let len = rng.below(512);
        let random: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        exercise(&random);

        // (2) A magic seed extended with random bytes and a few byte flips.
        let mut buf = seeds[rng.below(seeds.len())].to_vec();
        let extra = rng.below(256);
        buf.extend((0..extra).map(|_| rng.byte()));
        let flips = rng.below(8);
        for _ in 0..flips {
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] = rng.byte();
            }
        }
        exercise(&buf);
    }
}
