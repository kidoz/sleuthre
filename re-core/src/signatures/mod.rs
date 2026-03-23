//! Function signature matching (FLIRT-like).
//!
//! Matches byte patterns with wildcards against binary code to automatically
//! identify and name library functions.

use crate::analysis::functions::FunctionManager;
use crate::memory::MemoryMap;
use serde::{Deserialize, Serialize};

/// A single byte in a signature pattern: either a known byte or a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternByte {
    Exact(u8),
    Wildcard,
}

/// A function signature: a byte pattern with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Name to assign when matched.
    pub name: String,
    /// The byte pattern to match.
    pub pattern: Vec<PatternByte>,
    /// Optional library name (e.g. "libc", "msvcrt").
    pub library: String,
    /// Minimum match length before considering it a hit.
    pub min_match_length: usize,
}

/// A database of signatures that can be matched against memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureDatabase {
    pub signatures: Vec<Signature>,
}

/// A match result.
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub address: u64,
    pub signature_name: String,
    pub library: String,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load signatures from a JSON string.
    pub fn load_from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize signatures to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load signatures from a JSON file on disk.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, String> {
        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&data).map_err(|e| e.to_string())
    }

    /// Save signatures to a JSON file on disk.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    /// Merge another database into this one (deduplicates by name).
    pub fn merge(&mut self, other: &SignatureDatabase) {
        let existing: std::collections::HashSet<String> =
            self.signatures.iter().map(|s| s.name.clone()).collect();
        for sig in &other.signatures {
            if !existing.contains(&sig.name) {
                self.signatures.push(sig.clone());
            }
        }
    }

    /// Remove a signature by name.
    pub fn remove_by_name(&mut self, name: &str) {
        self.signatures.retain(|s| s.name != name);
    }

    /// Add a signature from a hex pattern string.
    /// Pattern format: "55 48 89 E5 ?? ?? 48"  where ?? is a wildcard.
    pub fn add_pattern(&mut self, name: &str, pattern_str: &str, library: &str) {
        let pattern = parse_pattern(pattern_str);
        let min_match_length = pattern.len();
        self.signatures.push(Signature {
            name: name.to_string(),
            pattern,
            library: library.to_string(),
            min_match_length,
        });
    }

    /// Scan memory for all signature matches.
    ///
    /// Uses a first-byte index to avoid testing every signature at every
    /// offset — only signatures whose first concrete byte matches `data[offset]`
    /// are tested.
    pub fn scan(&self, memory: &MemoryMap) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        // Build first-byte index: byte value -> list of signature indices.
        // Signatures starting with a wildcard go into a separate "any" bucket.
        let mut by_first_byte: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        let mut wildcard_start: Vec<usize> = Vec::new();
        for (i, sig) in self.signatures.iter().enumerate() {
            match sig.pattern.first() {
                Some(PatternByte::Exact(b)) => by_first_byte[*b as usize].push(i),
                _ => wildcard_start.push(i),
            }
        }

        for segment in &memory.segments {
            if !segment
                .permissions
                .contains(crate::memory::Permissions::EXECUTE)
            {
                continue;
            }

            let data = &segment.data;
            for offset in 0..data.len() {
                let byte = data[offset];
                // Test signatures whose first byte matches, plus wildcard-starts
                for &sig_idx in by_first_byte[byte as usize]
                    .iter()
                    .chain(wildcard_start.iter())
                {
                    let sig = &self.signatures[sig_idx];
                    if sig.pattern.len() > data.len() - offset {
                        continue;
                    }
                    if match_pattern(&data[offset..], &sig.pattern) {
                        matches.push(SignatureMatch {
                            address: segment.start + offset as u64,
                            signature_name: sig.name.clone(),
                            library: sig.library.clone(),
                        });
                    }
                }
            }
        }

        matches
    }

    /// Scan and apply: automatically rename matched functions.
    pub fn scan_and_apply(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
    ) -> Vec<SignatureMatch> {
        let matches = self.scan(memory);
        for m in &matches {
            if let Some(func) = functions.functions.get_mut(&m.address) {
                // Only rename auto-generated names (sub_XXXX)
                if func.name.starts_with("sub_") || func.name.starts_with("fcn_") {
                    func.name = m.signature_name.clone();
                }
            }
        }
        matches
    }

    /// Create a built-in database with common function prologues.
    pub fn builtin_x86_64() -> Self {
        let mut db = Self::new();

        // Standard function prologues
        db.add_pattern("push_rbp_prologue", "55 48 89 E5", "common");
        db.add_pattern("push_rbp_mov_rsp", "55 48 89 E5 48 83 EC", "common");
        db.add_pattern("sub_rsp_prologue", "48 83 EC", "common");
        db.add_pattern("push_rbx_prologue", "53 48 83 EC", "common");

        // libc functions
        db.add_pattern("strlen", "48 89 F8 80 38 00 74 ?? 48 FF C0", "libc");
        db.add_pattern(
            "memset",
            "48 89 D1 48 89 F8 88 30 48 FF C0 48 FF C9",
            "libc",
        );
        db.add_pattern("memcpy_sse", "48 89 F8 48 89 F1 48 89 D6", "libc");
        db.add_pattern("memcmp", "48 89 D1 31 C0 E3 ?? 0F B6 16 0F B6 1E", "libc");
        db.add_pattern("strcmp", "0F B6 07 0F B6 0E 38 C8 75", "libc");

        // malloc/free family
        db.add_pattern("malloc_wrapper", "48 89 F8 E8 ?? ?? ?? ?? 48 85 C0", "libc");
        db.add_pattern("free_wrapper", "48 85 FF 74 ?? E8", "libc");

        // Security-related
        db.add_pattern(
            "__stack_chk_fail",
            "48 8B 05 ?? ?? ?? ?? 64 48 33 04 25 28 00 00 00",
            "libc",
        );
        db.add_pattern(
            "stack_canary_check",
            "64 48 8B 04 25 28 00 00 00",
            "security",
        );
        db.add_pattern(
            "stack_canary_setup",
            "64 48 8B 04 25 28 00 00 00 48 89 45",
            "security",
        );

        // CRT startup
        db.add_pattern(
            "__libc_start_main_call",
            "48 89 C7 E8 ?? ?? ?? ?? F4",
            "crt",
        );
        db.add_pattern(
            "_start_glibc",
            "31 ED 49 89 D1 5E 48 89 E2 48 83 E4 F0",
            "crt",
        );

        // PLT stubs
        db.add_pattern("plt_stub", "FF 25 ?? ?? ?? ?? 68", "plt");
        db.add_pattern(
            "plt_lazy_bind",
            "FF 35 ?? ?? ?? ?? FF 25 ?? ?? ?? ??",
            "plt",
        );

        // Exception handling
        db.add_pattern(
            "personality_routine",
            "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC",
            "eh",
        );

        // Common compiler patterns
        db.add_pattern(
            "switch_jump",
            "48 63 C0 48 8D 15 ?? ?? ?? ?? 48 63 04 82 48 01 D0 FF E0",
            "compiler",
        );
        db.add_pattern("pic_thunk", "8B 04 24 C3", "compiler");
        db.add_pattern("rep_movsb", "F3 A4 C3", "compiler");
        db.add_pattern("rep_movsq", "F3 48 A5 C3", "compiler");
        db.add_pattern("rep_stosb", "F3 AA C3", "compiler");
        db.add_pattern("rep_stosq", "F3 48 AB C3", "compiler");

        // Crypto patterns
        db.add_pattern("aes_key_schedule", "66 0F 38 DB ?? 66 0F EF", "crypto");
        db.add_pattern("sha256_round", "0F 38 CC ?? 0F 38 CD", "crypto");

        // Intel CET (Control-flow Enforcement Technology)
        db.add_pattern("endbr64_prologue", "F3 0F 1E FA 55 48 89 E5", "common");

        // x86-32 prologues (for 32-bit code in 64-bit analysis)
        db.add_pattern("push_ebp_prologue", "55 89 E5", "common_x86");
        db.add_pattern("push_ebp_sub_esp", "55 89 E5 83 EC", "common_x86");

        db
    }

    /// Create a built-in database with common ARM64 patterns.
    pub fn builtin_arm64() -> Self {
        let mut db = Self::new();
        db.add_pattern("stp_prologue", "FD 7B ?? A9", "common");
        db.add_pattern("paciasp_prologue", "3F 23 03 D5 FD 7B ?? A9", "common");
        db
    }
}

/// Parse a hex pattern string like "55 48 89 E5 ?? ??" into PatternByte vec.
pub fn parse_pattern(pattern: &str) -> Vec<PatternByte> {
    pattern
        .split_whitespace()
        .filter_map(|tok| {
            if tok == "??" || tok == "?" {
                Some(PatternByte::Wildcard)
            } else {
                u8::from_str_radix(tok, 16).ok().map(PatternByte::Exact)
            }
        })
        .collect()
}

/// Check if data matches a pattern.
fn match_pattern(data: &[u8], pattern: &[PatternByte]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }
    for (i, pb) in pattern.iter().enumerate() {
        match pb {
            PatternByte::Exact(b) => {
                if data[i] != *b {
                    return false;
                }
            }
            PatternByte::Wildcard => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn parse_simple_pattern() {
        let pat = parse_pattern("55 48 89 E5");
        assert_eq!(pat.len(), 4);
        assert_eq!(pat[0], PatternByte::Exact(0x55));
        assert_eq!(pat[3], PatternByte::Exact(0xE5));
    }

    #[test]
    fn parse_pattern_with_wildcards() {
        let pat = parse_pattern("55 ?? 89 ??");
        assert_eq!(pat.len(), 4);
        assert_eq!(pat[0], PatternByte::Exact(0x55));
        assert_eq!(pat[1], PatternByte::Wildcard);
    }

    #[test]
    fn match_exact() {
        let data = [0x55, 0x48, 0x89, 0xE5, 0x00];
        let pat = parse_pattern("55 48 89 E5");
        assert!(match_pattern(&data, &pat));
    }

    #[test]
    fn match_with_wildcards() {
        let data = [0x55, 0xFF, 0x89, 0x00];
        let pat = parse_pattern("55 ?? 89 ??");
        assert!(match_pattern(&data, &pat));
    }

    #[test]
    fn no_match() {
        let data = [0x55, 0x48, 0x00, 0xE5];
        let pat = parse_pattern("55 48 89 E5");
        assert!(!match_pattern(&data, &pat));
    }

    #[test]
    fn scan_memory() {
        let mut memory = MemoryMap::default();
        memory
            .add_segment(MemorySegment {
                name: "code".into(),
                start: 0x1000,
                size: 16,
                data: vec![
                    0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x90,
                    0x90, 0x90, 0x90,
                ],
                permissions: Permissions::READ | Permissions::EXECUTE,
            })
            .unwrap();

        let mut db = SignatureDatabase::new();
        db.add_pattern("prologue", "55 48 89 E5", "common");
        let matches = db.scan(&memory);
        // Should find two matches at 0x1000 and 0x1008
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].address, 0x1000);
        assert_eq!(matches[1].address, 0x1008);
    }

    #[test]
    fn json_roundtrip() {
        let mut db = SignatureDatabase::new();
        db.add_pattern("test_func", "55 48 ?? E5", "test");
        let json = db.to_json().unwrap();
        let loaded = SignatureDatabase::load_from_json(&json).unwrap();
        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "test_func");
    }

    #[test]
    fn builtin_x86_64_has_at_least_30_signatures() {
        let db = SignatureDatabase::builtin_x86_64();
        assert!(
            db.signatures.len() >= 30,
            "Expected at least 30 signatures, got {}",
            db.signatures.len()
        );
    }

    #[test]
    fn builtin_arm64_has_signatures() {
        let db = SignatureDatabase::builtin_arm64();
        assert!(
            db.signatures.len() >= 2,
            "Expected at least 2 ARM64 signatures, got {}",
            db.signatures.len()
        );
    }

    #[test]
    fn builtin_x86_64_has_diverse_categories() {
        let db = SignatureDatabase::builtin_x86_64();
        let libraries: std::collections::HashSet<&str> =
            db.signatures.iter().map(|s| s.library.as_str()).collect();
        // Should have signatures across multiple categories
        assert!(libraries.contains("common"), "Missing 'common' library");
        assert!(libraries.contains("libc"), "Missing 'libc' library");
        assert!(libraries.contains("security"), "Missing 'security' library");
        assert!(libraries.contains("plt"), "Missing 'plt' library");
        assert!(libraries.contains("compiler"), "Missing 'compiler' library");
        assert!(libraries.contains("crypto"), "Missing 'crypto' library");
    }
}
