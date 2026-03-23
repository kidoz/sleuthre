//! Binary diffing — compare two analyzed binaries at the function level.
//!
//! Phase 1: function-level matching by name, then by byte-pattern hash.
//! Phase 2: instruction-level diff for matched functions.

use crate::analysis::functions::FunctionManager;
use crate::disasm::Instruction;
use crate::memory::MemoryMap;
use std::collections::BTreeMap;

/// A matched pair of functions across two binaries.
#[derive(Debug, Clone)]
pub struct FunctionMatch {
    pub name_a: String,
    pub name_b: String,
    pub addr_a: u64,
    pub addr_b: u64,
    pub match_type: MatchType,
    pub similarity: f64,
}

/// How two functions were matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    ExactName,
    ByteHash,
    Unmatched,
}

/// Result of a binary diff.
#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    pub matched: Vec<FunctionMatch>,
    pub only_in_a: Vec<(u64, String)>,
    pub only_in_b: Vec<(u64, String)>,
    pub identical_count: usize,
    pub modified_count: usize,
}

/// Instruction-level diff entry.
#[derive(Debug, Clone)]
pub enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
}

/// Compute a simple hash of a function's bytes (ignoring relocations).
fn function_byte_hash(memory: &MemoryMap, addr: u64, size: u64) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    if let Some(data) = memory.get_data(addr, size as usize) {
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
    }
    hash
}

/// Match functions between two binaries.
pub fn diff_functions(
    funcs_a: &FunctionManager,
    memory_a: &MemoryMap,
    funcs_b: &FunctionManager,
    memory_b: &MemoryMap,
) -> DiffResult {
    let mut result = DiffResult::default();
    let mut matched_b: std::collections::HashSet<u64> = std::collections::HashSet::new();

    // Build name index for B
    let name_to_b: BTreeMap<&str, u64> = funcs_b
        .functions
        .iter()
        .map(|(&addr, f)| (f.name.as_str(), addr))
        .collect();

    // Build hash index for B
    let mut hash_to_b: BTreeMap<u64, u64> = BTreeMap::new();
    for (&addr, f) in &funcs_b.functions {
        let size = f.end_address.unwrap_or(addr + 0x10).saturating_sub(addr);
        let hash = function_byte_hash(memory_b, addr, size);
        hash_to_b.insert(hash, addr);
    }

    // Phase 1: Match by exact name
    for (&addr_a, func_a) in &funcs_a.functions {
        if let Some(&addr_b) = name_to_b.get(func_a.name.as_str()) {
            if matched_b.contains(&addr_b) {
                continue;
            }
            let size_a = func_a
                .end_address
                .unwrap_or(addr_a + 0x10)
                .saturating_sub(addr_a);
            let size_b = funcs_b.functions[&addr_b]
                .end_address
                .unwrap_or(addr_b + 0x10)
                .saturating_sub(addr_b);

            let hash_a = function_byte_hash(memory_a, addr_a, size_a);
            let hash_b = function_byte_hash(memory_b, addr_b, size_b);
            let identical = hash_a == hash_b;

            if identical {
                result.identical_count += 1;
            } else {
                result.modified_count += 1;
            }

            result.matched.push(FunctionMatch {
                name_a: func_a.name.clone(),
                name_b: funcs_b.functions[&addr_b].name.clone(),
                addr_a,
                addr_b,
                match_type: MatchType::ExactName,
                similarity: if identical {
                    1.0
                } else {
                    compute_similarity(memory_a, addr_a, size_a, memory_b, addr_b, size_b)
                },
            });
            matched_b.insert(addr_b);
            continue;
        }
    }

    // Phase 2: Match remaining by byte hash
    let matched_a_addrs: std::collections::HashSet<u64> =
        result.matched.iter().map(|m| m.addr_a).collect();

    for (&addr_a, func_a) in &funcs_a.functions {
        if matched_a_addrs.contains(&addr_a) {
            continue;
        }
        let size_a = func_a
            .end_address
            .unwrap_or(addr_a + 0x10)
            .saturating_sub(addr_a);
        let hash_a = function_byte_hash(memory_a, addr_a, size_a);

        if let Some(&addr_b) = hash_to_b.get(&hash_a) {
            if matched_b.contains(&addr_b) {
                continue;
            }
            result.identical_count += 1;
            result.matched.push(FunctionMatch {
                name_a: func_a.name.clone(),
                name_b: funcs_b.functions[&addr_b].name.clone(),
                addr_a,
                addr_b,
                match_type: MatchType::ByteHash,
                similarity: 1.0,
            });
            matched_b.insert(addr_b);
        }
    }

    // Collect unmatched
    let final_matched_a: std::collections::HashSet<u64> =
        result.matched.iter().map(|m| m.addr_a).collect();
    for (&addr, func) in &funcs_a.functions {
        if !final_matched_a.contains(&addr) {
            result.only_in_a.push((addr, func.name.clone()));
        }
    }
    for (&addr, func) in &funcs_b.functions {
        if !matched_b.contains(&addr) {
            result.only_in_b.push((addr, func.name.clone()));
        }
    }

    result
}

/// Compute a rough similarity score (0.0–1.0) between two function bodies.
fn compute_similarity(
    mem_a: &MemoryMap,
    addr_a: u64,
    size_a: u64,
    mem_b: &MemoryMap,
    addr_b: u64,
    size_b: u64,
) -> f64 {
    let data_a = mem_a.get_data(addr_a, size_a as usize).unwrap_or(&[]);
    let data_b = mem_b.get_data(addr_b, size_b as usize).unwrap_or(&[]);

    if data_a.is_empty() && data_b.is_empty() {
        return 1.0;
    }

    let max_len = data_a.len().max(data_b.len());
    let min_len = data_a.len().min(data_b.len());
    let mut matching = 0;
    for i in 0..min_len {
        if data_a[i] == data_b[i] {
            matching += 1;
        }
    }

    matching as f64 / max_len as f64
}

/// Generate a simple instruction-level diff between two function disassemblies.
pub fn diff_instructions(insns_a: &[Instruction], insns_b: &[Instruction]) -> Vec<DiffLine> {
    let mut result = Vec::new();
    let lines_a: Vec<String> = insns_a
        .iter()
        .map(|i| format!("{} {}", i.mnemonic, i.op_str))
        .collect();
    let lines_b: Vec<String> = insns_b
        .iter()
        .map(|i| format!("{} {}", i.mnemonic, i.op_str))
        .collect();

    // Simple LCS-based diff
    let lcs = lcs_table(&lines_a, &lines_b);
    let mut i = lines_a.len();
    let mut j = lines_b.len();
    let mut stack = Vec::new();

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && lines_a[i - 1] == lines_b[j - 1] {
            stack.push(DiffLine::Same(lines_a[i - 1].clone()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || lcs[i][j - 1] >= lcs[i - 1][j]) {
            stack.push(DiffLine::Added(lines_b[j - 1].clone()));
            j -= 1;
        } else if i > 0 {
            stack.push(DiffLine::Removed(lines_a[i - 1].clone()));
            i -= 1;
        }
    }

    stack.reverse();
    result.extend(stack);
    result
}

fn lcs_table(a: &[String], b: &[String]) -> Vec<Vec<usize>> {
    let m = a.len();
    let n = b.len();
    let mut table = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                table[i][j] = table[i - 1][j - 1] + 1;
            } else {
                table[i][j] = table[i - 1][j].max(table[i][j - 1]);
            }
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::Function;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn diff_identical_binaries() {
        let mut memory = MemoryMap::default();
        memory
            .add_segment(MemorySegment {
                name: "text".into(),
                start: 0x1000,
                size: 16,
                data: vec![
                    0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0xC3, 0x55, 0x48, 0x89, 0xE5, 0x90,
                    0x90, 0x90, 0xC3,
                ],
                permissions: Permissions::READ | Permissions::EXECUTE,
            })
            .unwrap();

        let mut funcs = FunctionManager::default();
        funcs.add_function(Function {
            name: "func_a".into(),
            start_address: 0x1000,
            end_address: Some(0x1008),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });
        funcs.add_function(Function {
            name: "func_b".into(),
            start_address: 0x1008,
            end_address: Some(0x1010),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });

        let result = diff_functions(&funcs, &memory, &funcs, &memory);
        assert_eq!(result.matched.len(), 2);
        assert_eq!(result.identical_count, 2);
        assert_eq!(result.modified_count, 0);
        assert!(result.only_in_a.is_empty());
        assert!(result.only_in_b.is_empty());
    }

    #[test]
    fn diff_instructions_identical() {
        use crate::disasm::Instruction;
        let insns = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![],
                mnemonic: "push".into(),
                op_str: "rbp".into(),
                groups: vec![],
            },
            Instruction {
                address: 0x1001,
                bytes: vec![],
                mnemonic: "ret".into(),
                op_str: "".into(),
                groups: vec![],
            },
        ];
        let diff = diff_instructions(&insns, &insns);
        assert!(diff.iter().all(|d| matches!(d, DiffLine::Same(_))));
    }

    #[test]
    fn diff_instructions_different() {
        use crate::disasm::Instruction;
        let insns_a = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![],
                mnemonic: "push".into(),
                op_str: "rbp".into(),
                groups: vec![],
            },
            Instruction {
                address: 0x1001,
                bytes: vec![],
                mnemonic: "nop".into(),
                op_str: "".into(),
                groups: vec![],
            },
        ];
        let insns_b = vec![
            Instruction {
                address: 0x1000,
                bytes: vec![],
                mnemonic: "push".into(),
                op_str: "rbp".into(),
                groups: vec![],
            },
            Instruction {
                address: 0x1001,
                bytes: vec![],
                mnemonic: "ret".into(),
                op_str: "".into(),
                groups: vec![],
            },
        ];
        let diff = diff_instructions(&insns_a, &insns_b);
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Added(_) | DiffLine::Removed(_)))
        );
    }
}
