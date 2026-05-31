use crate::Result;
use crate::disasm::Disassembler;
use crate::memory::MemoryMap;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// Upper bound on jump-table cases we will follow, to cap pathological or
/// misidentified tables.
const MAX_JUMP_TABLE_CASES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<u64>, // addresses
}

/// Edge type in the control flow graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    /// True branch of a conditional (taken)
    ConditionalTrue,
    /// False branch / fallthrough of a conditional (not taken)
    ConditionalFalse,
    /// Unconditional jump
    Unconditional,
    /// Fallthrough after a call instruction
    CallFallthrough,
    /// Switch/jump table case edge
    Switch,
}

pub struct ControlFlowGraph {
    pub graph: DiGraph<BasicBlock, EdgeKind>,
    pub addr_to_node: HashMap<u64, NodeIndex>,
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            addr_to_node: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: BasicBlock) -> NodeIndex {
        let addr = block.start_address;
        if let Some(&node) = self.addr_to_node.get(&addr) {
            self.graph[node] = block;
            return node;
        }
        let node = self.graph.add_node(block);
        self.addr_to_node.insert(addr, node);
        node
    }

    pub fn build_for_function(
        &mut self,
        memory: &MemoryMap,
        disasm: &Disassembler,
        start_addr: u64,
    ) -> Result<()> {
        /// One decoded instruction: where the next one starts, its branch
        /// successors (target + edge kind), and whether it ends a basic block.
        struct InsnInfo {
            next: u64,
            succ: Vec<(u64, EdgeKind)>,
            terminates: bool,
        }

        // Cap to bound pathological/garbage decode walks.
        const MAX_INSNS: usize = 200_000;

        // --- Pass 1: recursive-descent decode; record instructions + leaders ---
        // A leader starts a basic block: the entry, and every branch target.
        // (Fall-through positions after a conditional/call are leaders too,
        // since they appear as successor targets below.)
        let mut insns: BTreeMap<u64, InsnInfo> = BTreeMap::new();
        let mut leaders: BTreeSet<u64> = BTreeSet::new();
        leaders.insert(start_addr);

        let mut queue = VecDeque::new();
        queue.push_back(start_addr);

        while let Some(addr) = queue.pop_front() {
            if insns.contains_key(&addr) || insns.len() >= MAX_INSNS {
                continue;
            }
            let Ok(insn) = disasm.disassemble_one(memory, addr) else {
                continue;
            };
            let next = insn.address + insn.bytes.len() as u64;
            let is_branch = insn
                .groups
                .iter()
                .any(|g| g == "jump" || g == "call" || g == "ret");

            let mut succ: Vec<(u64, EdgeKind)> = Vec::new();
            if is_branch {
                let mnemonic = insn.mnemonic.to_lowercase();
                if mnemonic == "ret" || mnemonic == "retn" {
                    // End of path — no successors.
                } else if mnemonic == "call" {
                    succ.push((next, EdgeKind::CallFallthrough));
                } else if mnemonic == "jmp" {
                    if let Some(target) = parse_target(&insn.op_str) {
                        succ.push((target, EdgeKind::Unconditional));
                    } else if let Some(base) = parse_jump_table_base(&insn.op_str) {
                        // Indirect jump through a compiler-emitted jump table
                        // (`jmp [reg*scale + base]`); a bare `[reg]` indirect
                        // jump has no statically recoverable target.
                        for case in detect_jump_table(memory, base, MAX_JUMP_TABLE_CASES) {
                            succ.push((case, EdgeKind::Switch));
                        }
                    }
                } else {
                    // Conditional: branch target (true) and fall-through (false).
                    if let Some(target) = parse_target(&insn.op_str) {
                        succ.push((target, EdgeKind::ConditionalTrue));
                    }
                    succ.push((next, EdgeKind::ConditionalFalse));
                }
            }

            for &(target, _) in &succ {
                leaders.insert(target);
                queue.push_back(target);
            }
            if !is_branch {
                // Straight-line: keep decoding the same block.
                queue.push_back(next);
            }

            insns.insert(
                addr,
                InsnInfo {
                    next,
                    succ,
                    terminates: is_branch,
                },
            );
        }

        // --- Pass 2: form blocks by walking from each leader until the next
        // address is itself a leader (a split point) or the instruction ends a
        // block. Record each block's outgoing edges as we go. ---
        let mut block_edges: Vec<(u64, Vec<(u64, EdgeKind)>)> = Vec::new();
        for &leader in &leaders {
            if !insns.contains_key(&leader) {
                continue; // a target with no decoded instruction (e.g. data)
            }
            let mut addr = leader;
            let mut instructions = Vec::new();
            let (end, edges) = loop {
                let info = &insns[&addr];
                instructions.push(addr);
                if info.terminates {
                    break (info.next, info.succ.clone());
                }
                // A non-terminating instruction whose successor begins another
                // block (a leader / split point) or runs off decoded code: end
                // here. If the successor forms a block, flow straight into it.
                if leaders.contains(&info.next) || !insns.contains_key(&info.next) {
                    let next = info.next;
                    let edges = if insns.contains_key(&next) {
                        vec![(next, EdgeKind::Unconditional)]
                    } else {
                        Vec::new()
                    };
                    break (next, edges);
                }
                addr = info.next;
            };
            self.add_block(BasicBlock {
                start_address: leader,
                end_address: end,
                instructions,
            });
            block_edges.push((leader, edges));
        }

        // --- Pass 3: add edges between formed blocks ---
        for (source_addr, edges) in &block_edges {
            if let Some(&source_node) = self.addr_to_node.get(source_addr) {
                for &(target_addr, edge_kind) in edges {
                    if let Some(&target_node) = self.addr_to_node.get(&target_addr)
                        && !self.graph.contains_edge(source_node, target_node)
                    {
                        self.graph.add_edge(source_node, target_node, edge_kind);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the edge kind between two nodes
    pub fn edge_kind(&self, from: NodeIndex, to: NodeIndex) -> Option<EdgeKind> {
        self.graph.find_edge(from, to).map(|e| self.graph[e])
    }

    /// Check if an edge is a back-edge (target layer <= source layer in BFS)
    pub fn is_back_edge(&self, from: NodeIndex, to: NodeIndex, entry: NodeIndex) -> bool {
        let mut depths: HashMap<NodeIndex, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        depths.insert(entry, 0);
        queue.push_back(entry);
        while let Some(node) = queue.pop_front() {
            let next_depth = depths[&node] + 1;
            for succ in self.graph.neighbors(node) {
                if let std::collections::hash_map::Entry::Vacant(e) = depths.entry(succ) {
                    e.insert(next_depth);
                    queue.push_back(succ);
                }
            }
        }
        let from_depth = depths.get(&from).copied().unwrap_or(0);
        let to_depth = depths.get(&to).copied().unwrap_or(0);
        to_depth <= from_depth
    }
}

/// Detect jump table entries at a given table base address.
/// Returns target addresses found in the table.
///
/// Reads consecutive 8-byte little-endian pointers from `table_addr`, accepting
/// only those that point into **executable** memory (a code target), and stops
/// at the first entry that does not — which also bounds the scan and rejects
/// tables that are actually data. Limitation: this assumes 8-byte absolute
/// pointers, so 32-bit and PC-relative/offset tables are not recovered here.
pub fn detect_jump_table(memory: &MemoryMap, table_addr: u64, max_entries: usize) -> Vec<u64> {
    let mut targets = Vec::new();
    for i in 0..max_entries {
        let addr = table_addr + (i as u64) * 8;
        if let Some(data) = memory.get_data(addr, 8) {
            let target = u64::from_le_bytes(data.try_into().unwrap_or([0u8; 8]));
            if memory.is_executable(target) {
                targets.push(target);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    targets
}

fn parse_target(op_str: &str) -> Option<u64> {
    let cleaned = op_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("loc_");
    u64::from_str_radix(cleaned, 16).ok()
}

/// Recover a jump-table base address from an indirect-jump operand such as
/// `qword ptr [rax*8 + 0x404060]`.
///
/// Only memory operands that use an index *scale* (`*2`/`*4`/`*8`) are treated
/// as tables: a bare `[reg]` indirect jump or a RIP-relative single pointer
/// (`[rip + disp]`, no scale) has no statically recoverable case list. Returns
/// the `0x`-prefixed displacement inside the brackets (the table base).
fn parse_jump_table_base(op_str: &str) -> Option<u64> {
    let start = op_str.find('[')?;
    let end = op_str[start..].find(']')? + start;
    let inner = &op_str[start + 1..end];
    // Must be a scaled, indexed access to look like a jump table.
    if !(inner.contains("*2") || inner.contains("*4") || inner.contains("*8")) {
        return None;
    }
    // The base is the `0x`-prefixed hex displacement within the brackets.
    let hex_start = inner.find("0x")? + 2;
    let hex: String = inner[hex_start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn linear_block_no_edges() {
        // 3 NOPs + RET = 1 block, 0 edges
        let code = vec![
            0x90, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut cfg = ControlFlowGraph::new();
        cfg.build_for_function(&map, &disasm, 0x1000).unwrap();

        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.graph.edge_count(), 0);
    }

    #[test]
    fn conditional_branch_has_edges() {
        // test eax, eax; jz +2; nop; ret; nop; ret
        let mut code = vec![
            0x85, 0xC0, // test eax, eax
            0x74, 0x02, // jz +2 (to offset 6)
            0x90, // nop (fallthrough)
            0xC3, // ret
            0x90, // nop (branch target)
            0xC3, // ret
        ];
        code.resize(32, 0x00);
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut cfg = ControlFlowGraph::new();
        cfg.build_for_function(&map, &disasm, 0x1000).unwrap();

        assert!(
            cfg.graph.node_count() >= 2,
            "expected at least 2 blocks, got {}",
            cfg.graph.node_count()
        );
        assert!(
            cfg.graph.edge_count() >= 1,
            "expected at least 1 edge, got {}",
            cfg.graph.edge_count()
        );
    }

    #[test]
    fn edge_kinds_correct() {
        // test eax, eax; jz +2; nop; ret; nop; ret
        let mut code = vec![
            0x85, 0xC0, // test eax, eax
            0x74, 0x02, // jz +2 (to offset 6 = 0x1006)
            0x90, // nop (fallthrough at 0x1004)
            0xC3, // ret
            0x90, // nop (branch target at 0x1006)
            0xC3, // ret
        ];
        code.resize(32, 0x00);
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut cfg = ControlFlowGraph::new();
        cfg.build_for_function(&map, &disasm, 0x1000).unwrap();

        // The first block (test + jz) should have two edges:
        // one ConditionalTrue (to 0x1006) and one ConditionalFalse (to 0x1004)
        if let Some(&first_node) = cfg.addr_to_node.get(&0x1000) {
            let edges: Vec<_> = cfg.graph.edges(first_node).map(|e| *e.weight()).collect();
            // Should have conditional edges
            let has_true = edges.contains(&EdgeKind::ConditionalTrue);
            let has_false = edges.contains(&EdgeKind::ConditionalFalse);
            assert!(
                has_true || has_false,
                "Expected conditional edges, got: {:?}",
                edges
            );
        }
    }

    #[test]
    fn test_jump_table_detection() {
        // Create a memory layout:
        //   0x2000..0x2100: code segment (targets live here)
        //   0x3000..0x3020: data segment containing jump table with 4 pointers
        let mut map = MemoryMap::default();

        // Code segment where jump targets reside
        let code = vec![0x90u8; 0x100]; // 256 bytes of NOPs
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x2000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        // Data segment with jump table: 4 entries pointing into code
        let mut table_data = Vec::new();
        for &addr in &[0x2000u64, 0x2010, 0x2020, 0x2030] {
            table_data.extend_from_slice(&addr.to_le_bytes());
        }
        // Add an invalid entry (points outside any segment) to terminate detection
        table_data.extend_from_slice(&0xDEADu64.to_le_bytes());

        map.add_segment(MemorySegment {
            name: "data".to_string(),
            start: 0x3000,
            size: table_data.len() as u64,
            data: table_data,
            permissions: Permissions::READ,
        })
        .unwrap();

        let targets = detect_jump_table(&map, 0x3000, 16);
        assert_eq!(
            targets.len(),
            4,
            "expected 4 jump table entries, got {}",
            targets.len()
        );
        assert_eq!(targets[0], 0x2000);
        assert_eq!(targets[1], 0x2010);
        assert_eq!(targets[2], 0x2020);
        assert_eq!(targets[3], 0x2030);
    }

    #[test]
    fn test_jump_table_empty() {
        // Table address outside any segment should return empty
        let map = MemoryMap::default();
        let targets = detect_jump_table(&map, 0x5000, 16);
        assert!(targets.is_empty());
    }

    #[test]
    fn jump_table_rejects_non_executable_targets() {
        let mut map = MemoryMap::default();
        // Executable code (valid jump target).
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x2000,
            size: 0x100,
            data: vec![0x90u8; 0x100],
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
        // Read-only data (must NOT be accepted as a code target).
        map.add_segment(MemorySegment {
            name: "rodata".to_string(),
            start: 0x3000,
            size: 0x100,
            data: vec![0u8; 0x100],
            permissions: Permissions::READ,
        })
        .unwrap();
        // Table: [0x2000 (code, ok), 0x3000 (data, reject and stop)].
        let mut table = Vec::new();
        table.extend_from_slice(&0x2000u64.to_le_bytes());
        table.extend_from_slice(&0x3000u64.to_le_bytes());
        map.add_segment(MemorySegment {
            name: "tbl".to_string(),
            start: 0x4000,
            size: table.len() as u64,
            data: table,
            permissions: Permissions::READ,
        })
        .unwrap();

        assert_eq!(detect_jump_table(&map, 0x4000, 16), vec![0x2000]);
    }

    #[test]
    fn parse_jump_table_base_requires_scale() {
        assert_eq!(
            parse_jump_table_base("qword ptr [rax*8 + 0x404060]"),
            Some(0x404060)
        );
        assert_eq!(parse_jump_table_base("[rdi*4 + 0x3000]"), Some(0x3000));
        // RIP-relative single pointer (no scale) is not a jump table.
        assert_eq!(parse_jump_table_base("qword ptr [rip + 0x2000]"), None);
        // Bare register-indirect jumps are unresolvable.
        assert_eq!(parse_jump_table_base("rax"), None);
        assert_eq!(parse_jump_table_base("qword ptr [rcx]"), None);
    }

    #[test]
    fn switch_jump_table_creates_switch_edges() {
        // `jmp qword ptr [rax*8 + 0x3000]` dispatching through a 2-entry table.
        let mut code = vec![0x90u8; 0x40];
        code[0] = 0xFF; // jmp r/m64 (/4)
        code[1] = 0x24; // ModRM: [SIB]
        code[2] = 0xC5; // SIB: rax*8, disp32 base
        code[3..7].copy_from_slice(&0x3000u32.to_le_bytes());
        code[0x10] = 0xC3; // ret — case target 0x1010
        code[0x18] = 0xC3; // ret — case target 0x1018

        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        // Jump table at 0x3000: two valid entries then an unmapped terminator.
        let mut table = Vec::new();
        table.extend_from_slice(&0x1010u64.to_le_bytes());
        table.extend_from_slice(&0x1018u64.to_le_bytes());
        table.extend_from_slice(&0xDEADu64.to_le_bytes());
        map.add_segment(MemorySegment {
            name: "data".to_string(),
            start: 0x3000,
            size: table.len() as u64,
            data: table,
            permissions: Permissions::READ,
        })
        .unwrap();

        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut cfg = ControlFlowGraph::new();
        cfg.build_for_function(&map, &disasm, 0x1000).unwrap();

        let head = *cfg.addr_to_node.get(&0x1000).unwrap();
        let switch_edges = cfg
            .graph
            .edges(head)
            .map(|e| *e.weight())
            .filter(|&k| k == EdgeKind::Switch)
            .count();
        assert_eq!(switch_edges, 2, "expected 2 switch edges");
        assert!(cfg.addr_to_node.contains_key(&0x1010));
        assert!(cfg.addr_to_node.contains_key(&0x1018));
    }

    #[test]
    fn branch_into_mid_block_splits_it() {
        // nop; nop; jmp 0x1001 — the jump targets the middle of the straight-line
        // run, which must split the block there rather than create an overlap.
        let mut code = vec![0x90u8, 0x90, 0xEB, 0xFD]; // nop; nop; jmp -3 (→ 0x1001)
        code.resize(64, 0x00); // pad so disassemble_one's read window stays in range
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: "code".to_string(),
            start: 0x1000,
            size: code.len() as u64,
            data: code,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let mut cfg = ControlFlowGraph::new();
        cfg.build_for_function(&map, &disasm, 0x1000).unwrap();

        // The mid-run target became a leader (the block was split there)…
        assert!(
            cfg.addr_to_node.contains_key(&0x1001),
            "mid-block jump target was not made a block leader"
        );
        // …so the entry block holds only the first instruction, not the whole run.
        let head = cfg.addr_to_node[&0x1000];
        assert_eq!(cfg.graph[head].instructions, vec![0x1000]);
    }
}
