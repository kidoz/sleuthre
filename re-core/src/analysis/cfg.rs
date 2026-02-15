use crate::Result;
use crate::disasm::Disassembler;
use crate::memory::MemoryMap;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

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
        let mut queue = VecDeque::new();
        queue.push_back(start_addr);

        // Collect block_start -> (successor_address, edge_kind) for edge creation
        let mut block_successors: Vec<(u64, Vec<(u64, EdgeKind)>)> = Vec::new();

        while let Some(current_addr) = queue.pop_front() {
            if self.addr_to_node.contains_key(&current_addr) {
                continue;
            }

            let mut addr = current_addr;
            let mut instructions = Vec::new();
            let mut targets: Vec<(u64, EdgeKind)> = Vec::new();

            while let Ok(insn) = disasm.disassemble_one(memory, addr) {
                instructions.push(insn.address);
                let next_addr = insn.address + insn.bytes.len() as u64;

                let is_branch = insn
                    .groups
                    .iter()
                    .any(|g| g == "jump" || g == "call" || g == "ret");

                if is_branch {
                    let mnemonic = insn.mnemonic.to_lowercase();

                    if mnemonic == "ret" || mnemonic == "retn" {
                        // End of function path — no successors
                    } else if mnemonic == "call" {
                        // Call usually returns, so continue to next instruction
                        targets.push((next_addr, EdgeKind::CallFallthrough));
                    } else if mnemonic == "jmp" {
                        // Unconditional jump
                        if let Some(target) = parse_target(&insn.op_str) {
                            targets.push((target, EdgeKind::Unconditional));
                        }
                    } else {
                        // Conditional jump: branch target (true) and fallthrough (false)
                        if let Some(target) = parse_target(&insn.op_str) {
                            targets.push((target, EdgeKind::ConditionalTrue));
                        }
                        targets.push((next_addr, EdgeKind::ConditionalFalse));
                    }
                    addr = next_addr;
                    break;
                }

                addr = next_addr;
            }

            if instructions.is_empty() {
                continue;
            }

            let block = BasicBlock {
                start_address: current_addr,
                end_address: addr,
                instructions,
            };
            self.add_block(block);

            // Queue targets for discovery
            for &(target, _) in &targets {
                if !self.addr_to_node.contains_key(&target) {
                    queue.push_back(target);
                }
            }

            block_successors.push((current_addr, targets));
        }

        // Second pass: add edges between blocks
        for (source_addr, targets) in &block_successors {
            if let Some(&source_node) = self.addr_to_node.get(source_addr) {
                for &(target_addr, edge_kind) in targets {
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
/// Reads consecutive 8-byte little-endian pointers from `table_addr`.
/// Stops when a pointer does not resolve to a valid address in memory
/// or when `max_entries` is reached.
pub fn detect_jump_table(memory: &MemoryMap, table_addr: u64, max_entries: usize) -> Vec<u64> {
    let mut targets = Vec::new();
    for i in 0..max_entries {
        let addr = table_addr + (i as u64) * 8;
        if let Some(data) = memory.get_data(addr, 8) {
            let target = u64::from_le_bytes(data.try_into().unwrap_or([0u8; 8]));
            if memory.contains_address(target) {
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
}
