use crate::app::{GraphLayoutMode, SleuthreApp};
use crate::views::graph_utils::{GenericGraph, GraphEdge, GraphNode};
use eframe::egui;
use petgraph::visit::EdgeRef;
use re_core::analysis::cfg::EdgeKind;

impl SleuthreApp {
    pub(crate) fn show_graph(&mut self, ui: &mut egui::Ui) {
        let (project, disasm, cfg) = match (&self.project, &self.disasm, &self.current_cfg) {
            (Some(p), Some(d), Some(c)) if c.graph.node_count() > 0 => (p, d, c),
            _ => {
                ui.label("No CFG available. Select a function and press Space.");
                return;
            }
        };

        // Layout controls
        ui.horizontal(|ui| {
            ui.label("Layout:");
            ui.selectable_value(
                &mut self.graph_options.layout_mode,
                GraphLayoutMode::Hierarchical,
                "Hierarchical",
            );
            ui.selectable_value(
                &mut self.graph_options.layout_mode,
                GraphLayoutMode::Compact,
                "Compact",
            );
            ui.separator();
            ui.checkbox(&mut self.graph_options.show_edge_labels, "Edge labels");
            ui.checkbox(&mut self.graph_options.show_minimap, "Minimap");
        });
        ui.separator();

        let mut gg = GenericGraph::new();
        let mut node_map = std::collections::HashMap::new();

        for node_idx in cfg.graph.node_indices() {
            let block = &cfg.graph[node_idx];
            let mut lines = Vec::new();
            for &insn_addr in &block.instructions {
                if let Ok(insn) = disasm.disassemble_one(&project.memory_map, insn_addr) {
                    lines.push(format!(
                        "{:08X}  {:<8} {}",
                        insn.address, insn.mnemonic, insn.op_str
                    ));
                }
            }
            let gg_node = GraphNode {
                title: format!("Block 0x{:X}", block.start_address),
                lines,
                address: block.start_address,
                instruction_addresses: block.instructions.clone(),
            };
            let gg_idx = gg.graph.add_node(gg_node);
            node_map.insert(node_idx, gg_idx);
        }

        for edge in cfg.graph.edge_references() {
            let src = node_map[&edge.source()];
            let tgt = node_map[&edge.target()];
            let kind = *edge.weight();

            let (color, label) = match kind {
                EdgeKind::ConditionalTrue => (self.syntax.edge_true, Some("T".to_string())),
                EdgeKind::ConditionalFalse => (self.syntax.edge_false, Some("F".to_string())),
                EdgeKind::Unconditional => (self.syntax.edge_unconditional, None),
                EdgeKind::CallFallthrough => (self.syntax.edge_fallthrough, None),
                EdgeKind::Switch => (self.syntax.edge_unconditional, None),
            };

            let is_back_edge =
                cfg.graph[edge.target()].start_address <= cfg.graph[edge.source()].start_address;

            gg.graph.add_edge(
                src,
                tgt,
                GraphEdge {
                    color,
                    is_back_edge,
                    label,
                },
            );
        }

        gg.entry_node = cfg
            .addr_to_node
            .get(&self.current_address)
            .and_then(|idx| node_map.get(idx))
            .copied();

        if let Some(addr) = gg.show_with_options(
            ui,
            &mut self.graph_zoom,
            &self.syntax,
            self.current_address,
            &self.graph_options,
        ) {
            self.current_address = addr;
            self.focused_address = Some(addr);
        }
    }
}
