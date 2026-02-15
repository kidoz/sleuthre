use eframe::egui;
use petgraph::visit::EdgeRef;
use re_core::analysis::cfg::EdgeKind;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_graph(&mut self, ui: &mut egui::Ui) {
        match &self.current_cfg {
            Some(c) if c.graph.node_count() > 0 => {}
            _ => {
                ui.label("No CFG available. Select a function and press Space.");
                return;
            }
        }
        if self.disasm.is_none() {
            ui.label("No disassembler available.");
            return;
        }
        if self.project.is_none() {
            return;
        }

        // --- Zoom controls ---
        ui.horizontal(|ui| {
            if ui.button("-").clicked() {
                self.graph_zoom = (self.graph_zoom - 0.1).max(0.3);
            }
            ui.label(format!("{:.0}%", self.graph_zoom * 100.0));
            if ui.button("+").clicked() {
                self.graph_zoom = (self.graph_zoom + 0.1).min(3.0);
            }
            if ui.button("Reset").clicked() {
                self.graph_zoom = 1.0;
            }
        });
        ui.separator();

        // Re-borrow after the mutable zoom controls
        let cfg = self.current_cfg.as_ref().unwrap();
        let disasm = self.disasm.as_ref().unwrap();
        let project = self.project.as_ref().unwrap();
        let zoom = self.graph_zoom;

        // --- Prepare block content ---
        struct BlockInfo {
            node_idx: petgraph::graph::NodeIndex,
            lines: Vec<String>,
            width: f32,
            height: f32,
        }

        let mut blocks: Vec<BlockInfo> = Vec::new();
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
            let width = 420.0 * zoom;
            let height = (lines.len() as f32 * 16.0 * zoom) + 28.0 * zoom;
            blocks.push(BlockInfo {
                node_idx,
                lines,
                width,
                height,
            });
        }

        // --- Layered layout via BFS from entry node ---
        use std::collections::{HashMap, VecDeque};

        let entry_node = cfg
            .addr_to_node
            .get(&self.current_address)
            .copied()
            .or_else(|| {
                cfg.graph.node_indices().find(|&n| {
                    cfg.graph
                        .neighbors_directed(n, petgraph::Direction::Incoming)
                        .next()
                        .is_none()
                })
            })
            .unwrap_or_else(|| cfg.graph.node_indices().next().unwrap());

        let mut layer_of: HashMap<petgraph::graph::NodeIndex, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        layer_of.insert(entry_node, 0);
        queue.push_back(entry_node);
        while let Some(node) = queue.pop_front() {
            let next_layer = layer_of[&node] + 1;
            for succ in cfg.graph.neighbors(node) {
                if let std::collections::hash_map::Entry::Vacant(e) = layer_of.entry(succ) {
                    e.insert(next_layer);
                    queue.push_back(succ);
                }
            }
        }
        for node_idx in cfg.graph.node_indices() {
            layer_of.entry(node_idx).or_insert(0);
        }

        // Group nodes by layer
        let max_layer = layer_of.values().copied().max().unwrap_or(0);
        let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
        for (i, block) in blocks.iter().enumerate() {
            let layer = layer_of[&block.node_idx];
            layers[layer].push(i);
        }
        for layer in &mut layers {
            layer.sort_by_key(|&i| cfg.graph[blocks[i].node_idx].start_address);
        }

        // --- Compute positions ---
        let h_gap = 40.0 * zoom;
        let v_gap = 60.0 * zoom;
        let padding = 30.0 * zoom;

        let mut block_pos: HashMap<petgraph::graph::NodeIndex, egui::Pos2> = HashMap::new();
        let mut layer_widths: Vec<f32> = Vec::new();
        let mut layer_heights: Vec<f32> = Vec::new();
        for layer in &layers {
            let total_width: f32 = layer.iter().map(|&i| blocks[i].width).sum::<f32>()
                + h_gap * (layer.len().saturating_sub(1)) as f32;
            let max_height = layer
                .iter()
                .map(|&i| blocks[i].height)
                .fold(0.0f32, f32::max);
            layer_widths.push(total_width);
            layer_heights.push(max_height);
        }

        let canvas_width = layer_widths.iter().copied().fold(0.0f32, f32::max) + padding * 2.0;

        let mut y = padding;
        for (layer_idx, layer) in layers.iter().enumerate() {
            let total_w = layer_widths[layer_idx];
            let start_x = padding + (canvas_width - padding * 2.0 - total_w) / 2.0;
            let mut x = start_x;
            for &block_i in layer {
                block_pos.insert(blocks[block_i].node_idx, egui::pos2(x, y));
                x += blocks[block_i].width + h_gap;
            }
            y += layer_heights[layer_idx] + v_gap;
        }

        let canvas_height = y + padding;

        // --- Draw on a scrollable canvas ---
        egui::ScrollArea::both().show(ui, |ui| {
            let (canvas_rect, response) = ui.allocate_exact_size(
                egui::vec2(canvas_width, canvas_height),
                egui::Sense::hover(),
            );
            let origin = canvas_rect.min.to_vec2();
            let painter = ui.painter_at(canvas_rect);

            // Handle scroll-wheel zoom
            if response.hovered() {
                let scroll = ui.input(|i| i.smooth_scroll_delta.y);
                if ui.input(|i| i.modifiers.command) && scroll != 0.0 {
                    self.graph_zoom = (self.graph_zoom + scroll * 0.002).clamp(0.3, 3.0);
                }
            }

            let mut block_rects: HashMap<petgraph::graph::NodeIndex, egui::Rect> = HashMap::new();
            for block in &blocks {
                let pos = block_pos[&block.node_idx] + origin;
                let rect = egui::Rect::from_min_size(pos, egui::vec2(block.width, block.height));
                block_rects.insert(block.node_idx, rect);
            }

            // Determine hovered block for highlighting
            let mouse_pos = response.hover_pos();
            let hovered_node = mouse_pos.and_then(|mp| {
                block_rects
                    .iter()
                    .find(|(_, rect)| rect.contains(mp))
                    .map(|(node, _)| *node)
            });

            // Collect successor/predecessor nodes of hovered block
            let mut highlight_nodes: std::collections::HashSet<petgraph::graph::NodeIndex> =
                std::collections::HashSet::new();
            if let Some(hn) = hovered_node {
                highlight_nodes.insert(hn);
                for succ in cfg.graph.neighbors(hn) {
                    highlight_nodes.insert(succ);
                }
                for pred in cfg
                    .graph
                    .neighbors_directed(hn, petgraph::Direction::Incoming)
                {
                    highlight_nodes.insert(pred);
                }
            }

            // Draw edges behind blocks
            for block in &blocks {
                let src_idx = block.node_idx;
                let src_rect = block_rects[&src_idx];
                for edge in cfg.graph.edges(src_idx) {
                    let tgt_idx = edge.target();
                    let edge_kind = *edge.weight();
                    let tgt_rect = match block_rects.get(&tgt_idx) {
                        Some(r) => *r,
                        None => continue,
                    };

                    let is_back_edge = layer_of.get(&tgt_idx).copied().unwrap_or(0)
                        <= layer_of.get(&src_idx).copied().unwrap_or(0);

                    let edge_color = match edge_kind {
                        EdgeKind::ConditionalTrue => self.syntax.edge_true,
                        EdgeKind::ConditionalFalse => self.syntax.edge_false,
                        EdgeKind::Unconditional => self.syntax.edge_unconditional,
                        EdgeKind::CallFallthrough => self.syntax.edge_fallthrough,
                        EdgeKind::Switch => self.syntax.edge_unconditional,
                    };
                    let color = if is_back_edge {
                        self.syntax.edge_back
                    } else {
                        edge_color
                    };

                    // Dim edges not connected to hovered node
                    let alpha = if hovered_node.is_some()
                        && !highlight_nodes.contains(&src_idx)
                        && !highlight_nodes.contains(&tgt_idx)
                    {
                        40
                    } else {
                        color.a()
                    };
                    let color = egui::Color32::from_rgba_premultiplied(
                        color.r(),
                        color.g(),
                        color.b(),
                        alpha,
                    );

                    let stroke_width = 1.5 * zoom;

                    let (from, to) = if is_back_edge {
                        (
                            egui::pos2(src_rect.min.x, src_rect.center().y),
                            egui::pos2(tgt_rect.min.x, tgt_rect.center().y),
                        )
                    } else {
                        (
                            egui::pos2(src_rect.center().x, src_rect.max.y),
                            egui::pos2(tgt_rect.center().x, tgt_rect.min.y),
                        )
                    };

                    let mid_y = (from.y + to.y) / 2.0;
                    let ctrl1 = egui::pos2(from.x, mid_y);
                    let ctrl2 = egui::pos2(to.x, mid_y);
                    let bezier = egui::epaint::CubicBezierShape::from_points_stroke(
                        [from, ctrl1, ctrl2, to],
                        false,
                        egui::Color32::TRANSPARENT,
                        egui::Stroke::new(stroke_width, color),
                    );
                    painter.add(bezier);

                    // Arrowhead
                    let arrow_size = 6.0 * zoom;
                    let (tip, dir) = if is_back_edge {
                        (to, egui::vec2(arrow_size, 0.0))
                    } else {
                        (to, egui::vec2(0.0, -arrow_size))
                    };
                    painter.line_segment(
                        [
                            tip,
                            tip + egui::vec2(-arrow_size * 0.5, dir.y - dir.x * 0.5),
                        ],
                        egui::Stroke::new(stroke_width, color),
                    );
                    painter.line_segment(
                        [tip, tip + egui::vec2(arrow_size * 0.5, dir.y + dir.x * 0.5)],
                        egui::Stroke::new(stroke_width, color),
                    );

                    // Edge label for conditional branches
                    let label = match edge_kind {
                        EdgeKind::ConditionalTrue => Some("T"),
                        EdgeKind::ConditionalFalse => Some("F"),
                        _ => None,
                    };
                    if let Some(lbl) = label {
                        let label_pos = egui::pos2(
                            (from.x + ctrl1.x) / 2.0 + 4.0 * zoom,
                            (from.y + ctrl1.y) / 2.0,
                        );
                        painter.text(
                            label_pos,
                            egui::Align2::LEFT_CENTER,
                            lbl,
                            egui::FontId::monospace(10.0 * zoom),
                            color,
                        );
                    }
                }
            }

            // Draw blocks
            for block in &blocks {
                let rect = block_rects[&block.node_idx];
                let bb = &cfg.graph[block.node_idx];

                // Dim blocks not related to hovered node
                let bg = if hovered_node.is_some() && !highlight_nodes.contains(&block.node_idx) {
                    let c = self.syntax.block_bg;
                    egui::Color32::from_rgba_premultiplied(c.r(), c.g(), c.b(), 100)
                } else {
                    self.syntax.block_bg
                };

                let border = if Some(block.node_idx) == hovered_node {
                    egui::Stroke::new(2.0 * zoom, self.syntax.link)
                } else {
                    egui::Stroke::new(1.0 * zoom, self.syntax.block_border)
                };

                painter.rect_filled(rect, 4.0, bg);
                painter.rect_stroke(rect, 4.0, border, egui::StrokeKind::Outside);

                painter.text(
                    rect.min + egui::vec2(4.0 * zoom, 4.0 * zoom),
                    egui::Align2::LEFT_TOP,
                    format!("Block 0x{:X}", bb.start_address),
                    egui::FontId::monospace(12.0 * zoom),
                    self.syntax.link,
                );

                for (i, line) in block.lines.iter().enumerate() {
                    painter.text(
                        rect.min + egui::vec2(4.0 * zoom, 22.0 * zoom + i as f32 * 16.0 * zoom),
                        egui::Align2::LEFT_TOP,
                        line,
                        egui::FontId::monospace(11.0 * zoom),
                        self.syntax.text,
                    );
                }
            }

            // --- Minimap (bottom-right corner) ---
            if blocks.len() > 1 {
                let minimap_w = 120.0;
                let minimap_h = 90.0;
                let minimap_margin = 8.0;
                let minimap_rect = egui::Rect::from_min_size(
                    egui::pos2(
                        canvas_rect.max.x - minimap_w - minimap_margin,
                        canvas_rect.max.y - minimap_h - minimap_margin,
                    ),
                    egui::vec2(minimap_w, minimap_h),
                );

                painter.rect_filled(
                    minimap_rect,
                    2.0,
                    egui::Color32::from_rgba_premultiplied(30, 30, 30, 180),
                );
                painter.rect_stroke(
                    minimap_rect,
                    2.0,
                    egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 80, 80)),
                    egui::StrokeKind::Outside,
                );

                if canvas_width > 0.0 && canvas_height > 0.0 {
                    let scale_x = minimap_w / canvas_width;
                    let scale_y = minimap_h / canvas_height;
                    let scale = scale_x.min(scale_y);

                    for block in &blocks {
                        let pos = block_pos[&block.node_idx];
                        let mini_x = minimap_rect.min.x + pos.x * scale;
                        let mini_y = minimap_rect.min.y + pos.y * scale;
                        let mini_w = (block.width * scale).max(2.0);
                        let mini_h = (block.height * scale).max(2.0);
                        painter.rect_filled(
                            egui::Rect::from_min_size(
                                egui::pos2(mini_x, mini_y),
                                egui::vec2(mini_w, mini_h),
                            ),
                            0.0,
                            self.syntax.link,
                        );
                    }
                }
            }
        });
    }
}
