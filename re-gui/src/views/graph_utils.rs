use eframe::egui;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct GraphNode {
    pub title: String,
    pub lines: Vec<String>,
    pub address: u64,
    pub instruction_addresses: Vec<u64>,
}

pub struct GraphEdge {
    pub color: egui::Color32,
    pub is_back_edge: bool,
    pub label: Option<String>,
}

pub struct GenericGraph {
    pub graph: DiGraph<GraphNode, GraphEdge>,
    pub entry_node: Option<NodeIndex>,
}

impl GenericGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            entry_node: None,
        }
    }

    pub fn show(
        &self,
        ui: &mut egui::Ui,
        zoom: &mut f32,
        syntax: &crate::theme::SyntaxColors,
        current_addr: u64,
    ) -> Option<u64> {
        let mut jump_to = None;

        if self.graph.node_count() == 0 {
            ui.label("Empty graph.");
            return None;
        }

        // --- Zoom controls ---
        let available_size = ui.available_size();
        ui.horizontal(|ui| {
            if ui.button("-").clicked() {
                *zoom = (*zoom - 0.1).max(0.3);
            }
            ui.label(format!("{:.0}%", *zoom * 100.0));
            if ui.button("+").clicked() {
                *zoom = (*zoom + 0.1).min(3.0);
            }
            if ui.button("Reset").clicked() {
                *zoom = 1.0;
            }
            if ui.button("Fit").clicked() {
                // Calculate zoom to fit graph in available area
                // We need to estimate the graph size at zoom=1.0
                let est_max_layer = self.graph.node_count();
                let est_width = 400.0; // rough estimate
                let est_height = est_max_layer as f32 * 100.0;
                if est_width > 0.0 && est_height > 0.0 {
                    let zoom_w = available_size.x / est_width;
                    let zoom_h = available_size.y / est_height;
                    *zoom = zoom_w.min(zoom_h).clamp(0.3, 3.0);
                }
            }
        });
        ui.separator();

        let zoom_val = *zoom;

        // --- Layout Calculation ---
        let entry = self
            .entry_node
            .unwrap_or_else(|| self.graph.node_indices().next().unwrap());

        let mut layer_of: HashMap<NodeIndex, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        layer_of.insert(entry, 0);
        queue.push_back(entry);

        while let Some(node) = queue.pop_front() {
            let next_layer = layer_of[&node] + 1;
            for succ in self.graph.neighbors(node) {
                if let std::collections::hash_map::Entry::Vacant(e) = layer_of.entry(succ) {
                    e.insert(next_layer);
                    queue.push_back(succ);
                }
            }
        }

        // Ensure all nodes have a layer
        for node_idx in self.graph.node_indices() {
            layer_of.entry(node_idx).or_insert(0);
        }

        let max_layer = layer_of.values().copied().max().unwrap_or(0);
        let mut layers: Vec<Vec<NodeIndex>> = vec![Vec::new(); max_layer + 1];
        for node_idx in self.graph.node_indices() {
            let layer = layer_of[&node_idx];
            layers[layer].push(node_idx);
        }

        // Sort nodes within layers by address for stability
        for layer in &mut layers {
            layer.sort_by_key(|&n| self.graph[n].address);
        }

        // --- Compute sizes and positions ---
        let mut node_sizes: HashMap<NodeIndex, egui::Vec2> = HashMap::new();
        for node_idx in self.graph.node_indices() {
            let node = &self.graph[node_idx];
            let w = 300.0 * zoom_val;
            let h = (node.lines.len() as f32 * 16.0 * zoom_val) + 28.0 * zoom_val;
            node_sizes.insert(node_idx, egui::vec2(w, h));
        }

        let h_gap = 40.0 * zoom_val;
        let v_gap = 60.0 * zoom_val;
        let padding = 30.0 * zoom_val;

        let mut layer_widths = vec![0.0f32; layers.len()];
        let mut layer_heights = vec![0.0f32; layers.len()];

        for (i, layer) in layers.iter().enumerate() {
            let mut total_w = 0.0;
            let mut max_h: f32 = 0.0;
            for &node_idx in layer {
                let size = node_sizes[&node_idx];
                total_w += size.x;
                max_h = max_h.max(size.y);
            }
            total_w += h_gap * (layer.len().saturating_sub(1)) as f32;
            layer_widths[i] = total_w;
            layer_heights[i] = max_h;
        }

        let canvas_width = layer_widths.iter().copied().fold(0.0f32, f32::max) + padding * 2.0;
        let mut node_pos: HashMap<NodeIndex, egui::Pos2> = HashMap::new();
        let mut current_y = padding;

        for (i, layer) in layers.iter().enumerate() {
            let start_x = padding + (canvas_width - padding * 2.0 - layer_widths[i]) / 2.0;
            let mut current_x = start_x;
            for &node_idx in layer {
                node_pos.insert(node_idx, egui::pos2(current_x, current_y));
                current_x += node_sizes[&node_idx].x + h_gap;
            }
            current_y += layer_heights[i] + v_gap;
        }

        let canvas_height = current_y + padding;

        // --- Rendering ---
        egui::ScrollArea::both().show(ui, |ui| {
            let (canvas_rect, response) = ui.allocate_exact_size(
                egui::vec2(canvas_width, canvas_height),
                egui::Sense::hover(),
            );
            let origin = canvas_rect.min.to_vec2();
            let painter = ui.painter_at(canvas_rect);

            // Handle zoom shortcut
            if response.hovered() {
                let scroll = ui.input(|i| i.smooth_scroll_delta.y);
                if ui.input(|i| i.modifiers.command) && scroll != 0.0 {
                    *zoom = (*zoom + scroll * 0.002).clamp(0.3, 3.0);
                }
            }

            let mut node_rects = HashMap::new();
            let mut selected_node = None;
            for node_idx in self.graph.node_indices() {
                let pos = node_pos[&node_idx] + origin;
                let size = node_sizes[&node_idx];
                let rect = egui::Rect::from_min_size(pos, size);
                node_rects.insert(node_idx, rect);

                let node_data = &self.graph[node_idx];
                if node_data.address == current_addr
                    || node_data.instruction_addresses.contains(&current_addr)
                {
                    selected_node = Some(node_idx);
                }
            }

            let mouse_pos = response.hover_pos();
            let hovered_node = mouse_pos.and_then(|mp| {
                node_rects
                    .iter()
                    .find(|(_, r)| r.contains(mp))
                    .map(|(n, _)| *n)
            });

            // Active node for highlighting: hovered takes priority, then selected
            let active_node = hovered_node.or(selected_node);

            let mut highlight_nodes = HashSet::new();
            if let Some(hn) = active_node {
                highlight_nodes.insert(hn);
                for succ in self.graph.neighbors(hn) {
                    highlight_nodes.insert(succ);
                }
                for pred in self
                    .graph
                    .neighbors_directed(hn, petgraph::Direction::Incoming)
                {
                    highlight_nodes.insert(pred);
                }
            }

            // Pre-compute per-node outgoing/incoming port positions so edges
            // don't all depart/arrive at the center.
            let margin = 20.0 * zoom_val;

            // Collect outgoing edges per source, sorted by target x-position
            let mut outgoing: HashMap<NodeIndex, Vec<(NodeIndex, petgraph::graph::EdgeIndex)>> =
                HashMap::new();
            let mut incoming: HashMap<NodeIndex, Vec<(NodeIndex, petgraph::graph::EdgeIndex)>> =
                HashMap::new();
            for edge in self.graph.edge_references() {
                outgoing
                    .entry(edge.source())
                    .or_default()
                    .push((edge.target(), edge.id()));
                incoming
                    .entry(edge.target())
                    .or_default()
                    .push((edge.source(), edge.id()));
            }

            // Sort outgoing by target center-x, incoming by source center-x
            for (_, targets) in outgoing.iter_mut() {
                targets.sort_by(|a, b| {
                    let ax = node_rects[&a.0].center().x;
                    let bx = node_rects[&b.0].center().x;
                    ax.partial_cmp(&bx).unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            for (_, sources) in incoming.iter_mut() {
                sources.sort_by(|a, b| {
                    let ax = node_rects[&a.0].center().x;
                    let bx = node_rects[&b.0].center().x;
                    ax.partial_cmp(&bx).unwrap_or(std::cmp::Ordering::Equal)
                });
            }

            // Build port-position map: edge_id -> (from_pos, to_pos)
            let mut port_positions: HashMap<petgraph::graph::EdgeIndex, (egui::Pos2, egui::Pos2)> =
                HashMap::new();

            // Assign outgoing (bottom) ports
            let mut out_port_x: HashMap<(NodeIndex, petgraph::graph::EdgeIndex), f32> =
                HashMap::new();
            for (&node, targets) in &outgoing {
                let rect = node_rects[&node];
                let usable = rect.width() - 2.0 * margin;
                let count = targets.len();
                for (i, &(_, edge_id)) in targets.iter().enumerate() {
                    let x = if count == 1 {
                        rect.center().x
                    } else {
                        rect.min.x + margin + usable * (i as f32) / (count as f32 - 1.0)
                    };
                    out_port_x.insert((node, edge_id), x);
                }
            }

            // Assign incoming (top) ports
            let mut in_port_x: HashMap<(NodeIndex, petgraph::graph::EdgeIndex), f32> =
                HashMap::new();
            for (&node, sources) in &incoming {
                let rect = node_rects[&node];
                let usable = rect.width() - 2.0 * margin;
                let count = sources.len();
                for (i, &(_, edge_id)) in sources.iter().enumerate() {
                    let x = if count == 1 {
                        rect.center().x
                    } else {
                        rect.min.x + margin + usable * (i as f32) / (count as f32 - 1.0)
                    };
                    in_port_x.insert((node, edge_id), x);
                }
            }

            // Build final port positions
            for edge in self.graph.edge_references() {
                let src = edge.source();
                let tgt = edge.target();
                let eid = edge.id();
                let src_rect = node_rects[&src];
                let tgt_rect = node_rects[&tgt];

                let from_x = out_port_x
                    .get(&(src, eid))
                    .copied()
                    .unwrap_or(src_rect.center().x);
                let to_x = in_port_x
                    .get(&(tgt, eid))
                    .copied()
                    .unwrap_or(tgt_rect.center().x);

                let from = egui::pos2(from_x, src_rect.max.y);
                let to = egui::pos2(to_x, tgt_rect.min.y);
                port_positions.insert(eid, (from, to));
            }

            // Draw Edges
            for edge in self.graph.edge_references() {
                let src = edge.source();
                let tgt = edge.target();
                let weight = edge.weight();

                let is_highlighted =
                    active_node.is_none() || active_node == Some(src) || active_node == Some(tgt);
                let alpha = if is_highlighted { 255 } else { 40 };
                let color = egui::Color32::from_rgba_premultiplied(
                    weight.color.r(),
                    weight.color.g(),
                    weight.color.b(),
                    alpha,
                );

                let stroke = egui::Stroke::new(1.5 * zoom_val, color);
                let arrow_size = 6.0 * zoom_val;

                if weight.is_back_edge {
                    // Route back edge around nodes via the side
                    let src_rect = node_rects[&src];
                    let tgt_rect = node_rects[&tgt];
                    let canvas_cx = canvas_rect.center().x;

                    // Choose side: go right if source is left of center, else left
                    let go_right = src_rect.center().x < canvas_cx;
                    let offset = 30.0 * zoom_val;

                    let from = if go_right {
                        egui::pos2(src_rect.max.x, src_rect.center().y)
                    } else {
                        egui::pos2(src_rect.min.x, src_rect.center().y)
                    };
                    let to = if go_right {
                        egui::pos2(tgt_rect.max.x, tgt_rect.center().y)
                    } else {
                        egui::pos2(tgt_rect.min.x, tgt_rect.center().y)
                    };

                    let ctrl_x = if go_right {
                        src_rect.max.x.max(tgt_rect.max.x) + offset
                    } else {
                        src_rect.min.x.min(tgt_rect.min.x) - offset
                    };
                    let ctrl1 = egui::pos2(ctrl_x, from.y);
                    let ctrl2 = egui::pos2(ctrl_x, to.y);

                    let bezier = egui::epaint::CubicBezierShape::from_points_stroke(
                        [from, ctrl1, ctrl2, to],
                        false,
                        egui::Color32::TRANSPARENT,
                        stroke,
                    );
                    painter.add(bezier);

                    // Sideways arrowhead pointing inward
                    let dir_x = if go_right { -1.0 } else { 1.0 };
                    painter.line_segment(
                        [to, to + egui::vec2(dir_x * arrow_size, -arrow_size * 0.5)],
                        stroke,
                    );
                    painter.line_segment(
                        [to, to + egui::vec2(dir_x * arrow_size, arrow_size * 0.5)],
                        stroke,
                    );
                } else {
                    let (from, to) = port_positions[&edge.id()];

                    let mid_y = (from.y + to.y) / 2.0;
                    let ctrl1 = egui::pos2(from.x, mid_y);
                    let ctrl2 = egui::pos2(to.x, mid_y);
                    let bezier = egui::epaint::CubicBezierShape::from_points_stroke(
                        [from, ctrl1, ctrl2, to],
                        false,
                        egui::Color32::TRANSPARENT,
                        stroke,
                    );
                    painter.add(bezier);

                    // Downward arrowhead
                    painter.line_segment(
                        [to, to + egui::vec2(-arrow_size * 0.5, -arrow_size)],
                        stroke,
                    );
                    painter
                        .line_segment([to, to + egui::vec2(arrow_size * 0.5, -arrow_size)], stroke);

                    // Branch label at midpoint
                    if let Some(ref label) = weight.label {
                        let mid = egui::pos2(
                            (from.x + to.x) / 2.0 + 6.0 * zoom_val,
                            (from.y + to.y) / 2.0,
                        );
                        painter.text(
                            mid,
                            egui::Align2::LEFT_CENTER,
                            label,
                            egui::FontId::monospace(10.0 * zoom_val),
                            color,
                        );
                    }
                }
            }

            // Draw Nodes
            for node_idx in self.graph.node_indices() {
                let rect = node_rects[&node_idx];
                let node = &self.graph[node_idx];

                let is_dimmed = active_node.is_some() && !highlight_nodes.contains(&node_idx);
                let bg_color = if is_dimmed {
                    let c = syntax.block_bg;
                    egui::Color32::from_rgba_premultiplied(c.r(), c.g(), c.b(), 100)
                } else {
                    syntax.block_bg
                };

                let border = if Some(node_idx) == active_node {
                    egui::Stroke::new(2.0 * zoom_val, syntax.link)
                } else {
                    egui::Stroke::new(1.0 * zoom_val, syntax.block_border)
                };

                painter.rect_filled(rect, 4.0, bg_color);
                painter.rect_stroke(rect, 4.0, border, egui::StrokeKind::Outside);

                // Check for click to navigate
                let node_resp = ui.interact(rect, ui.id().with(node_idx), egui::Sense::click());
                if node_resp.clicked() {
                    jump_to = Some(node.address);
                }

                painter.text(
                    rect.min + egui::vec2(4.0 * zoom_val, 4.0 * zoom_val),
                    egui::Align2::LEFT_TOP,
                    &node.title,
                    egui::FontId::monospace(12.0 * zoom_val),
                    syntax.link,
                );

                for (i, line) in node.lines.iter().enumerate() {
                    painter.text(
                        rect.min
                            + egui::vec2(
                                4.0 * zoom_val,
                                22.0 * zoom_val + i as f32 * 16.0 * zoom_val,
                            ),
                        egui::Align2::LEFT_TOP,
                        line,
                        egui::FontId::monospace(11.0 * zoom_val),
                        if is_dimmed {
                            syntax.text_dim
                        } else {
                            syntax.text
                        },
                    );
                }
            }

            // --- Minimap overlay ---
            let minimap_w = 120.0;
            let minimap_h = 80.0;
            let minimap_margin = 8.0;
            let minimap_origin = egui::pos2(
                canvas_rect.max.x - minimap_w - minimap_margin,
                canvas_rect.min.y + minimap_margin,
            );
            let minimap_rect =
                egui::Rect::from_min_size(minimap_origin, egui::vec2(minimap_w, minimap_h));

            // Semi-transparent background
            painter.rect_filled(
                minimap_rect,
                4.0,
                egui::Color32::from_rgba_unmultiplied(0, 0, 0, 140),
            );
            painter.rect_stroke(
                minimap_rect,
                4.0,
                egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 80, 80)),
                egui::StrokeKind::Outside,
            );

            if canvas_width > 0.0 && canvas_height > 0.0 {
                let scale_x = minimap_w / canvas_width;
                let scale_y = minimap_h / canvas_height;
                let scale = scale_x.min(scale_y);

                // Draw scaled-down node rectangles
                for node_idx in self.graph.node_indices() {
                    let pos = node_pos[&node_idx];
                    let size = node_sizes[&node_idx];
                    let mini_rect = egui::Rect::from_min_size(
                        egui::pos2(
                            minimap_origin.x + pos.x * scale,
                            minimap_origin.y + pos.y * scale,
                        ),
                        egui::vec2((size.x * scale).max(2.0), (size.y * scale).max(1.0)),
                    );
                    let color = if self.graph[node_idx].address == current_addr
                        || self.graph[node_idx]
                            .instruction_addresses
                            .contains(&current_addr)
                    {
                        syntax.link
                    } else {
                        egui::Color32::from_rgb(100, 100, 100)
                    };
                    painter.rect_filled(mini_rect, 0.0, color);
                }
            }
        });

        jump_to
    }
}
