use crate::app::SleuthreApp;
use crate::views::graph_utils::{GenericGraph, GraphEdge, GraphNode};
use eframe::egui;
use re_core::analysis::xrefs::XrefType;
use std::collections::{HashMap, HashSet};

impl SleuthreApp {
    pub(crate) fn show_call_graph(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No project loaded.");
                return;
            }
        };

        let current_func_addr = self.current_address;

        // Find the actual start address of the current function
        let current_func = project
            .functions
            .functions
            .range(..=current_func_addr)
            .next_back()
            .and_then(|(&addr, func)| {
                if let Some(end) = func.end_address {
                    if current_func_addr < end {
                        Some((addr, func))
                    } else {
                        None
                    }
                } else {
                    Some((addr, func))
                }
            });

        if current_func.is_none() {
            ui.label("Cursor is not inside a known function.");
            return;
        }
        let (center_addr, func) = current_func.unwrap();

        let mut gg = GenericGraph::new();
        let mut node_indices = HashMap::new();
        let mut processed_callers = HashSet::new();
        let mut processed_callees = HashSet::new();

        // Helper to add node
        let add_func_node =
            |addr: u64,
             gg: &mut GenericGraph,
             node_indices: &mut HashMap<u64, petgraph::graph::NodeIndex>| {
                if let std::collections::hash_map::Entry::Vacant(e) = node_indices.entry(addr) {
                    let name = project
                        .functions
                        .functions
                        .get(&addr)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| format!("sub_{:X}", addr));
                    let idx = gg.graph.add_node(GraphNode {
                        title: name,
                        lines: vec![format!("0x{:X}", addr)],
                        address: addr,
                        instruction_addresses: vec![addr],
                    });
                    e.insert(idx);
                    idx
                } else {
                    node_indices[&addr]
                }
            };

        // Recursive helper for depth
        let add_neighbors = |addr: u64,
                             depth: usize,
                             is_caller: bool,
                             gg: &mut GenericGraph,
                             node_indices: &mut HashMap<u64, petgraph::graph::NodeIndex>,
                             processed: &mut HashSet<u64>,
                             project: &re_core::project::Project| {
            if depth == 0 || !processed.insert(addr) {
                return;
            }

            let u = add_func_node(addr, gg, node_indices);

            if is_caller {
                if let Some(xrefs) = project.xrefs.to_address_xrefs.get(&addr) {
                    for xref in xrefs {
                        if xref.xref_type == XrefType::Call
                            && let Some((&caller_addr, _)) = project
                                .functions
                                .functions
                                .range(..=xref.from_address)
                                .next_back()
                        {
                            let v = add_func_node(caller_addr, gg, node_indices);
                            if gg.graph.find_edge(v, u).is_none() {
                                gg.graph.add_edge(
                                    v,
                                    u,
                                    GraphEdge {
                                        color: self.syntax.text,
                                        is_back_edge: false,
                                        label: None,
                                    },
                                );
                            }
                            // Recurse if needed... (simplified for now to 1 level)
                        }
                    }
                }
            } else if let Some(f) = project.functions.functions.get(&addr) {
                let end = f.end_address.unwrap_or(addr + 0x1000);
                for (&from_addr, xrefs) in &project.xrefs.from_address_xrefs {
                    if from_addr >= addr && from_addr < end {
                        for xref in xrefs {
                            if xref.xref_type == XrefType::Call {
                                let v = add_func_node(xref.to_address, gg, node_indices);
                                if gg.graph.find_edge(u, v).is_none() {
                                    gg.graph.add_edge(
                                        u,
                                        v,
                                        GraphEdge {
                                            color: self.syntax.text,
                                            is_back_edge: false,
                                            label: None,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };

        add_neighbors(
            center_addr,
            1,
            true,
            &mut gg,
            &mut node_indices,
            &mut processed_callers,
            project,
        );
        add_neighbors(
            center_addr,
            1,
            false,
            &mut gg,
            &mut node_indices,
            &mut processed_callees,
            project,
        );

        let mut jump_request = None;

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("Call Graph for {}", func.name)).heading());
                ui.add_space(20.0);
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.call_graph_filter);
                if ui.button("Go").clicked() {
                    let filter = self.call_graph_filter.to_lowercase();
                    if let Some(f) = project
                        .functions
                        .functions
                        .values()
                        .find(|f| f.name.to_lowercase() == filter)
                    {
                        jump_request = Some(f.start_address);
                    }
                }
            });
            ui.separator();

            if let Some(addr) = gg.show(ui, &mut self.graph_zoom, &self.syntax, center_addr) {
                jump_request = Some(addr);
            }
        });

        if let Some(addr) = jump_request {
            if let Some(ref mut p) = self.project {
                p.navigate_to(addr);
            }
            self.current_address = addr;
            self.update_cfg();
        }
    }
}
