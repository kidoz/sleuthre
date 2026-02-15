use eframe::egui;
use re_core::analysis::xrefs::XrefType;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_call_graph(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No project loaded.");
                return;
            }
        };

        // Filter bar
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.call_graph_filter);
        });
        ui.separator();

        // Build call graph from xrefs
        egui::ScrollArea::vertical().show(ui, |ui| {
            let filter = self.call_graph_filter.to_lowercase();

            for (&addr, func) in &project.functions.functions {
                let name = &func.name;
                if !filter.is_empty() && !name.to_lowercase().contains(&filter) {
                    continue;
                }

                let func_end = func.end_address.unwrap_or(addr + 0x1000);

                // Find calls FROM this function
                let callees: Vec<(u64, String)> = project
                    .xrefs
                    .from_address_xrefs
                    .iter()
                    .filter(|(from, _)| **from >= addr && **from < func_end)
                    .flat_map(|(_, xrefs)| xrefs)
                    .filter(|x| x.xref_type == XrefType::Call)
                    .map(|x| {
                        let callee_name = project
                            .functions
                            .functions
                            .get(&x.to_address)
                            .map(|f| f.name.clone())
                            .unwrap_or_else(|| format!("sub_{:x}", x.to_address));
                        (x.to_address, callee_name)
                    })
                    .collect();

                // Find callers TO this function
                let callers: Vec<(u64, String)> = project
                    .xrefs
                    .to_address_xrefs
                    .get(&addr)
                    .map(|xrefs| {
                        xrefs
                            .iter()
                            .filter(|x| x.xref_type == XrefType::Call)
                            .map(|x| {
                                // Find which function contains this call
                                let caller_name = project
                                    .functions
                                    .functions
                                    .range(..=x.from_address)
                                    .next_back()
                                    .map(|(_, f)| f.name.clone())
                                    .unwrap_or_else(|| format!("sub_{:x}", x.from_address));
                                (x.from_address, caller_name)
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                if callees.is_empty() && callers.is_empty() && !filter.is_empty() {
                    continue;
                }

                let header = format!("{} (0x{:x})", name, addr);
                egui::CollapsingHeader::new(header)
                    .default_open(false)
                    .show(ui, |ui| {
                        if !callers.is_empty() {
                            ui.label(egui::RichText::new("Called by:").strong());
                            for (caller_addr, caller_name) in &callers {
                                let label = format!("  <- {} (0x{:x})", caller_name, caller_addr);
                                let _ = ui.selectable_label(false, &label);
                            }
                        }
                        if !callees.is_empty() {
                            ui.label(egui::RichText::new("Calls:").strong());
                            for (callee_addr, callee_name) in &callees {
                                let label = format!("  -> {} (0x{:x})", callee_name, callee_addr);
                                let _ = ui.selectable_label(false, &label);
                            }
                        }
                        if callers.is_empty() && callees.is_empty() {
                            ui.label("  (no calls)");
                        }
                    });
            }
        });
    }
}
