use eframe::egui;
use re_core::analysis::xrefs::XrefType;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_xrefs(&mut self, ui: &mut egui::Ui) {
        let (project, current_addr) = match &self.project {
            Some(p) => (p, self.current_address),
            None => {
                ui.label("No binary loaded.");
                return;
            }
        };

        // Find the function containing current_address
        let func_info = project
            .functions
            .functions
            .range(..=current_addr)
            .next_back()
            .map(|(_, f)| (f.start_address, f.name.clone()));

        let (func_addr, func_name) =
            func_info.unwrap_or((current_addr, format!("0x{:X}", current_addr)));

        ui.horizontal(|ui| {
            ui.heading(format!("Cross References: {}", func_name));
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("0x{:X}", func_addr))
                    .monospace()
                    .color(self.syntax.address),
            );
        });
        ui.separator();

        // Filter
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.xref_filter)
                    .desired_width(200.0)
                    .hint_text("Filter by address, name, or type..."),
            );
        });
        ui.separator();

        let filter_lower = self.xref_filter.to_lowercase();
        let mut jump_to = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            // === Xrefs TO this function (callers / incoming) ===
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Incoming (xrefs to this address)")
                    .strong()
                    .color(self.syntax.label),
            );
            ui.separator();

            let xrefs_to = project.xrefs.to_address_xrefs.get(&func_addr);
            let to_count = xrefs_to.map(|v| v.len()).unwrap_or(0);

            if to_count == 0 {
                ui.label(
                    egui::RichText::new("  No incoming references").color(self.syntax.text_dim),
                );
            } else {
                egui::Grid::new("xrefs_to_grid")
                    .striped(true)
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        // Header
                        ui.label(egui::RichText::new("From").strong().size(11.0));
                        ui.label(egui::RichText::new("Type").strong().size(11.0));
                        ui.label(egui::RichText::new("Function").strong().size(11.0));
                        ui.end_row();

                        for xref in xrefs_to.unwrap() {
                            let type_str = xref_type_label(xref.xref_type);
                            let caller_name = project
                                .functions
                                .functions
                                .range(..=xref.from_address)
                                .next_back()
                                .map(|(_, f)| f.name.as_str())
                                .unwrap_or("unknown");

                            // Apply filter
                            if !filter_lower.is_empty() {
                                let addr_str = format!("{:08X}", xref.from_address).to_lowercase();
                                let matches = addr_str.contains(&filter_lower)
                                    || type_str.to_lowercase().contains(&filter_lower)
                                    || caller_name.to_lowercase().contains(&filter_lower);
                                if !matches {
                                    continue;
                                }
                            }

                            let type_color = xref_type_color(xref.xref_type, &self.syntax);

                            if ui
                                .add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{:08X}", xref.from_address))
                                            .monospace()
                                            .color(self.syntax.link),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .clicked()
                            {
                                jump_to = Some(xref.from_address);
                            }
                            ui.label(egui::RichText::new(type_str).color(type_color).size(11.0));
                            ui.label(egui::RichText::new(caller_name).size(11.0));
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(12.0);

            // === Xrefs FROM this function (callees / outgoing) ===
            ui.label(
                egui::RichText::new("Outgoing (xrefs from this address)")
                    .strong()
                    .color(self.syntax.label),
            );
            ui.separator();

            let xrefs_from = project.xrefs.from_address_xrefs.get(&func_addr);
            let from_count = xrefs_from.map(|v| v.len()).unwrap_or(0);

            if from_count == 0 {
                // Also check all instructions within the function range
                let mut all_outgoing = Vec::new();
                if let Some(func) = project.functions.functions.get(&func_addr) {
                    let end = func.end_address.unwrap_or(func.start_address + 0x100);
                    for (&from_addr, xrefs) in &project.xrefs.from_address_xrefs {
                        if from_addr >= func_addr && from_addr < end {
                            all_outgoing.extend(xrefs.iter());
                        }
                    }
                }

                if all_outgoing.is_empty() {
                    ui.label(
                        egui::RichText::new("  No outgoing references").color(self.syntax.text_dim),
                    );
                } else {
                    egui::Grid::new("xrefs_from_func_grid")
                        .striped(true)
                        .min_col_width(60.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("From").strong().size(11.0));
                            ui.label(egui::RichText::new("To").strong().size(11.0));
                            ui.label(egui::RichText::new("Type").strong().size(11.0));
                            ui.label(egui::RichText::new("Target").strong().size(11.0));
                            ui.end_row();

                            for xref in &all_outgoing {
                                let type_str = xref_type_label(xref.xref_type);
                                let target_name = resolve_name(project, xref.to_address);

                                if !filter_lower.is_empty() {
                                    let matches = format!("{:08X}", xref.to_address)
                                        .to_lowercase()
                                        .contains(&filter_lower)
                                        || type_str.to_lowercase().contains(&filter_lower)
                                        || target_name.to_lowercase().contains(&filter_lower);
                                    if !matches {
                                        continue;
                                    }
                                }

                                let type_color = xref_type_color(xref.xref_type, &self.syntax);

                                ui.monospace(
                                    egui::RichText::new(format!("{:08X}", xref.from_address))
                                        .size(11.0)
                                        .color(self.syntax.address),
                                );
                                if ui
                                    .add(
                                        egui::Label::new(
                                            egui::RichText::new(format!("{:08X}", xref.to_address))
                                                .monospace()
                                                .color(self.syntax.link),
                                        )
                                        .sense(egui::Sense::click()),
                                    )
                                    .clicked()
                                {
                                    jump_to = Some(xref.to_address);
                                }
                                ui.label(
                                    egui::RichText::new(type_str).color(type_color).size(11.0),
                                );
                                ui.label(egui::RichText::new(&target_name).size(11.0));
                                ui.end_row();
                            }
                        });
                }
            } else {
                egui::Grid::new("xrefs_from_grid")
                    .striped(true)
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("To").strong().size(11.0));
                        ui.label(egui::RichText::new("Type").strong().size(11.0));
                        ui.label(egui::RichText::new("Target").strong().size(11.0));
                        ui.end_row();

                        for xref in xrefs_from.unwrap() {
                            let type_str = xref_type_label(xref.xref_type);
                            let target_name = resolve_name(project, xref.to_address);

                            if !filter_lower.is_empty() {
                                let matches = format!("{:08X}", xref.to_address)
                                    .to_lowercase()
                                    .contains(&filter_lower)
                                    || type_str.to_lowercase().contains(&filter_lower)
                                    || target_name.to_lowercase().contains(&filter_lower);
                                if !matches {
                                    continue;
                                }
                            }

                            let type_color = xref_type_color(xref.xref_type, &self.syntax);

                            if ui
                                .add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{:08X}", xref.to_address))
                                            .monospace()
                                            .color(self.syntax.link),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .clicked()
                            {
                                jump_to = Some(xref.to_address);
                            }
                            ui.label(egui::RichText::new(type_str).color(type_color).size(11.0));
                            ui.label(egui::RichText::new(&target_name).size(11.0));
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(12.0);

            // Summary
            ui.separator();
            let total_to = xrefs_to.map(|v| v.len()).unwrap_or(0);
            let total_from = xrefs_from.map(|v| v.len()).unwrap_or(0);
            ui.label(
                egui::RichText::new(format!(
                    "{} incoming, {} outgoing references",
                    total_to, total_from,
                ))
                .size(11.0)
                .color(self.syntax.text_dim),
            );
        });

        if let Some(addr) = jump_to {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.update_cfg();
        }
    }
}

fn xref_type_label(t: XrefType) -> &'static str {
    match t {
        XrefType::Call => "Call",
        XrefType::Jump => "Jump",
        XrefType::DataRead => "Read",
        XrefType::DataWrite => "Write",
        XrefType::StringRef => "String",
    }
}

fn xref_type_color(t: XrefType, syntax: &crate::theme::SyntaxColors) -> egui::Color32 {
    match t {
        XrefType::Call => syntax.keyword,
        XrefType::Jump => syntax.mnemonic,
        XrefType::DataRead => syntax.number,
        XrefType::DataWrite => syntax.string,
        XrefType::StringRef => syntax.comment,
    }
}

fn resolve_name(project: &re_core::project::Project, addr: u64) -> String {
    // Check functions
    if let Some(func) = project.functions.functions.get(&addr) {
        return func.name.clone();
    }
    // Check imports
    for imp in &project.imports {
        if imp.address == addr {
            return format!("{} [import]", imp.name);
        }
    }
    // Check exports
    for exp in &project.exports {
        if exp.address == addr {
            return format!("{} [export]", exp.name);
        }
    }
    // Check strings
    for s in &project.strings.strings {
        if s.address == addr {
            let truncated: String = s.value.chars().take(40).collect();
            return format!("\"{}\"", truncated);
        }
    }
    format!("0x{:X}", addr)
}
