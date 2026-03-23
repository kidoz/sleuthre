use eframe::egui;
use re_core::analysis::diff::{self, DiffLine, MatchType};

use crate::app::{SleuthreApp, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_diff(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Binary Diff");
            ui.add_space(16.0);
            if ui.button("Load Second Binary...").clicked() {
                self.load_diff_binary();
            }
            if self.diff_project_b.is_some()
                && self.diff_result.is_none()
                && ui.button("Run Diff").clicked()
            {
                self.run_diff();
            }
            if self.diff_result.is_some() && ui.button("Clear").clicked() {
                self.diff_project_b = None;
                self.diff_result = None;
                self.diff_lines.clear();
                self.diff_selected = None;
            }
        });
        ui.separator();

        if self.project.is_none() {
            ui.label("Load a primary binary first (File > Open).");
            return;
        }

        if self.diff_project_b.is_none() {
            ui.label("Load a second binary to compare against the current project.");
            return;
        }

        let Some(ref diff_result) = self.diff_result else {
            ui.label("Click 'Run Diff' to compare the two binaries.");
            return;
        };

        // Summary
        ui.label(
            egui::RichText::new(format!(
                "Matched: {} ({} identical, {} modified) | Only in A: {} | Only in B: {}",
                diff_result.matched.len(),
                diff_result.identical_count,
                diff_result.modified_count,
                diff_result.only_in_a.len(),
                diff_result.only_in_b.len(),
            ))
            .size(11.0),
        );

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.diff_filter);
        });
        ui.separator();

        let filter_lower = self.diff_filter.to_lowercase();
        let mut clicked_idx: Option<usize> = None;

        let avail = ui.available_size();
        ui.horizontal(|ui| {
            // Left pane: function match list
            ui.vertical(|ui| {
                ui.set_width(avail.x * 0.4);
                egui::ScrollArea::vertical()
                    .id_salt("diff_func_list")
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("Modified Functions")
                                .strong()
                                .color(egui::Color32::YELLOW),
                        );
                        for (idx, m) in diff_result.matched.iter().enumerate() {
                            if m.similarity >= 1.0 {
                                continue;
                            }
                            if !filter_lower.is_empty()
                                && !m.name_a.to_lowercase().contains(&filter_lower)
                            {
                                continue;
                            }
                            let label = format!(
                                "{} ({:.0}%) [{}]",
                                m.name_a,
                                m.similarity * 100.0,
                                match m.match_type {
                                    MatchType::ExactName => "name",
                                    MatchType::ByteHash => "hash",
                                    MatchType::Unmatched => "?",
                                },
                            );
                            if ui
                                .selectable_label(
                                    self.diff_selected == Some(idx),
                                    egui::RichText::new(label)
                                        .size(11.0)
                                        .color(egui::Color32::YELLOW),
                                )
                                .clicked()
                            {
                                clicked_idx = Some(idx);
                            }
                        }

                        ui.separator();
                        ui.label(
                            egui::RichText::new("Identical Functions")
                                .strong()
                                .color(egui::Color32::GREEN),
                        );
                        for (idx, m) in diff_result.matched.iter().enumerate() {
                            if m.similarity < 1.0 {
                                continue;
                            }
                            if !filter_lower.is_empty()
                                && !m.name_a.to_lowercase().contains(&filter_lower)
                            {
                                continue;
                            }
                            if ui
                                .selectable_label(
                                    self.diff_selected == Some(idx),
                                    egui::RichText::new(&m.name_a)
                                        .size(11.0)
                                        .color(egui::Color32::GREEN),
                                )
                                .clicked()
                            {
                                self.diff_selected = Some(idx);
                                self.diff_lines.clear();
                            }
                        }

                        if !diff_result.only_in_a.is_empty() {
                            ui.separator();
                            ui.label(
                                egui::RichText::new("Only in A (removed)")
                                    .strong()
                                    .color(egui::Color32::from_rgb(220, 80, 80)),
                            );
                            for (addr, name) in &diff_result.only_in_a {
                                if !filter_lower.is_empty()
                                    && !name.to_lowercase().contains(&filter_lower)
                                {
                                    continue;
                                }
                                ui.label(
                                    egui::RichText::new(format!("{:08X} {}", addr, name))
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(220, 80, 80)),
                                );
                            }
                        }

                        if !diff_result.only_in_b.is_empty() {
                            ui.separator();
                            ui.label(
                                egui::RichText::new("Only in B (added)")
                                    .strong()
                                    .color(egui::Color32::from_rgb(80, 180, 80)),
                            );
                            for (addr, name) in &diff_result.only_in_b {
                                if !filter_lower.is_empty()
                                    && !name.to_lowercase().contains(&filter_lower)
                                {
                                    continue;
                                }
                                ui.label(
                                    egui::RichText::new(format!("{:08X} {}", addr, name))
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(80, 180, 80)),
                                );
                            }
                        }
                    });
            });

            ui.separator();

            // Right pane: instruction diff
            ui.vertical(|ui| {
                if self.diff_lines.is_empty() {
                    if self.diff_selected.is_some() {
                        ui.label("Functions are identical.");
                    } else {
                        ui.label("Select a modified function to see the instruction diff.");
                    }
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("diff_insn_view")
                        .show(ui, |ui| {
                            for line in &self.diff_lines {
                                let (prefix, text, color) = match line {
                                    DiffLine::Same(t) => (" ", t.as_str(), egui::Color32::GRAY),
                                    DiffLine::Added(t) => {
                                        ("+", t.as_str(), egui::Color32::from_rgb(80, 200, 80))
                                    }
                                    DiffLine::Removed(t) => {
                                        ("-", t.as_str(), egui::Color32::from_rgb(220, 80, 80))
                                    }
                                };
                                ui.monospace(
                                    egui::RichText::new(format!("{} {}", prefix, text))
                                        .color(color)
                                        .size(11.0),
                                );
                            }
                        });
                }
            });
        });

        // Deferred: compute instruction diff after borrow of diff_result is released
        if let Some(idx) = clicked_idx {
            self.diff_selected = Some(idx);
            self.compute_instruction_diff(idx);
        }
    }

    fn load_diff_binary(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Executables", &["elf", "exe", "dll", "so", "bin"])
            .pick_file()
        else {
            return;
        };

        match re_core::analysis::pipeline::analyze_binary(&path, |_| {}) {
            Ok(result) => {
                self.add_toast(
                    ToastKind::Success,
                    format!(
                        "Loaded '{}' ({} functions)",
                        result.project.name,
                        result.project.functions.functions.len()
                    ),
                );
                self.diff_project_b = Some(result.project);
                self.diff_result = None;
                self.diff_lines.clear();
                self.diff_selected = None;
            }
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Load error: {}", e));
            }
        }
    }

    fn run_diff(&mut self) {
        let (Some(project_a), Some(project_b)) = (&self.project, &self.diff_project_b) else {
            return;
        };

        let result = diff::diff_functions(
            &project_a.functions,
            &project_a.memory_map,
            &project_b.functions,
            &project_b.memory_map,
        );
        self.add_toast(
            ToastKind::Success,
            format!(
                "Diff complete: {} matched, {} only in A, {} only in B",
                result.matched.len(),
                result.only_in_a.len(),
                result.only_in_b.len(),
            ),
        );
        self.diff_result = Some(result);
        self.diff_selected = None;
        self.diff_lines.clear();
    }

    fn compute_instruction_diff(&mut self, match_idx: usize) {
        let func_match = match self.diff_result {
            Some(ref dr) => match dr.matched.get(match_idx) {
                Some(m) => (m.addr_a, m.addr_b),
                None => return,
            },
            None => return,
        };

        let (Some(project_a), Some(project_b)) = (&self.project, &self.diff_project_b) else {
            return;
        };

        let disasm_a = re_core::disasm::Disassembler::new(project_a.arch).ok();
        let disasm_b = re_core::disasm::Disassembler::new(project_b.arch).ok();

        let (Some(ref da), Some(ref db)) = (disasm_a, disasm_b) else {
            return;
        };

        let insns_a = da
            .disassemble_range(&project_a.memory_map, func_match.0, 500)
            .unwrap_or_default();
        let insns_b = db
            .disassemble_range(&project_b.memory_map, func_match.1, 500)
            .unwrap_or_default();

        self.diff_lines = diff::diff_instructions(&insns_a, &insns_b);
    }
}
