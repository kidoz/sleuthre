use eframe::egui;
use re_core::signatures::SignatureDatabase;

use crate::app::{SleuthreApp, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_signatures(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Signature Manager");
            ui.add_space(16.0);
            if ui.button("Load from File...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("Signature DB", &["json"])
                    .pick_file()
            {
                match SignatureDatabase::load_from_file(&path) {
                    Ok(db) => {
                        let count = db.signatures.len();
                        self.user_sig_db.merge(&db);
                        self.add_toast(
                            ToastKind::Success,
                            format!("Loaded {} signatures from '{}'", count, path.display()),
                        );
                    }
                    Err(e) => {
                        self.add_toast(ToastKind::Error, format!("Load error: {}", e));
                    }
                }
            }
            if ui.button("Save to File...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("Signature DB", &["json"])
                    .save_file()
            {
                match self.user_sig_db.save_to_file(&path) {
                    Ok(()) => {
                        self.add_toast(
                            ToastKind::Success,
                            format!(
                                "Saved {} signatures to '{}'",
                                self.user_sig_db.signatures.len(),
                                path.display()
                            ),
                        );
                    }
                    Err(e) => {
                        self.add_toast(ToastKind::Error, format!("Save error: {}", e));
                    }
                }
            }
            if ui.button("Scan Binary").clicked() {
                self.run_user_signatures();
            }
        });
        ui.separator();

        // Add new signature form
        ui.horizontal(|ui| {
            ui.label("Name:");
            ui.add(egui::TextEdit::singleline(&mut self.new_sig_name).desired_width(120.0));
            ui.label("Pattern:");
            ui.add(egui::TextEdit::singleline(&mut self.new_sig_pattern).desired_width(200.0));
            ui.label("Library:");
            ui.add(egui::TextEdit::singleline(&mut self.new_sig_library).desired_width(80.0));
            if ui.button("Add").clicked() {
                let name = self.new_sig_name.trim();
                let pattern = self.new_sig_pattern.trim();
                if !name.is_empty() && !pattern.is_empty() {
                    self.user_sig_db.add_pattern(
                        name,
                        pattern,
                        if self.new_sig_library.is_empty() {
                            "user"
                        } else {
                            &self.new_sig_library
                        },
                    );
                    self.new_sig_name.clear();
                    self.new_sig_pattern.clear();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.sig_filter);
            ui.label(format!("{} signatures", self.user_sig_db.signatures.len()));
        });
        ui.separator();

        // Signature list
        let mut remove_idx = None;
        let filter_lower = self.sig_filter.to_lowercase();
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Header
            ui.horizontal(|ui| {
                ui.style_mut().spacing.item_spacing.x = 4.0;
                ui.monospace(
                    egui::RichText::new(format!(
                        "{:<30} {:<40} {:<15} {:>5}",
                        "Name", "Pattern", "Library", "Len"
                    ))
                    .strong()
                    .size(11.0),
                );
            });
            ui.separator();

            for (i, sig) in self.user_sig_db.signatures.iter().enumerate() {
                if !filter_lower.is_empty()
                    && !sig.name.to_lowercase().contains(&filter_lower)
                    && !sig.library.to_lowercase().contains(&filter_lower)
                {
                    continue;
                }
                let pattern_str: String = sig
                    .pattern
                    .iter()
                    .map(|p| match p {
                        re_core::signatures::PatternByte::Exact(b) => format!("{:02X}", b),
                        re_core::signatures::PatternByte::Wildcard => "??".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ");

                ui.horizontal(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 4.0;
                    ui.monospace(
                        egui::RichText::new(format!(
                            "{:<30} {:<40} {:<15} {:>5}",
                            truncate(&sig.name, 30),
                            truncate(&pattern_str, 40),
                            sig.library,
                            sig.pattern.len(),
                        ))
                        .size(11.0),
                    );
                    if ui.small_button("x").clicked() {
                        remove_idx = Some(i);
                    }
                });
            }
        });

        if let Some(idx) = remove_idx {
            self.user_sig_db.signatures.remove(idx);
        }
    }

    fn run_user_signatures(&mut self) {
        let Some(ref mut project) = self.project else {
            self.add_toast(ToastKind::Warning, "No binary loaded.".into());
            return;
        };

        // Merge builtin + user for scanning
        let mut combined = match project.arch {
            re_core::arch::Architecture::X86_64 => SignatureDatabase::builtin_x86_64(),
            re_core::arch::Architecture::Arm64 => SignatureDatabase::builtin_arm64(),
            _ => SignatureDatabase::new(),
        };
        combined.merge(&self.user_sig_db);

        let matches = combined.scan_and_apply(&project.memory_map, &mut project.functions);
        self.cached_func_list_dirty = true;
        if matches.is_empty() {
            self.add_toast(ToastKind::Info, "No new signatures matched.".into());
        } else {
            self.add_toast(
                ToastKind::Success,
                format!("Matched {} signatures.", matches.len()),
            );
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
