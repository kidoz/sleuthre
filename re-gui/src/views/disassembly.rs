use eframe::egui;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_disassembly(&mut self, ui: &mut egui::Ui) {
        let (project, disasm) = match (&self.project, &self.disasm) {
            (Some(p), Some(d)) => (p, d),
            _ => {
                ui.label("No binary loaded");
                return;
            }
        };
        egui::ScrollArea::vertical().show_rows(ui, 18.0, 1000, |ui, range| {
            let mut addr = self.current_address + (range.start as u64 * 4);
            for _ in range {
                if let Ok(insn) = disasm.disassemble_one(&project.memory_map, addr) {
                    let is_simd = insn
                        .groups
                        .iter()
                        .any(|g| g == "sse" || g == "mmx" || g == "avx");
                    let mn = insn.mnemonic.to_lowercase();
                    let is_branch = mn.starts_with('j') || mn == "call" || mn == "ret";

                    let mnemonic_color = if is_simd {
                        self.syntax.simd
                    } else if is_branch {
                        self.syntax.keyword
                    } else {
                        self.syntax.mnemonic
                    };

                    let is_focused = self.focused_address == Some(insn.address);

                    let response = ui
                        .horizontal(|ui| {
                            let rect = ui.max_rect();
                            if is_focused {
                                ui.painter()
                                    .rect_filled(rect, 0.0, self.syntax.selection_bg);
                            }

                            if ui.selectable_label(is_focused, "").clicked() {
                                self.focused_address = Some(insn.address);
                            }

                            ui.monospace(
                                egui::RichText::new(format!("{:08X}", insn.address))
                                    .color(self.syntax.address),
                            );
                            ui.add_space(8.0);
                            let bytes_str = insn
                                .bytes
                                .iter()
                                .take(6)
                                .map(|b| format!("{:02X}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            ui.monospace(
                                egui::RichText::new(format!("{:<17}", bytes_str))
                                    .color(self.syntax.bytes),
                            );

                            ui.monospace(
                                egui::RichText::new(&insn.mnemonic)
                                    .color(mnemonic_color)
                                    .strong(),
                            );

                            // Colorize operands: registers vs numbers
                            let op_color = if insn.op_str.starts_with("0x")
                                || insn
                                    .op_str
                                    .chars()
                                    .next()
                                    .is_some_and(|c| c.is_ascii_digit())
                            {
                                self.syntax.number
                            } else {
                                self.syntax.text
                            };
                            ui.monospace(egui::RichText::new(&insn.op_str).color(op_color));

                            if let Some(c) = project.comments.get(&insn.address) {
                                ui.label(
                                    egui::RichText::new(format!("; {}", c))
                                        .color(self.syntax.comment),
                                );
                            }
                        })
                        .response;

                    response.context_menu(|ui| {
                        if ui.button("Rename (N)").clicked() {
                            self.rename_active = true;
                            self.rename_input = String::new();
                            ui.close();
                        }
                        if ui.button("Comment (;)").clicked() {
                            self.comment_active = true;
                            if let Some(project) = &self.project {
                                self.comment_input = project
                                    .comments
                                    .get(&insn.address)
                                    .cloned()
                                    .unwrap_or_default();
                            }
                            ui.close();
                        }
                        if ui.button("Xrefs (X)").clicked() {
                            self.xref_active = true;
                            ui.close();
                        }
                        if ui.button("Decompile (F5)").clicked() {
                            self.trigger_decompile = true;
                            ui.close();
                        }
                    });

                    addr += insn.bytes.len() as u64;
                } else {
                    ui.label("??");
                    addr += 1;
                }
            }
        });
    }
}
