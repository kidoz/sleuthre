use eframe::egui;

use crate::app::SleuthreApp;

const DISASM_CACHE_SIZE: usize = 2000;

impl SleuthreApp {
    /// Ensure the disasm cache contains instructions starting from current_address.
    /// Only re-disassembles when the base address changes.
    fn ensure_disasm_cache(&mut self) {
        if self.disasm_cache_base == self.current_address && !self.disasm_cache.is_empty() {
            return;
        }
        self.disasm_cache.clear();
        let (project, disasm) = match (&self.project, &self.disasm) {
            (Some(p), Some(d)) => (p, d),
            _ => return,
        };
        // Disassemble a window of instructions from current_address
        if let Ok(insns) =
            disasm.disassemble_range(&project.memory_map, self.current_address, DISASM_CACHE_SIZE)
        {
            self.disasm_cache = insns;
        }
        self.disasm_cache_base = self.current_address;
    }

    pub(crate) fn show_disassembly(&mut self, ui: &mut egui::Ui) {
        if self.project.is_none() || self.disasm.is_none() {
            ui.label("No binary loaded");
            return;
        }

        self.ensure_disasm_cache();

        let total_rows = self.disasm_cache.len();
        if total_rows == 0 {
            ui.label("No instructions at this address");
            return;
        }

        let project = self.project.as_ref().unwrap();

        egui::ScrollArea::vertical().show_rows(ui, 18.0, total_rows, |ui, range| {
            for i in range {
                let insn = &self.disasm_cache[i];
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
                                egui::RichText::new(format!("; {}", c)).color(self.syntax.comment),
                            );
                        }
                    })
                    .response;

                let addr = insn.address;
                response.context_menu(|ui| {
                    if ui.button("Rename (N)").clicked() {
                        self.rename_active = true;
                        self.rename_input = String::new();
                        ui.close();
                    }
                    if ui.button("Comment (;)").clicked() {
                        self.comment_active = true;
                        if let Some(project) = &self.project {
                            self.comment_input =
                                project.comments.get(&addr).cloned().unwrap_or_default();
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
            }
        });
    }
}
