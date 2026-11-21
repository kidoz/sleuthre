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
        if self.project.is_none() {
            let can_open = !self.is_loading();
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);
                ui.heading("No binary loaded");
                ui.add_space(8.0);
                if ui
                    .add_enabled(can_open, egui::Button::new("Open Binary…"))
                    .clicked()
                {
                    self.open_binary(ui.ctx());
                }
                self.raw_image_button(ui);
                if ui
                    .add_enabled(can_open, egui::Button::new("Load Project…"))
                    .clicked()
                {
                    self.load_project();
                }
            });
            return;
        }
        if self.disasm.is_none() {
            ui.label("Disassembly is unavailable for this architecture.");
            return;
        }

        self.ensure_disasm_cache();

        let total_rows = self.disasm_cache.len();
        if total_rows == 0 {
            ui.label("No instructions at this address");
            return;
        }

        let project = self
            .project
            .as_ref()
            .expect("project presence checked at the top of show_disassembly");

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

                let addr = insn.address;
                let selected = self.focused_address.unwrap_or(self.current_address) == addr;
                let full_bytes = insn
                    .bytes
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let preview = if insn.bytes.len() > 6 {
                    format!("{}…", &full_bytes[..17])
                } else {
                    full_bytes.clone()
                };
                let op_color = if insn.op_str.starts_with("0x")
                    || insn.op_str.starts_with(|c: char| c.is_ascii_digit())
                {
                    self.syntax.number
                } else {
                    self.syntax.text
                };
                let mut row = egui::text::LayoutJob::default();
                let font = egui::TextStyle::Monospace.resolve(ui.style());
                let mut append = |text: &str, color| {
                    row.append(text, 0.0, egui::TextFormat::simple(font.clone(), color));
                };
                append(&format!("{addr:08X}  "), self.syntax.address);
                append(&format!("{preview:<18} "), self.syntax.bytes);
                append(&insn.mnemonic, mnemonic_color);
                append(&format!(" {}", insn.op_str), op_color);
                if let Some(comment) = project.comments.get(&addr) {
                    append(&format!("  ; {comment}"), self.syntax.comment);
                }
                let mut button = egui::Button::selectable(selected, (row, egui::Atom::grow()))
                    .min_size(egui::vec2(ui.available_width(), 18.0))
                    .truncate();
                if selected {
                    button = button
                        .fill(self.syntax.selection_bg)
                        .stroke(egui::Stroke::new(1.0, self.syntax.link));
                }
                let response = ui.add(button);
                if response.clicked() || response.secondary_clicked() {
                    self.focused_address = Some(addr);
                }
                let response = if insn.bytes.len() > 6 {
                    response.on_hover_text(&full_bytes)
                } else {
                    response
                };

                response.context_menu(|ui| {
                    if ui.button("Copy instruction bytes").clicked() {
                        ui.ctx().copy_text(full_bytes.clone());
                        ui.close();
                    }
                    if ui.button("Rename (N)").clicked() {
                        self.rename_address = Some(addr);
                        self.rename_input.clear();
                        ui.close();
                    }
                    if ui.button("Comment (;)").clicked() {
                        self.comment_address = Some(addr);
                        self.comment_input =
                            project.comments.get(&addr).cloned().unwrap_or_default();
                        ui.close();
                    }
                    if ui.button("Xrefs (X)").clicked() {
                        self.xref_address = Some(addr);
                        ui.close();
                    }
                    if ui.button("Decompile (F5)").clicked() {
                        self.focused_address = Some(addr);
                        self.trigger_decompile = true;
                        ui.close();
                    }
                    if ui.button("Show Inference Evidence").clicked() {
                        // Pre-filter the panel to the function containing this
                        // instruction (fall back to the raw address).
                        self.inference_filter = project
                            .functions
                            .find_function_containing(addr)
                            .map(|start| format!("{:x}", start))
                            .unwrap_or_else(|| format!("{:x}", addr));
                        self.trigger_inference_view = true;
                        ui.close();
                    }
                    // Debugger integrations only appear when a remote is
                    // connected — keeps the menu uncluttered for static-only
                    // sessions. We can't borrow `self` mutably here (the
                    // outer scroll closure already holds it), so we defer the
                    // intent into a flag the post-closure handler reads.
                    if self.debugger_remote.is_some() {
                        ui.separator();
                        if ui.button("Set Breakpoint Here").clicked() {
                            self.pending_bp_set = Some((addr, false));
                            ui.close();
                        }
                        if ui.button("Set Hardware BP Here").clicked() {
                            self.pending_bp_set = Some((addr, true));
                            ui.close();
                        }
                    }
                });
            }
        });

        if let Some((addr, hardware)) = self.pending_bp_set.take() {
            self.debugger_bp_input = format!("0x{:x}", addr);
            self.debugger_set_breakpoint(hardware);
        }
    }
}
