use eframe::egui;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_hex_view(&mut self, ui: &mut egui::Ui) {
        if self.project.is_none() {
            ui.label("No binary loaded");
            return;
        }

        let bytes_per_row = 16usize;
        let (total_rows, start_addr) = {
            let project = self.project.as_ref().unwrap();
            let segment = project
                .memory_map
                .segments
                .iter()
                .find(|s| {
                    self.current_address >= s.start && self.current_address < s.start + s.size
                })
                .or_else(|| project.memory_map.segments.first());

            let segment = match segment {
                Some(s) => s,
                None => {
                    ui.label("No memory segments loaded");
                    return;
                }
            };
            (segment.data.len().div_ceil(bytes_per_row), segment.start)
        };

        let mut patch_request = None;
        let mut select_request = None;

        // Identify the segment once for zero-copy row access
        let seg_idx = self
            .project
            .as_ref()
            .and_then(|p| {
                p.memory_map
                    .segments
                    .iter()
                    .position(|s| start_addr >= s.start && start_addr < s.start + s.size)
            })
            .unwrap_or(0);

        egui::ScrollArea::vertical().show_rows(ui, 18.0, total_rows, |ui, range| {
            let seg_data = self
                .project
                .as_ref()
                .and_then(|p| p.memory_map.segments.get(seg_idx))
                .map(|s| &s.data[..]);

            for row in range {
                let offset = row * bytes_per_row;
                let addr = start_addr + offset as u64;

                let row_data: &[u8] = seg_data
                    .and_then(|data| {
                        let end = (offset + bytes_per_row).min(data.len());
                        data.get(offset..end)
                    })
                    .unwrap_or(&[]);

                ui.horizontal(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 2.0;
                    ui.monospace(
                        egui::RichText::new(format!("{:08X}  ", addr)).color(self.syntax.address),
                    );

                    for (i, &byte) in row_data.iter().enumerate() {
                        let byte_addr = addr + i as u64;
                        let is_selected = self.hex_selected_addr == Some(byte_addr);

                        if is_selected {
                            let mut buf = self.hex_edit_buffer.clone();
                            let response = ui.add(
                                egui::TextEdit::singleline(&mut buf)
                                    .desired_width(20.0)
                                    .font(egui::FontId::monospace(12.0)),
                            );
                            response.request_focus();

                            if response.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                if let Ok(val) = u8::from_str_radix(&buf, 16) {
                                    patch_request = Some((byte_addr, val));
                                }
                                select_request = Some(None);
                            }
                            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                select_request = Some(None);
                            }
                        } else {
                            let text = format!("{:02X}", byte);
                            let color = if byte == 0 {
                                self.syntax.bytes
                            } else {
                                self.syntax.text
                            };
                            if ui
                                .selectable_label(
                                    false,
                                    egui::RichText::new(text).monospace().color(color),
                                )
                                .clicked()
                            {
                                select_request = Some(Some((byte_addr, format!("{:02X}", byte))));
                            }
                        }

                        if i == 7 {
                            ui.label(" ");
                        }
                    }

                    if row_data.len() < bytes_per_row {
                        for i in row_data.len()..bytes_per_row {
                            ui.label("   ");
                            if i == 7 {
                                ui.label(" ");
                            }
                        }
                    }

                    ui.add_space(8.0);

                    let ascii: String = row_data
                        .iter()
                        .map(|&b| {
                            if (0x20..=0x7E).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    ui.monospace(egui::RichText::new(ascii).color(self.syntax.ascii_text));
                });
            }
        });

        if let Some(req) = select_request {
            if let Some((addr, buf)) = req {
                self.hex_selected_addr = Some(addr);
                self.hex_edit_buffer = buf;
            } else {
                self.hex_selected_addr = None;
            }
        }

        if let Some((addr, val)) = patch_request
            && let Some(ref mut project) = self.project
        {
            let old_byte = project.memory_map.get_data(addr, 1).unwrap_or(&[0])[0];
            project.execute(re_core::project::UndoCommand::PatchMemory {
                address: addr,
                old_bytes: vec![old_byte],
                new_bytes: vec![val],
            });
            self.add_toast(
                crate::app::ToastKind::Success,
                format!("Patched 0x{:X}", addr),
            );
        }
    }
}
