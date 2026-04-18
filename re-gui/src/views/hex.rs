use eframe::egui;
use re_core::types::CompoundType;

use crate::app::SleuthreApp;

/// A resolved overlay field range in absolute address space.
struct OverlayFieldRange {
    start: u64,
    end: u64,
    label: String,
    field_name: String,
    tint: egui::Color32,
}

fn overlay_field_ranges(project: &re_core::project::Project) -> Vec<OverlayFieldRange> {
    let palette = [
        egui::Color32::from_rgba_unmultiplied(255, 180, 100, 40),
        egui::Color32::from_rgba_unmultiplied(100, 200, 255, 40),
        egui::Color32::from_rgba_unmultiplied(180, 255, 120, 40),
        egui::Color32::from_rgba_unmultiplied(255, 140, 200, 40),
        egui::Color32::from_rgba_unmultiplied(200, 160, 255, 40),
    ];
    let mut ranges = Vec::new();
    for (ov_idx, overlay) in project.struct_overlays.iter().enumerate() {
        let tint = palette[ov_idx % palette.len()];
        let compound = project.types.types.get(&overlay.type_name);
        let (fields, struct_size) = match compound {
            Some(CompoundType::Struct { fields, .. })
            | Some(CompoundType::Union { fields, .. }) => {
                (fields.clone(), compound.unwrap().size(project.arch))
            }
            _ => continue,
        };
        for elem_idx in 0..overlay.count {
            let elem_base = overlay.address + (elem_idx * struct_size) as u64;
            for field in &fields {
                let start = elem_base + field.offset as u64;
                let end = start + field.type_ref.size(project.arch) as u64;
                ranges.push(OverlayFieldRange {
                    start,
                    end,
                    label: overlay.label.clone(),
                    field_name: field.name.clone(),
                    tint,
                });
            }
        }
    }
    ranges
}

impl SleuthreApp {
    pub(crate) fn show_hex_view(&mut self, ui: &mut egui::Ui) {
        if self.project.is_none() {
            ui.label("No binary loaded");
            return;
        }

        // Global Variables panel (overlays quick-jump).
        let jump_target = self.draw_global_variables_panel(ui);
        if let Some(addr) = jump_target {
            self.current_address = addr;
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.update_cfg();
        }

        let overlay_ranges = self
            .project
            .as_ref()
            .map(overlay_field_ranges)
            .unwrap_or_default();

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
                        let overlay = overlay_ranges
                            .iter()
                            .find(|r| byte_addr >= r.start && byte_addr < r.end);

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
                            let rich = egui::RichText::new(text).monospace().color(color);
                            // Wrap in a colored frame when inside an overlay field.
                            let response = if let Some(ov) = overlay {
                                egui::Frame::new()
                                    .fill(ov.tint)
                                    .show(ui, |ui| ui.selectable_label(false, rich))
                                    .inner
                            } else {
                                ui.selectable_label(false, rich)
                            };
                            if let Some(ov) = overlay {
                                response.on_hover_text(format!(
                                    "{}::{}  (0x{:X}..0x{:X})",
                                    ov.label, ov.field_name, ov.start, ov.end
                                ));
                            } else if response.clicked() {
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

    /// Render a compact "Global Variables" chip-bar of struct overlays.
    /// Returns `Some(address)` if the user clicked a chip to jump.
    fn draw_global_variables_panel(&self, ui: &mut egui::Ui) -> Option<u64> {
        let project = self.project.as_ref()?;
        if project.struct_overlays.is_empty() {
            return None;
        }
        let mut jump = None;
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new("Globals:")
                    .size(10.0)
                    .color(egui::Color32::GRAY),
            );
            for overlay in &project.struct_overlays {
                let chip = format!("{} @ 0x{:X}", overlay.label, overlay.address);
                if ui.small_button(chip).clicked() {
                    jump = Some(overlay.address);
                }
            }
        });
        ui.separator();
        jump
    }
}
