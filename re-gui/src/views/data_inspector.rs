use eframe::egui;
use re_core::types::{CompoundType, PrimitiveType, TypeRef};

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_data_inspector(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        // Header
        ui.horizontal(|ui| {
            ui.heading("Data Inspector");
            ui.add_space(8.0);
            ui.label(format!("{} overlays", project.struct_overlays.len()));
            ui.add_space(8.0);
            if ui.button("+ Add Overlay").clicked() {
                self.overlay_add_active = true;
                self.overlay_add_address = String::new();
                self.overlay_add_type = String::new();
                self.overlay_add_count = "1".into();
                self.overlay_add_label = String::new();
            }
        });
        ui.separator();

        if project.struct_overlays.is_empty() {
            ui.label(
                "No struct overlays. Click '+ Add Overlay' to apply a type to a memory region.",
            );
            self.show_add_overlay_dialog(ui.ctx());
            return;
        }

        let mut delete_idx = None;
        let mut navigate_to = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            let overlays = self.project.as_ref().unwrap().struct_overlays.to_vec();

            for (idx, overlay) in overlays.iter().enumerate() {
                let header = format!(
                    "{} @ 0x{:X} ({}[{}])",
                    overlay.label, overlay.address, overlay.type_name, overlay.count
                );

                ui.horizontal(|ui| {
                    let id = ui.make_persistent_id(format!("overlay_{}", idx));
                    egui::CollapsingHeader::new(
                        egui::RichText::new(&header)
                            .monospace()
                            .color(egui::Color32::from_rgb(0, 160, 80)),
                    )
                    .id_salt(id)
                    .show(ui, |ui| {
                        if ui.small_button("Delete").clicked() {
                            delete_idx = Some(idx);
                        }
                        ui.separator();

                        let project = self.project.as_ref().unwrap();

                        // Resolve the type
                        let compound = project.types.types.get(&overlay.type_name);
                        let fields = match compound {
                            Some(CompoundType::Struct { fields, .. })
                            | Some(CompoundType::Union { fields, .. }) => fields.clone(),
                            _ => {
                                ui.label(format!(
                                    "Type '{}' not found or not a struct/union",
                                    overlay.type_name
                                ));
                                return;
                            }
                        };

                        let struct_size = compound.map(|c| c.size(project.arch)).unwrap_or(0);

                        for elem_idx in 0..overlay.count {
                            if overlay.count > 1 {
                                ui.label(
                                    egui::RichText::new(format!("[{}]", elem_idx))
                                        .strong()
                                        .monospace(),
                                );
                            }
                            let elem_base = overlay.address + (elem_idx * struct_size) as u64;

                            for field in &fields {
                                let field_addr = elem_base + field.offset as u64;
                                let field_size = type_ref_size(&field.type_ref, project.arch);

                                let value_str = if field_size > 0 {
                                    if let Some(data) =
                                        project.memory_map.get_data(field_addr, field_size)
                                    {
                                        format_field_value(data, &field.type_ref, project.arch)
                                    } else {
                                        "??".to_string()
                                    }
                                } else {
                                    "??".to_string()
                                };

                                ui.horizontal(|ui| {
                                    ui.monospace(format!(
                                        "  +{:#04X}  {:12}  {:16}  = {}",
                                        field.offset,
                                        field.type_ref.display_name(),
                                        field.name,
                                        value_str,
                                    ));

                                    // If pointer field, allow navigation
                                    if is_pointer_type(&field.type_ref)
                                        && field_size > 0
                                        && let Some(data) =
                                            project.memory_map.get_data(field_addr, field_size)
                                    {
                                        let ptr_val = read_pointer(data, project.arch);
                                        if ui.small_button("Go").clicked() {
                                            navigate_to = Some(ptr_val);
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
            }
        });

        // Apply deferred actions
        if let Some(idx) = delete_idx
            && let Some(ref mut project) = self.project
            && idx < project.struct_overlays.len()
        {
            project.struct_overlays.remove(idx);
        }

        if let Some(addr) = navigate_to {
            self.current_address = addr;
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.update_cfg();
        }

        // Show add overlay dialog
        self.show_add_overlay_dialog(ui.ctx());
    }

    fn show_add_overlay_dialog(&mut self, ctx: &egui::Context) {
        if !self.overlay_add_active {
            return;
        }
        egui::Window::new("Add Struct Overlay")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Address:");
                    ui.text_edit_singleline(&mut self.overlay_add_address);
                });
                ui.horizontal(|ui| {
                    ui.label("Type:");
                    ui.text_edit_singleline(&mut self.overlay_add_type);
                });
                // Show available type names as suggestions
                if let Some(ref project) = self.project {
                    ui.horizontal_wrapped(|ui| {
                        let type_names: Vec<String> = project.types.types.keys().cloned().collect();
                        for name in &type_names {
                            if ui.small_button(name).clicked() {
                                self.overlay_add_type = name.clone();
                            }
                        }
                    });
                }
                ui.horizontal(|ui| {
                    ui.label("Count:");
                    ui.text_edit_singleline(&mut self.overlay_add_count);
                });
                ui.horizontal(|ui| {
                    ui.label("Label:");
                    ui.text_edit_singleline(&mut self.overlay_add_label);
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Add").clicked() {
                        if let Some(addr) = parse_hex_or_dec_u64(&self.overlay_add_address) {
                            let count: usize = self.overlay_add_count.parse().unwrap_or(1).max(1);
                            let label = if self.overlay_add_label.is_empty() {
                                format!("overlay_{:X}", addr)
                            } else {
                                self.overlay_add_label.clone()
                            };
                            let overlay = re_core::project::StructOverlay {
                                address: addr,
                                type_name: self.overlay_add_type.clone(),
                                count,
                                label,
                            };
                            if let Some(ref mut project) = self.project {
                                project.struct_overlays.push(overlay);
                            }
                        }
                        self.overlay_add_active = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.overlay_add_active = false;
                    }
                });
            });
    }
}

fn type_ref_size(type_ref: &TypeRef, arch: re_core::arch::Architecture) -> usize {
    type_ref.size(arch)
}

fn is_pointer_type(type_ref: &TypeRef) -> bool {
    matches!(
        type_ref,
        TypeRef::Pointer(_) | TypeRef::Primitive(PrimitiveType::Pointer)
    )
}

fn read_pointer(data: &[u8], arch: re_core::arch::Architecture) -> u64 {
    match arch.pointer_size() {
        4 if data.len() >= 4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64,
        8 if data.len() >= 8 => u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]),
        _ => 0,
    }
}

fn format_field_value(
    data: &[u8],
    type_ref: &TypeRef,
    arch: re_core::arch::Architecture,
) -> String {
    match type_ref {
        TypeRef::Primitive(prim) => match prim {
            PrimitiveType::U8 if !data.is_empty() => format!("{} (0x{:02X})", data[0], data[0]),
            PrimitiveType::I8 if !data.is_empty() => {
                format!("{} (0x{:02X})", data[0] as i8, data[0])
            }
            PrimitiveType::U16 if data.len() >= 2 => {
                let v = u16::from_le_bytes([data[0], data[1]]);
                format!("{} (0x{:04X})", v, v)
            }
            PrimitiveType::I16 if data.len() >= 2 => {
                let v = i16::from_le_bytes([data[0], data[1]]);
                format!("{} (0x{:04X})", v, v as u16)
            }
            PrimitiveType::U32 if data.len() >= 4 => {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("{} (0x{:08X})", v, v)
            }
            PrimitiveType::I32 if data.len() >= 4 => {
                let v = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("{} (0x{:08X})", v, v as u32)
            }
            PrimitiveType::U64 if data.len() >= 8 => {
                let v = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                format!("{} (0x{:016X})", v, v)
            }
            PrimitiveType::I64 if data.len() >= 8 => {
                let v = i64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                format!("{} (0x{:016X})", v, v as u64)
            }
            PrimitiveType::F32 if data.len() >= 4 => {
                let v = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("{:.6}", v)
            }
            PrimitiveType::F64 if data.len() >= 8 => {
                let v = f64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                format!("{:.6}", v)
            }
            PrimitiveType::Bool if !data.is_empty() => {
                format!("{}", data[0] != 0)
            }
            PrimitiveType::Char if !data.is_empty() => {
                let ch = data[0] as char;
                if ch.is_ascii_graphic() || ch == ' ' {
                    format!("'{}' (0x{:02X})", ch, data[0])
                } else {
                    format!("0x{:02X}", data[0])
                }
            }
            PrimitiveType::Pointer | PrimitiveType::USize | PrimitiveType::ISize => {
                let v = read_pointer(data, arch);
                format!("0x{:X}", v)
            }
            PrimitiveType::Void => "void".to_string(),
            _ => hex_dump(data),
        },
        TypeRef::Pointer(_) | TypeRef::FunctionPointer { .. } => {
            let v = read_pointer(data, arch);
            format!("0x{:X}", v)
        }
        _ => hex_dump(data),
    }
}

fn hex_dump(data: &[u8]) -> String {
    data.iter()
        .take(16)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_hex_or_dec_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
