use eframe::egui;
use re_core::types::CompoundType;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_structures(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.structure_filter);
            ui.label(format!("{} types", project.types.types.len()));
            ui.add_space(8.0);
            if ui.button("+ New Struct").clicked() {
                self.create_struct_active = true;
                self.new_struct_name = "NewStruct".into();
            }
        });
        ui.separator();

        if project.types.types.is_empty() {
            ui.label(
                "No user-defined types. Types can be added via the MCP server or project file.",
            );
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for ty in project.types.types.values() {
                if !self.structure_filter.is_empty()
                    && !ty
                        .name()
                        .to_lowercase()
                        .contains(&self.structure_filter.to_lowercase())
                {
                    continue;
                }

                let header = format!(
                    "{} {} (size: {} bytes)",
                    ty.kind_name(),
                    ty.name(),
                    ty.size(project.arch)
                );
                egui::CollapsingHeader::new(
                    egui::RichText::new(&header)
                        .monospace()
                        .color(egui::Color32::from_rgb(0, 80, 160)),
                )
                .show(ui, |ui| match ty {
                    CompoundType::Struct { fields, name, .. }
                    | CompoundType::Union { fields, name, .. } => {
                        for field in fields {
                            ui.monospace(format!(
                                "  +{:#04X}  {}  {}",
                                field.offset,
                                field.type_ref.display_name(),
                                field.name
                            ));
                        }
                        if ui.button("+ Add Field").clicked() {
                            self.editing_struct = Some(name.clone());
                            self.new_field_name = format!("field_{}", fields.len());
                            self.new_field_offset = fields
                                .last()
                                .map(|f| format!("{:#X}", f.offset + 4))
                                .unwrap_or("0x0".into());
                            self.new_field_type = "int32_t".into();
                        }
                    }
                    CompoundType::Enum { variants, .. } => {
                        for (name, val) in variants {
                            ui.monospace(format!("  {} = {}", name, val));
                        }
                    }
                    CompoundType::Typedef { target, .. } => {
                        ui.monospace(format!("  -> {}", target.display_name()));
                    }
                });
            }
        });
    }
}
