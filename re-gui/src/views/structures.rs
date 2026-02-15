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
                    ty.size()
                );
                egui::CollapsingHeader::new(
                    egui::RichText::new(&header)
                        .monospace()
                        .color(egui::Color32::from_rgb(0, 80, 160)),
                )
                .show(ui, |ui| match ty {
                    CompoundType::Struct { fields, .. } | CompoundType::Union { fields, .. } => {
                        for field in fields {
                            ui.monospace(format!(
                                "  +{:#04X}  {}  {}",
                                field.offset,
                                field.type_ref.display_name(),
                                field.name
                            ));
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
