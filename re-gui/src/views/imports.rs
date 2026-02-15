use eframe::egui;

use crate::app::{SleuthreApp, Tab};

impl SleuthreApp {
    pub(crate) fn show_imports(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.import_filter);
            ui.label(format!("{} imports", project.imports.len()));
            if !project.libraries.is_empty() {
                ui.label(format!("from {} libraries", project.libraries.len()));
            }
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.monospace(
                egui::RichText::new(format!("{:<10} {:<30} {}", "Address", "Name", "Library"))
                    .strong(),
            );
        });
        ui.separator();

        let mut jump_to = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for imp in &project.imports {
                if !self.import_filter.is_empty()
                    && !imp
                        .name
                        .to_lowercase()
                        .contains(&self.import_filter.to_lowercase())
                    && !imp
                        .library
                        .to_lowercase()
                        .contains(&self.import_filter.to_lowercase())
                {
                    continue;
                }

                ui.horizontal(|ui| {
                    if ui
                        .monospace(
                            egui::RichText::new(format!("{:08X}", imp.address))
                                .color(self.syntax.link),
                        )
                        .clicked()
                    {
                        jump_to = Some(imp.address);
                    }
                    ui.monospace(
                        egui::RichText::new(&imp.name).color(egui::Color32::from_rgb(0, 0, 180)),
                    );
                    if !imp.library.is_empty() {
                        ui.monospace(egui::RichText::new(&imp.library).color(egui::Color32::GRAY));
                    }
                });
            }
        });

        if let Some(addr) = jump_to {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.active_tab = Tab::Disassembly;
            self.update_cfg();
        }
    }
}
