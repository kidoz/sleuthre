use eframe::egui;

use crate::app::{SleuthreApp, Tab};

impl SleuthreApp {
    pub(crate) fn show_exports(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.export_filter);
            ui.label(format!("{} exports", project.exports.len()));
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.monospace(egui::RichText::new(format!("{:<10} {}", "Address", "Name")).strong());
        });
        ui.separator();

        let mut jump_to = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for exp in &project.exports {
                if !self.export_filter.is_empty()
                    && !exp
                        .name
                        .to_lowercase()
                        .contains(&self.export_filter.to_lowercase())
                {
                    continue;
                }

                ui.horizontal(|ui| {
                    if ui
                        .monospace(
                            egui::RichText::new(format!("{:08X}", exp.address))
                                .color(self.syntax.link),
                        )
                        .clicked()
                    {
                        jump_to = Some(exp.address);
                    }
                    ui.monospace(
                        egui::RichText::new(&exp.name).color(egui::Color32::from_rgb(0, 120, 0)),
                    );
                });
            }
        });

        if let Some(addr) = jump_to {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.focus_or_open_tab(Tab::Disassembly);
            self.update_cfg();
        }
    }
}
