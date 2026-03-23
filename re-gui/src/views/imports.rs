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

        let filter_lower = self.import_filter.to_lowercase();
        let filtered: Vec<usize> = project
            .imports
            .iter()
            .enumerate()
            .filter(|(_, imp)| {
                filter_lower.is_empty()
                    || imp.name.to_lowercase().contains(&filter_lower)
                    || imp.library.to_lowercase().contains(&filter_lower)
            })
            .map(|(i, _)| i)
            .collect();

        let row_height = 18.0;
        let total = filtered.len();
        egui::ScrollArea::vertical().show_rows(ui, row_height, total, |ui, range| {
            for &idx in &filtered[range] {
                let imp = &project.imports[idx];
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
            self.focus_or_open_tab(Tab::Disassembly);
            self.update_cfg();
        }
    }
}
