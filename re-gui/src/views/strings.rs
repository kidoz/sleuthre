use eframe::egui;
use re_core::analysis::strings::StringEncoding;

use crate::app::{SleuthreApp, Tab};

impl SleuthreApp {
    pub(crate) fn show_strings(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.string_filter);
            ui.label(format!("{} strings", project.strings.strings.len()));
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.monospace(
                egui::RichText::new(format!(
                    "{:<10} {:<6} {:<8} {}",
                    "Address", "Len", "Encoding", "Value"
                ))
                .strong(),
            );
        });
        ui.separator();

        let mut jump_to = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for s in &project.strings.strings {
                if !self.string_filter.is_empty()
                    && !s
                        .value
                        .to_lowercase()
                        .contains(&self.string_filter.to_lowercase())
                {
                    continue;
                }

                let enc = match s.encoding {
                    StringEncoding::Ascii => "ASCII",
                    StringEncoding::Utf16Le => "UTF16LE",
                    StringEncoding::Utf16Be => "UTF16BE",
                };

                let display_val = if s.value.len() > 80 {
                    format!("{}...", &s.value[..80])
                } else {
                    s.value.clone()
                };

                let response = ui.horizontal(|ui| {
                    if ui
                        .monospace(
                            egui::RichText::new(format!("{:08X}", s.address))
                                .color(self.syntax.link),
                        )
                        .clicked()
                    {
                        jump_to = Some(s.address);
                    }
                    ui.monospace(format!("{:<6}", s.length));
                    ui.monospace(enc);
                    ui.add_space(8.0);
                    ui.monospace(&display_val);
                });
                response.response.on_hover_text(&s.value);
            }
        });

        if let Some(addr) = jump_to {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.active_tab = Tab::HexView;
        }
    }
}
