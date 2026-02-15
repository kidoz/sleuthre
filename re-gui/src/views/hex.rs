use eframe::egui;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_hex_view(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        let segment = project
            .memory_map
            .segments
            .iter()
            .find(|s| self.current_address >= s.start && self.current_address < s.start + s.size)
            .or_else(|| project.memory_map.segments.first());

        let segment = match segment {
            Some(s) => s,
            None => {
                ui.label("No memory segments loaded");
                return;
            }
        };

        let bytes_per_row = 16usize;
        let total_rows = segment.data.len().div_ceil(bytes_per_row);

        egui::ScrollArea::vertical().show_rows(ui, 18.0, total_rows, |ui, range| {
            for row in range {
                let offset = row * bytes_per_row;
                let addr = segment.start + offset as u64;
                let end = (offset + bytes_per_row).min(segment.data.len());
                let row_data = &segment.data[offset..end];

                ui.horizontal(|ui| {
                    ui.monospace(
                        egui::RichText::new(format!("{:08X}  ", addr)).color(self.syntax.address),
                    );

                    let mut hex = String::with_capacity(bytes_per_row * 3);
                    for (i, &byte) in row_data.iter().enumerate() {
                        hex.push_str(&format!("{:02X} ", byte));
                        if i == 7 {
                            hex.push(' ');
                        }
                    }
                    for i in row_data.len()..bytes_per_row {
                        hex.push_str("   ");
                        if i == 7 {
                            hex.push(' ');
                        }
                    }
                    ui.monospace(&hex);

                    ui.add_space(4.0);

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
    }
}
