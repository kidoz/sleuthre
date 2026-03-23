use eframe::egui;

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_entropy(&mut self, ui: &mut egui::Ui) {
        let Some(ref entropy_map) = self.entropy_map else {
            ui.centered_and_justified(|ui| {
                ui.label("Load a binary to view entropy analysis.");
            });
            return;
        };

        if entropy_map.samples.is_empty() {
            ui.label("No entropy data available.");
            return;
        }

        // Legend
        ui.horizontal(|ui| {
            ui.label("Entropy: ");
            let legend = [
                ("Low (data/padding)", egui::Color32::from_rgb(50, 80, 180)),
                ("Medium (code)", egui::Color32::from_rgb(50, 180, 80)),
                (
                    "High (packed/encrypted)",
                    egui::Color32::from_rgb(220, 60, 60),
                ),
            ];
            for (label, color) in legend {
                ui.label(egui::RichText::new("  ").background_color(color));
                ui.label(egui::RichText::new(label).size(10.0));
                ui.add_space(8.0);
            }
        });
        ui.separator();

        let total = entropy_map.samples.len();
        let avail = ui.available_size();
        let bar_height = (avail.y - 60.0).max(100.0);

        // Summary stats
        let avg_entropy: f64 =
            entropy_map.samples.iter().map(|s| s.entropy).sum::<f64>() / total as f64;
        let max_entropy = entropy_map
            .samples
            .iter()
            .map(|s| s.entropy)
            .fold(0.0f64, f64::max);
        ui.label(
            egui::RichText::new(format!(
                "{} samples | avg: {:.2} | max: {:.2} | range: {:08X}-{:08X}",
                total, avg_entropy, max_entropy, entropy_map.min_address, entropy_map.max_address,
            ))
            .size(10.0)
            .color(egui::Color32::GRAY),
        );

        // Draw entropy bars
        let (response, painter) =
            ui.allocate_painter(egui::vec2(avail.x, bar_height), egui::Sense::click());
        let rect = response.rect;

        let bar_width = if total > 0 {
            (rect.width() / total as f32).max(1.0)
        } else {
            1.0
        };

        for (i, sample) in entropy_map.samples.iter().enumerate() {
            let x = rect.left() + i as f32 * bar_width;
            let norm = (sample.entropy as f32 / 8.0).clamp(0.0, 1.0);
            let height = norm * rect.height();
            let color = entropy_color(norm);

            let bar_rect = egui::Rect::from_min_max(
                egui::pos2(x, rect.bottom() - height),
                egui::pos2((x + bar_width).min(rect.right()), rect.bottom()),
            );
            painter.rect_filled(bar_rect, 0.0, color);
        }

        // Draw baseline
        painter.line_segment(
            [
                egui::pos2(rect.left(), rect.bottom()),
                egui::pos2(rect.right(), rect.bottom()),
            ],
            egui::Stroke::new(1.0, egui::Color32::GRAY),
        );

        // Hover tooltip — collect data before any mutable borrow
        let mut hover_info = None;
        let mut click_addr = None;

        if response.hovered()
            && let Some(pos) = ui.input(|i| i.pointer.hover_pos())
        {
            let rel_x = (pos.x - rect.left()) / rect.width();
            let idx = ((rel_x * total as f32) as usize).min(total.saturating_sub(1));
            let sample = &entropy_map.samples[idx];
            let classification = if sample.entropy < 2.0 {
                "padding/data"
            } else if sample.entropy < 5.5 {
                "code/structured"
            } else if sample.entropy < 7.0 {
                "compressed/dense"
            } else {
                "encrypted/packed"
            };
            hover_info = Some(format!(
                "Address: {:08X}\nEntropy: {:.3}\nClass: {}",
                sample.address, sample.entropy, classification,
            ));
        }

        if response.clicked()
            && let Some(pos) = response.interact_pointer_pos()
        {
            let rel_x = (pos.x - rect.left()) / rect.width();
            let idx = ((rel_x * total as f32) as usize).min(total.saturating_sub(1));
            click_addr = Some(entropy_map.samples[idx].address);
        }

        // Now render tooltip (no borrow on self.entropy_map needed)
        if let Some(info) = hover_info {
            response.on_hover_ui(|ui| {
                ui.label(info);
            });
        }

        // Handle click navigation (needs &mut self)
        if let Some(addr) = click_addr {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.update_cfg();
        }
    }
}

fn entropy_color(normalized: f32) -> egui::Color32 {
    if normalized < 0.35 {
        let t = normalized / 0.35;
        egui::Color32::from_rgb(
            (50.0 + t * 0.0) as u8,
            (80.0 + t * 100.0) as u8,
            (180.0 - t * 100.0) as u8,
        )
    } else if normalized < 0.7 {
        let t = (normalized - 0.35) / 0.35;
        egui::Color32::from_rgb(
            (50.0 + t * 170.0) as u8,
            (180.0 - t * 120.0) as u8,
            (80.0 - t * 60.0) as u8,
        )
    } else {
        let t = (normalized - 0.7) / 0.3;
        egui::Color32::from_rgb(
            (220.0 + t * 35.0).min(255.0) as u8,
            (60.0 - t * 40.0).max(20.0) as u8,
            (20.0 + t * 10.0) as u8,
        )
    }
}
