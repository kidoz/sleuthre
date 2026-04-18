use eframe::egui;
use re_core::formats::image::DecodedImage;

use crate::app::{SleuthreApp, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_image_preview(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Image Preview");
            ui.add_space(16.0);
            if ui.button("Open Image...").clicked() {
                self.open_image_file();
            }
            if ui.button("Open Folder (Thumbnails)...").clicked() {
                self.open_image_folder();
            }
            if !self.image_preview_slots.is_empty() && ui.button("Clear").clicked() {
                self.image_preview_slots.clear();
                self.image_preview_selected = None;
            }
        });
        ui.separator();

        if self.image_preview_slots.is_empty() {
            ui.label("Open an image file or a folder of images to preview.");
            return;
        }

        let avail = ui.available_size();

        ui.horizontal(|ui| {
            // Left: thumbnail grid (click to select).
            ui.vertical(|ui| {
                ui.set_width((avail.x * 0.25).max(140.0));
                ui.label(
                    egui::RichText::new(format!("{} images", self.image_preview_slots.len()))
                        .size(10.0)
                        .color(egui::Color32::GRAY),
                );
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("image_preview_thumbs")
                    .show(ui, |ui| {
                        let indices: Vec<usize> = (0..self.image_preview_slots.len()).collect();
                        let selected = self.image_preview_selected;
                        for idx in indices {
                            let slot = &self.image_preview_slots[idx];
                            let is_selected = selected == Some(idx);
                            let caption = format!(
                                "{}\n{}x{}",
                                slot.name, slot.image.width, slot.image.height
                            );
                            if ui
                                .selectable_label(
                                    is_selected,
                                    egui::RichText::new(caption).size(10.0).monospace(),
                                )
                                .clicked()
                            {
                                self.image_preview_selected = Some(idx);
                                self.image_zoom = 1.0;
                                self.image_pan = egui::Vec2::ZERO;
                            }
                        }
                    });
            });

            ui.separator();

            // Right: selected image + controls + palette + pixel inspector.
            ui.vertical(|ui| {
                let Some(idx) = self.image_preview_selected else {
                    ui.label("Select an image.");
                    return;
                };
                let Some(slot) = self.image_preview_slots.get(idx) else {
                    return;
                };

                let (w, h) = (slot.image.width as f32, slot.image.height as f32);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&slot.name).strong().size(12.0));
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "{}×{}  |  {} KB  |  {} pixels",
                            slot.image.width,
                            slot.image.height,
                            slot.raw_bytes / 1024,
                            slot.image.width * slot.image.height,
                        ))
                        .size(10.0)
                        .color(egui::Color32::GRAY),
                    );
                });

                ui.horizontal(|ui| {
                    if ui.button("−").clicked() {
                        self.image_zoom = (self.image_zoom * 0.8).max(0.1);
                    }
                    if ui.button("Reset").clicked() {
                        self.image_zoom = 1.0;
                        self.image_pan = egui::Vec2::ZERO;
                    }
                    if ui.button("+").clicked() {
                        self.image_zoom = (self.image_zoom * 1.25).min(32.0);
                    }
                    ui.add(
                        egui::DragValue::new(&mut self.image_zoom)
                            .speed(0.1)
                            .range(0.1..=32.0)
                            .prefix("zoom: ")
                            .fixed_decimals(2),
                    );
                });

                ui.separator();

                let image_area = ui.available_size() - egui::vec2(0.0, 140.0);
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(image_area.x.max(100.0), image_area.y.max(100.0)),
                    egui::Sense::click_and_drag(),
                );

                // Handle pan.
                if response.dragged() {
                    self.image_pan += response.drag_delta();
                }
                // Handle zoom via scroll.
                if response.hovered() {
                    let scroll = ui.input(|i| i.smooth_scroll_delta.y);
                    if scroll != 0.0 {
                        self.image_zoom =
                            (self.image_zoom * (1.0 + scroll * 0.002)).clamp(0.1, 32.0);
                    }
                }

                let painter = ui.painter_at(rect);
                painter.rect_filled(rect, 0.0, egui::Color32::from_gray(20));

                let draw_size = egui::vec2(w * self.image_zoom, h * self.image_zoom);
                let center = rect.center() + self.image_pan;
                let draw_rect = egui::Rect::from_center_size(center, draw_size);

                if let Some(tex) = &slot.texture {
                    let uv = egui::Rect::from_min_max(
                        egui::pos2(0.0_f32, 0.0_f32),
                        egui::pos2(1.0_f32, 1.0_f32),
                    );
                    let mut mesh = egui::Mesh::with_texture(tex.id());
                    mesh.add_rect_with_uv(draw_rect, uv, egui::Color32::WHITE);
                    painter.add(egui::Shape::mesh(mesh));
                }

                // Pixel inspector on hover.
                let mut inspector: Option<(u32, u32, [u8; 4])> = None;
                if let Some(hover_pos) = response.hover_pos() {
                    let img_x = ((hover_pos.x - draw_rect.left()) / self.image_zoom) as i32;
                    let img_y = ((hover_pos.y - draw_rect.top()) / self.image_zoom) as i32;
                    if img_x >= 0
                        && img_y >= 0
                        && (img_x as u32) < slot.image.width
                        && (img_y as u32) < slot.image.height
                    {
                        let pix_off =
                            ((img_y as u32) * slot.image.width + img_x as u32) as usize * 4;
                        if pix_off + 4 <= slot.image.pixels.len() {
                            let px = [
                                slot.image.pixels[pix_off],
                                slot.image.pixels[pix_off + 1],
                                slot.image.pixels[pix_off + 2],
                                slot.image.pixels[pix_off + 3],
                            ];
                            inspector = Some((img_x as u32, img_y as u32, px));
                        }
                    }
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if let Some((x, y, rgba)) = inspector {
                        let color = egui::Color32::from_rgba_unmultiplied(
                            rgba[0], rgba[1], rgba[2], rgba[3],
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "px({}, {}) = #{:02X}{:02X}{:02X}{:02X}",
                                x, y, rgba[0], rgba[1], rgba[2], rgba[3]
                            ))
                            .monospace()
                            .size(11.0),
                        );
                        let (swatch, _) =
                            ui.allocate_exact_size(egui::vec2(18.0, 14.0), egui::Sense::hover());
                        ui.painter().rect_filled(swatch, 2.0, color);
                    } else {
                        ui.label(
                            egui::RichText::new("Hover over image to inspect pixel.")
                                .size(10.0)
                                .color(egui::Color32::GRAY),
                        );
                    }
                });

                // Palette panel (if present).
                if let Some(ref palette) = slot.image.palette {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("Palette ({} entries)", palette.len()))
                            .size(10.0)
                            .color(egui::Color32::GRAY),
                    );
                    egui::ScrollArea::horizontal()
                        .id_salt("image_preview_palette")
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                for (i, entry) in palette.iter().enumerate().take(256) {
                                    let color =
                                        egui::Color32::from_rgb(entry[0], entry[1], entry[2]);
                                    let (r, _) = ui.allocate_exact_size(
                                        egui::vec2(10.0, 10.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().rect_filled(r, 0.0, color);
                                    if i % 32 == 31 {
                                        ui.end_row();
                                    }
                                }
                            });
                        });
                }
            });
        });
    }

    fn open_image_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Images", &["bmp", "tga", "pcx"])
            .pick_file()
        else {
            return;
        };
        self.load_image_path(&path);
    }

    fn open_image_folder(&mut self) {
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        let mut count = 0usize;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Some(ext) = path.extension().and_then(|e| e.to_str())
                {
                    let lower = ext.to_lowercase();
                    if lower == "bmp" || lower == "tga" || lower == "pcx" {
                        self.load_image_path(&path);
                        count += 1;
                        if count >= 128 {
                            break;
                        }
                    }
                }
            }
        }
        self.add_toast(
            ToastKind::Success,
            format!("Loaded {} images from '{}'", count, dir.display()),
        );
    }

    fn load_image_path(&mut self, path: &std::path::Path) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Read error: {}", e));
                return;
            }
        };
        let ctx_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let raw_bytes = data.len();
        let Some(image) = self.archive_image_registry.decode(&data, &ctx_name) else {
            self.add_toast(ToastKind::Error, format!("No decoder for '{}'", ctx_name));
            return;
        };
        self.image_preview_slots.push(crate::app::ImagePreviewSlot {
            name: ctx_name,
            image,
            raw_bytes,
            texture: None,
        });
        let new_idx = self.image_preview_slots.len() - 1;
        self.image_preview_selected = Some(new_idx);
        self.image_zoom = 1.0;
        self.image_pan = egui::Vec2::ZERO;
    }

    /// Ensure selected image has a GPU texture. Called each frame before painting.
    pub(crate) fn ensure_image_textures(&mut self, ctx: &egui::Context) {
        for (i, slot) in self.image_preview_slots.iter_mut().enumerate() {
            if slot.texture.is_none() {
                let color = egui::ColorImage::from_rgba_unmultiplied(
                    [slot.image.width as usize, slot.image.height as usize],
                    &slot.image.pixels,
                );
                let tex = ctx.load_texture(
                    format!("image_slot_{}", i),
                    color,
                    egui::TextureOptions::NEAREST,
                );
                slot.texture = Some(tex);
            }
        }
    }
}

/// Storage for a single loaded image in the preview pane.
pub(crate) struct ImagePreviewSlot {
    pub(crate) name: String,
    pub(crate) image: DecodedImage,
    pub(crate) raw_bytes: usize,
    pub(crate) texture: Option<egui::TextureHandle>,
}
