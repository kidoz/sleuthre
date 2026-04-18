use eframe::egui;
use re_core::formats::archive::ArchiveEntryType;

use crate::app::{SleuthreApp, ToastKind};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreviewKind {
    Image,
    Table,
    Text,
    Hex,
}

fn classify_preview(name: &str, data: &[u8]) -> PreviewKind {
    let lower = name.to_lowercase();
    if lower.ends_with(".bmp")
        || lower.ends_with(".tga")
        || lower.ends_with(".pcx")
        || (data.len() >= 2 && &data[..2] == b"BM")
        || (data.len() >= 4 && data[0] == 0x0A && data[3] == 8)
    {
        return PreviewKind::Image;
    }
    if lower.ends_with(".csv") || lower.ends_with(".tsv") || lower.ends_with(".tab") {
        return PreviewKind::Table;
    }
    let sample_len = data.len().min(256);
    let printable = data[..sample_len]
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7E).contains(&b))
        .count();
    if sample_len > 0 && printable * 10 >= sample_len * 9 {
        PreviewKind::Text
    } else {
        PreviewKind::Hex
    }
}

/// Parse CSV/TSV content into a TabularData preview (first 100 rows).
fn parse_tabular_preview(content: &str) -> Option<crate::app::TabularData> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return None;
    }
    let first = lines[0];
    let delim = if first.contains('\t') {
        '\t'
    } else if first.contains(',') {
        ','
    } else if first.contains(';') {
        ';'
    } else {
        return None;
    };
    let split =
        |line: &str| -> Vec<String> { line.split(delim).map(|s| s.trim().to_string()).collect() };
    let headers = split(lines[0]);
    if headers.is_empty() {
        return None;
    }
    let rows = lines[1..]
        .iter()
        .filter(|l| !l.trim().is_empty())
        .take(500)
        .map(|l| split(l))
        .collect();
    Some(crate::app::TabularData {
        headers,
        rows,
        source_name: String::new(),
    })
}

impl SleuthreApp {
    pub(crate) fn show_archives(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Archive Browser");
            ui.add_space(16.0);
            if ui.button("Open Archive...").clicked() {
                self.open_archive_file();
            }
            if self.archive_dir.is_some() && ui.button("Close").clicked() {
                self.archive_data = None;
                self.archive_dir = None;
                self.archive_format = None;
                self.archive_selected = None;
                self.archive_preview = None;
                self.archive_filter.clear();
            }
        });
        ui.separator();

        if self.archive_dir.is_none() {
            ui.label("Open an archive file to browse its contents.");
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!(
                    "Supported formats: {}",
                    self.archive_registry.format_names().join(", ")
                ))
                .size(10.0)
                .color(egui::Color32::GRAY),
            );
            return;
        }

        // Gather info we need without holding a borrow on self
        let entry_count = self
            .archive_dir
            .as_ref()
            .map(|d| d.entries.len())
            .unwrap_or(0);
        let fmt_name = self.archive_format.clone();
        let metadata: Vec<(String, String)> = self
            .archive_dir
            .as_ref()
            .map(|d| {
                d.metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();

        // Archive metadata
        if let Some(ref name) = fmt_name {
            ui.label(
                egui::RichText::new(format!("Format: {} | {} entries", name, entry_count))
                    .size(11.0),
            );
        }
        if !metadata.is_empty() {
            ui.horizontal(|ui| {
                for (key, value) in &metadata {
                    ui.label(
                        egui::RichText::new(format!("{}: {}", key, value))
                            .size(10.0)
                            .color(egui::Color32::GRAY),
                    );
                    ui.add_space(12.0);
                }
            });
        }

        // Toolbar with filter and extract-all
        let mut extract_all_clicked = false;
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.archive_filter);
            ui.add_space(16.0);
            if ui.button("Extract All...").clicked() {
                extract_all_clicked = true;
            }
        });
        ui.separator();

        if extract_all_clicked {
            self.extract_all_archive_entries();
        }

        let filter_lower = self.archive_filter.to_lowercase();
        let avail = ui.available_size();
        let mut clicked_idx: Option<usize> = None;
        let mut extract_clicked = false;

        // Snapshot entry data for display (clone what we need to avoid borrow conflicts)
        let entries_snapshot: Vec<ArchiveEntrySnapshot> = self
            .archive_dir
            .as_ref()
            .map(|d| {
                d.entries
                    .iter()
                    .map(|e| ArchiveEntrySnapshot {
                        name: e.name.clone(),
                        compressed_size: e.compressed_size,
                        decompressed_size: e.decompressed_size,
                        is_compressed: e.is_compressed,
                        entry_type: e.entry_type,
                        offset: e.offset,
                    })
                    .collect()
            })
            .unwrap_or_default();

        ui.horizontal(|ui| {
            // Left pane: entry list
            ui.vertical(|ui| {
                ui.set_width(avail.x * 0.55);
                egui::ScrollArea::vertical()
                    .id_salt("archive_entry_list")
                    .show(ui, |ui| {
                        // Column headers
                        egui::Grid::new("archive_header")
                            .min_col_width(80.0)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Name").strong().size(11.0));
                                ui.label(egui::RichText::new("Size").strong().size(11.0));
                                ui.label(egui::RichText::new("Compressed").strong().size(11.0));
                                ui.label(egui::RichText::new("Type").strong().size(11.0));
                                ui.end_row();
                            });
                        ui.separator();

                        for (idx, entry) in entries_snapshot.iter().enumerate() {
                            if !filter_lower.is_empty()
                                && !entry.name.to_lowercase().contains(&filter_lower)
                            {
                                continue;
                            }

                            let is_selected = self.archive_selected == Some(idx);
                            let type_str = match entry.entry_type {
                                ArchiveEntryType::File => "File",
                                ArchiveEntryType::Directory => "Dir",
                            };
                            let comp_str = if entry.is_compressed {
                                format_size(entry.compressed_size)
                            } else {
                                "-".to_string()
                            };

                            let label_text = format!(
                                "{}  {}  {}  {}",
                                entry.name,
                                format_size(entry.decompressed_size),
                                comp_str,
                                type_str,
                            );

                            let color = if entry.is_compressed {
                                egui::Color32::from_rgb(120, 180, 255)
                            } else {
                                egui::Color32::LIGHT_GRAY
                            };

                            let text = egui::RichText::new(label_text)
                                .monospace()
                                .size(11.0)
                                .color(color);

                            if ui.selectable_label(is_selected, text).clicked() {
                                clicked_idx = Some(idx);
                            }
                        }
                    });
            });

            ui.separator();

            // Right pane: preview + extract
            ui.vertical(|ui| {
                if let Some(sel) = self.archive_selected {
                    if let Some(entry) = entries_snapshot.get(sel) {
                        ui.label(egui::RichText::new(&entry.name).strong().size(12.0));
                        ui.label(
                            egui::RichText::new(format!(
                                "Size: {} | Offset: 0x{:X}{}",
                                format_size(entry.decompressed_size),
                                entry.offset,
                                if entry.is_compressed {
                                    format!(" | Compressed: {}", format_size(entry.compressed_size))
                                } else {
                                    String::new()
                                },
                            ))
                            .size(10.0)
                            .color(egui::Color32::GRAY),
                        );

                        if ui.button("Extract...").clicked() {
                            extract_clicked = true;
                        }
                        ui.separator();

                        // Preview pane
                        if let Some(ref preview) = self.archive_preview {
                            let kind = classify_preview(&entry.name, preview);
                            match kind {
                                PreviewKind::Image => {
                                    ui.label(
                                        egui::RichText::new("Image Preview")
                                            .size(10.0)
                                            .color(egui::Color32::GRAY),
                                    );
                                    if self.archive_image_texture.is_none()
                                        && let Some(img) =
                                            self.archive_image_registry.decode(preview, &entry.name)
                                    {
                                        let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                            [img.width as usize, img.height as usize],
                                            &img.pixels,
                                        );
                                        let texture = ui.ctx().load_texture(
                                            "archive_preview_image",
                                            color_image,
                                            egui::TextureOptions::NEAREST,
                                        );
                                        self.archive_image_texture =
                                            Some((texture, img.width as f32, img.height as f32));
                                    }
                                    if let Some((tex, w, h)) = &self.archive_image_texture {
                                        let avail = ui.available_size();
                                        let scale = (avail.x / w).min(avail.y / h).clamp(0.1, 2.0);
                                        ui.add(
                                            egui::Image::new(tex).fit_to_exact_size(egui::vec2(
                                                w * scale,
                                                h * scale,
                                            )),
                                        );
                                    } else {
                                        ui.label("Cannot decode image.");
                                    }
                                }
                                PreviewKind::Table => {
                                    ui.label(
                                        egui::RichText::new("Table Preview")
                                            .size(10.0)
                                            .color(egui::Color32::GRAY),
                                    );
                                    let text = String::from_utf8_lossy(preview);
                                    if let Some(data) = parse_tabular_preview(&text) {
                                        egui::ScrollArea::both()
                                            .id_salt("archive_table_preview")
                                            .show(ui, |ui| {
                                                egui::Grid::new("archive_table_grid")
                                                    .striped(true)
                                                    .show(ui, |ui| {
                                                        for h in &data.headers {
                                                            ui.label(
                                                                egui::RichText::new(h)
                                                                    .strong()
                                                                    .size(11.0),
                                                            );
                                                        }
                                                        ui.end_row();
                                                        for row in data.rows.iter().take(100) {
                                                            for cell in row {
                                                                ui.label(
                                                                    egui::RichText::new(cell)
                                                                        .monospace()
                                                                        .size(11.0),
                                                                );
                                                            }
                                                            ui.end_row();
                                                        }
                                                    });
                                                if data.rows.len() > 100 {
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "... {} more rows",
                                                            data.rows.len() - 100
                                                        ))
                                                        .size(10.0)
                                                        .color(egui::Color32::GRAY),
                                                    );
                                                }
                                            });
                                    } else {
                                        ui.label("Could not parse tabular data.");
                                    }
                                }
                                PreviewKind::Text => {
                                    ui.label(
                                        egui::RichText::new("Text Preview")
                                            .size(10.0)
                                            .color(egui::Color32::GRAY),
                                    );
                                    egui::ScrollArea::vertical()
                                        .id_salt("archive_text_preview")
                                        .show(ui, |ui| {
                                            let text = String::from_utf8_lossy(preview);
                                            ui.monospace(
                                                egui::RichText::new(text.as_ref()).size(11.0),
                                            );
                                        });
                                }
                                PreviewKind::Hex => {
                                    ui.label(
                                        egui::RichText::new("Hex Preview")
                                            .size(10.0)
                                            .color(egui::Color32::GRAY),
                                    );
                                    egui::ScrollArea::vertical()
                                        .id_salt("archive_hex_preview")
                                        .show(ui, |ui| {
                                            let hex = format_hex_preview(preview, 256);
                                            ui.monospace(egui::RichText::new(&hex).size(11.0));
                                        });
                                }
                            }
                        } else {
                            ui.label("Loading preview...");
                        }
                    }
                } else {
                    ui.label("Select an entry to preview its contents.");
                }
            });
        });

        // Handle deferred actions after the UI borrow is released
        if let Some(idx) = clicked_idx {
            self.archive_selected = Some(idx);
            self.load_archive_preview(idx);
        }
        if extract_clicked && let Some(sel) = self.archive_selected {
            self.extract_single_archive_entry(sel);
        }
    }

    fn open_archive_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter(
                "Archive Files",
                &["lod", "vid", "snd", "pak", "wad", "vpk", "zip", "dat"],
            )
            .pick_file()
        else {
            return;
        };

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Read error: {}", e));
                return;
            }
        };

        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match self.archive_registry.open(&data, &extension) {
            Ok((dir, format)) => {
                let fmt_name = format.name().to_string();
                self.add_toast(
                    ToastKind::Success,
                    format!("Opened {} ({} entries)", fmt_name, dir.entries.len()),
                );
                self.archive_format = Some(fmt_name);
                self.archive_dir = Some(dir);
                self.archive_data = Some(data);
                self.archive_selected = None;
                self.archive_preview = None;
                self.archive_filter.clear();
            }
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Parse error: {}", e));
            }
        }
    }

    fn load_archive_preview(&mut self, entry_idx: usize) {
        // Drop any cached image texture from a prior entry.
        self.archive_image_texture = None;

        let (Some(data), Some(dir)) = (&self.archive_data, &self.archive_dir) else {
            return;
        };
        let Some(entry) = dir.entries.get(entry_idx) else {
            return;
        };

        const PREVIEW_CAP: usize = 4 * 1024 * 1024; // 4 MB cap for images/tables

        // Use the registry to extract
        if let Some(format) = self.archive_registry.detect(data, "") {
            match format.extract(data, entry) {
                Ok(mut extracted) => {
                    if extracted.len() > PREVIEW_CAP {
                        extracted.truncate(PREVIEW_CAP);
                    }
                    self.archive_preview = Some(extracted);
                }
                Err(_) => {
                    let start = entry.offset as usize;
                    let end = (start + 256).min(data.len());
                    if start < data.len() {
                        self.archive_preview = Some(data[start..end].to_vec());
                    } else {
                        self.archive_preview = Some(Vec::new());
                    }
                }
            }
        }
    }

    fn extract_single_archive_entry(&mut self, entry_idx: usize) {
        let (Some(data), Some(dir)) = (&self.archive_data, &self.archive_dir) else {
            return;
        };
        let Some(entry) = dir.entries.get(entry_idx) else {
            return;
        };
        let entry_name = entry.name.clone();

        let Some(save_path) = rfd::FileDialog::new()
            .set_file_name(&entry_name)
            .save_file()
        else {
            return;
        };

        if let Some(format) = self.archive_registry.detect(data, "") {
            match format.extract(data, entry) {
                Ok(extracted) => match std::fs::write(&save_path, &extracted) {
                    Ok(()) => {
                        self.add_toast(
                            ToastKind::Success,
                            format!("Extracted '{}' ({} bytes)", entry_name, extracted.len()),
                        );
                    }
                    Err(e) => {
                        self.add_toast(ToastKind::Error, format!("Write error: {}", e));
                    }
                },
                Err(e) => {
                    self.add_toast(ToastKind::Error, format!("Extract error: {}", e));
                }
            }
        }
    }

    fn extract_all_archive_entries(&mut self) {
        let (Some(data), Some(dir)) = (&self.archive_data, &self.archive_dir) else {
            return;
        };

        let Some(out_dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };

        let Some(format) = self.archive_registry.detect(data, "") else {
            self.add_toast(ToastKind::Error, "Cannot detect archive format.".into());
            return;
        };

        let mut extracted_count = 0usize;
        let mut error_count = 0usize;

        for entry in &dir.entries {
            if entry.entry_type == ArchiveEntryType::Directory {
                continue;
            }
            match format.extract(data, entry) {
                Ok(bytes) => {
                    let dest = out_dir.join(&entry.name);
                    if std::fs::write(&dest, &bytes).is_ok() {
                        extracted_count += 1;
                    } else {
                        error_count += 1;
                    }
                }
                Err(_) => {
                    error_count += 1;
                }
            }
        }

        self.add_toast(
            ToastKind::Success,
            format!(
                "Extracted {} files to '{}' ({} errors)",
                extracted_count,
                out_dir.display(),
                error_count,
            ),
        );
    }
}

/// Snapshot of an archive entry for display purposes (avoids borrow conflicts).
struct ArchiveEntrySnapshot {
    name: String,
    compressed_size: u64,
    decompressed_size: u64,
    is_compressed: bool,
    entry_type: ArchiveEntryType,
    offset: u64,
}

/// Format a byte size as human-readable.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Format bytes as a hex dump with ASCII sidebar.
fn format_hex_preview(data: &[u8], max_bytes: usize) -> String {
    let mut output = String::new();
    let limit = data.len().min(max_bytes);
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        // Offset
        output.push_str(&format!("{:08X}  ", i * 16));
        // Hex bytes
        for (j, &byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02X} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }
        // Pad if short row
        for j in chunk.len()..16 {
            output.push_str("   ");
            if j == 7 {
                output.push(' ');
            }
        }
        output.push_str(" |");
        // ASCII
        for &byte in chunk {
            if (0x20..=0x7E).contains(&byte) {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }
    if limit < data.len() {
        output.push_str(&format!("... ({} more bytes)\n", data.len() - limit));
    }
    output
}
