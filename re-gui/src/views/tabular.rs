use eframe::egui;

use crate::app::{SleuthreApp, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_tabular_data(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Tabular Data");
            ui.add_space(16.0);
            if ui.button("Load File...").clicked() {
                self.load_tabular_file();
            }
            if self.tabular_data.is_some() && ui.button("Clear").clicked() {
                self.tabular_data = None;
                self.tabular_filter.clear();
                self.tabular_sort_col = None;
                self.tabular_sort_asc = true;
            }
        });
        ui.separator();

        let Some(ref data) = self.tabular_data else {
            ui.label("Load a CSV or TSV file to view tabular data.");
            return;
        };

        // Info bar
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "File: {} | {} columns | {} rows",
                    data.source_name,
                    data.headers.len(),
                    data.rows.len(),
                ))
                .size(11.0),
            );
        });

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.tabular_filter);
        });
        ui.separator();

        let filter_lower = self.tabular_filter.to_lowercase();

        // Build sorted + filtered row indices
        let mut indices: Vec<usize> = (0..data.rows.len())
            .filter(|&i| {
                if filter_lower.is_empty() {
                    return true;
                }
                data.rows[i]
                    .iter()
                    .any(|cell| cell.to_lowercase().contains(&filter_lower))
            })
            .collect();

        if let Some(sort_col) = self.tabular_sort_col
            && sort_col < data.headers.len()
        {
            let asc = self.tabular_sort_asc;
            indices.sort_by(|&a, &b| {
                let va = data.rows[a].get(sort_col).map(|s| s.as_str()).unwrap_or("");
                let vb = data.rows[b].get(sort_col).map(|s| s.as_str()).unwrap_or("");
                // Try numeric comparison first
                if let (Ok(na), Ok(nb)) = (va.parse::<f64>(), vb.parse::<f64>()) {
                    let cmp = na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal);
                    if asc { cmp } else { cmp.reverse() }
                } else {
                    let cmp = va.to_lowercase().cmp(&vb.to_lowercase());
                    if asc { cmp } else { cmp.reverse() }
                }
            });
        }

        let filtered_count = indices.len();
        ui.label(
            egui::RichText::new(format!(
                "Showing {} of {} rows",
                filtered_count,
                data.rows.len(),
            ))
            .size(10.0)
            .color(egui::Color32::GRAY),
        );

        // Capture sort_col/sort_asc to detect clicks
        let mut new_sort_col = self.tabular_sort_col;
        let mut new_sort_asc = self.tabular_sort_asc;

        egui::ScrollArea::both()
            .id_salt("tabular_scroll")
            .show(ui, |ui| {
                egui::Grid::new("tabular_grid")
                    .striped(true)
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        // Headers
                        for (col_idx, header) in data.headers.iter().enumerate() {
                            let arrow = if new_sort_col == Some(col_idx) {
                                if new_sort_asc { " ^" } else { " v" }
                            } else {
                                ""
                            };
                            let text = format!("{}{}", header, arrow);
                            if ui
                                .button(egui::RichText::new(text).strong().size(11.0))
                                .clicked()
                            {
                                if new_sort_col == Some(col_idx) {
                                    new_sort_asc = !new_sort_asc;
                                } else {
                                    new_sort_col = Some(col_idx);
                                    new_sort_asc = true;
                                }
                            }
                        }
                        ui.end_row();

                        // Data rows
                        for &row_idx in &indices {
                            let row = &data.rows[row_idx];
                            for col_idx in 0..data.headers.len() {
                                let cell = row.get(col_idx).map(|s| s.as_str()).unwrap_or("");
                                ui.label(egui::RichText::new(cell).monospace().size(11.0));
                            }
                            ui.end_row();
                        }
                    });
            });

        // Apply sort changes
        self.tabular_sort_col = new_sort_col;
        self.tabular_sort_asc = new_sort_asc;
    }

    fn load_tabular_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Tabular Data", &["csv", "tsv", "txt", "tab"])
            .pick_file()
        else {
            return;
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Read error: {}", e));
                return;
            }
        };

        let source_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        match parse_tabular(&content) {
            Some(mut data) => {
                data.source_name = source_name;
                let row_count = data.rows.len();
                let col_count = data.headers.len();
                self.tabular_data = Some(data);
                self.tabular_filter.clear();
                self.tabular_sort_col = None;
                self.tabular_sort_asc = true;
                self.add_toast(
                    ToastKind::Success,
                    format!("Loaded {} rows x {} columns", row_count, col_count),
                );
            }
            None => {
                self.add_toast(ToastKind::Error, "Could not parse tabular data.".into());
            }
        }
    }
}

/// Parse tabular data with auto-detected delimiter.
fn parse_tabular(content: &str) -> Option<crate::app::TabularData> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return None;
    }

    // Detect delimiter: tab > comma > semicolon > space
    let delimiter = detect_delimiter(lines[0]);

    let headers = split_row(lines[0], delimiter);
    if headers.is_empty() {
        return None;
    }

    let mut rows = Vec::with_capacity(lines.len().saturating_sub(1));
    for line in &lines[1..] {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(split_row(line, delimiter));
    }

    Some(crate::app::TabularData {
        headers,
        rows,
        source_name: String::new(),
    })
}

/// Detect the most likely delimiter character.
fn detect_delimiter(line: &str) -> char {
    let tab_count = line.matches('\t').count();
    let comma_count = line.matches(',').count();
    let semicolon_count = line.matches(';').count();

    if tab_count > 0 && tab_count >= comma_count {
        '\t'
    } else if comma_count > 0 {
        ','
    } else if semicolon_count > 0 {
        ';'
    } else {
        '\t' // fallback
    }
}

/// Split a row respecting basic quoted fields.
fn split_row(line: &str, delimiter: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '"' {
            if in_quotes {
                // Check for escaped quote ("")
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                in_quotes = true;
            }
        } else if ch == delimiter && !in_quotes {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    fields.push(current);
    fields
}
