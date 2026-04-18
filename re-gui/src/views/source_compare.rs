use eframe::egui;

use crate::app::{SleuthreApp, SourceMatchStatus, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_source_compare(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Source Comparison");
            ui.add_space(16.0);
            if ui.button("Load Source Directory...").clicked() {
                self.load_source_directory();
            }
            if !self.source_compare_files.is_empty() && ui.button("Clear").clicked() {
                self.source_compare_dir = None;
                self.source_compare_files.clear();
                self.source_compare_mappings.clear();
                self.source_compare_selected = None;
            }
        });
        ui.separator();

        if self.project.is_none() {
            ui.label("Load a binary first (File > Open).");
            return;
        }

        if self.source_compare_files.is_empty() {
            ui.label("Load a source directory to compare against the current binary.");
            return;
        }

        // Coverage stats
        let total = self.source_compare_mappings.len();
        let matched = self
            .source_compare_mappings
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    SourceMatchStatus::Matched | SourceMatchStatus::Divergent
                )
            })
            .count();
        let pct = if total > 0 {
            (matched as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        ui.label(
            egui::RichText::new(format!(
                "{}/{} functions matched ({:.1}%) | {} source files loaded",
                matched,
                total,
                pct,
                self.source_compare_files.len(),
            ))
            .size(11.0),
        );

        if let Some(ref dir) = self.source_compare_dir {
            ui.label(
                egui::RichText::new(format!("Source: {}", dir.display()))
                    .size(10.0)
                    .color(egui::Color32::GRAY),
            );
        }
        ui.separator();

        let avail = ui.available_size();
        let mut clicked_idx: Option<usize> = None;

        ui.horizontal(|ui| {
            // Left pane: function mapping table
            ui.vertical(|ui| {
                ui.set_width(avail.x * 0.45);
                egui::ScrollArea::vertical()
                    .id_salt("source_compare_list")
                    .show(ui, |ui| {
                        // Header
                        egui::Grid::new("source_compare_header")
                            .striped(false)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Address").strong().size(11.0));
                                ui.label(egui::RichText::new("Binary Name").strong().size(11.0));
                                ui.label(egui::RichText::new("Source Match").strong().size(11.0));
                                ui.label(egui::RichText::new("Status").strong().size(11.0));
                                ui.end_row();
                            });
                        ui.separator();

                        for (idx, mapping) in self.source_compare_mappings.iter().enumerate() {
                            let (status_text, status_color) = match mapping.status {
                                SourceMatchStatus::Matched => ("Matched", egui::Color32::GREEN),
                                SourceMatchStatus::Divergent => {
                                    ("Divergent", egui::Color32::YELLOW)
                                }
                                SourceMatchStatus::Unmatched => ("Unmatched", egui::Color32::GRAY),
                            };

                            let is_selected = self.source_compare_selected == Some(idx);
                            let label_text = format!(
                                "{:08X}  {}  {}  {}",
                                mapping.address,
                                mapping.binary_name,
                                mapping.source_function.as_deref().unwrap_or("-"),
                                status_text,
                            );

                            let text = egui::RichText::new(label_text)
                                .monospace()
                                .size(11.0)
                                .color(status_color);

                            if ui.selectable_label(is_selected, text).clicked() {
                                clicked_idx = Some(idx);
                            }
                        }
                    });
            });

            ui.separator();

            // Right pane: side-by-side comparison
            ui.vertical(|ui| {
                if let Some(sel) = self.source_compare_selected {
                    if let Some(mapping) = self.source_compare_mappings.get(sel) {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("Binary: {}", mapping.binary_name))
                                    .strong()
                                    .size(12.0),
                            );
                            ui.add_space(32.0);
                            if let Some(ref src_func) = mapping.source_function {
                                ui.label(
                                    egui::RichText::new(format!("Source: {}", src_func))
                                        .strong()
                                        .size(12.0),
                                );
                            }
                        });
                        ui.separator();

                        // Build excerpt strings.
                        let decompiled = self.get_decompiled_for_address(mapping.address);
                        let source_excerpt = mapping.source_file.as_ref().and_then(|src_file| {
                            self.source_compare_files
                                .iter()
                                .find(|(name, _)| name == src_file)
                                .map(|(_, content)| {
                                    if let Some(ref func_name) = mapping.source_function {
                                        extract_function_source(content, func_name)
                                    } else {
                                        content.clone()
                                    }
                                })
                        });

                        // Produce per-line diff with markers.
                        let marked = source_excerpt
                            .as_deref()
                            .map(|src| diff_lines_with_markers(&decompiled, src));

                        let half_width = ui.available_width() / 2.0 - 8.0;

                        // Synchronize scroll offset across both panes.
                        let scroll_y = self.source_compare_scroll_y;

                        let mut new_scroll_y = scroll_y;
                        ui.horizontal(|ui| {
                            // Left: decompiled output with +/-/~ gutters.
                            ui.vertical(|ui| {
                                ui.set_width(half_width);
                                ui.label(
                                    egui::RichText::new("Decompiled (HLIL)")
                                        .size(10.0)
                                        .color(egui::Color32::GRAY),
                                );
                                let scroll_out = egui::ScrollArea::vertical()
                                    .id_salt("source_compare_decompiled")
                                    .vertical_scroll_offset(scroll_y)
                                    .show(ui, |ui| {
                                        if let Some((left_marks, _)) = &marked {
                                            render_marked(ui, left_marks);
                                        } else {
                                            ui.monospace(
                                                egui::RichText::new(&decompiled).size(11.0),
                                            );
                                        }
                                    });
                                new_scroll_y = scroll_out.state.offset.y.max(new_scroll_y);
                            });

                            ui.separator();

                            // Right: source code.
                            ui.vertical(|ui| {
                                ui.set_width(half_width);
                                ui.label(
                                    egui::RichText::new("Source Code")
                                        .size(10.0)
                                        .color(egui::Color32::GRAY),
                                );
                                let scroll_out = egui::ScrollArea::vertical()
                                    .id_salt("source_compare_source")
                                    .vertical_scroll_offset(scroll_y)
                                    .show(ui, |ui| {
                                        if let Some((_, right_marks)) = &marked {
                                            render_marked(ui, right_marks);
                                        } else if let Some(src) = &source_excerpt {
                                            ui.monospace(egui::RichText::new(src).size(11.0));
                                        } else {
                                            ui.label("No source file matched.");
                                        }
                                    });
                                new_scroll_y = scroll_out.state.offset.y.max(new_scroll_y);
                            });
                        });
                        self.source_compare_scroll_y = new_scroll_y;
                    }
                } else {
                    ui.label("Select a function from the list to see the comparison.");
                }
            });
        });

        if let Some(idx) = clicked_idx {
            self.source_compare_selected = Some(idx);
        }
    }

    fn load_source_directory(&mut self) {
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };

        let mut files = Vec::new();
        collect_source_files(&dir, &mut files);

        if files.is_empty() {
            self.add_toast(
                ToastKind::Warning,
                "No .c, .cpp, or .h files found in directory.".into(),
            );
            return;
        }

        self.add_toast(
            ToastKind::Success,
            format!(
                "Loaded {} source files from '{}'",
                files.len(),
                dir.display()
            ),
        );

        self.source_compare_dir = Some(dir);
        self.source_compare_files = files;
        self.source_compare_selected = None;

        // Build mappings
        self.build_source_mappings();
    }

    fn build_source_mappings(&mut self) {
        self.source_compare_mappings.clear();

        let Some(ref project) = self.project else {
            return;
        };

        // Collect function signatures from source files
        let mut source_functions: Vec<(String, String)> = Vec::new(); // (func_name, filename)
        for (filename, content) in &self.source_compare_files {
            let funcs = extract_function_names(content);
            for func_name in funcs {
                source_functions.push((func_name, filename.clone()));
            }
        }

        // Clone what we need to avoid holding project borrow over mapping mutation.
        let functions: Vec<(u64, String, Option<String>)> = project
            .functions
            .functions
            .values()
            .map(|f| {
                let decompiled = project
                    .decompilation_cache
                    .get(&f.start_address)
                    .map(|c| c.text.clone());
                (f.start_address, f.name.clone(), decompiled)
            })
            .collect();

        let files_snapshot = self.source_compare_files.clone();

        for (address, name, decompiled) in functions {
            let clean_binary_name = name.trim_start_matches("sub_").to_lowercase();

            let mut matched = None;
            for (src_name, src_file) in &source_functions {
                if name.to_lowercase() == src_name.to_lowercase()
                    || clean_binary_name == src_name.to_lowercase()
                {
                    matched = Some((src_name.clone(), src_file.clone()));
                    break;
                }
            }

            let (source_function, source_file, status) = match matched {
                Some((sname, sfile)) => {
                    let status = match (
                        &decompiled,
                        files_snapshot
                            .iter()
                            .find(|(n, _)| n == &sfile)
                            .map(|(_, c)| c.as_str()),
                    ) {
                        (Some(d), Some(content)) => {
                            let src_excerpt = extract_function_source(content, &sname);
                            let ratio = divergence_ratio(d, &src_excerpt);
                            if ratio > 0.25 {
                                SourceMatchStatus::Divergent
                            } else {
                                SourceMatchStatus::Matched
                            }
                        }
                        _ => SourceMatchStatus::Matched,
                    };
                    (Some(sname), Some(sfile), status)
                }
                None => (None, None, SourceMatchStatus::Unmatched),
            };

            self.source_compare_mappings
                .push(crate::app::SourceMapping {
                    address,
                    binary_name: name,
                    source_function,
                    source_file,
                    status,
                });
        }

        // Sort by address
        self.source_compare_mappings.sort_by_key(|m| m.address);
    }

    fn get_decompiled_for_address(&self, address: u64) -> String {
        if let Some(ref project) = self.project
            && let Some(cached) = project.decompilation_cache.get(&address)
        {
            return cached.text.clone();
        }
        format!("// Press F5 at {:08X} to decompile first", address)
    }
}

/// Recursively collect .c, .cpp, .h files from a directory.
fn collect_source_files(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            if (ext_lower == "c" || ext_lower == "cpp" || ext_lower == "h" || ext_lower == "cc")
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                out.push((name, content));
            }
        }
    }
}

/// Extract function names from C/C++ source code using simple heuristics.
fn extract_function_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    // Simple regex-like scan: look for patterns like `type name(` at the start of a line
    for line in source.lines() {
        let trimmed = line.trim();
        // Skip preprocessor directives, comments, blank lines
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        // Look for function definition pattern: something followed by name(
        if let Some(paren_pos) = trimmed.find('(') {
            let before_paren = trimmed[..paren_pos].trim();
            // Must have at least two tokens (return type + name)
            let tokens: Vec<&str> = before_paren.split_whitespace().collect();
            if tokens.len() >= 2 {
                let candidate = tokens.last().unwrap().trim_start_matches('*');
                // Filter out control flow keywords
                if !matches!(
                    candidate,
                    "if" | "for"
                        | "while"
                        | "switch"
                        | "return"
                        | "sizeof"
                        | "typeof"
                        | "defined"
                        | "else"
                ) && !candidate.is_empty()
                    && candidate.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    names.push(candidate.to_string());
                }
            }
        }
    }
    names
}

#[derive(Clone, Copy)]
enum LineMark {
    Same,
    Added,
    Removed,
    Changed,
}

fn render_marked(ui: &mut egui::Ui, lines: &[(LineMark, String)]) {
    for (mark, line) in lines {
        let (prefix, color) = match mark {
            LineMark::Same => (" ", egui::Color32::LIGHT_GRAY),
            LineMark::Added => ("+", egui::Color32::from_rgb(90, 200, 90)),
            LineMark::Removed => ("-", egui::Color32::from_rgb(220, 90, 90)),
            LineMark::Changed => ("~", egui::Color32::from_rgb(230, 200, 70)),
        };
        ui.monospace(
            egui::RichText::new(format!("{} {}", prefix, line))
                .color(color)
                .size(11.0),
        );
    }
}

type MarkedLines = Vec<(LineMark, String)>;

/// Produce aligned per-line marks for the left (decompiled) and right (source) panes.
/// Uses an LCS over tokenized, whitespace-normalized lines to align common content.
fn diff_lines_with_markers(left: &str, right: &str) -> (MarkedLines, MarkedLines) {
    let left_lines: Vec<&str> = left.lines().collect();
    let right_lines: Vec<&str> = right.lines().collect();

    let n = left_lines.len();
    let m = right_lines.len();
    let eq = |a: &str, b: &str| normalize_tokens(a) == normalize_tokens(b);

    // Classic LCS DP.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            dp[i + 1][j + 1] = if eq(left_lines[i], right_lines[j]) {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    // Walk back to produce diff operations.
    let mut left_out: Vec<(LineMark, String)> = Vec::new();
    let mut right_out: Vec<(LineMark, String)> = Vec::new();
    let (mut i, mut j) = (n, m);
    let mut ops: Vec<(char, &str, &str)> = Vec::new();
    while i > 0 && j > 0 {
        if eq(left_lines[i - 1], right_lines[j - 1]) {
            ops.push(('=', left_lines[i - 1], right_lines[j - 1]));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            ops.push(('-', left_lines[i - 1], ""));
            i -= 1;
        } else {
            ops.push(('+', "", right_lines[j - 1]));
            j -= 1;
        }
    }
    while i > 0 {
        ops.push(('-', left_lines[i - 1], ""));
        i -= 1;
    }
    while j > 0 {
        ops.push(('+', "", right_lines[j - 1]));
        j -= 1;
    }
    ops.reverse();

    // Collapse '-' followed by '+' into a single Changed pair to align visually.
    let mut k = 0;
    while k < ops.len() {
        match ops[k].0 {
            '=' => {
                left_out.push((LineMark::Same, ops[k].1.to_string()));
                right_out.push((LineMark::Same, ops[k].2.to_string()));
                k += 1;
            }
            '-' if k + 1 < ops.len() && ops[k + 1].0 == '+' => {
                left_out.push((LineMark::Changed, ops[k].1.to_string()));
                right_out.push((LineMark::Changed, ops[k + 1].2.to_string()));
                k += 2;
            }
            '-' => {
                left_out.push((LineMark::Removed, ops[k].1.to_string()));
                right_out.push((LineMark::Removed, String::new()));
                k += 1;
            }
            '+' => {
                left_out.push((LineMark::Added, String::new()));
                right_out.push((LineMark::Added, ops[k].2.to_string()));
                k += 1;
            }
            _ => k += 1,
        }
    }

    (left_out, right_out)
}

/// Normalize a line into comparable tokens: strip comments, collapse whitespace, drop trailing semicolons.
fn normalize_tokens(line: &str) -> String {
    let mut out = String::new();
    let trimmed = line.trim();
    // Strip // line comments.
    let no_comment = if let Some(pos) = trimmed.find("//") {
        &trimmed[..pos]
    } else {
        trimmed
    };
    let mut last_space = true;
    for ch in no_comment.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out.trim().trim_end_matches(';').to_string()
}

/// Compute the ratio of lines that differ (including Changed) to total rendered lines.
pub(crate) fn divergence_ratio(left: &str, right: &str) -> f32 {
    let (lm, _) = diff_lines_with_markers(left, right);
    if lm.is_empty() {
        return 1.0;
    }
    let diffs = lm
        .iter()
        .filter(|(m, _)| !matches!(m, LineMark::Same))
        .count();
    diffs as f32 / lm.len() as f32
}

/// Extract a function body from source code given its name.
fn extract_function_source(source: &str, func_name: &str) -> String {
    let search = format!("{func_name}(");
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.contains(&search) {
            // Find the opening brace
            let mut brace_depth = 0i32;
            let mut found_open = false;

            // Collect from the line with the function signature
            let mut result: Vec<&str> = Vec::new();
            for &line in &lines[i..] {
                result.push(line);
                for ch in line.chars() {
                    if ch == '{' {
                        brace_depth += 1;
                        found_open = true;
                    } else if ch == '}' {
                        brace_depth -= 1;
                    }
                }
                if found_open && brace_depth == 0 {
                    return result.join("\n");
                }
                // Safety limit
                if result.len() > 500 {
                    result.push("// ... (truncated)");
                    return result.join("\n");
                }
            }

            // If we didn't find balanced braces, return what we got
            if !result.is_empty() {
                return result.join("\n");
            }
        }
    }

    format!("// Function '{}' not found in source file", func_name)
}
