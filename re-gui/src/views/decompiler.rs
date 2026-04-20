use eframe::egui;
use re_core::Debugger;

use crate::app::SleuthreApp;
use crate::theme::SyntaxColors;

impl SleuthreApp {
    pub(crate) fn show_decompiler(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .button("🔄 Refresh")
                .on_hover_text("Clear cache and re-decompile")
                .clicked()
                && let Some(ref mut project) = self.project
            {
                project.decompilation_cache.remove(&self.current_address);
                self.trigger_decompile = true;
            }
            ui.add_space(8.0);
            ui.label(format!("Function: 0x{:X}", self.current_address));
        });
        ui.separator();

        let mut pending_run_to: Option<u64> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            let job = highlight_pseudocode(&self.decompiled_code.text, &self.syntax);
            let galley = ui.painter().layout_job(job);
            let response = ui.add(
                egui::Label::new(galley.clone())
                    .sense(egui::Sense::click())
                    .sense(egui::Sense::click_and_drag()),
            );

            let hover_addr = response.hover_pos().and_then(|pos| {
                let relative_pos = pos - response.rect.min;
                let cursor = galley.cursor_from_pos(relative_pos);
                let char_idx = cursor.index;
                // Any Function/Global annotation at this char index is a candidate
                // target for run-to-cursor.
                self.decompiled_code.annotations.iter().find_map(|ann| {
                    if char_idx >= ann.start && char_idx < ann.end {
                        match &ann.kind {
                            re_core::il::hlil::AnnotationKind::Function(a)
                            | re_core::il::hlil::AnnotationKind::Global(a) => Some(*a),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            });

            if response.clicked()
                && let Some(pos) = response.interact_pointer_pos()
            {
                let relative_pos = pos - response.rect.min;
                let cursor = galley.cursor_from_pos(relative_pos);
                let char_idx = cursor.index;

                // Find annotation at this index
                for ann in &self.decompiled_code.annotations {
                    if char_idx >= ann.start && char_idx < ann.end {
                        match &ann.kind {
                            re_core::il::hlil::AnnotationKind::Function(addr)
                            | re_core::il::hlil::AnnotationKind::Global(addr) => {
                                self.current_address = *addr;
                                self.update_cfg();
                            }
                            _ => {}
                        }
                        break;
                    }
                }
            }

            // Right-click "Run to cursor" — only enabled when a debugger is
            // connected and the hover landed on an annotated address.
            if self.debugger_remote.is_some() {
                response.context_menu(|ui| {
                    let enabled = hover_addr.is_some();
                    if ui
                        .add_enabled(enabled, egui::Button::new("Run to Cursor"))
                        .clicked()
                    {
                        pending_run_to = hover_addr;
                        ui.close();
                    }
                });
            }
        });

        if let Some(addr) = pending_run_to {
            self.debugger_run_to_cursor(addr);
        }
    }

    fn debugger_run_to_cursor(&mut self, addr: u64) {
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.set_breakpoint(addr, re_core::BreakpointKind::Software) {
            Ok(()) => {
                self.debugger_temp_breakpoints.push(addr);
                self.debugger_continue();
            }
            Err(e) => self.add_toast(
                crate::app::ToastKind::Error,
                format!("Run-to-cursor BP failed: {}", e),
            ),
        }
    }
}

fn highlight_pseudocode(code: &str, syntax: &SyntaxColors) -> egui::text::LayoutJob {
    use egui::text::LayoutJob;
    use egui::{FontId, TextFormat};

    let mut job = LayoutJob::default();
    let font = FontId::monospace(13.0);

    let keyword_color = syntax.keyword;
    let string_color = syntax.string;
    let number_color = syntax.number;
    let comment_color = syntax.comment;
    let type_color = syntax.register;
    let default_color = syntax.text;
    let fn_color = syntax.address;

    let keywords: &[&str] = &[
        "if", "else", "while", "do", "for", "return", "void", "int", "char", "switch", "case",
        "break", "continue", "goto",
    ];
    let types: &[&str] = &[
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "void", "char", "float", "double", "bool",
    ];

    for line in code.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("//") {
            // Comment line
            let indent = &line[..line.len() - trimmed.len()];
            job.append(indent, 0.0, TextFormat::simple(font.clone(), default_color));
            job.append(
                trimmed,
                0.0,
                TextFormat::simple(font.clone(), comment_color),
            );
            job.append("\n", 0.0, TextFormat::simple(font.clone(), default_color));
            continue;
        }

        // Process token by token using char indices for UTF-8 safety
        let line_bytes = line.as_bytes();
        let mut pos = 0;

        while pos < line.len() {
            // SAFETY: we only advance `pos` by ASCII byte counts or full
            // char widths, so it always sits on a char boundary.
            let ch = line_bytes[pos];

            // Skip whitespace
            if ch == b' ' || ch == b'\t' {
                let start = pos;
                while pos < line.len() && (line_bytes[pos] == b' ' || line_bytes[pos] == b'\t') {
                    pos += 1;
                }
                job.append(
                    &line[start..pos],
                    0.0,
                    TextFormat::simple(font.clone(), default_color),
                );
                continue;
            }

            // Numbers: 0x... or digits
            if ch == b'0' && pos + 1 < line.len() && line_bytes[pos + 1] == b'x' {
                let start = pos;
                pos += 2;
                while pos < line.len() && line_bytes[pos].is_ascii_hexdigit() {
                    pos += 1;
                }
                job.append(
                    &line[start..pos],
                    0.0,
                    TextFormat::simple(font.clone(), number_color),
                );
                continue;
            }
            if ch.is_ascii_digit() {
                let start = pos;
                while pos < line.len() && line_bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                job.append(
                    &line[start..pos],
                    0.0,
                    TextFormat::simple(font.clone(), number_color),
                );
                continue;
            }

            // String literals
            if ch == b'"' {
                let start = pos;
                pos += 1;
                while pos < line.len() && line_bytes[pos] != b'"' {
                    if line_bytes[pos] == b'\\' {
                        pos += 1;
                    }
                    pos += 1;
                }
                if pos < line.len() {
                    pos += 1;
                }
                job.append(
                    &line[start..pos],
                    0.0,
                    TextFormat::simple(font.clone(), string_color),
                );
                continue;
            }

            // Identifiers / keywords
            if ch.is_ascii_alphabetic() || ch == b'_' {
                let start = pos;
                while pos < line.len()
                    && (line_bytes[pos].is_ascii_alphanumeric() || line_bytes[pos] == b'_')
                {
                    pos += 1;
                }
                let word = &line[start..pos];

                // Check if followed by '(' -> function call
                let is_call = pos < line.len() && line_bytes[pos] == b'(';

                let color = if keywords.contains(&word) {
                    keyword_color
                } else if types.contains(&word) {
                    type_color
                } else if is_call {
                    fn_color
                } else {
                    default_color
                };

                job.append(word, 0.0, TextFormat::simple(font.clone(), color));
                continue;
            }

            // Inline comment: // within a line
            if ch == b'/' && pos + 1 < line.len() && line_bytes[pos + 1] == b'/' {
                job.append(
                    &line[pos..],
                    0.0,
                    TextFormat::simple(font.clone(), comment_color),
                );
                pos = line.len();
                continue;
            }

            // Non-ASCII or single-byte operators/punctuation: advance by
            // full char width to stay on a UTF-8 boundary.
            let c = line[pos..].chars().next().unwrap();
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            job.append(s, 0.0, TextFormat::simple(font.clone(), default_color));
            pos += c.len_utf8();
        }

        job.append("\n", 0.0, TextFormat::simple(font.clone(), default_color));
    }

    job
}
