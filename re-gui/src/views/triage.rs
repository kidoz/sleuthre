use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, mpsc};

use eframe::egui;
use re_core::analysis::strings::StringEncoding;
use re_core::analysis::triage::{Evidence, ReportFormat, TriageReport};

use crate::app::{SleuthreApp, Tab, ToastKind};

/// Replace the destination only after the complete export has been flushed.
pub(crate) fn save_report(
    report: &TriageReport,
    format: ReportFormat,
    path: &Path,
) -> io::Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
    {
        let mut writer = io::BufWriter::new(temp.as_file_mut());
        report.write(format, &mut writer)?;
        writer.flush()?;
    }
    temp.persist(path)?;
    Ok(())
}

impl SleuthreApp {
    pub(crate) fn show_triage(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.triage else {
            ui.label("Open the original executable to view its triage report.");
            if ui
                .add_enabled(!self.is_loading(), egui::Button::new("Open Binary…"))
                .clicked()
            {
                self.open_binary(ui.ctx());
            }
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.heading("Triage");
            ui.label(format!(
                "{:?} · {} · entry {:#x}",
                report.format, report.architecture, report.entry_point.0
            ));
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("SHA-256");
            ui.monospace(&report.sha256);
        });
        ui.label(format!(
            "{} segments · {} imports · entropy {:.6} bits/byte",
            report.segments.len(),
            report.imports.len(),
            report.entropy
        ));
        let mut export = None;
        ui.horizontal(|ui| {
            for (label, format) in [
                ("Export JSON…", ReportFormat::Json),
                ("Export Markdown…", ReportFormat::Markdown),
            ] {
                if ui
                    .add_enabled(self.triage_export.is_none(), egui::Button::new(label))
                    .clicked()
                {
                    export = Some(format);
                }
            }
            if self.triage_export.is_some() {
                ui.spinner();
            }
        });
        ui.separator();
        ui.strong(format!("Findings ({})", report.findings.len()));
        if report.findings.is_empty() {
            ui.label("No strings or constants found.");
        }
        egui::ScrollArea::vertical().show_rows(
            ui,
            ui.spacing().interact_size.y,
            report.findings.len(),
            |ui, visible| {
                for index in visible {
                    let finding = &report.findings[index];
                    let (kind, value) = match &finding.evidence {
                        Evidence::String { encoding, value } => {
                            (format!("{encoding:?} string"), value)
                        }
                        Evidence::Constant { description, value } => (description.clone(), value),
                    };
                    // Avoid laying out a multi-megabyte extracted string in a single row.
                    let mut chars = value.chars();
                    let mut preview: String = chars
                        .by_ref()
                        .take(120)
                        .flat_map(char::escape_debug)
                        .collect();
                    if chars.next().is_some() {
                        preview.push('…');
                    }
                    let label = format!("{:#x}   {kind}   {preview}", finding.address.0);
                    if ui
                        .add(egui::Button::selectable(false, label).truncate())
                        .clicked()
                    {
                        self.pending_triage_finding = Some(index);
                    }
                }
            },
        );
        if let Some(format) = export {
            let ext = match format {
                ReportFormat::Json => "json",
                ReportFormat::Markdown => "md",
            };
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Report", &[ext])
                .set_file_name(format!("triage.{ext}"))
                .save_file()
            {
                let report = Arc::clone(report);
                let ctx = ui.ctx().clone();
                let (tx, rx) = mpsc::channel();
                self.triage_export = Some(rx);
                std::thread::spawn(move || {
                    let _ = tx.send(save_report(&report, format, &path));
                    ctx.request_repaint();
                });
            }
        }
    }

    pub(crate) fn poll_triage_export(&mut self) {
        let Some(rx) = &self.triage_export else {
            return;
        };
        let (kind, message) = match rx.try_recv() {
            Ok(Ok(())) => (ToastKind::Success, "Triage report exported.".into()),
            Ok(Err(e)) => (ToastKind::Error, format!("Triage export failed: {e}")),
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                (ToastKind::Error, "Triage export worker stopped.".into())
            }
        };
        self.triage_export = None;
        self.add_toast(kind, message);
    }

    pub(crate) fn open_triage_finding(&mut self, index: usize) {
        let Some(f) = self.triage.as_ref().and_then(|r| r.findings.get(index)) else {
            return;
        };
        let start = f.address.0;
        let Some(segment) = self
            .project
            .as_ref()
            .and_then(|p| p.memory_map.segment_at(start))
        else {
            return;
        };
        let len = match &f.evidence {
            Evidence::String {
                encoding: StringEncoding::Ascii,
                value,
            } => value.len(),
            Evidence::String { value, .. } => value.encode_utf16().count().saturating_mul(2),
            Evidence::Constant { .. } => 1,
        };
        let end = start
            .saturating_add(len as u64)
            .min(segment.start.saturating_add(segment.size));
        self.focus_or_open_tab(Tab::HexView);
        self.follow_reference(self.current_address, start);
        self.hex_selected_addr = None;
        self.hex_evidence = Some(start..end);
        self.scroll_to_evidence = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::LoadProgress;
    use eframe::App;
    use re_core::analysis::pipeline::{AnalysisMode, analyze_binary_with_triage};

    #[test]
    fn finding_click_opens_highlighted_bytes_and_gui_exports_match_fixture() {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../re-core/tests/fixtures/triage.pe");
        let result =
            analyze_binary_with_triage(&fixture, AnalysisMode::QuickTriage, None, |_| {}).unwrap();
        let (tx, rx) = mpsc::channel();
        tx.send(LoadProgress::Done(Ok(Box::new(result)))).unwrap();
        let mut app = SleuthreApp::default();
        app.load_receiver = Some(rx);
        app.poll_load();
        app.focus_or_open_tab(Tab::Triage);

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("report");
        for (format, expected) in [
            (ReportFormat::Json, fixture.with_extension("json")),
            (ReportFormat::Markdown, fixture.with_extension("md")),
        ] {
            save_report(app.triage.as_ref().unwrap(), format, &output).unwrap();
            assert_eq!(
                std::fs::read(&output).unwrap(),
                std::fs::read(expected).unwrap()
            );
        }

        let ctx = egui::Context::default();
        let mut frame = eframe::Frame::_new_kittest();
        let mut draw = |events| {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 800.0),
                )),
                events,
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |ui| app.ui(ui, &mut frame));
            output.textures_delta.clear();
            output
        };
        let output = draw(vec![]);
        let pos = output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text().contains("sleuthre triage fixture") => {
                    Some(t.visual_bounding_rect().center())
                }
                _ => None,
            })
            .expect("the fixture string is a visible finding");
        for pressed in [true, false] {
            draw(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
        let hex = draw(vec![]);
        let highlighted: Vec<_> = hex
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::Shape::Text(t)
                    if t.galley.text().len() == 2
                        && t.galley
                            .job
                            .sections
                            .iter()
                            .any(|s| s.format.background != egui::Color32::TRANSPARENT) =>
                {
                    Some(t.galley.text())
                }
                _ => None,
            })
            .collect();
        let expected: Vec<_> = b"sleuthre triage fixture"
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(highlighted, expected);
        assert_eq!(app.active_tab, Tab::HexView);
        assert_eq!(app.current_address, 0x140002000);
        assert!(app.hex_selected_addr.is_none());
    }
}
