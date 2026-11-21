use std::path::PathBuf;

use eframe::egui;
use re_core::arch::{Architecture, Endianness};
use re_core::loader::{RawRegion, load_raw_regions};

use super::parse_hex_u64;
use crate::app::{SleuthreApp, ToastKind};

pub(crate) struct RawImageDialog {
    path: PathBuf,
    arch: Architecture,
    order: Endianness,
    entry: String,
    regions: Vec<RegionRow>,
    pub(crate) error: Option<String>,
}

struct RegionRow {
    name: String,
    offset: String,
    length: String,
    start: String,
}

impl RegionRow {
    fn parse(&self, index: usize) -> Result<RawRegion, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(format!("Enter a name for region {}.", index + 1));
        }
        let number = |value, field| {
            parse_hex_u64(value)
                .ok_or_else(|| format!("Enter a decimal or 0x-prefixed {field} for '{name}'."))
        };
        let size = |value, field| {
            usize::try_from(number(value, field)?)
                .map_err(|_| format!("The {field} for '{name}' is too large."))
        };
        Ok(RawRegion {
            name: name.into(),
            file_offset: size(&self.offset, "file offset")?,
            length: size(&self.length, "length")?,
            start: number(&self.start, "virtual start")?,
        })
    }
}

impl RawImageDialog {
    fn new(path: PathBuf, length: u64) -> Self {
        let arch = Architecture::default();
        Self {
            path,
            arch,
            order: arch.default_endianness(),
            entry: String::new(),
            regions: vec![RegionRow {
                name: "raw".into(),
                offset: "0".into(),
                length: length.to_string(),
                start: "0x0".into(),
            }],
            error: None,
        }
    }

    fn settings(&self) -> Result<(Vec<RawRegion>, Option<u64>), String> {
        let entry = if self.entry.trim().is_empty() {
            None
        } else {
            Some(parse_hex_u64(&self.entry).ok_or("Enter a decimal or 0x-prefixed entry point.")?)
        };
        let regions = self
            .regions
            .iter()
            .enumerate()
            .map(|(i, row)| row.parse(i))
            .collect::<Result<_, _>>()?;
        Ok((regions, entry))
    }

    fn fields(&mut self, ui: &mut egui::Ui) {
        ui.heading("Open Raw Image");
        ui.label(self.path.display().to_string());
        ui.horizontal(|ui| {
            egui::ComboBox::from_label("Architecture")
                .selected_text(self.arch.display_name())
                .show_ui(ui, |ui| {
                    use Architecture::*;
                    for arch in [X86, X86_64, Arm, Arm64, Mips, Mips64, RiscV32, RiscV64] {
                        if ui
                            .selectable_value(&mut self.arch, arch, arch.display_name())
                            .changed()
                        {
                            self.order = arch.default_endianness();
                        }
                    }
                });
            egui::ComboBox::from_label("Byte order")
                .selected_text(format!("{:?}", self.order))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.order, Endianness::Little, "Little");
                    ui.selectable_value(&mut self.order, Endianness::Big, "Big");
                });
        });
        ui.horizontal(|ui| {
            ui.label("Entry point");
            ui.add(egui::TextEdit::singleline(&mut self.entry).hint_text("First region start"));
        });
        ui.label("Enter offsets, lengths, and addresses in decimal or 0x-prefixed hex.");
        let mut remove = None;
        let can_remove = self.regions.len() > 1;
        egui::ScrollArea::vertical()
            .max_height(240.0)
            .show(ui, |ui| {
                egui::Grid::new("raw_regions").show(ui, |ui| {
                    for label in ["Name", "File offset", "Length", "Virtual start"] {
                        ui.strong(label);
                    }
                    ui.end_row();
                    for (i, row) in self.regions.iter_mut().enumerate() {
                        for field in [
                            &mut row.name,
                            &mut row.offset,
                            &mut row.length,
                            &mut row.start,
                        ] {
                            ui.add(egui::TextEdit::singleline(field).desired_width(95.0));
                        }
                        if ui
                            .add_enabled(can_remove, egui::Button::new("Remove"))
                            .clicked()
                        {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
            });
        if let Some(i) = remove {
            self.regions.remove(i);
        }
        if ui.button("Add region").clicked() {
            self.regions.push(RegionRow {
                name: String::new(),
                offset: String::new(),
                length: String::new(),
                start: String::new(),
            });
        }
        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
    }
}

impl SleuthreApp {
    pub(crate) fn raw_image_button(&mut self, ui: &mut egui::Ui) -> bool {
        let clicked = ui
            .add_enabled(!self.is_loading(), egui::Button::new("Open Raw Image…"))
            .clicked();
        if clicked {
            self.open_raw_image();
        }
        clicked
    }

    pub(crate) fn open_raw_image(&mut self) {
        if self.is_loading() {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open Raw Image")
            .pick_file()
        {
            match path.metadata() {
                Ok(metadata) => self.raw_dialog = Some(RawImageDialog::new(path, metadata.len())),
                Err(error) => self.add_toast(
                    ToastKind::Error,
                    format!("Cannot open {}: {error}", path.display()),
                ),
            }
        }
    }

    pub(crate) fn show_raw_image_dialog(&mut self, ctx: &egui::Context) {
        if self.is_loading() {
            return;
        }
        let Some(dialog) = &mut self.raw_dialog else {
            return;
        };
        let response = egui::Modal::new("open_raw_image".into()).show(ctx, |ui| {
            dialog.fields(ui);
            ui.horizontal(|ui| {
                let open = ui.button("Open").clicked();
                if ui.button("Cancel").clicked() {
                    ui.close();
                }
                open
            })
            .inner
        });
        if response.should_close() {
            self.raw_dialog = None;
        } else if response.inner {
            self.submit_raw_image(ctx);
        }
    }

    fn submit_raw_image(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.raw_dialog else {
            return;
        };
        match dialog.settings() {
            Ok((regions, entry)) => {
                let (arch, order) = (dialog.arch, dialog.order);
                let path = dialog.path.clone();
                dialog.error = None;
                self.start_file_load(ctx, path, move |bytes| {
                    load_raw_regions(bytes, &regions, arch, order, entry)
                });
            }
            Err(error) => dialog.error = Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::triage::save_report;
    use re_core::analysis::triage::ReportFormat;
    use std::time::{Duration, Instant};

    fn fixture_dialog() -> RawImageDialog {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../re-core/tests/fixtures/two-regions.raw");
        let mut dialog = RawImageDialog::new(path, 8);
        dialog.arch = Architecture::Mips;
        dialog.order = Endianness::Little;
        dialog.entry = "0x8001".into();
        dialog.regions = [("high", "4", "0x8000"), ("low", "0", "0x1000")]
            .map(|(name, offset, start)| RegionRow {
                name: name.into(),
                offset: offset.into(),
                length: "4".into(),
                start: start.into(),
            })
            .into();
        dialog
    }

    fn wait_for_load(app: &mut SleuthreApp) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while app.is_loading() {
            assert!(Instant::now() < deadline, "raw load timed out");
            app.poll_load();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn raw_project_reopens_with_both_regions_and_the_original_cli_report() {
        let mut app = SleuthreApp::default();
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sample.raw");
        let mut dialog = fixture_dialog();
        std::fs::copy(&dialog.path, &source).unwrap();
        dialog.path = source.clone();
        app.raw_dialog = Some(dialog);
        let mut draw = |events| {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 700.0),
                )),
                events,
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |_| app.show_raw_image_dialog(&ctx));
            output.textures_delta.clear();
            output
        };
        draw(vec![]);
        let dialog = draw(vec![]);
        let open = dialog
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == "Open" => {
                    Some(text.visual_bounding_rect().center())
                }
                _ => None,
            })
            .expect("the raw dialog has an Open button");
        for pressed in [true, false] {
            draw(vec![
                egui::Event::PointerMoved(open),
                egui::Event::PointerButton {
                    pos: open,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
        wait_for_load(&mut app);
        assert!(app.raw_dialog.is_none(), "{}", app.output);
        assert_eq!(app.current_address, 0x8001);
        let export = dir.path().join("report.json");
        save_report(app.triage.as_ref().unwrap(), ReportFormat::Json, &export).unwrap();
        let before = std::fs::read(&export).unwrap();
        assert_eq!(
            before,
            include_bytes!("../../../re-core/tests/fixtures/two-regions.json")
        );

        let saved = dir.path().join("project.slre");
        app.remember_view_address();
        app.project.as_mut().unwrap().save_new(&saved).unwrap();
        drop(app);
        std::fs::remove_file(source).unwrap();
        let mut app = SleuthreApp::default();
        app.load_project_from_path(&saved);
        assert_eq!(app.current_address, 0x8001, "{}", app.output);
        for (address, displayed) in [
            (0x1001, "ABCD"),
            (0x8001, "EFGH"),
            (0x1004, "Address 0x1004 is unmapped."),
        ] {
            app.current_address = address;
            let mut output = ctx.run_ui(Default::default(), |ui| app.show_hex_view(ui));
            output.textures_delta.clear();
            assert!(
                output.shapes.iter().any(
                    |s| matches!(&s.shape, egui::Shape::Text(t) if t.galley.text() == displayed)
                ),
                "{address:#x}"
            );
        }
        let memory = &app.project.as_ref().unwrap().memory_map;
        assert_eq!(memory.get_data(0x1001, 1), Some(&b"B"[..]));
        assert_eq!(memory.get_data(0x8001, 1), Some(&b"F"[..]));
        assert_eq!(memory.get_data(0x1004, 1), None);

        save_report(app.triage.as_ref().unwrap(), ReportFormat::Json, &export).unwrap();
        assert_eq!(std::fs::read(export).unwrap(), before);
    }

    #[test]
    fn raw_project_decodes_big_endian_instructions() {
        let mut dialog = fixture_dialog();
        dialog.path.set_file_name("mips-addiu.raw");
        dialog.order = Endianness::Big;
        dialog.entry.clear();
        dialog.regions.truncate(1);
        let mut app = SleuthreApp::default();
        app.raw_dialog = Some(dialog);
        app.submit_raw_image(&egui::Context::default());
        wait_for_load(&mut app);
        let memory = &app.project.as_ref().unwrap().memory_map;
        let insn = app
            .disasm
            .as_ref()
            .unwrap()
            .disassemble_one(memory, app.current_address)
            .unwrap();
        assert_eq!(insn.mnemonic, "addiu");
    }

    #[test]
    fn invalid_mapping_keeps_the_project_and_can_be_corrected() {
        let ctx = egui::Context::default();
        let mut app = SleuthreApp::default();
        app.project = Some(re_core::project::Project::new(
            "original".into(),
            PathBuf::new(),
        ));
        let mut dialog = fixture_dialog();
        dialog.regions[0].start = "oops".into();
        app.raw_dialog = Some(dialog);
        app.submit_raw_image(&ctx);
        assert!(!app.is_loading());
        let dialog = app.raw_dialog.as_mut().unwrap();
        assert!(dialog.error.as_ref().unwrap().contains("virtual start"));
        dialog.regions[0].start = "0x1002".into();
        app.submit_raw_image(&ctx);
        wait_for_load(&mut app);
        assert_eq!(app.project.as_ref().unwrap().name, "original");
        let dialog = app.raw_dialog.as_mut().unwrap();
        let error = dialog.error.as_ref().unwrap();
        assert!(
            ["high", "low", "overlaps"]
                .iter()
                .all(|part| error.contains(part)),
            "{error}"
        );
        dialog.regions[0].start = "0x8000".into();
        dialog.entry.clear();
        app.submit_raw_image(&ctx);
        wait_for_load(&mut app);
        assert!(app.raw_dialog.is_none());
        assert_eq!(app.current_address, 0x8000);
    }
}
