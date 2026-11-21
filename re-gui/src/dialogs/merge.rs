use std::path::{Path, PathBuf};
use std::sync::mpsc;

use eframe::egui;
use re_core::project::{MergeReview, MergeSide, Project};
use serde_json::Value;

use crate::app::{SleuthreApp, ToastKind};

#[derive(Default)]
pub(crate) struct MergeDialog {
    base: Option<PathBuf>,
    incoming: Option<PathBuf>,
    loading: Option<mpsc::Receiver<Result<MergeReview, String>>>,
    review: Option<MergeReview>,
    index: usize,
    error: Option<String>,
}

fn select_export(ui: &mut egui::Ui, title: &str, path: &mut Option<PathBuf>) {
    ui.horizontal(|ui| {
        if ui.button(title).clicked()
            && let Some(picked) = rfd::FileDialog::new()
                .set_title(title)
                .add_filter("JSON Lines", &["jsonl", "ndjson"])
                .pick_file()
        {
            *path = Some(picked);
        }
        if let Some(path) = path {
            ui.label(path.display().to_string());
        }
    });
}

fn read_export(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

impl MergeDialog {
    fn start(&mut self, project: &Project, ctx: &egui::Context) {
        let (Some(base), Some(incoming)) = (self.base.clone(), self.incoming.clone()) else {
            return;
        };
        let current = project.export_jsonl();
        let (tx, rx) = mpsc::channel();
        self.loading = Some(rx);
        self.error = None;
        self.index = 0;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = (|| {
                MergeReview::prepare(&read_export(&base)?, current, &read_export(&incoming)?)
                    .map_err(|e| e.to_string())
            })();
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let Some(rx) = &self.loading else { return };
        match rx.try_recv() {
            Ok(Ok(review)) => self.review = Some(review),
            Ok(Err(e)) => self.error = Some(e),
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some("Merge preview worker stopped.".into())
            }
        }
        self.loading = None;
    }
}

fn value_text(value: Option<&Value>) -> String {
    let Some(record) = value else {
        return "Absent".into();
    };
    match record["kind"].as_str() {
        Some("rename") => record["name"].as_str(),
        Some("comment") => record["text"].as_str(),
        Some("bookmark") => record["note"].as_str(),
        Some("tag") => record["tag"].as_str(),
        _ => None,
    }
    .map(str::to_owned)
    .unwrap_or_else(|| record.to_string())
}

fn show_preview(ui: &mut egui::Ui, review: &mut MergeReview, index: &mut usize) -> bool {
    let count = review.conflicts().len();
    ui.label(format!(
        "{} automatic changes · {count} conflicts",
        review.automatic_changes().len()
    ));
    if review.automatic_changes().len() > 0 {
        ui.collapsing("Automatic changes", |ui| {
            egui::ScrollArea::vertical()
                .id_salt("merge_auto")
                .max_height(150.0)
                .show_rows(
                    ui,
                    ui.spacing().interact_size.y,
                    review.automatic_changes().len(),
                    |ui, rows| {
                        for (kind, id, value) in
                            review.automatic_changes().skip(rows.start).take(rows.len())
                        {
                            let detail = value
                                .map(|v| value_text(Some(v)))
                                .unwrap_or_else(|| "Remove record".into());
                            ui.add(
                                egui::Label::new(format!("{kind} at {id} · {detail}")).truncate(),
                            );
                        }
                    },
                );
        });
    }
    if count > 0 {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(*index > 0, egui::Button::new("Previous"))
                .clicked()
            {
                *index -= 1;
            }
            ui.label(format!("Conflict {} of {count}", *index + 1));
            if ui
                .add_enabled(*index + 1 < count, egui::Button::new("Next"))
                .clicked()
            {
                *index += 1;
            }
        });
        let conflict = &review.conflicts()[*index];
        ui.strong(format!("{} at {}", conflict.kind(), conflict.identifier()));
        let mut choice = conflict.choice;
        egui::ScrollArea::vertical()
            .max_height(300.0)
            .show(ui, |ui| {
                ui.label("Common ancestor");
                ui.monospace(value_text(conflict.base.as_ref()));
                for (side, label, value) in [
                    (MergeSide::Current, "Current branch", &conflict.current),
                    (MergeSide::Incoming, "Incoming branch", &conflict.incoming),
                ] {
                    ui.radio_value(&mut choice, Some(side), label);
                    ui.monospace(value_text(value.as_ref()));
                }
            });
        if let Some(side) = choice {
            review.choose(*index, side);
        }
    }
    let ready = review.conflicts().iter().all(|c| c.choice.is_some());
    ui.add_enabled(ready, egui::Button::new("Apply merge"))
        .clicked()
}

impl SleuthreApp {
    pub(crate) fn show_merge_dialog(&mut self, ctx: &egui::Context) {
        let (Some(dialog), Some(project)) = (&mut self.merge_dialog, &mut self.project) else {
            return;
        };
        dialog.poll();
        let mut applied = None;
        let response = egui::Modal::new("jsonl_merge".into()).show(ctx, |ui| {
            ui.set_max_width(650.0);
            ui.heading("Review JSONL merge");
            ui.label(format!("Current branch · {}", project.name));
            if let Some(review) = &mut dialog.review {
                if show_preview(ui, review, &mut dialog.index) {
                    match review.apply(project) {
                        Ok(changed) => applied = Some(changed),
                        Err(e) => dialog.error = Some(e.to_string()),
                    }
                }
                if ui.button("Change inputs").clicked() {
                    dialog.review = None;
                    dialog.error = None;
                }
            } else if dialog.loading.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Preparing merge preview…");
                });
            } else {
                select_export(ui, "Select common ancestor…", &mut dialog.base);
                select_export(ui, "Select incoming branch…", &mut dialog.incoming);
                if ui
                    .add_enabled(
                        dialog.base.is_some() && dialog.incoming.is_some(),
                        egui::Button::new("Preview merge"),
                    )
                    .clicked()
                {
                    dialog.start(project, ctx);
                }
            }
            if let Some(error) = &dialog.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            if ui.button("Cancel").clicked() {
                ui.close();
            }
        });
        if applied.is_some() || response.should_close() {
            self.merge_dialog = None;
        }
        if let Some(changed) = applied {
            if changed > 0 {
                self.cached_func_list_dirty = true;
                self.decompiled_code = Default::default();
                self.update_cfg();
            }
            self.add_toast(
                ToastKind::Success,
                format!("Merge applied · {changed} changed records"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use re_core::analysis::functions::{CallingConvention, Function};
    use std::time::{Duration, Instant};

    fn draw(
        app: &mut SleuthreApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 800.0),
            )),
            events,
            ..Default::default()
        };
        let mut frame = ctx.run_ui(input, |_| app.show_merge_dialog(ctx));
        frame.textures_delta.clear();
        frame
    }

    fn click(app: &mut SleuthreApp, ctx: &egui::Context, label: &str) {
        draw(app, ctx, vec![]);
        let frame = draw(app, ctx, vec![]);
        let pos = frame
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text() == label => {
                    Some(t.visual_bounding_rect().center())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing button {label}"));
        for pressed in [true, false] {
            draw(
                app,
                ctx,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        pressed,
                        button: egui::PointerButton::Primary,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
    }

    #[test]
    fn review_conflicting_rename_and_independent_comments_then_apply_or_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("ancestor.jsonl");
        let incoming = dir.path().join("incoming.jsonl");
        std::fs::write(
            &base,
            r#"{"kind":"rename","address":"0x1000","name":"original"}"#,
        )
        .unwrap();
        std::fs::write(
            &incoming,
            concat!(
                "{\"kind\":\"rename\",\"address\":\"0x1000\",\"name\":\"their_name\"}\n",
                "{\"kind\":\"comment\",\"address\":\"0x1002\",\"text\":\"theirs\"}\n"
            ),
        )
        .unwrap();

        for (branch, finish, expected) in [
            ("Incoming branch", "Apply merge", "their_name"),
            ("Current branch", "Apply merge", "our_name"),
            ("Incoming branch", "Cancel", "our_name"),
        ] {
            let mut project = Project::new("sample".into(), dir.path().join("sample.bin"));
            project.functions.add_function(Function {
                name: "our_name".into(),
                start_address: 0x1000,
                end_address: None,
                calling_convention: CallingConvention::default(),
                stack_frame_size: 0,
            });
            project.comments.insert(0x1001, "ours".into());
            let before = project.export_jsonl();
            let mut app = SleuthreApp::default();
            app.project = Some(project);
            app.merge_dialog = Some(MergeDialog {
                base: Some(base.clone()),
                incoming: Some(incoming.clone()),
                ..Default::default()
            });
            let ctx = egui::Context::default();
            click(&mut app, &ctx, "Preview merge");
            let deadline = Instant::now() + Duration::from_secs(5);
            while app.merge_dialog.as_ref().unwrap().review.is_none() {
                assert!(Instant::now() < deadline, "preview timed out");
                draw(&mut app, &ctx, vec![]);
                std::thread::yield_now();
            }
            let frame = draw(&mut app, &ctx, vec![]);
            let labels: Vec<_> = frame
                .shapes
                .iter()
                .filter_map(|s| match &s.shape {
                    egui::Shape::Text(t) => Some(t.galley.text()),
                    _ => None,
                })
                .collect();
            for value in ["rename at 0x1000", "original", "our_name", "their_name"] {
                assert!(labels.contains(&value), "missing {value}: {labels:?}");
            }
            click(&mut app, &ctx, "Apply merge");
            assert!(
                app.merge_dialog.is_some(),
                "unresolved conflict must block apply"
            );
            click(&mut app, &ctx, branch);
            assert_eq!(app.project.as_ref().unwrap().export_jsonl(), before);
            click(&mut app, &ctx, finish);
            assert!(app.merge_dialog.is_none());
            let project = app.project.as_mut().unwrap();
            assert_eq!(project.functions.functions[&0x1000].name, expected);
            assert_eq!(project.comments[&0x1001], "ours");
            if finish == "Cancel" {
                assert_eq!(project.export_jsonl(), before);
            } else {
                assert_eq!(project.comments[&0x1002], "theirs");
                let saved = dir.path().join(format!("merged-{expected}.slre"));
                project.save_new(&saved).unwrap();
                let reopened = Project::load(&saved).unwrap();
                assert_eq!(reopened.functions.functions[&0x1000].name, expected);
                assert_eq!(reopened.comments, project.comments);
            }
        }
    }
}
