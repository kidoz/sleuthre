//! Inference Evidence panel: reviews struct-pointer candidates recorded by
//! the analysis pipeline. Each candidate lists the concrete access sites
//! (address, read/write, width) behind every inferred field plus a heuristic
//! confidence, and can be accepted (materializing a struct type), rejected,
//! or reset — all undoable through the project command stack.

use eframe::egui;
use re_core::analysis::struct_inference::{AccessKind, EvidenceStatus, StructCandidate};

use crate::app::SleuthreApp;

/// Amber shared with the decompiler's "⚠ inferred signature" badge so both
/// inference surfaces read as one system.
pub(crate) const INFERRED_AMBER: egui::Color32 = egui::Color32::from_rgb(200, 170, 90);

/// Deferred accept/reject/reset intent from the evidence panel's scroll-area
/// closure — it cannot call `&mut self` project methods while the candidate
/// list is borrowed, so clicks stash intent here for the post-closure handler.
pub(crate) enum InferenceAction {
    Accept {
        function: u64,
        base: String,
        type_name: String,
    },
    SetStatus {
        function: u64,
        base: String,
        status: EvidenceStatus,
    },
}

impl SleuthreApp {
    pub(crate) fn show_inference_evidence(&mut self, ui: &mut egui::Ui) {
        let Some(project) = &self.project else {
            ui.label("No binary loaded.");
            return;
        };
        let candidates = &project.struct_candidates;

        ui.horizontal(|ui| {
            ui.heading("Inference Evidence");
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(summary_line(candidates))
                    .size(11.0)
                    .color(self.syntax.text_dim),
            );
        });
        ui.separator();

        if candidates.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No struct candidates recorded. Evidence appears after running \
                     analysis with struct inference enabled — re-analyze the binary \
                     if this project predates inference.",
                )
                .color(self.syntax.text_dim),
            );
            return;
        }

        // Filter row
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.inference_filter)
                    .desired_width(180.0)
                    .hint_text("function, address, or register..."),
            );
            ui.checkbox(&mut self.inference_show_rejected, "Show rejected");
            ui.add_space(8.0);
            ui.label("Min confidence:");
            ui.add(
                egui::Slider::new(&mut self.inference_min_confidence, 0.0..=1.0).fixed_decimals(2),
            );
        });
        ui.separator();

        let mut jump_to: Option<u64> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut shown = 0usize;
            for cand in candidates {
                if !candidate_visible(
                    cand,
                    &self.inference_filter,
                    self.inference_show_rejected,
                    self.inference_min_confidence,
                ) {
                    continue;
                }
                shown += 1;
                let key = (cand.function, cand.base.clone());
                let expanded = self.inference_expanded.contains(&key);

                ui.horizontal(|ui| {
                    if ui.small_button(if expanded { "▼" } else { "▶" }).clicked() {
                        if expanded {
                            self.inference_expanded.remove(&key);
                        } else {
                            self.inference_expanded.insert(key.clone());
                        }
                    }
                    ui.label(egui::RichText::new(&cand.function_name).strong());
                    ui.label(
                        egui::RichText::new(format!("{:08X}", cand.function))
                            .monospace()
                            .color(self.syntax.address),
                    );
                    ui.label(
                        egui::RichText::new(&cand.base)
                            .monospace()
                            .color(self.syntax.register),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "{} field{}",
                            cand.fields.len(),
                            if cand.fields.len() == 1 { "" } else { "s" }
                        ))
                        .size(11.0)
                        .color(self.syntax.text_dim),
                    );
                    ui.label(
                        egui::RichText::new(format!("{:.0}%", cand.confidence * 100.0))
                            .size(11.0)
                            .color(self.syntax.number),
                    )
                    .on_hover_text("Heuristic confidence — never claims certainty.");
                    ui.label(status_chip(cand));

                    match cand.status {
                        EvidenceStatus::Proposed => {
                            if ui.small_button("Accept").clicked() {
                                let type_name = self
                                    .inference_type_names
                                    .get(&key)
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or_else(|| cand.suggested_type_name());
                                self.pending_inference_action = Some(InferenceAction::Accept {
                                    function: cand.function,
                                    base: cand.base.clone(),
                                    type_name,
                                });
                            }
                            if ui.small_button("Reject").clicked() {
                                self.pending_inference_action = Some(InferenceAction::SetStatus {
                                    function: cand.function,
                                    base: cand.base.clone(),
                                    status: EvidenceStatus::Rejected,
                                });
                            }
                        }
                        EvidenceStatus::Accepted | EvidenceStatus::Rejected => {
                            if ui.small_button("Reset").clicked() {
                                self.pending_inference_action = Some(InferenceAction::SetStatus {
                                    function: cand.function,
                                    base: cand.base.clone(),
                                    status: EvidenceStatus::Proposed,
                                });
                            }
                        }
                    }
                });

                if expanded {
                    ui.indent(("inference_cand", cand.function, &cand.base), |ui| {
                        if cand.status == EvidenceStatus::Proposed {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Type name:").size(11.0));
                                let name = self
                                    .inference_type_names
                                    .entry(key.clone())
                                    .or_insert_with(|| cand.suggested_type_name());
                                ui.add(egui::TextEdit::singleline(name).desired_width(220.0));
                            });
                        }
                        egui::Grid::new(("inference_fields", cand.function, &cand.base))
                            .striped(true)
                            .min_col_width(60.0)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Field").strong().size(11.0));
                                ui.label(egui::RichText::new("Access").strong().size(11.0));
                                ui.label(egui::RichText::new("Kind").strong().size(11.0));
                                ui.label(egui::RichText::new("Size").strong().size(11.0));
                                ui.end_row();

                                for field in &cand.fields {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "+0x{:x} ({}B, {} access{})",
                                            field.offset,
                                            field.size,
                                            field.accesses.len(),
                                            if field.accesses.len() == 1 { "" } else { "es" },
                                        ))
                                        .monospace()
                                        .size(11.0),
                                    );
                                    ui.label("");
                                    ui.label("");
                                    ui.label("");
                                    ui.end_row();

                                    for access in &field.accesses {
                                        ui.label("");
                                        if ui
                                            .add(
                                                egui::Label::new(
                                                    egui::RichText::new(format!(
                                                        "{:08X}",
                                                        access.address
                                                    ))
                                                    .monospace()
                                                    .color(self.syntax.link),
                                                )
                                                .sense(egui::Sense::click()),
                                            )
                                            .clicked()
                                        {
                                            jump_to = Some(access.address);
                                        }
                                        let (kind_str, kind_color) = match access.kind {
                                            AccessKind::Read => ("Read", self.syntax.number),
                                            AccessKind::Write => ("Write", self.syntax.string),
                                        };
                                        ui.label(
                                            egui::RichText::new(kind_str)
                                                .color(kind_color)
                                                .size(11.0),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!("{}B", access.size))
                                                .size(11.0),
                                        );
                                        ui.end_row();
                                    }
                                }
                            });
                    });
                }
                ui.separator();
            }

            if shown == 0 {
                ui.label(
                    egui::RichText::new("No candidates match the current filter.")
                        .color(self.syntax.text_dim),
                );
            }
        });

        // Apply deferred accept/reject/reset now that the candidate borrow
        // has ended; both wrappers are undoable and return a log description.
        if let Some(action) = self.pending_inference_action.take() {
            let desc = match (&mut self.project, action) {
                (
                    Some(project),
                    InferenceAction::Accept {
                        function,
                        base,
                        type_name,
                    },
                ) => project.accept_struct_candidate(function, &base, &type_name),
                (
                    Some(project),
                    InferenceAction::SetStatus {
                        function,
                        base,
                        status,
                    },
                ) => project.set_struct_candidate_status(function, &base, status),
                (None, _) => None,
            };
            if let Some(desc) = desc {
                self.output.push_str(&desc);
                self.output.push('\n');
                self.add_toast(crate::app::ToastKind::Success, desc);
            }
        }

        if let Some(addr) = jump_to {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.update_cfg();
        }
    }
}

/// Status chip text: amber Proposed (matching the decompiler badge), green
/// Accepted (with the materialized type name), gray struck-through Rejected.
fn status_chip(cand: &StructCandidate) -> egui::RichText {
    match cand.status {
        EvidenceStatus::Proposed => egui::RichText::new("Proposed").color(INFERRED_AMBER),
        EvidenceStatus::Accepted => {
            let label = match &cand.accepted_type {
                Some(t) => format!("Accepted as {}", t),
                None => "Accepted".to_string(),
            };
            egui::RichText::new(label).color(egui::Color32::from_rgb(120, 190, 120))
        }
        EvidenceStatus::Rejected => egui::RichText::new("Rejected")
            .color(egui::Color32::GRAY)
            .strikethrough(),
    }
    .size(11.0)
}

/// Pure visibility predicate for one candidate under the panel's filter
/// controls. The text filter matches the function name, the function address
/// (hex, with or without `0x` / zero-padding), or the base register.
fn candidate_visible(
    cand: &StructCandidate,
    filter: &str,
    show_rejected: bool,
    min_confidence: f32,
) -> bool {
    if cand.status == EvidenceStatus::Rejected && !show_rejected {
        return false;
    }
    if cand.confidence < min_confidence {
        return false;
    }
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return true;
    }
    let addr_query = filter.strip_prefix("0x").unwrap_or(&filter);
    cand.function_name.to_lowercase().contains(&filter)
        || cand.base.to_lowercase().contains(&filter)
        || (!addr_query.is_empty()
            && (format!("{:x}", cand.function).contains(addr_query)
                || format!("{:08x}", cand.function).contains(addr_query)))
}

/// Header summary, e.g. `12 candidates — 3 accepted, 2 rejected`.
fn summary_line(candidates: &[StructCandidate]) -> String {
    let total = candidates.len();
    if total == 0 {
        return "no candidates".to_string();
    }
    let accepted = candidates
        .iter()
        .filter(|c| c.status == EvidenceStatus::Accepted)
        .count();
    let rejected = candidates
        .iter()
        .filter(|c| c.status == EvidenceStatus::Rejected)
        .count();
    format!(
        "{} candidate{} — {} accepted, {} rejected",
        total,
        if total == 1 { "" } else { "s" },
        accepted,
        rejected
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use re_core::analysis::struct_inference::{AccessSite, FieldEvidence};

    fn candidate(
        name: &str,
        function: u64,
        base: &str,
        confidence: f32,
        status: EvidenceStatus,
    ) -> StructCandidate {
        StructCandidate {
            function,
            function_name: name.to_string(),
            base: base.to_string(),
            fields: vec![FieldEvidence {
                offset: 8,
                size: 4,
                accesses: vec![AccessSite {
                    address: function + 0x10,
                    kind: AccessKind::Read,
                    size: 4,
                }],
            }],
            confidence,
            status,
            accepted_type: None,
        }
    }

    #[test]
    fn filter_matches_name_address_and_base() {
        let c = candidate(
            "ProcessPacket",
            0x401200,
            "rdi",
            0.7,
            EvidenceStatus::Proposed,
        );
        assert!(candidate_visible(&c, "", false, 0.0));
        assert!(candidate_visible(&c, "processpa", false, 0.0));
        assert!(candidate_visible(&c, "401200", false, 0.0));
        assert!(candidate_visible(&c, "0x401200", false, 0.0));
        assert!(candidate_visible(&c, "00401200", false, 0.0));
        assert!(candidate_visible(&c, "RDI", false, 0.0));
        assert!(!candidate_visible(&c, "unrelated", false, 0.0));
        // A bare "0x" must not match everything.
        assert!(!candidate_visible(&c, "0x", false, 0.0));
    }

    #[test]
    fn rejected_hidden_unless_opted_in() {
        let c = candidate("f", 0x1000, "rsi", 0.9, EvidenceStatus::Rejected);
        assert!(!candidate_visible(&c, "", false, 0.0));
        assert!(candidate_visible(&c, "", true, 0.0));
    }

    #[test]
    fn min_confidence_threshold() {
        let c = candidate("f", 0x1000, "rdi", 0.5, EvidenceStatus::Proposed);
        assert!(candidate_visible(&c, "", false, 0.5));
        assert!(!candidate_visible(&c, "", false, 0.51));
    }

    #[test]
    fn summary_counts() {
        let cands = vec![
            candidate("a", 0x1, "rdi", 0.5, EvidenceStatus::Proposed),
            candidate("b", 0x2, "rsi", 0.5, EvidenceStatus::Accepted),
            candidate("c", 0x3, "rdx", 0.5, EvidenceStatus::Accepted),
            candidate("d", 0x4, "rcx", 0.5, EvidenceStatus::Rejected),
        ];
        assert_eq!(
            summary_line(&cands),
            "4 candidates — 2 accepted, 1 rejected"
        );
    }

    #[test]
    fn summary_singular_and_empty() {
        assert_eq!(summary_line(&[]), "no candidates");
        let one = vec![candidate("a", 0x1, "rdi", 0.5, EvidenceStatus::Proposed)];
        assert_eq!(summary_line(&one), "1 candidate — 0 accepted, 0 rejected");
    }
}
