use eframe::egui;
use re_core::analysis::xrefs::XrefType;
use re_core::project::{ActionKind, UndoCommand};

use crate::app::{SearchMode, SleuthreApp};

impl SleuthreApp {
    pub(crate) fn show_modals(&mut self, ctx: &egui::Context) {
        self.show_rename_dialog(ctx);
        self.show_comment_dialog(ctx);
        self.show_xref_dialog(ctx);
        self.show_approval_queue(ctx);
        self.show_goto_dialog(ctx);
        self.show_bookmark_dialog(ctx);
        self.show_search_dialog(ctx);
        self.show_findings_window(ctx);
        self.show_create_struct_dialog(ctx);
        self.show_add_field_dialog(ctx);
    }

    fn show_add_field_dialog(&mut self, ctx: &egui::Context) {
        let Some(struct_name) = self.editing_struct.clone() else {
            return;
        };

        egui::Window::new(format!("Add Field to {}", struct_name)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.text_edit_singleline(&mut self.new_field_name);
            });
            ui.horizontal(|ui| {
                ui.label("Offset:");
                ui.text_edit_singleline(&mut self.new_field_offset);
            });
            ui.horizontal(|ui| {
                ui.label("Type:");
                ui.text_edit_singleline(&mut self.new_field_type);
            });

            ui.horizontal(|ui| {
                if ui.button("Add").clicked() {
                    let offset = self
                        .new_field_offset
                        .trim_start_matches("0x")
                        .trim_start_matches("0X");
                    let mut toast = None;

                    if let Ok(off) = usize::from_str_radix(offset, 16)
                        && let Some(ref mut project) = self.project
                    {
                        let tref = match self.new_field_type.as_str() {
                            "int8_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::I8,
                            ),
                            "int16_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::I16,
                            ),
                            "int32_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::I32,
                            ),
                            "int64_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::I64,
                            ),
                            "uint8_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::U8,
                            ),
                            "uint16_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::U16,
                            ),
                            "uint32_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::U32,
                            ),
                            "uint64_t" => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::U64,
                            ),
                            _ if self.new_field_type.ends_with('*') => {
                                re_core::types::TypeRef::Pointer(Box::new(
                                    re_core::types::TypeRef::Primitive(
                                        re_core::types::PrimitiveType::Void,
                                    ),
                                ))
                            }
                            _ => re_core::types::TypeRef::Primitive(
                                re_core::types::PrimitiveType::I32,
                            ),
                        };

                        project.types.add_struct_field(
                            &struct_name,
                            re_core::types::StructField {
                                name: self.new_field_name.clone(),
                                type_ref: tref,
                                offset: off,
                                bit_offset: None,
                                bit_size: None,
                            },
                        );
                        toast = Some(format!("Added field '{}'", self.new_field_name));
                        // Invalidate cache since field names might change decompilation
                        project.decompilation_cache.clear();
                    }

                    if let Some(msg) = toast {
                        self.add_toast(crate::app::ToastKind::Success, msg);
                    }
                    self.editing_struct = None;
                }
                if ui.button("Cancel").clicked() {
                    self.editing_struct = None;
                }
            });
        });
    }

    fn show_create_struct_dialog(&mut self, ctx: &egui::Context) {
        if !self.create_struct_active {
            return;
        }
        egui::Window::new("Create New Struct").show(ctx, |ui| {
            ui.label("Struct Name:");
            ui.text_edit_singleline(&mut self.new_struct_name);
            ui.horizontal(|ui| {
                if ui.button("Create").clicked() {
                    if let Some(ref mut project) = self.project {
                        let name = self.new_struct_name.clone();
                        project
                            .types
                            .add_type(re_core::types::CompoundType::Struct {
                                name: name.clone(),
                                fields: vec![],
                                size: 0,
                            });
                        self.add_toast(
                            crate::app::ToastKind::Success,
                            format!("Created struct '{}'", name),
                        );
                    }
                    self.create_struct_active = false;
                }
                if ui.button("Cancel").clicked() {
                    self.create_struct_active = false;
                }
            });
        });
    }

    fn show_rename_dialog(&mut self, ctx: &egui::Context) {
        if !self.rename_active {
            return;
        }
        egui::Window::new("Rename").show(ctx, |ui| {
            ui.text_edit_singleline(&mut self.rename_input);
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let (Some(p), Some(addr)) = (&mut self.project, self.focused_address) {
                        let old_name = p
                            .functions
                            .functions
                            .get(&addr)
                            .map(|f| f.name.clone())
                            .unwrap_or_default();
                        p.execute(UndoCommand::Rename {
                            address: addr,
                            old_name,
                            new_name: self.rename_input.clone(),
                        });
                    }
                    self.rename_active = false;
                }
                if ui.button("Cancel").clicked() {
                    self.rename_active = false;
                }
            });
        });
    }

    fn show_comment_dialog(&mut self, ctx: &egui::Context) {
        if !self.comment_active {
            return;
        }
        egui::Window::new("Comment").show(ctx, |ui| {
            ui.text_edit_singleline(&mut self.comment_input);
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let (Some(p), Some(addr)) = (&mut self.project, self.focused_address) {
                        let old_comment = p.comments.get(&addr).cloned();
                        let new_comment = if self.comment_input.is_empty() {
                            None
                        } else {
                            Some(self.comment_input.clone())
                        };
                        p.execute(UndoCommand::Comment {
                            address: addr,
                            old_comment,
                            new_comment,
                        });
                    }
                    self.comment_active = false;
                }
                if ui.button("Cancel").clicked() {
                    self.comment_active = false;
                }
            });
        });
    }

    fn show_xref_dialog(&mut self, ctx: &egui::Context) {
        if !self.xref_active {
            return;
        }
        let addr = self.focused_address.unwrap_or(0);
        egui::Window::new(format!("Xrefs to {:08X}", addr)).show(ctx, |ui| {
            if let Some(project) = &self.project {
                if let Some(xrefs) = project.xrefs.to_address_xrefs.get(&addr) {
                    for xref in xrefs {
                        let type_str = match xref.xref_type {
                            XrefType::Call => "Call",
                            XrefType::Jump => "Jump",
                            XrefType::DataRead => "DataRead",
                            XrefType::DataWrite => "DataWrite",
                            XrefType::StringRef => "StringRef",
                        };
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{:08X}", xref.from_address));
                            ui.label(type_str);
                        });
                    }
                    if xrefs.is_empty() {
                        ui.label("No xrefs found.");
                    }
                } else {
                    ui.label("No xrefs found.");
                }
            }
            if ui.button("Close").clicked() {
                self.xref_active = false;
            }
        });
    }

    fn show_approval_queue(&mut self, ctx: &egui::Context) {
        if !self.approval_queue_open {
            return;
        }
        egui::Window::new("AI Approval Queue").show(ctx, |ui| {
            let mut to_remove = None;
            if let Some(ref mut project) = self.project {
                if project.pending_actions.is_empty() {
                    ui.label("No pending actions.");
                }
                for (i, action) in project.pending_actions.iter().enumerate() {
                    ui.group(|ui| {
                        ui.label(format!("Confidence: {:.0}%", action.confidence * 100.0));
                        ui.label(&action.rationale);
                        if ui.button("Approve").clicked() {
                            if let ActionKind::Rename {
                                address, new_name, ..
                            } = &action.kind
                                && let Some(f) = project.functions.functions.get_mut(address)
                            {
                                f.name = new_name.clone();
                            }
                            to_remove = Some(i);
                        }
                    });
                }
                if let Some(idx) = to_remove {
                    project.pending_actions.remove(idx);
                }
            }
            if ui.button("Close").clicked() {
                self.approval_queue_open = false;
            }
        });
    }

    fn show_goto_dialog(&mut self, ctx: &egui::Context) {
        if !self.goto_active {
            return;
        }
        egui::Window::new("Go to Address")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("Enter address (hex):");
                let response = ui.text_edit_singleline(&mut self.goto_input);
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || ui.button("Go").clicked()
                {
                    let cleaned = self
                        .goto_input
                        .trim()
                        .trim_start_matches("0x")
                        .trim_start_matches("0X");
                    if let Ok(addr) = u64::from_str_radix(cleaned, 16) {
                        if let Some(ref mut project) = self.project {
                            project.navigate_to(addr);
                        }
                        self.current_address = addr;
                        self.update_cfg();
                        self.goto_active = false;
                    } else {
                        self.add_toast(
                            crate::app::ToastKind::Error,
                            format!("Invalid hex address: {}", cleaned),
                        );
                    }
                }
                if ui.button("Cancel").clicked() {
                    self.goto_active = false;
                }
            });
    }

    fn show_bookmark_dialog(&mut self, ctx: &egui::Context) {
        if !self.bookmark_active {
            return;
        }
        egui::Window::new("Bookmark")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(format!("Address: {:08X}", self.current_address));
                ui.label("Note:");
                ui.text_edit_singleline(&mut self.bookmark_input);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter))
                    {
                        if let Some(ref mut project) = self.project {
                            project.execute(UndoCommand::AddBookmark {
                                address: self.current_address,
                                note: self.bookmark_input.clone(),
                            });
                        }
                        self.bookmark_active = false;
                    }
                    if ui.button("Remove").clicked() {
                        if let Some(ref mut project) = self.project {
                            let note = project
                                .bookmarks
                                .get(&self.current_address)
                                .cloned()
                                .unwrap_or_default();
                            project.execute(UndoCommand::RemoveBookmark {
                                address: self.current_address,
                                note,
                            });
                        }
                        self.bookmark_active = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.bookmark_active = false;
                    }
                });
            });
    }

    fn show_search_dialog(&mut self, ctx: &egui::Context) {
        if !self.search_active {
            return;
        }
        egui::Window::new("Search")
            .collapsible(false)
            .default_width(400.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.search_mode, SearchMode::String, "String");
                    ui.selectable_value(
                        &mut self.search_mode,
                        SearchMode::HexPattern,
                        "Hex Pattern",
                    );
                    ui.selectable_value(&mut self.search_mode, SearchMode::Address, "Address");
                });
                ui.separator();
                let hint = match self.search_mode {
                    SearchMode::String => "Search string...",
                    SearchMode::HexPattern => "e.g. 48 89 e5 ?? ??",
                    SearchMode::Address => "e.g. 0x401000",
                };
                ui.horizontal(|ui| {
                    ui.label("Query:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search_input)
                            .hint_text(hint)
                            .desired_width(280.0),
                    );
                });
                if ui.button("Search").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.search_results.clear();
                    if let Some(ref project) = self.project {
                        match self.search_mode {
                            SearchMode::String => {
                                let query = self.search_input.to_lowercase();
                                for s in &project.strings.strings {
                                    if s.value.to_lowercase().contains(&query) {
                                        self.search_results.push((
                                            s.address,
                                            format!(
                                                "[{}] {}",
                                                s.section_name,
                                                if s.value.chars().count() > 60 {
                                                    let truncated: String =
                                                        s.value.chars().take(60).collect();
                                                    format!("{}...", truncated)
                                                } else {
                                                    s.value.clone()
                                                }
                                            ),
                                        ));
                                    }
                                }
                            }
                            SearchMode::HexPattern => {
                                let pattern: Vec<Option<u8>> = self
                                    .search_input
                                    .split_whitespace()
                                    .filter_map(|tok| {
                                        if tok == "??" {
                                            Some(None)
                                        } else {
                                            u8::from_str_radix(tok, 16).ok().map(Some)
                                        }
                                    })
                                    .collect();
                                if !pattern.is_empty() {
                                    for addr in project.memory_map.search_bytes(&pattern) {
                                        self.search_results
                                            .push((addr, format!("Match at {:08X}", addr)));
                                    }
                                }
                            }
                            SearchMode::Address => {
                                let cleaned = self
                                    .search_input
                                    .trim()
                                    .trim_start_matches("0x")
                                    .trim_start_matches("0X");
                                if let Ok(addr) = u64::from_str_radix(cleaned, 16) {
                                    self.search_results
                                        .push((addr, format!("Address {:08X}", addr)));
                                }
                            }
                        }
                    }
                }
                if !self.search_results.is_empty() {
                    ui.separator();
                    ui.label(format!("{} results:", self.search_results.len()));
                    let mut jump_to = None;
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            for (addr, desc) in &self.search_results {
                                if ui
                                    .horizontal(|ui| {
                                        ui.monospace(
                                            egui::RichText::new(format!("{:08X}", addr))
                                                .color(egui::Color32::from_rgb(0, 0, 200)),
                                        );
                                        ui.label(desc);
                                    })
                                    .response
                                    .interact(egui::Sense::click())
                                    .clicked()
                                {
                                    jump_to = Some(*addr);
                                }
                            }
                        });
                    if let Some(addr) = jump_to {
                        if let Some(ref mut project) = self.project {
                            project.navigate_to(addr);
                        }
                        self.current_address = addr;
                        self.update_cfg();
                    }
                }
                if ui.button("Close").clicked() {
                    self.search_active = false;
                }
            });
    }

    fn show_findings_window(&mut self, ctx: &egui::Context) {
        if !self.show_findings_window {
            return;
        }
        egui::Window::new("Analysis Findings")
            .collapsible(false)
            .default_width(600.0)
            .default_height(400.0)
            .show(ctx, |ui| {
                if self.plugin_findings.is_empty() {
                    ui.label("No findings to display.");
                } else {
                    let mut jump_to = None;
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for finding in &self.plugin_findings {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    let color = match finding.category {
                                        re_core::plugin::FindingCategory::Vulnerability => {
                                            egui::Color32::RED
                                        }
                                        re_core::plugin::FindingCategory::Pattern => {
                                            egui::Color32::GREEN
                                        }
                                        re_core::plugin::FindingCategory::Anomaly => {
                                            egui::Color32::YELLOW
                                        }
                                        re_core::plugin::FindingCategory::Info => {
                                            egui::Color32::LIGHT_BLUE
                                        }
                                    };
                                    ui.colored_label(color, format!("{:?}", finding.category));
                                    ui.label(format!("Severity: {:.2}", finding.severity));
                                });
                                ui.horizontal(|ui| {
                                    if ui
                                        .button(format!("Jump to 0x{:X}", finding.address))
                                        .clicked()
                                    {
                                        jump_to = Some(finding.address);
                                    }
                                    ui.label(&finding.message);
                                });
                            });
                        }
                    });
                    if let Some(addr) = jump_to {
                        if let Some(ref mut project) = self.project {
                            project.navigate_to(addr);
                        }
                        self.current_address = addr;
                        self.update_cfg();
                    }
                }
                if ui.button("Close").clicked() {
                    self.show_findings_window = false;
                }
            });
    }
}
