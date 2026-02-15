use eframe::egui;

use crate::app::{SleuthreApp, Tab};
use crate::theme::{SyntaxColors, ThemeMode, apply_theme};

impl eframe::App for SleuthreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_changed {
            apply_theme(ctx, self.theme_mode);
            self.syntax = SyntaxColors::for_theme(self.theme_mode);
            self.theme_changed = false;
        }

        if self.trigger_decompile {
            self.active_tab = Tab::Decompiler;
            self.decompile_current_function();
            self.trigger_decompile = false;
        }

        // Keyboard shortcuts (only when no modal is active)
        if !self.any_modal_active() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::F5) {
                    self.trigger_decompile = true;
                }
                if i.key_pressed(egui::Key::Space) {
                    self.active_tab = Tab::Graph;
                }
                if i.key_pressed(egui::Key::N) && self.focused_address.is_some() {
                    self.rename_active = true;
                    self.rename_input = String::new();
                }
                if i.key_pressed(egui::Key::Semicolon) && self.focused_address.is_some() {
                    self.comment_active = true;
                    if let (Some(project), Some(addr)) = (&self.project, self.focused_address) {
                        self.comment_input =
                            project.comments.get(&addr).cloned().unwrap_or_default();
                    }
                }
                if i.key_pressed(egui::Key::X) && self.focused_address.is_some() {
                    self.xref_active = true;
                }
                if i.modifiers.command && i.key_pressed(egui::Key::G) {
                    self.goto_active = true;
                    self.goto_input = String::new();
                }
                if i.modifiers.command && i.key_pressed(egui::Key::D) {
                    self.bookmark_active = true;
                    if let Some(project) = &self.project {
                        self.bookmark_input = project
                            .bookmarks
                            .get(&self.current_address)
                            .cloned()
                            .unwrap_or_default();
                    }
                }
                if i.modifiers.command && i.key_pressed(egui::Key::F) {
                    self.search_active = true;
                }
                if i.modifiers.command
                    && !i.modifiers.shift
                    && i.key_pressed(egui::Key::Z)
                    && let Some(ref mut project) = self.project
                    && let Some(msg) = project.undo()
                {
                    self.output.push_str(&format!("{}\n", msg));
                }
                if i.modifiers.command
                    && i.modifiers.shift
                    && i.key_pressed(egui::Key::Z)
                    && let Some(ref mut project) = self.project
                    && let Some(msg) = project.redo()
                {
                    self.output.push_str(&format!("{}\n", msg));
                }
                if i.modifiers.alt
                    && i.key_pressed(egui::Key::ArrowLeft)
                    && let Some(ref mut project) = self.project
                    && let Some(addr) = project.navigate_back()
                {
                    self.current_address = addr;
                    self.update_cfg();
                }
                if i.modifiers.alt
                    && i.key_pressed(egui::Key::ArrowRight)
                    && let Some(ref mut project) = self.project
                    && let Some(addr) = project.navigate_forward()
                {
                    self.current_address = addr;
                    self.update_cfg();
                }
            });
        }

        self.show_top_panel(ctx);
        self.show_bottom_panel(ctx);
        self.show_left_panel(ctx);
        self.show_central_panel(ctx);
        self.show_modals(ctx);
    }
}

impl SleuthreApp {
    fn show_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            self.show_menu_bar(ui, ctx);
            ui.separator();
            ui.horizontal(|ui| {
                ui.style_mut().spacing.item_spacing.x = 2.0;
                if ui.button("Open").clicked() {
                    self.open_binary();
                }
                if ui.button("Save").clicked() {
                    self.save_project();
                }
                ui.separator();
                let can_undo = self.project.as_ref().is_some_and(|p| p.can_undo());
                let can_redo = self.project.as_ref().is_some_and(|p| p.can_redo());
                if ui
                    .add_enabled(can_undo, egui::Button::new("Undo"))
                    .clicked()
                    && let Some(ref mut project) = self.project
                    && let Some(msg) = project.undo()
                {
                    self.output.push_str(&format!("{}\n", msg));
                }
                if ui
                    .add_enabled(can_redo, egui::Button::new("Redo"))
                    .clicked()
                    && let Some(ref mut project) = self.project
                    && let Some(msg) = project.redo()
                {
                    self.output.push_str(&format!("{}\n", msg));
                }
                ui.separator();
                if ui.button("Search").clicked() {
                    self.search_active = true;
                }
                if ui.button("Goto").clicked() {
                    self.goto_active = true;
                    self.goto_input = String::new();
                }
                ui.separator();
                let has_project = self.project.is_some();
                if ui
                    .add_enabled(has_project, egui::Button::new("Back"))
                    .clicked()
                    && let Some(ref mut project) = self.project
                    && let Some(addr) = project.navigate_back()
                {
                    self.current_address = addr;
                    self.update_cfg();
                }
                if ui
                    .add_enabled(has_project, egui::Button::new("Fwd"))
                    .clicked()
                    && let Some(ref mut project) = self.project
                    && let Some(addr) = project.navigate_forward()
                {
                    self.current_address = addr;
                    self.update_cfg();
                }
                ui.separator();
                ui.monospace(format!("{:08X}", self.current_address));
            });
            ui.separator();
            self.show_navigation_band(ui);
            ui.horizontal(|ui| {
                ui.style_mut().spacing.item_spacing.x = 8.0;
                let legend = [
                    (egui::Color32::from_rgb(0, 200, 255), "Regular function"),
                    (egui::Color32::from_rgb(0, 0, 255), "Library function"),
                    (egui::Color32::from_rgb(160, 80, 0), "Instruction"),
                    (egui::Color32::from_rgb(180, 180, 180), "Data"),
                    (egui::Color32::from_rgb(180, 180, 100), "Unexplored"),
                ];
                for (color, label) in legend {
                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_at_least(egui::vec2(12.0, 12.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 0.0, color);
                        ui.label(egui::RichText::new(label).size(10.0));
                    });
                }
            });
        });
    }

    fn show_menu_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open Binary...").clicked() {
                    self.open_binary();
                    ui.close();
                }
                if ui.button("Save Project...").clicked() {
                    self.save_project();
                    ui.close();
                }
                if ui.button("Load Project...").clicked() {
                    self.load_project();
                    ui.close();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Edit", |ui| {
                let can_undo = self.project.as_ref().is_some_and(|p| p.can_undo());
                let can_redo = self.project.as_ref().is_some_and(|p| p.can_redo());
                if ui
                    .add_enabled(can_undo, egui::Button::new("Undo (Ctrl+Z)"))
                    .clicked()
                {
                    if let Some(ref mut project) = self.project
                        && let Some(msg) = project.undo()
                    {
                        self.output.push_str(&format!("{}\n", msg));
                    }
                    ui.close();
                }
                if ui
                    .add_enabled(can_redo, egui::Button::new("Redo (Ctrl+Shift+Z)"))
                    .clicked()
                {
                    if let Some(ref mut project) = self.project
                        && let Some(msg) = project.redo()
                    {
                        self.output.push_str(&format!("{}\n", msg));
                    }
                    ui.close();
                }
                ui.separator();
                if ui.button("Rename (N)").clicked() {
                    if self.focused_address.is_some() {
                        self.rename_active = true;
                        self.rename_input = String::new();
                    }
                    ui.close();
                }
                if ui.button("Comment (;)").clicked() {
                    if self.focused_address.is_some() {
                        self.comment_active = true;
                    }
                    ui.close();
                }
            });
            ui.menu_button("Jump", |ui| {
                if ui.button("Go to Address (Ctrl+G)").clicked() {
                    self.goto_active = true;
                    self.goto_input = String::new();
                    ui.close();
                }
                ui.separator();
                if ui.button("Navigate Back (Alt+Left)").clicked() {
                    if let Some(ref mut project) = self.project
                        && let Some(addr) = project.navigate_back()
                    {
                        self.current_address = addr;
                        self.update_cfg();
                    }
                    ui.close();
                }
                if ui.button("Navigate Forward (Alt+Right)").clicked() {
                    if let Some(ref mut project) = self.project
                        && let Some(addr) = project.navigate_forward()
                    {
                        self.current_address = addr;
                        self.update_cfg();
                    }
                    ui.close();
                }
                ui.separator();
                if ui.button("Bookmark (Ctrl+D)").clicked() {
                    self.bookmark_active = true;
                    if let Some(project) = &self.project {
                        self.bookmark_input = project
                            .bookmarks
                            .get(&self.current_address)
                            .cloned()
                            .unwrap_or_default();
                    }
                    ui.close();
                }
            });
            ui.menu_button("Search", |ui| {
                if ui.button("Search... (Ctrl+F)").clicked() {
                    self.search_active = true;
                    ui.close();
                }
            });
            ui.menu_button("View", |ui| {
                if ui.button("Pseudocode (F5)").clicked() {
                    self.trigger_decompile = true;
                    ui.close();
                }
                ui.separator();
                let theme_label = match self.theme_mode {
                    ThemeMode::Dark => "Switch to Light Theme",
                    ThemeMode::Light => "Switch to Dark Theme",
                };
                if ui.button(theme_label).clicked() {
                    self.theme_mode = match self.theme_mode {
                        ThemeMode::Dark => ThemeMode::Light,
                        ThemeMode::Light => ThemeMode::Dark,
                    };
                    self.theme_changed = true;
                    ui.close();
                }
                ui.separator();
                if ui.button("AI Naming Heuristics").clicked() {
                    self.run_ai_naming_heuristics();
                    ui.close();
                }
            });
            ui.menu_button("Debugger", |ui| {
                ui.label(egui::RichText::new("No debugger attached").color(egui::Color32::GRAY));
            });
            ui.menu_button("Options", |ui| {
                let theme_label = match self.theme_mode {
                    ThemeMode::Dark => "Switch to Light Theme",
                    ThemeMode::Light => "Switch to Dark Theme",
                };
                if ui.button(theme_label).clicked() {
                    self.theme_mode = match self.theme_mode {
                        ThemeMode::Dark => ThemeMode::Light,
                        ThemeMode::Light => ThemeMode::Dark,
                    };
                    self.theme_changed = true;
                    ui.close();
                }
            });
            ui.menu_button("Plugins", |ui| {
                if ui.button("Run Analysis Passes").clicked() {
                    if let Some(ref mut project) = self.project {
                        match self.plugin_manager.run_all_analysis_passes(
                            &project.memory_map,
                            &mut project.functions,
                        ) {
                            Ok(findings) => {
                                self.plugin_findings = findings;
                                self.show_findings_window = true;
                                self.output.push_str(&format!(
                                    "Analysis complete: {} findings.\n",
                                    self.plugin_findings.len()
                                ));
                            }
                            Err(e) => {
                                self.output.push_str(&format!("Analysis error: {}\n", e));
                            }
                        }
                    } else {
                        self.output.push_str("No project loaded.\n");
                    }
                    ui.close();
                }
                if ui.button("Show Findings").clicked() {
                    self.show_findings_window = true;
                    ui.close();
                }
            });
            ui.menu_button("Windows", |ui| {
                for (name, tab) in [
                    ("Disassembly", Tab::Disassembly),
                    ("Graph", Tab::Graph),
                    ("Pseudocode", Tab::Decompiler),
                    ("Hex View", Tab::HexView),
                    ("Strings", Tab::Strings),
                    ("Imports", Tab::Imports),
                    ("Exports", Tab::Exports),
                    ("Structures", Tab::Structures),
                    ("Call Graph", Tab::CallGraph),
                ] {
                    if ui.button(name).clicked() {
                        self.active_tab = tab;
                        ui.close();
                    }
                }
            });
            ui.menu_button("Help", |ui| {
                ui.label("sleuthre v0.1.0");
                ui.label("Open-source reverse engineering tool");
                ui.separator();
                ui.label("Keyboard shortcuts:");
                ui.monospace("F5        Decompile");
                ui.monospace("Space     Graph view");
                ui.monospace("N         Rename");
                ui.monospace(";         Comment");
                ui.monospace("X         Xrefs");
                ui.monospace("Ctrl+G    Go to address");
                ui.monospace("Ctrl+D    Bookmark");
                ui.monospace("Ctrl+F    Search");
                ui.monospace("Ctrl+Z    Undo");
                ui.monospace("Ctrl+Shift+Z  Redo");
                ui.monospace("Alt+Left  Navigate back");
                ui.monospace("Alt+Right Navigate forward");
            });
        });
    }

    fn show_navigation_band(&self, ui: &mut egui::Ui) {
        let (rect, _) =
            ui.allocate_at_least(egui::vec2(ui.available_width(), 14.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, self.syntax.nav_band_bg);

        if let Some(project) = &self.project {
            let min_addr = project
                .memory_map
                .segments
                .first()
                .map(|s| s.start)
                .unwrap_or(0);
            let max_addr = project
                .memory_map
                .segments
                .last()
                .map(|s| s.start + s.size)
                .unwrap_or(1);
            let total_size = (max_addr - min_addr) as f32;

            if total_size > 0.0 {
                for segment in &project.memory_map.segments {
                    let color = if segment
                        .permissions
                        .contains(re_core::memory::Permissions::EXECUTE)
                    {
                        self.syntax.nav_band_exec
                    } else {
                        self.syntax.nav_band_data
                    };
                    let start_ratio = (segment.start - min_addr) as f32 / total_size;
                    let size_ratio = segment.size as f32 / total_size;
                    let x = rect.min.x + (rect.width() * start_ratio);
                    let w = rect.width() * size_ratio;
                    painter.rect_filled(
                        egui::Rect::from_min_size(
                            egui::pos2(x, rect.min.y),
                            egui::vec2(w, rect.height()),
                        ),
                        0.0,
                        color,
                    );
                }
                let cursor_ratio =
                    (self.current_address.saturating_sub(min_addr)) as f32 / total_size;
                let cursor_x = rect.min.x + (rect.width() * cursor_ratio);
                painter.text(
                    egui::pos2(cursor_x, rect.min.y - 2.0),
                    egui::Align2::CENTER_TOP,
                    "▼",
                    egui::FontId::proportional(12.0),
                    self.syntax.text,
                );
            }
        }
    }

    fn show_bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("bottom_panel")
            .resizable(true)
            .default_height(150.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Output");
                        ui.add_space(ui.available_width() - 60.0);
                        if ui.button("Clear").clicked() {
                            self.output.clear();
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .max_height(100.0)
                        .show(ui, |ui| {
                            ui.monospace(&self.output);
                        });
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(" Python ")
                                .background_color(egui::Color32::from_rgb(220, 220, 220)),
                        );
                        ui.text_edit_singleline(&mut self.command_input);
                    });
                });
            });
    }

    fn show_left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(220.0)
            .show(ctx, |ui| {
                ui.heading("Functions window");
                ui.horizontal(|ui| {
                    ui.label("🔍");
                    ui.text_edit_singleline(&mut self.function_filter);
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut jump = None;
                    if let Some(project) = &self.project {
                        for func in project.functions.functions.values() {
                            if self.function_filter.is_empty()
                                || func
                                    .name
                                    .to_lowercase()
                                    .contains(&self.function_filter.to_lowercase())
                            {
                                let is_selected = self.current_address == func.start_address;
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(" f ")
                                            .background_color(self.syntax.func_badge_bg),
                                    );
                                    if ui.selectable_label(is_selected, &func.name).clicked() {
                                        jump = Some(func.start_address);
                                    }
                                });
                            }
                        }
                    }
                    if let Some(addr) = jump {
                        if let Some(ref mut project) = self.project {
                            project.navigate_to(addr);
                        }
                        self.current_address = addr;
                        self.update_cfg();
                    }
                });
                // Bookmarks section
                ui.separator();
                ui.heading("Bookmarks");
                let mut bookmark_jump = None;
                if let Some(project) = &self.project {
                    if project.bookmarks.is_empty() {
                        ui.label(
                            egui::RichText::new("No bookmarks. Ctrl+D to add.")
                                .color(egui::Color32::GRAY)
                                .size(11.0),
                        );
                    }
                    for (&addr, note) in &project.bookmarks {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(" B ")
                                    .background_color(self.syntax.bookmark_badge_bg),
                            );
                            let label = if note.is_empty() {
                                format!("{:08X}", addr)
                            } else {
                                format!("{:08X} - {}", addr, note)
                            };
                            if ui
                                .selectable_label(self.current_address == addr, label)
                                .clicked()
                            {
                                bookmark_jump = Some(addr);
                            }
                        });
                    }
                }
                if let Some(addr) = bookmark_jump {
                    if let Some(ref mut project) = self.project {
                        project.navigate_to(addr);
                    }
                    self.current_address = addr;
                    self.update_cfg();
                }
            });
    }

    fn show_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let tabs = [
                    ("Disassembly", Tab::Disassembly),
                    ("Graph", Tab::Graph),
                    ("Pseudocode", Tab::Decompiler),
                    ("Hex View", Tab::HexView),
                    ("Strings", Tab::Strings),
                    ("Imports", Tab::Imports),
                    ("Exports", Tab::Exports),
                    ("Structures", Tab::Structures),
                    ("Call Graph", Tab::CallGraph),
                ];
                for (name, tab) in tabs {
                    ui.selectable_value(&mut self.active_tab, tab, name);
                }
            });
            ui.separator();
            match self.active_tab {
                Tab::Disassembly => self.show_disassembly(ui),
                Tab::Graph => self.show_graph(ui),
                Tab::Decompiler => self.show_decompiler(ui),
                Tab::HexView => self.show_hex_view(ui),
                Tab::Strings => self.show_strings(ui),
                Tab::Imports => self.show_imports(ui),
                Tab::Exports => self.show_exports(ui),
                Tab::Structures => self.show_structures(ui),
                Tab::CallGraph => self.show_call_graph(ui),
            }
        });
    }
}
