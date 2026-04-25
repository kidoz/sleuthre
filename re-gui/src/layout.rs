use eframe::egui;
use egui_dock::TabViewer;

use crate::app::{
    CommandAction, CommandBarResult, CommandBarResultKind, FunctionSortColumn, FunctionTypeFilter,
    NavBandLayer, SleuthreApp, Tab,
};
use crate::theme::{SyntaxColors, ThemeMode, apply_theme};

struct SleuthreTabViewer<'a> {
    app: &'a mut SleuthreApp,
}

impl TabViewer for SleuthreTabViewer<'_> {
    type Tab = Tab;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.to_string().into()
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        self.app.active_tab = *tab;
        match tab {
            Tab::Disassembly => self.app.show_disassembly(ui),
            Tab::Graph => self.app.show_graph(ui),
            Tab::Decompiler => self.app.show_decompiler(ui),
            Tab::HexView => self.app.show_hex_view(ui),
            Tab::Strings => self.app.show_strings(ui),
            Tab::Imports => self.app.show_imports(ui),
            Tab::Exports => self.app.show_exports(ui),
            Tab::Structures => self.app.show_structures(ui),
            Tab::CallGraph => self.app.show_call_graph(ui),
            Tab::Xrefs => self.app.show_xrefs(ui),
            Tab::Entropy => self.app.show_entropy(ui),
            Tab::Signatures => self.app.show_signatures(ui),
            Tab::Diff => self.app.show_diff(ui),
            Tab::Archives => self.app.show_archives(ui),
            Tab::DataInspector => self.app.show_data_inspector(ui),
            Tab::SourceCompare => self.app.show_source_compare(ui),
            Tab::Tabular => self.app.show_tabular_data(ui),
            Tab::ImagePreview => {
                self.app.ensure_image_textures(ui.ctx());
                self.app.show_image_preview(ui);
            }
            Tab::Bytecode => self.app.show_bytecode(ui),
            Tab::Debugger => self.app.show_debugger(ui),
        }
    }
}

impl eframe::App for SleuthreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_changed {
            apply_theme(ctx, self.theme_mode);
            self.syntax = SyntaxColors::for_theme(self.theme_mode);
            self.theme_changed = false;
        }

        // Poll background loader
        self.poll_load();
        self.poll_reanalysis();

        if self.trigger_decompile {
            self.focus_or_open_tab(Tab::Decompiler);
            self.decompile_current_function();
            self.trigger_decompile = false;
        }

        // Deferred script execution (from file picker)
        if !self.script_input.is_empty() {
            let src = std::mem::take(&mut self.script_input);
            self.run_script(&src);
        }

        // Auto-save check
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        if self.last_save_time == 0.0 {
            self.last_save_time = now;
        }

        if now - self.last_save_time > 300.0 {
            // 5 minutes
            if let Some(ref mut project) = self.project {
                let path = project.path.with_extension("slre");
                if let Ok(()) = project.save(&path) {
                    self.add_toast(crate::app::ToastKind::Info, "Project auto-saved.".into());
                }
            }
            self.last_save_time = now;
        }

        // Keyboard shortcuts (only when no modal is active)
        if !self.any_modal_active() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::F5) {
                    self.trigger_decompile = true;
                }
                if i.key_pressed(egui::Key::Space) {
                    self.focus_or_open_tab(Tab::Graph);
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
                    self.command_bar_active = true;
                    self.command_bar_input.clear();
                    self.command_bar_results.clear();
                }
                if i.modifiers.command && i.key_pressed(egui::Key::P) {
                    self.command_bar_active = true;
                    self.command_bar_input = ">".to_string();
                    self.update_command_bar_results();
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
        self.show_status_bar(ctx);
        if self.output_panel_visible {
            self.show_bottom_panel(ctx);
        }
        self.show_left_panel(ctx);
        self.show_right_panel(ctx);
        self.show_central_panel(ctx);
        self.show_command_bar_dropdown(ctx);
        self.show_modals(ctx);
        self.show_toasts(ctx);
        self.show_loading_overlay(ctx);
        self.broadcast_pending_undo_events();
        self.poll_plugin_results();
        self.apply_inbound_collab_events();
        self.poll_debugger_op();
    }
}

impl SleuthreApp {
    fn show_right_panel(&mut self, ctx: &egui::Context) {
        let state = self.debugger.state();
        if state == re_core::DebuggerState::Detached {
            return;
        }

        egui::SidePanel::right("right_panel")
            .resizable(true)
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.heading("Registers");
                ui.separator();
                let regs = self.debugger.registers();
                let mut names: Vec<_> = regs.keys().collect();
                names.sort();

                egui::Grid::new("reg_grid").striped(true).show(ui, |ui| {
                    for name in names {
                        ui.label(name);
                        ui.monospace(format!("{:016X}", regs[name]));
                        ui.end_row();
                    }
                });
            });
    }

    fn show_toasts(&mut self, ctx: &egui::Context) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Expire old toasts
        self.toasts.retain(|t| t.expires_at > now);

        if self.toasts.is_empty() {
            return;
        }

        // Render toasts in the top right corner
        egui::Area::new(egui::Id::new("toast_area"))
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-10.0, 40.0))
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    for toast in &self.toasts {
                        let (bg, text_color) = match toast.kind {
                            crate::app::ToastKind::Info => {
                                (egui::Color32::from_rgb(40, 40, 40), egui::Color32::WHITE)
                            }
                            crate::app::ToastKind::Success => {
                                (egui::Color32::from_rgb(0, 100, 0), egui::Color32::WHITE)
                            }
                            crate::app::ToastKind::Warning => {
                                (egui::Color32::from_rgb(100, 100, 0), egui::Color32::BLACK)
                            }
                            crate::app::ToastKind::Error => {
                                (egui::Color32::from_rgb(100, 0, 0), egui::Color32::WHITE)
                            }
                        };

                        egui::Frame::window(ui.style()).fill(bg).show(ui, |ui| {
                            ui.label(egui::RichText::new(&toast.message).color(text_color));
                        });
                        ui.add_space(4.0);
                    }
                });
            });
    }

    fn show_loading_overlay(&mut self, ctx: &egui::Context) {
        let Some(stage) = self.load_stage.clone() else {
            return;
        };
        // Semi-transparent backdrop
        egui::Area::new(egui::Id::new("loading_backdrop"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::LEFT_TOP, [0.0, 0.0])
            .show(ctx, |ui| {
                #[allow(deprecated)]
                let screen = ui.ctx().screen_rect();
                ui.allocate_exact_size(screen.size(), egui::Sense::hover());
                ui.painter().rect_filled(
                    screen,
                    0.0,
                    egui::Color32::from_rgba_unmultiplied(0, 0, 0, 120),
                );
            });
        egui::Area::new(egui::Id::new("loading_overlay"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style())
                    .inner_margin(egui::Margin::same(24))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.spinner();
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(stage).size(14.0));
                            ui.add_space(8.0);
                            if ui.button("Cancel analysis").clicked()
                                && let Some(cancel) = &self.load_cancel
                            {
                                cancel.cancel();
                            }
                        });
                    });
            });
    }

    fn show_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(20.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 12.0;

                    if let Some(ref project) = self.project {
                        // File name
                        ui.label(
                            egui::RichText::new(&project.name)
                                .size(11.0)
                                .color(self.syntax.text),
                        );
                        ui.separator();

                        // Architecture
                        let arch_str = format!("{:?}", project.arch);
                        ui.label(egui::RichText::new(arch_str).size(11.0));
                        ui.separator();

                        // Base address
                        let base = project
                            .memory_map
                            .segments
                            .first()
                            .map(|s| s.start)
                            .unwrap_or(0);
                        ui.label(
                            egui::RichText::new(format!("Base: {:08X}", base))
                                .size(11.0)
                                .monospace(),
                        );
                        ui.separator();

                        // Cursor address (colored)
                        ui.label(
                            egui::RichText::new(format!("Cursor: {:08X}", self.current_address))
                                .size(11.0)
                                .monospace()
                                .color(self.syntax.link),
                        );
                        ui.separator();

                        // Function count
                        ui.label(
                            egui::RichText::new(format!(
                                "{} funcs",
                                project.functions.functions.len()
                            ))
                            .size(11.0),
                        );

                        // Current function name
                        if let Some(func) = project
                            .functions
                            .functions
                            .range(..=self.current_address)
                            .next_back()
                            .map(|(_, f)| f)
                        {
                            ui.separator();
                            ui.label(
                                egui::RichText::new(&func.name)
                                    .size(11.0)
                                    .color(self.syntax.label),
                            );
                        }
                    } else {
                        ui.label(
                            egui::RichText::new("No binary loaded")
                                .size(11.0)
                                .color(self.syntax.text_dim),
                        );
                    }

                    // Right-aligned toggle for output panel
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let icon = if self.output_panel_visible {
                            "Output [-]"
                        } else {
                            "Output [+]"
                        };
                        if ui.button(egui::RichText::new(icon).size(11.0)).clicked() {
                            self.output_panel_visible = !self.output_panel_visible;
                        }
                    });
                });
            });
    }

    fn show_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            self.show_menu_bar(ui, ctx);
            ui.separator();
            ui.horizontal(|ui| {
                ui.style_mut().spacing.item_spacing.x = 2.0;
                if ui.button("Open").clicked() && !self.is_loading() {
                    self.open_binary(ui.ctx());
                }
                egui::ComboBox::from_id_salt("analysis_mode_combo")
                    .selected_text(self.analysis_mode.label())
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        for mode in re_core::analysis::pipeline::AnalysisMode::ALL_PRESETS {
                            if ui
                                .selectable_label(self.analysis_mode == mode, mode.label())
                                .clicked()
                            {
                                self.analysis_mode = mode;
                                self.reanalyze_config =
                                    re_core::analysis::pipeline::AnalysisConfig::for_mode(mode);
                            }
                        }
                    });
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

                // Command bar (replaces static address display and Goto button)
                self.show_command_bar(ui);
            });
            ui.separator();
            self.show_navigation_band(ui);
        });
    }

    fn show_command_bar(&mut self, ui: &mut egui::Ui) {
        let placeholder = format!("{:08X}", self.current_address);
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.command_bar_input)
                .hint_text(placeholder)
                .desired_width(300.0)
                .font(egui::TextStyle::Monospace),
        );

        if response.gained_focus() {
            self.command_bar_active = true;
        }

        // Handle keyboard navigation in the dropdown
        if self.command_bar_active && !self.command_bar_results.is_empty() {
            let mut navigate = false;
            ui.input(|i| {
                if i.key_pressed(egui::Key::ArrowDown) {
                    self.command_bar_selected = (self.command_bar_selected + 1)
                        .min(self.command_bar_results.len().saturating_sub(1));
                }
                if i.key_pressed(egui::Key::ArrowUp) {
                    self.command_bar_selected = self.command_bar_selected.saturating_sub(1);
                }
                if i.key_pressed(egui::Key::Enter) {
                    navigate = true;
                }
                if i.key_pressed(egui::Key::Escape) {
                    self.command_bar_active = false;
                    self.command_bar_results.clear();
                }
            });

            if navigate
                && let Some(result) = self.command_bar_results.get(self.command_bar_selected)
            {
                let result = result.clone();
                self.command_bar_input.clear();
                self.command_bar_results.clear();
                self.command_bar_active = false;
                self.execute_command_bar_result(result, ui.ctx());
            }
        } else if self.command_bar_active {
            // Enter on empty results = try direct address
            ui.input(|i| {
                if i.key_pressed(egui::Key::Escape) {
                    self.command_bar_active = false;
                    self.command_bar_input.clear();
                }
            });
            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.navigate_command_bar();
            }
        }

        // Update search results on input change
        if response.changed() && !self.command_bar_input.is_empty() {
            self.update_command_bar_results();
        } else if self.command_bar_input.is_empty() {
            self.command_bar_results.clear();
        }

        if response.lost_focus() && !ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.command_bar_active = false;
        }
    }

    fn navigate_command_bar(&mut self) {
        let input = self.command_bar_input.trim().to_string();
        self.command_bar_input.clear();
        self.command_bar_active = false;
        self.command_bar_results.clear();

        if input.is_empty() {
            return;
        }

        // Try as hex address
        let addr_str = input.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
            if let Some(ref mut project) = self.project {
                project.navigate_to(addr);
            }
            self.current_address = addr;
            self.update_cfg();
        }
    }

    fn update_command_bar_results(&mut self) {
        self.command_bar_results.clear();
        self.command_bar_selected = 0;

        let query = self.command_bar_input.to_lowercase();
        self.push_command_actions(&query);
        self.push_command_views(&query);

        let Some(ref project) = self.project else {
            self.command_bar_results.truncate(20);
            return;
        };

        // Check for scoped queries
        if let Some(rest) = query.strip_prefix("#string:") {
            for s in &project.strings.strings {
                if s.value.to_lowercase().contains(rest) {
                    self.command_bar_results.push(CommandBarResult {
                        label: format!("{:08X} \"{}\"", s.address, truncate_str(&s.value, 40)),
                        address: s.address,
                        kind: CommandBarResultKind::StringRef,
                    });
                    if self.command_bar_results.len() >= 20 {
                        break;
                    }
                }
            }
            return;
        }

        if let Some(rest) = query.strip_prefix("#import:") {
            for imp in &project.imports {
                if imp.name.to_lowercase().contains(rest) {
                    self.command_bar_results.push(CommandBarResult {
                        label: format!("{:08X} {} ({})", imp.address, imp.name, imp.library),
                        address: imp.address,
                        kind: CommandBarResultKind::Import,
                    });
                    if self.command_bar_results.len() >= 20 {
                        break;
                    }
                }
            }
            return;
        }

        // Try hex address first
        let addr_str = query.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
            self.command_bar_results.push(CommandBarResult {
                label: format!("Go to {:08X}", addr),
                address: addr,
                kind: CommandBarResultKind::Function,
            });
        }

        // Functions (fuzzy subsequence match)
        for func in project.functions.functions.values() {
            if fuzzy_match(&func.name, &query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("{:08X} {}", func.start_address, func.name),
                    address: func.start_address,
                    kind: CommandBarResultKind::Function,
                });
                if self.command_bar_results.len() >= 20 {
                    return;
                }
            }
        }

        // Imports
        for imp in &project.imports {
            if fuzzy_match(&imp.name, &query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("{:08X} {} [import]", imp.address, imp.name),
                    address: imp.address,
                    kind: CommandBarResultKind::Import,
                });
                if self.command_bar_results.len() >= 20 {
                    return;
                }
            }
        }

        // Exports
        for exp in &project.exports {
            if fuzzy_match(&exp.name, &query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("{:08X} {} [export]", exp.address, exp.name),
                    address: exp.address,
                    kind: CommandBarResultKind::Export,
                });
                if self.command_bar_results.len() >= 20 {
                    return;
                }
            }
        }

        // Strings
        for s in &project.strings.strings {
            if s.value.to_lowercase().contains(&query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("{:08X} \"{}\"", s.address, truncate_str(&s.value, 40)),
                    address: s.address,
                    kind: CommandBarResultKind::StringRef,
                });
                if self.command_bar_results.len() >= 20 {
                    return;
                }
            }
        }
    }

    fn show_command_bar_dropdown(&mut self, ctx: &egui::Context) {
        if !self.command_bar_active || self.command_bar_results.is_empty() {
            return;
        }

        egui::Area::new(egui::Id::new("command_bar_dropdown"))
            .order(egui::Order::Foreground)
            .fixed_pos(egui::pos2(400.0, 80.0))
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_min_width(300.0);
                    let mut selected_result = None;
                    for (i, result) in self.command_bar_results.iter().enumerate() {
                        let is_selected = i == self.command_bar_selected;
                        let kind_color = match result.kind {
                            CommandBarResultKind::Function => self.syntax.label,
                            CommandBarResultKind::Import => self.syntax.keyword,
                            CommandBarResultKind::Export => self.syntax.number,
                            CommandBarResultKind::StringRef => self.syntax.string,
                            CommandBarResultKind::View(_) => self.syntax.link,
                            CommandBarResultKind::Action(_) => self.syntax.keyword,
                        };
                        let text = egui::RichText::new(&result.label)
                            .monospace()
                            .size(11.0)
                            .color(kind_color);
                        if ui.selectable_label(is_selected, text).clicked() {
                            selected_result = Some(result.clone());
                        }
                    }
                    if let Some(result) = selected_result {
                        self.command_bar_input.clear();
                        self.command_bar_results.clear();
                        self.command_bar_active = false;
                        self.execute_command_bar_result(result, ctx);
                    }
                });
            });
    }

    fn execute_command_bar_result(&mut self, result: CommandBarResult, ctx: &egui::Context) {
        match result.kind {
            CommandBarResultKind::Function
            | CommandBarResultKind::Import
            | CommandBarResultKind::Export
            | CommandBarResultKind::StringRef => {
                if let Some(ref mut project) = self.project {
                    project.navigate_to(result.address);
                }
                self.current_address = result.address;
                self.update_cfg();
            }
            CommandBarResultKind::View(tab) => {
                self.focus_or_open_tab(tab);
            }
            CommandBarResultKind::Action(action) => self.execute_command_action(action, ctx),
        }
    }

    fn execute_command_action(&mut self, action: CommandAction, ctx: &egui::Context) {
        match action {
            CommandAction::OpenBinary => {
                if !self.is_loading() {
                    self.open_binary(ctx);
                }
            }
            CommandAction::SaveProject => self.save_project(),
            CommandAction::Search => {
                self.search_active = true;
            }
            CommandAction::Reanalyze => {
                self.reanalyze_active = true;
            }
            CommandAction::Decompile => {
                self.trigger_decompile = true;
            }
            CommandAction::ToggleOutput => {
                self.output_panel_visible = !self.output_panel_visible;
            }
            CommandAction::Findings => {
                self.show_findings_window = true;
            }
        }
    }

    fn push_command_actions(&mut self, query: &str) {
        let action_query = query.strip_prefix('>').unwrap_or(query).trim();
        if action_query.is_empty() && !query.starts_with('>') {
            return;
        }
        for (label, action, requires_project) in [
            ("Open Binary", CommandAction::OpenBinary, false),
            ("Save Project", CommandAction::SaveProject, true),
            ("Search", CommandAction::Search, false),
            ("Re-Analyze", CommandAction::Reanalyze, true),
            ("Decompile Current Function", CommandAction::Decompile, true),
            ("Toggle Output Panel", CommandAction::ToggleOutput, false),
            ("Show Analysis Findings", CommandAction::Findings, true),
        ] {
            if requires_project && self.project.is_none() {
                continue;
            }
            if fuzzy_match(label, action_query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("> {}", label),
                    address: action as u64,
                    kind: CommandBarResultKind::Action(action),
                });
            }
        }
    }

    fn push_command_views(&mut self, query: &str) {
        let view_query = query
            .strip_prefix("view ")
            .or_else(|| query.strip_prefix("@"))
            .unwrap_or(query)
            .trim();
        if view_query.is_empty() && !query.starts_with('@') && !query.starts_with("view ") {
            return;
        }
        for tab in [
            Tab::Disassembly,
            Tab::Graph,
            Tab::Decompiler,
            Tab::HexView,
            Tab::Strings,
            Tab::Imports,
            Tab::Exports,
            Tab::Structures,
            Tab::CallGraph,
            Tab::Xrefs,
            Tab::Entropy,
            Tab::Signatures,
            Tab::Diff,
            Tab::Archives,
            Tab::DataInspector,
            Tab::SourceCompare,
            Tab::Tabular,
            Tab::ImagePreview,
            Tab::Bytecode,
            Tab::Debugger,
        ] {
            let label = tab.to_string();
            if fuzzy_match(&label, view_query) {
                self.command_bar_results.push(CommandBarResult {
                    label: format!("@ {}", label),
                    address: tab as u64,
                    kind: CommandBarResultKind::View(tab),
                });
            }
        }
    }

    fn show_menu_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open Binary...").clicked() && !self.is_loading() {
                    self.open_binary(ui.ctx());
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
                if ui.button("Import Symbols...").clicked() {
                    self.import_symbols_active = true;
                    self.import_symbols_preview = None;
                    self.import_symbols_path = String::new();
                    ui.close();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Edit", |ui| {
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
                    self.command_bar_active = true;
                    self.command_bar_input.clear();
                    self.command_bar_results.clear();
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
                ui.menu_button(
                    format!(
                        "Theme: {}",
                        match self.theme_mode {
                            ThemeMode::Dark => "Dark",
                            ThemeMode::Light => "Light",
                            ThemeMode::Solarized => "Solarized",
                        }
                    ),
                    |ui| {
                        for (label, mode) in [
                            ("Dark", ThemeMode::Dark),
                            ("Light", ThemeMode::Light),
                            ("Solarized", ThemeMode::Solarized),
                        ] {
                            if ui
                                .selectable_label(self.theme_mode == mode, label)
                                .clicked()
                            {
                                self.theme_mode = mode;
                                self.theme_changed = true;
                                ui.close();
                            }
                        }
                    },
                );
                ui.separator();
                if ui.button("AI Naming Heuristics").clicked() {
                    self.run_ai_naming_heuristics();
                    ui.close();
                }
                ui.separator();
                if ui.button("Re-Analyze...").clicked() {
                    self.reanalyze_active = true;
                    ui.close();
                }
            });
            ui.menu_button("Debugger", |ui| {
                let state = self.debugger.state();
                ui.label(format!("State: {:?}", state));
                ui.separator();
                match state {
                    re_core::DebuggerState::Detached => {
                        if ui.button("Attach to Process...").clicked() {
                            let _ = self.debugger.attach(1234);
                            self.add_toast(
                                crate::app::ToastKind::Success,
                                "Attached to mock process 1234".into(),
                            );
                            ui.close();
                        }
                    }
                    re_core::DebuggerState::Paused => {
                        if ui.button("Continue (F9)").clicked() {
                            let _ = self.debugger.continue_exec();
                            ui.close();
                        }
                        if ui.button("Step Into (F7)").clicked() {
                            let _ = self.debugger.step();
                            ui.close();
                        }
                        if ui.button("Detach").clicked() {
                            let _ = self.debugger.detach();
                            ui.close();
                        }
                    }
                    re_core::DebuggerState::Running => {
                        if ui.button("Pause").clicked() {
                            // Mock pause
                            let _ = self.debugger.attach(1234);
                            ui.close();
                        }
                    }
                }
            });
            ui.menu_button("Plugins", |ui| {
                if ui.button("Run Analysis Passes").clicked() {
                    if let Some(ref mut project) = self.project {
                        match self.plugin_manager.run_all_analysis_passes(
                            &project.memory_map,
                            &mut project.functions,
                            &project.xrefs,
                            &project.strings,
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
            ui.menu_button("Tools", |ui| {
                ui.menu_button("Plugins", |ui| {
                    if ui.button("Reload from disk").clicked() {
                        let report = self.plugins.reload_changed();
                        if report.is_empty() {
                            self.add_toast(
                                crate::app::ToastKind::Info,
                                "No plugin changes detected.".into(),
                            );
                        } else {
                            self.add_toast(
                                crate::app::ToastKind::Success,
                                format!(
                                    "Plugins: +{} ~{} -{}",
                                    report.added.len(),
                                    report.updated.len(),
                                    report.removed.len(),
                                ),
                            );
                        }
                        ui.close();
                    }
                    ui.separator();
                    let scripts: Vec<(String, String)> = self
                        .plugins
                        .scripts()
                        .iter()
                        .map(|s| (s.name.clone(), s.source.clone()))
                        .collect();
                    if scripts.is_empty() {
                        ui.label(
                            egui::RichText::new("No plugins discovered.")
                                .color(egui::Color32::GRAY)
                                .size(11.0),
                        );
                    }
                    for (name, source) in scripts {
                        if ui.button(format!("Run: {}", name)).clicked() {
                            self.submit_plugin_script(&name, &source);
                            ui.close();
                        }
                    }
                });
                ui.separator();
                if ui.button("Start Collab Server...").clicked() {
                    self.collab_dialog_active = true;
                    if self.collab_port_input.is_empty() {
                        self.collab_port_input = "0".into();
                    }
                    ui.close();
                }
                if self.collab_broadcaster.is_some() && ui.button("Stop Collab Server").clicked() {
                    self.collab_broadcaster = None;
                    self.collab_status = None;
                    self.add_toast(crate::app::ToastKind::Info, "Collab server stopped.".into());
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
                    ("Cross References", Tab::Xrefs),
                    ("Entropy", Tab::Entropy),
                    ("Signatures", Tab::Signatures),
                    ("Binary Diff", Tab::Diff),
                    ("Archives", Tab::Archives),
                    ("Data Inspector", Tab::DataInspector),
                    ("Source Compare", Tab::SourceCompare),
                    ("Tabular", Tab::Tabular),
                    ("Images", Tab::ImagePreview),
                    ("Bytecode", Tab::Bytecode),
                    ("Debugger", Tab::Debugger),
                ] {
                    if ui.button(name).clicked() {
                        self.focus_or_open_tab(tab);
                        ui.close();
                    }
                }
            });
            ui.menu_button("Help", |ui| {
                ui.label("sleuthre v0.3.0");
                ui.label("Open-source reverse engineering tool");
                ui.separator();
                ui.label("Keyboard shortcuts:");
                ui.monospace("F5        Decompile");
                ui.monospace("Space     Graph view");
                ui.monospace("N         Rename");
                ui.monospace(";         Comment");
                ui.monospace("X         Xrefs");
                ui.monospace("Ctrl+G    Command bar");
                ui.monospace("Ctrl+D    Bookmark");
                ui.monospace("Ctrl+F    Search");
                ui.monospace("Ctrl+Z    Undo");
                ui.monospace("Ctrl+Shift+Z  Redo");
                ui.monospace("Alt+Left  Navigate back");
                ui.monospace("Alt+Right Navigate forward");
            });
        });
    }

    fn show_navigation_band(&mut self, ui: &mut egui::Ui) {
        // Layer toggle buttons
        ui.horizontal(|ui| {
            ui.style_mut().spacing.item_spacing.x = 2.0;
            ui.selectable_value(&mut self.nav_band_layer, NavBandLayer::Segments, "Segments");
            ui.selectable_value(
                &mut self.nav_band_layer,
                NavBandLayer::Functions,
                "Functions",
            );
            ui.selectable_value(
                &mut self.nav_band_layer,
                NavBandLayer::AnalysisState,
                "Analysis",
            );
            ui.selectable_value(&mut self.nav_band_layer, NavBandLayer::Entropy, "Entropy");
        });

        let (rect, response) =
            ui.allocate_at_least(egui::vec2(ui.available_width(), 14.0), egui::Sense::click());

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
                match self.nav_band_layer {
                    NavBandLayer::Segments => {
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
                            let seg_rect = egui::Rect::from_min_size(
                                egui::pos2(x, rect.min.y),
                                egui::vec2(w, rect.height()),
                            );
                            painter.rect_filled(seg_rect, 0.0, color);
                        }
                    }
                    NavBandLayer::Functions => {
                        // Paint function ranges
                        let import_addrs: std::collections::HashSet<u64> =
                            project.imports.iter().map(|imp| imp.address).collect();
                        for func in project.functions.functions.values() {
                            let func_size = func
                                .end_address
                                .unwrap_or(func.start_address + 0x10)
                                .saturating_sub(func.start_address);
                            let start_ratio = (func.start_address - min_addr) as f32 / total_size;
                            let size_ratio = (func_size as f32 / total_size).max(0.002);
                            let x = rect.min.x + (rect.width() * start_ratio);
                            let w = (rect.width() * size_ratio).max(1.0);
                            let color = if import_addrs.contains(&func.start_address) {
                                self.syntax.nav_band_func_lib
                            } else {
                                self.syntax.nav_band_func_user
                            };
                            let func_rect = egui::Rect::from_min_size(
                                egui::pos2(x, rect.min.y),
                                egui::vec2(w, rect.height()),
                            );
                            painter.rect_filled(func_rect, 0.0, color);
                        }
                    }
                    NavBandLayer::AnalysisState => {
                        // Color by coverage: functions = exec color, strings = string color,
                        // segments without functions = unexplored
                        for segment in &project.memory_map.segments {
                            let start_ratio = (segment.start - min_addr) as f32 / total_size;
                            let size_ratio = segment.size as f32 / total_size;
                            let x = rect.min.x + (rect.width() * start_ratio);
                            let w = rect.width() * size_ratio;
                            let seg_rect = egui::Rect::from_min_size(
                                egui::pos2(x, rect.min.y),
                                egui::vec2(w, rect.height()),
                            );
                            painter.rect_filled(seg_rect, 0.0, self.syntax.nav_band_unexplored);
                        }
                        // Overlay functions
                        for func in project.functions.functions.values() {
                            let func_size = func
                                .end_address
                                .unwrap_or(func.start_address + 0x10)
                                .saturating_sub(func.start_address);
                            let start_ratio = (func.start_address - min_addr) as f32 / total_size;
                            let size_ratio = (func_size as f32 / total_size).max(0.002);
                            let x = rect.min.x + (rect.width() * start_ratio);
                            let w = (rect.width() * size_ratio).max(1.0);
                            let func_rect = egui::Rect::from_min_size(
                                egui::pos2(x, rect.min.y),
                                egui::vec2(w, rect.height()),
                            );
                            painter.rect_filled(func_rect, 0.0, self.syntax.nav_band_exec);
                        }
                        // Overlay strings
                        for s in &project.strings.strings {
                            let start_ratio = (s.address - min_addr) as f32 / total_size;
                            let size_ratio = ((s.length as f32) / total_size).max(0.001);
                            let x = rect.min.x + (rect.width() * start_ratio);
                            let w = (rect.width() * size_ratio).max(1.0);
                            let str_rect = egui::Rect::from_min_size(
                                egui::pos2(x, rect.min.y),
                                egui::vec2(w, rect.height()),
                            );
                            painter.rect_filled(str_rect, 0.0, self.syntax.nav_band_string);
                        }
                    }
                    NavBandLayer::Entropy => {
                        if let Some(ref emap) = self.entropy_map {
                            for sample in &emap.samples {
                                let start_ratio = (sample.address - min_addr) as f32 / total_size;
                                let size_ratio = (sample.size as f32 / total_size).max(0.001);
                                let x = rect.min.x + (rect.width() * start_ratio);
                                let w = (rect.width() * size_ratio).max(1.0);
                                let norm = (sample.entropy as f32 / 8.0).clamp(0.0, 1.0);
                                let color = entropy_nav_color(norm);
                                let e_rect = egui::Rect::from_min_size(
                                    egui::pos2(x, rect.min.y),
                                    egui::vec2(w, rect.height()),
                                );
                                painter.rect_filled(e_rect, 0.0, color);
                            }
                        }
                    }
                }

                // Enhanced tooltips
                if let Some(hover_pos) = ui.input(|i| i.pointer.hover_pos())
                    && rect.contains(hover_pos)
                {
                    let ratio = (hover_pos.x - rect.min.x) / rect.width();
                    let hover_addr = min_addr + (total_size * ratio) as u64;

                    // Find segment at hover
                    let segment_info = project
                        .memory_map
                        .segments
                        .iter()
                        .find(|s| hover_addr >= s.start && hover_addr < s.start + s.size);

                    // Find function at hover
                    let func_info = project
                        .functions
                        .functions
                        .range(..=hover_addr)
                        .next_back()
                        .and_then(|(_, f)| {
                            let end = f.end_address.unwrap_or(f.start_address + 0x100);
                            if hover_addr < end { Some(f) } else { None }
                        });

                    #[allow(deprecated)]
                    egui::show_tooltip(ui.ctx(), ui.layer_id(), ui.id(), |ui| {
                        ui.label(format!("Address: {:08X}", hover_addr));
                        if let Some(seg) = segment_info {
                            ui.label(format!(
                                "{}: {:08X} - {:08X} ({})",
                                seg.name,
                                seg.start,
                                seg.start + seg.size,
                                if seg
                                    .permissions
                                    .contains(re_core::memory::Permissions::EXECUTE)
                                {
                                    "Code"
                                } else {
                                    "Data"
                                }
                            ));
                        }
                        if let Some(func) = func_info {
                            ui.label(format!("Function: {}", func.name));
                        }
                    });
                }

                // Interaction: Jump to address on click
                if response.clicked()
                    && let Some(click_pos) = response.interact_pointer_pos()
                {
                    let ratio = (click_pos.x - rect.min.x) / rect.width();
                    let target_addr = min_addr + (total_size * ratio) as u64;

                    // In Functions layer, snap to nearest function start
                    let final_addr = if self.nav_band_layer == NavBandLayer::Functions {
                        project
                            .functions
                            .functions
                            .range(..=target_addr)
                            .next_back()
                            .map(|(_, f)| f.start_address)
                            .unwrap_or(target_addr)
                    } else {
                        target_addr
                    };

                    self.current_address = final_addr;
                    self.update_cfg();
                    if let Some(ref mut p) = self.project {
                        p.navigate_to(final_addr);
                    }
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
            .default_height(self.output_panel_height)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Output");
                        ui.add_space(4.0);
                        if ui.small_button("Clear").clicked() {
                            self.output.clear();
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Run Script...").clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .add_filter("Rhai Scripts", &["rhai", "rs", "txt"])
                                    .pick_file()
                            {
                                match std::fs::read_to_string(&path) {
                                    Ok(src) => {
                                        self.output
                                            .push_str(&format!("Running {}...\n", path.display()));
                                        self.script_input = src;
                                    }
                                    Err(e) => {
                                        self.output
                                            .push_str(&format!("Error reading file: {}\n", e));
                                    }
                                }
                            }
                        });
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
                            egui::RichText::new(" Console ")
                                .background_color(egui::Color32::from_rgb(220, 220, 220))
                                .color(egui::Color32::BLACK),
                        );
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.command_input).hint_text(
                                "Commands: help, goto, rename, script <expr>, run [path]",
                            ),
                        );

                        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            self.execute_command();
                        }
                    });
                });
            });
    }

    fn execute_command(&mut self) {
        let cmd = self.command_input.trim().to_string();
        self.command_input.clear();

        if cmd.is_empty() {
            return;
        }

        // Normalize syntax: goto(0x1000) -> goto 0x1000
        let normalized = cmd.replace("(", " ").replace(")", " ").replace(",", " ");
        let parts: Vec<&str> = normalized.split_whitespace().collect();

        match parts[0] {
            "g" | "goto" => {
                if parts.len() > 1 {
                    let addr_str = parts[1].trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        self.current_address = addr;
                        self.update_cfg();
                        self.add_toast(
                            crate::app::ToastKind::Info,
                            format!("Jumped to 0x{:X}", addr),
                        );
                    }
                }
            }
            "rename" => {
                if parts.len() > 2 {
                    let addr_str = parts[1].trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        let new_name = parts[2].trim_matches('"').to_string();
                        if let Some(ref mut project) = self.project {
                            let old_name = project
                                .functions
                                .functions
                                .get(&addr)
                                .map(|f| f.name.clone())
                                .unwrap_or_default();
                            project.execute(re_core::project::UndoCommand::Rename {
                                address: addr,
                                old_name,
                                new_name: new_name.clone(),
                            });
                            self.add_toast(
                                crate::app::ToastKind::Success,
                                format!("Renamed 0x{:X} to {}", addr, new_name),
                            );
                        }
                    }
                }
            }
            "comment" => {
                if parts.len() > 2 {
                    let addr_str = parts[1].trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        let text = parts[2..].join(" ").trim_matches('"').to_string();
                        if let Some(ref mut project) = self.project {
                            let old_comment = project.comments.get(&addr).cloned();
                            project.execute(re_core::project::UndoCommand::Comment {
                                address: addr,
                                old_comment,
                                new_comment: Some(text.clone()),
                            });
                            self.add_toast(
                                crate::app::ToastKind::Success,
                                format!("Added comment at 0x{:X}", addr),
                            );
                        }
                    }
                }
            }
            "list" | "ls" => {
                if let Some(ref project) = self.project {
                    self.output.push_str("Functions:\n");
                    for f in project.functions.functions.values().take(10) {
                        self.output
                            .push_str(&format!("  0x{:X} - {}\n", f.start_address, f.name));
                    }
                    self.output.push_str("  ...\n");
                }
            }
            "script" | "eval" => {
                // Evaluate inline Rhai script: script <expression>
                let script_src = parts[1..].join(" ");
                if script_src.is_empty() {
                    self.output.push_str("Usage: script <rhai expression>\n");
                } else {
                    self.run_script(&script_src);
                }
            }
            "run" | "load" => {
                // Load and run a Rhai script file: run <path>
                if parts.len() > 1 {
                    let path = parts[1..].join(" ").trim_matches('"').to_string();
                    let path = std::path::PathBuf::from(path);
                    if path.exists() {
                        match std::fs::read_to_string(&path) {
                            Ok(script_src) => {
                                self.output
                                    .push_str(&format!("Running {}...\n", path.display()));
                                self.run_script(&script_src);
                            }
                            Err(e) => {
                                self.output
                                    .push_str(&format!("Error reading file: {}\n", e));
                            }
                        }
                    } else {
                        self.output
                            .push_str(&format!("File not found: {}\n", path.display()));
                    }
                } else {
                    // Open file picker
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Rhai Scripts", &["rhai", "rs", "txt"])
                        .pick_file()
                    {
                        match std::fs::read_to_string(&path) {
                            Ok(script_src) => {
                                self.output
                                    .push_str(&format!("Running {}...\n", path.display()));
                                self.run_script(&script_src);
                            }
                            Err(e) => {
                                self.output
                                    .push_str(&format!("Error reading file: {}\n", e));
                            }
                        }
                    }
                }
            }
            "help" => {
                self.output.push_str("Commands:\n");
                self.output
                    .push_str("  g/goto <addr>          - Jump to address\n");
                self.output
                    .push_str("  rename <addr> <name>   - Rename function\n");
                self.output
                    .push_str("  comment <addr> <text>  - Add comment\n");
                self.output
                    .push_str("  list                   - List first 10 functions\n");
                self.output
                    .push_str("  script <expr>          - Evaluate Rhai expression\n");
                self.output
                    .push_str("  run [path]             - Run a Rhai script file\n");
                self.output
                    .push_str("  help                   - Show this help\n");
            }
            _ => {
                self.add_toast(
                    crate::app::ToastKind::Error,
                    format!("Unknown command: {}", parts[0]),
                );
            }
        }
    }

    fn run_script(&mut self, source: &str) {
        let mut goto_addr = None;

        if let Some(ref mut project) = self.project {
            match self.script_engine.eval(source, project) {
                Ok(result) => {
                    for action in &result.actions {
                        match action {
                            re_core::scripting::ScriptAction::Rename { address, new_name } => {
                                let old_name = project
                                    .functions
                                    .functions
                                    .get(address)
                                    .map(|f| f.name.clone())
                                    .unwrap_or_default();
                                project.execute(re_core::project::UndoCommand::Rename {
                                    address: *address,
                                    old_name,
                                    new_name: new_name.clone(),
                                });
                                self.output.push_str(&format!(
                                    "Renamed 0x{:x} -> {}\n",
                                    address, new_name
                                ));
                            }
                            re_core::scripting::ScriptAction::Comment { address, text } => {
                                let old_comment = project.comments.get(address).cloned();
                                project.execute(re_core::project::UndoCommand::Comment {
                                    address: *address,
                                    old_comment,
                                    new_comment: Some(text.clone()),
                                });
                                self.output
                                    .push_str(&format!("Comment at 0x{:x}: {}\n", address, text));
                            }
                            re_core::scripting::ScriptAction::Goto(addr) => {
                                self.current_address = *addr;
                                goto_addr = Some(*addr);
                                self.output.push_str(&format!("Jumped to 0x{:x}\n", addr));
                            }
                            re_core::scripting::ScriptAction::Print(msg) => {
                                self.output.push_str(msg);
                                self.output.push('\n');
                            }
                            re_core::scripting::ScriptAction::ImportSymbols { path } => {
                                match import_symbols_from_path(project, path) {
                                    Ok(n) => self.output.push_str(&format!(
                                        "Imported {} symbols from {}\n",
                                        n, path
                                    )),
                                    Err(e) => self
                                        .output
                                        .push_str(&format!("Import symbols failed: {}\n", e)),
                                }
                            }
                        }
                    }
                    if !result.output.is_empty() {
                        self.output.push_str("=> ");
                        self.output.push_str(&result.output);
                        self.output.push('\n');
                    }
                }
                Err(e) => {
                    self.output.push_str(&format!("Script error: {}\n", e));
                }
            }
        } else {
            self.output.push_str("No project loaded.\n");
        }

        if goto_addr.is_some() {
            self.update_cfg();
        }
    }

    fn show_left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                ui.heading("Functions");

                // Filter row
                ui.horizontal(|ui| {
                    ui.label("Filter:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.function_filter).desired_width(120.0),
                    );
                    egui::ComboBox::from_id_salt("func_type_filter")
                        .selected_text(match self.func_type_filter {
                            FunctionTypeFilter::All => "All",
                            FunctionTypeFilter::User => "User",
                            FunctionTypeFilter::Library => "Lib",
                        })
                        .width(50.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.func_type_filter,
                                FunctionTypeFilter::All,
                                "All",
                            );
                            ui.selectable_value(
                                &mut self.func_type_filter,
                                FunctionTypeFilter::User,
                                "User",
                            );
                            ui.selectable_value(
                                &mut self.func_type_filter,
                                FunctionTypeFilter::Library,
                                "Library",
                            );
                        });
                    // Tag filter
                    let all_tags = self
                        .project
                        .as_ref()
                        .map(|p| p.all_tags())
                        .unwrap_or_default();
                    if !all_tags.is_empty() {
                        let tag_label = self.func_tag_filter.as_deref().unwrap_or("Tag");
                        egui::ComboBox::from_id_salt("func_tag_filter")
                            .selected_text(tag_label)
                            .width(60.0)
                            .show_ui(ui, |ui| {
                                if ui
                                    .selectable_label(self.func_tag_filter.is_none(), "All")
                                    .clicked()
                                {
                                    self.func_tag_filter = None;
                                }
                                for tag in &all_tags {
                                    if ui
                                        .selectable_label(
                                            self.func_tag_filter.as_deref() == Some(tag.as_str()),
                                            tag,
                                        )
                                        .clicked()
                                    {
                                        self.func_tag_filter = Some(tag.clone());
                                    }
                                }
                            });
                    }
                });
                ui.separator();

                // Column headers
                ui.horizontal(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 4.0;
                    // Badge column spacer (matches badge width in data rows)
                    ui.add_sized(egui::vec2(20.0, 16.0), egui::Label::new(""));
                    let header = |ui: &mut egui::Ui,
                                  label: &str,
                                  col: FunctionSortColumn,
                                  sort_col: &mut FunctionSortColumn,
                                  ascending: &mut bool,
                                  width: f32| {
                        let is_active = *sort_col == col;
                        let arrow = if is_active {
                            if *ascending { " ^" } else { " v" }
                        } else {
                            ""
                        };
                        let text = format!("{}{}", label, arrow);
                        let resp = ui.add_sized(
                            egui::vec2(width, 16.0),
                            egui::Button::new(egui::RichText::new(text).size(10.0).strong()),
                        );
                        if resp.clicked() {
                            if *sort_col == col {
                                *ascending = !*ascending;
                            } else {
                                *sort_col = col;
                                *ascending = true;
                            }
                        }
                    };
                    header(
                        ui,
                        "Address",
                        FunctionSortColumn::Address,
                        &mut self.func_sort_column,
                        &mut self.func_sort_ascending,
                        70.0,
                    );
                    header(
                        ui,
                        "Name",
                        FunctionSortColumn::Name,
                        &mut self.func_sort_column,
                        &mut self.func_sort_ascending,
                        120.0,
                    );
                    header(
                        ui,
                        "Size",
                        FunctionSortColumn::Size,
                        &mut self.func_sort_column,
                        &mut self.func_sort_ascending,
                        50.0,
                    );
                    header(
                        ui,
                        "Xrefs",
                        FunctionSortColumn::XrefsIn,
                        &mut self.func_sort_column,
                        &mut self.func_sort_ascending,
                        45.0,
                    );
                });
                ui.separator();

                // Rebuild cached function list only when inputs change
                let mut jump = None;

                if let Some(project) = &self.project {
                    let func_count = project.functions.functions.len();
                    let needs_rebuild = self.cached_func_list_dirty
                        || self.cached_func_filter != self.function_filter
                        || self.cached_func_sort_col != self.func_sort_column
                        || self.cached_func_sort_asc != self.func_sort_ascending
                        || self.cached_func_type_filter != self.func_type_filter
                        || self.cached_func_tag_filter != self.func_tag_filter
                        || self.cached_func_count != func_count;

                    if needs_rebuild {
                        let filter_lower = self.function_filter.to_lowercase();
                        let import_addrs: std::collections::HashSet<u64> =
                            project.imports.iter().map(|imp| imp.address).collect();

                        let mut funcs: Vec<_> = project
                            .functions
                            .functions
                            .values()
                            .filter(|func| {
                                if !filter_lower.is_empty()
                                    && !fuzzy_match(&func.name, &filter_lower)
                                {
                                    return false;
                                }
                                let type_ok = match self.func_type_filter {
                                    FunctionTypeFilter::All => true,
                                    FunctionTypeFilter::Library => {
                                        import_addrs.contains(&func.start_address)
                                    }
                                    FunctionTypeFilter::User => {
                                        !import_addrs.contains(&func.start_address)
                                    }
                                };
                                if !type_ok {
                                    return false;
                                }
                                if let Some(ref tag_filter) = self.func_tag_filter {
                                    project
                                        .tags
                                        .get(&func.start_address)
                                        .map(|tags| tags.contains(tag_filter))
                                        .unwrap_or(false)
                                } else {
                                    true
                                }
                            })
                            .collect();

                        let xref_counts = &self.func_xref_counts;
                        match self.func_sort_column {
                            FunctionSortColumn::Address => {
                                funcs.sort_by_key(|f| f.start_address);
                            }
                            FunctionSortColumn::Name => {
                                funcs.sort_by(|a, b| {
                                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                                });
                            }
                            FunctionSortColumn::Size => {
                                funcs.sort_by_key(|f| {
                                    f.end_address
                                        .unwrap_or(f.start_address)
                                        .saturating_sub(f.start_address)
                                });
                            }
                            FunctionSortColumn::XrefsIn => {
                                funcs.sort_by_key(|f| {
                                    xref_counts
                                        .get(&f.start_address)
                                        .map(|(i, _)| *i)
                                        .unwrap_or(0)
                                });
                            }
                        }
                        if !self.func_sort_ascending {
                            funcs.reverse();
                        }

                        self.cached_func_list = funcs.iter().map(|f| f.start_address).collect();
                        self.cached_func_filter = self.function_filter.clone();
                        self.cached_func_sort_col = self.func_sort_column;
                        self.cached_func_sort_asc = self.func_sort_ascending;
                        self.cached_func_type_filter = self.func_type_filter;
                        self.cached_func_tag_filter = self.func_tag_filter.clone();
                        self.cached_func_count = func_count;
                        self.cached_func_list_dirty = false;
                    }

                    let import_addrs: std::collections::HashSet<u64> =
                        project.imports.iter().map(|imp| imp.address).collect();

                    ui.label(
                        egui::RichText::new(format!(
                            "{} / {} functions",
                            self.cached_func_list.len(),
                            func_count
                        ))
                        .size(10.0)
                        .color(self.syntax.text_dim),
                    );

                    let row_height = 18.0;
                    let total = self.cached_func_list.len();
                    let xref_counts = &self.func_xref_counts;
                    egui::ScrollArea::vertical()
                        .id_salt("func_scroll")
                        .show_rows(ui, row_height, total, |ui, range| {
                            for &addr in &self.cached_func_list[range] {
                                let func = match project.functions.functions.get(&addr) {
                                    Some(f) => f,
                                    None => continue,
                                };
                                let is_selected = self.current_address == addr;
                                let size = func.end_address.unwrap_or(addr).saturating_sub(addr);
                                let xrefs = xref_counts.get(&addr).map(|(i, _)| *i).unwrap_or(0);
                                let is_lib = import_addrs.contains(&addr);
                                let badge_text = if is_lib { " L " } else { " f " };
                                let badge_color = if is_lib {
                                    self.syntax.nav_band_func_lib
                                } else {
                                    self.syntax.func_badge_bg
                                };

                                ui.horizontal(|ui| {
                                    ui.style_mut().spacing.item_spacing.x = 4.0;
                                    ui.add_sized(
                                        egui::vec2(20.0, row_height),
                                        egui::Label::new(
                                            egui::RichText::new(badge_text)
                                                .size(10.0)
                                                .background_color(badge_color),
                                        ),
                                    );
                                    ui.add_sized(
                                        egui::vec2(70.0, row_height),
                                        egui::Label::new(
                                            egui::RichText::new(format!("{:08X}", addr))
                                                .size(10.0)
                                                .color(self.syntax.address)
                                                .monospace(),
                                        ),
                                    );
                                    let name_resp = ui.add_sized(
                                        egui::vec2(120.0, row_height),
                                        egui::Button::selectable(
                                            is_selected,
                                            egui::RichText::new(&func.name).size(11.0),
                                        ),
                                    );
                                    if name_resp.clicked() {
                                        jump = Some(addr);
                                    }
                                    name_resp.context_menu(|ui| {
                                        if ui.button("Add Tag...").clicked() {
                                            self.focused_address = Some(addr);
                                            self.tag_active = true;
                                            self.tag_input.clear();
                                            ui.close();
                                        }
                                        // Show existing tags with remove option
                                        if let Some(project) = &self.project
                                            && let Some(tags) = project.tags.get(&addr)
                                            && !tags.is_empty()
                                        {
                                            ui.separator();
                                            ui.label(egui::RichText::new("Tags:").strong());
                                            for tag in tags {
                                                if ui.button(format!("  x  {}", tag)).clicked() {
                                                    // Will be handled below
                                                    self.focused_address = Some(addr);
                                                    self.tag_input = format!("__remove__{}", tag);
                                                    ui.close();
                                                }
                                            }
                                        }
                                    });
                                    ui.add_sized(
                                        egui::vec2(50.0, row_height),
                                        egui::Label::new(
                                            egui::RichText::new(format!("{:X}", size))
                                                .size(10.0)
                                                .color(self.syntax.text_dim)
                                                .monospace(),
                                        ),
                                    );
                                    ui.add_sized(
                                        egui::vec2(45.0, row_height),
                                        egui::Label::new(
                                            egui::RichText::new(format!("{}", xrefs))
                                                .size(10.0)
                                                .color(self.syntax.text_dim)
                                                .monospace(),
                                        ),
                                    );
                                    // Show tag badges after fixed columns
                                    if let Some(tags) = project.tags.get(&addr) {
                                        for tag in tags {
                                            ui.label(
                                                egui::RichText::new(tag)
                                                    .size(9.0)
                                                    .color(egui::Color32::WHITE)
                                                    .background_color(egui::Color32::from_rgb(
                                                        80, 80, 160,
                                                    )),
                                            );
                                        }
                                    }
                                });
                            }
                        });
                }

                if let Some(addr) = jump {
                    if let Some(ref mut project) = self.project {
                        project.navigate_to(addr);
                    }
                    self.current_address = addr;
                    self.update_cfg();
                }

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
        // Use std::mem::take to temporarily extract dock_state for the viewer
        let mut dock_state = std::mem::replace(
            &mut self.dock_state,
            egui_dock::DockState::new(vec![Tab::Disassembly]),
        );

        let style = egui_dock::Style::from_egui(ctx.style().as_ref());
        let mut viewer = SleuthreTabViewer { app: self };

        egui_dock::DockArea::new(&mut dock_state)
            .style(style)
            .show(ctx, &mut viewer);

        self.dock_state = dock_state;
    }
}

/// Case-insensitive subsequence match
fn fuzzy_match(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.to_lowercase();
    let mut chars = needle.chars();
    let mut current = chars.next();
    for h in haystack.chars() {
        if let Some(c) = current {
            if h == c {
                current = chars.next();
            }
        } else {
            return true;
        }
    }
    current.is_none()
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn entropy_nav_color(normalized: f32) -> egui::Color32 {
    if normalized < 0.35 {
        egui::Color32::from_rgb(50, 80, 180)
    } else if normalized < 0.7 {
        egui::Color32::from_rgb(50, 180, 80)
    } else {
        egui::Color32::from_rgb(220, 60, 60)
    }
}

impl SleuthreApp {
    /// Submit a plugin script to the background runner so the UI never
    /// blocks on long-running scripts. Snapshots the project state at the
    /// moment of submission; mutations come back asynchronously via
    /// [`Self::poll_plugin_results`].
    pub(crate) fn submit_plugin_script(&mut self, name: &str, source: &str) {
        let snapshot = self.snapshot_for_plugins();
        match self.plugin_runner.submit(source.to_string(), snapshot) {
            Ok(_id) => {
                self.add_toast(
                    crate::app::ToastKind::Info,
                    format!("Plugin '{}' running in background...", name),
                );
            }
            Err(e) => {
                self.add_toast(
                    crate::app::ToastKind::Error,
                    format!("Plugin submit failed: {}", e),
                );
            }
        }
    }

    fn snapshot_for_plugins(&self) -> re_core::scripting::ProjectSnapshot {
        use re_core::scripting::ProjectSnapshot;
        let Some(ref project) = self.project else {
            return ProjectSnapshot::default();
        };
        let functions: Vec<(u64, String, usize)> = project
            .functions
            .functions
            .values()
            .map(|f| {
                let size = f
                    .end_address
                    .and_then(|e| e.checked_sub(f.start_address))
                    .map(|s| s as usize)
                    .unwrap_or(0);
                (f.start_address, f.name.clone(), size)
            })
            .collect();
        let strings: Vec<(u64, String)> = project
            .strings
            .strings
            .iter()
            .map(|s| (s.address, s.value.clone()))
            .collect();
        let comments: Vec<(u64, String)> = project
            .comments
            .iter()
            .map(|(&a, t)| (a, t.clone()))
            .collect();
        ProjectSnapshot {
            functions,
            strings,
            comments,
            arch: project.arch.display_name().to_string(),
        }
    }

    /// Drain finished plugin results and apply their actions on the main
    /// thread. Called once per UI frame.
    pub(crate) fn poll_plugin_results(&mut self) {
        let results = self.plugin_runner.poll();
        if results.is_empty() {
            return;
        }
        for msg in results {
            if let Some(err) = msg.error {
                self.add_toast(
                    crate::app::ToastKind::Error,
                    format!("Plugin job {} error: {}", msg.id, err),
                );
                continue;
            }
            for action in msg.actions {
                self.apply_script_action(action);
            }
            if !msg.output.is_empty() {
                self.output.push_str("=> ");
                self.output.push_str(&msg.output);
                self.output.push('\n');
            }
        }
    }

    fn apply_script_action(&mut self, action: re_core::scripting::ScriptAction) {
        use re_core::scripting::ScriptAction;
        let Some(ref mut project) = self.project else {
            return;
        };
        match action {
            ScriptAction::Rename { address, new_name } => {
                let old_name = project
                    .functions
                    .functions
                    .get(&address)
                    .map(|f| f.name.clone())
                    .unwrap_or_default();
                project.execute(re_core::project::UndoCommand::Rename {
                    address,
                    old_name,
                    new_name,
                });
            }
            ScriptAction::Comment { address, text } => {
                let old_comment = project.comments.get(&address).cloned();
                project.execute(re_core::project::UndoCommand::Comment {
                    address,
                    old_comment,
                    new_comment: Some(text),
                });
            }
            ScriptAction::Goto(addr) => {
                self.current_address = addr;
                self.update_cfg();
            }
            ScriptAction::Print(msg) => {
                self.output.push_str(&msg);
                self.output.push('\n');
            }
            ScriptAction::ImportSymbols { path } => {
                if let Some(ref mut project) = self.project {
                    let _ = import_symbols_from_path(project, &path);
                }
            }
        }
    }

    /// Drain inbound collab events from the broadcaster and apply them as
    /// local `UndoCommand`s. The high-water mark is bumped past the resulting
    /// undo entries so we don't immediately re-publish events we just applied.
    pub(crate) fn apply_inbound_collab_events(&mut self) {
        let Some(ref bcast) = self.collab_broadcaster else {
            return;
        };
        let events = bcast.drain_inbound();
        if events.is_empty() {
            return;
        }
        let Some(ref mut project) = self.project else {
            return;
        };
        for ev in events {
            if let Some(cmd) = collab_event_to_undo(&ev, project) {
                project.execute(cmd);
                self.output
                    .push_str(&format!("[collab:{}] applied {}\n", ev.author, ev.kind));
            }
        }
        // Mark all newly-applied commands as already-published so the
        // outbound hook doesn't fan them back out.
        self.last_published_undo_idx = project.undo_stack.len();
    }

    /// Drain any newly-executed `UndoCommand`s from the project's undo stack
    /// and publish them as `CollabEvent`s on the broadcaster, if one is
    /// running. This intercept point captures every mutation regardless of
    /// which dialog or shortcut produced it — wiring publish at each
    /// `execute()` call site would have been a 15-place patch.
    pub(crate) fn broadcast_pending_undo_events(&mut self) {
        let Some(ref bcast) = self.collab_broadcaster else {
            return;
        };
        let Some(ref project) = self.project else {
            return;
        };
        let stack_len = project.undo_stack.len();
        if stack_len <= self.last_published_undo_idx {
            self.last_published_undo_idx = stack_len;
            return;
        }
        for cmd in &project.undo_stack[self.last_published_undo_idx..stack_len] {
            let event = undo_command_to_event(cmd);
            let _ = bcast.publish(event);
        }
        self.last_published_undo_idx = stack_len;
    }
}

/// Translate an inbound `CollabEvent` into a local `UndoCommand`. Returns
/// `None` for kinds we don't yet apply (e.g. `patch`, which would need bytes
/// rather than a length).
fn collab_event_to_undo(
    event: &re_core::collab::CollabEvent,
    project: &re_core::project::Project,
) -> Option<re_core::project::UndoCommand> {
    let payload = &event.payload;
    let parse_addr = |key: &str| -> Option<u64> {
        let s = payload.get(key)?.as_str()?;
        if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(rest, 16).ok()
        } else {
            s.parse().ok()
        }
    };
    match event.kind.as_str() {
        "rename" => {
            let address = parse_addr("address")?;
            let new_name = payload
                .get("new_name")
                .and_then(|v| v.as_str())?
                .to_string();
            let old_name = project
                .functions
                .functions
                .get(&address)
                .map(|f| f.name.clone())
                .unwrap_or_default();
            Some(re_core::project::UndoCommand::Rename {
                address,
                old_name,
                new_name,
            })
        }
        "comment" => {
            let address = parse_addr("address")?;
            let new_comment = payload
                .get("text")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let old_comment = project.comments.get(&address).cloned();
            Some(re_core::project::UndoCommand::Comment {
                address,
                old_comment,
                new_comment,
            })
        }
        "add_bookmark" => {
            let address = parse_addr("address")?;
            let note = payload.get("note").and_then(|v| v.as_str())?.to_string();
            Some(re_core::project::UndoCommand::AddBookmark { address, note })
        }
        "remove_bookmark" => {
            let address = parse_addr("address")?;
            let note = payload.get("note").and_then(|v| v.as_str())?.to_string();
            Some(re_core::project::UndoCommand::RemoveBookmark { address, note })
        }
        "add_tag" => {
            let address = parse_addr("address")?;
            let tag = payload.get("tag").and_then(|v| v.as_str())?.to_string();
            Some(re_core::project::UndoCommand::AddTag { address, tag })
        }
        "remove_tag" => {
            let address = parse_addr("address")?;
            let tag = payload.get("tag").and_then(|v| v.as_str())?.to_string();
            Some(re_core::project::UndoCommand::RemoveTag { address, tag })
        }
        _ => None,
    }
}

fn undo_command_to_event(cmd: &re_core::project::UndoCommand) -> re_core::collab::CollabEvent {
    use re_core::project::UndoCommand;
    let (kind, payload) = match cmd {
        UndoCommand::Rename {
            address,
            old_name,
            new_name,
        } => (
            "rename",
            serde_json::json!({
                "address": format!("0x{:x}", address),
                "old_name": old_name,
                "new_name": new_name,
            }),
        ),
        UndoCommand::Comment {
            address,
            new_comment,
            ..
        } => (
            "comment",
            serde_json::json!({
                "address": format!("0x{:x}", address),
                "text": new_comment,
            }),
        ),
        UndoCommand::AddBookmark { address, note } => (
            "add_bookmark",
            serde_json::json!({"address": format!("0x{:x}", address), "note": note}),
        ),
        UndoCommand::RemoveBookmark { address, note } => (
            "remove_bookmark",
            serde_json::json!({"address": format!("0x{:x}", address), "note": note}),
        ),
        UndoCommand::PatchMemory {
            address, new_bytes, ..
        } => (
            "patch",
            serde_json::json!({
                "address": format!("0x{:x}", address),
                "len": new_bytes.len(),
            }),
        ),
        UndoCommand::AddTag { address, tag } => (
            "add_tag",
            serde_json::json!({"address": format!("0x{:x}", address), "tag": tag}),
        ),
        UndoCommand::RemoveTag { address, tag } => (
            "remove_tag",
            serde_json::json!({"address": format!("0x{:x}", address), "tag": tag}),
        ),
    };
    re_core::collab::CollabEvent {
        kind: kind.into(),
        author: "local".into(),
        seq: 0,
        payload,
    }
}

/// Import symbols from a file, applying renames and comments to the project.
/// Returns the number of symbols applied.
pub(crate) fn import_symbols_from_path(
    project: &mut re_core::project::Project,
    path: &str,
) -> Result<usize, String> {
    use re_core::import::symbols::{detect_format, parse_symbols};

    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let fmt = detect_format(&content);
    let symbols = parse_symbols(&content, fmt)?;

    let mut applied = 0usize;
    for sym in &symbols {
        let old_name = project
            .functions
            .functions
            .get(&sym.address)
            .map(|f| f.name.clone());
        match old_name {
            Some(old) if old != sym.name => {
                project.execute(re_core::project::UndoCommand::Rename {
                    address: sym.address,
                    old_name: old,
                    new_name: sym.name.clone(),
                });
                applied += 1;
            }
            None => {
                // No function record yet; register rename via symbols list and comments map.
                project.symbols.push(re_core::loader::Symbol {
                    name: sym.name.clone(),
                    address: sym.address,
                    size: 0,
                    kind: re_core::loader::SymbolKind::Function,
                });
                applied += 1;
            }
            _ => {}
        }
        if let Some(ref c) = sym.comment {
            let old_comment = project.comments.get(&sym.address).cloned();
            project.execute(re_core::project::UndoCommand::Comment {
                address: sym.address,
                old_comment,
                new_comment: Some(c.clone()),
            });
        }
    }
    Ok(applied)
}
