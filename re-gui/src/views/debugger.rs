//! Debugger panel.
//!
//! Connects to a `gdbserver`-compatible stub via the GDB Remote Serial
//! Protocol backend in `re-core`. Provides attach/detach/step/continue
//! controls, a register dump, and a memory inspector at a user-supplied
//! address. The actual transport lives in `re_core::debuggers::GdbRemoteDebugger`.

use eframe::egui;
use re_core::arch::Architecture;
use re_core::project::{DebugProfile, DebugTransport};
use re_core::{BreakpointKind, Debugger, StopReason, WatchpointHit};

use crate::app::{PendingDebuggerOp, SleuthreApp, ToastKind};

/// Architectures offered in the debugger's arch-override selector.
const ALL_DEBUG_ARCHES: &[Architecture] = &[
    Architecture::X86,
    Architecture::X86_64,
    Architecture::Arm,
    Architecture::Arm64,
    Architecture::Mips,
    Architecture::Mips64,
    Architecture::RiscV32,
    Architecture::RiscV64,
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum DebuggerOp {
    Step,
    Continue,
}

impl SleuthreApp {
    pub(crate) fn show_debugger(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Debugger (GDB Remote)");
            ui.add_space(16.0);
            let connected = self.debugger_remote.is_some();
            if connected {
                ui.label(
                    egui::RichText::new(format!("Connected to {}", self.debugger_addr_input))
                        .color(egui::Color32::from_rgb(120, 200, 120)),
                );
            } else {
                ui.label(egui::RichText::new("Not connected").color(egui::Color32::GRAY));
            }
        });
        ui.separator();

        // ---- Connection / transport bar ----
        let connected = self.debugger_remote.is_some();
        let mut do_connect = false;
        let mut do_attach = false;
        let mut do_launch = false;
        let mut do_disconnect = false;

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!connected, |ui| {
                ui.label("Transport:");
                egui::ComboBox::from_id_salt("dbg_transport")
                    .selected_text(transport_label(self.debugger_transport))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.debugger_transport,
                            DebugTransport::GdbRemote,
                            "GDB Remote",
                        );
                        ui.selectable_value(
                            &mut self.debugger_transport,
                            DebugTransport::LocalLaunch,
                            "Local launch",
                        );
                    });
            });
            if connected && ui.button("Disconnect").clicked() {
                do_disconnect = true;
            }
        });

        if !connected {
            match self.debugger_transport {
                DebugTransport::GdbRemote => {
                    ui.horizontal(|ui| {
                        ui.label("Address:");
                        ui.text_edit_singleline(&mut self.debugger_addr_input);
                        if ui.button("Connect").clicked() {
                            do_connect = true;
                        }
                        ui.separator();
                        ui.label("PID:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.debugger_attach_pid)
                                .desired_width(70.0),
                        );
                        if ui.button("Attach").clicked() {
                            do_attach = true;
                        }
                    });
                }
                DebugTransport::LocalLaunch => {
                    ui.horizontal(|ui| {
                        ui.label("Exe:");
                        ui.text_edit_singleline(&mut self.debugger_launch_exe);
                        if ui.button("Browse").clicked()
                            && let Some(path) = rfd::FileDialog::new().pick_file()
                        {
                            self.debugger_launch_exe = path.display().to_string();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Args:");
                        ui.text_edit_singleline(&mut self.debugger_launch_args);
                        let can_launch = cfg!(target_os = "linux");
                        if ui
                            .add_enabled(can_launch, egui::Button::new("Launch"))
                            .clicked()
                        {
                            do_launch = true;
                        }
                        if !can_launch {
                            ui.label(
                                egui::RichText::new("(local launch needs gdbserver — Linux only)")
                                    .size(10.0)
                                    .color(egui::Color32::GRAY),
                            );
                        }
                    });
                }
            }
            // Optional architecture override.
            ui.horizontal(|ui| {
                let proj_arch = self.project.as_ref().map(|p| p.arch).unwrap_or_default();
                ui.label("Arch:");
                egui::ComboBox::from_id_salt("dbg_arch")
                    .selected_text(
                        self.debugger_arch_override
                            .map(|a| a.display_name().to_string())
                            .unwrap_or_else(|| format!("project ({})", proj_arch.display_name())),
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.debugger_arch_override,
                            None,
                            format!("project ({})", proj_arch.display_name()),
                        );
                        for a in ALL_DEBUG_ARCHES {
                            ui.selectable_value(
                                &mut self.debugger_arch_override,
                                Some(*a),
                                a.display_name(),
                            );
                        }
                    });
            });
        }

        // ---- Saved profiles ----
        self.show_debugger_profiles(ui);

        if do_disconnect {
            self.debugger_disconnect();
        }
        if do_connect {
            self.debugger_connect();
        }
        if do_attach {
            self.debugger_attach();
        }
        if do_launch {
            self.debugger_launch_local();
        }

        if self.debugger_remote.is_none() {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Tip: pick a transport (or save a profile), then Connect / Attach / Launch.",
                )
                .size(10.0)
                .color(egui::Color32::GRAY),
            );
            return;
        }

        ui.separator();

        // Control bar. Disable Step/Continue while a previous async op is
        // still in flight so we don't double-issue RSP commands on the same
        // socket.
        let mut step_clicked = false;
        let mut step_over_clicked = false;
        let mut step_out_clicked = false;
        let mut continue_clicked = false;
        let busy = self.debugger_pending.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("Step Into"))
                .clicked()
            {
                step_clicked = true;
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Step Over"))
                .clicked()
            {
                step_over_clicked = true;
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Step Out"))
                .clicked()
            {
                step_out_clicked = true;
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Continue"))
                .clicked()
            {
                continue_clicked = true;
            }
            if ui.button("Refresh").clicked() {
                self.debugger_refresh();
            }
            // Stop while a continue is in flight: the debugger handle has been
            // moved to the worker thread, so we use the socket-sharing
            // interrupt handle captured at spawn time. The unframed 0x03 lands
            // on the same connection the worker is blocked reading on.
            if busy
                && ui.button("Stop").clicked()
                && let Some(h) = self.debugger_interrupt.as_mut()
                && let Err(e) = h.interrupt()
            {
                self.add_toast(ToastKind::Error, format!("Interrupt failed: {}", e));
            }
            if busy {
                ui.add_space(16.0);
                ui.label(
                    egui::RichText::new("running...")
                        .color(egui::Color32::from_rgb(255, 200, 80))
                        .size(11.0),
                );
            } else if let Some(ref reason) = self.debugger_last_stop {
                ui.add_space(16.0);
                let (label, color) = stop_reason_summary(reason);
                ui.label(egui::RichText::new(label).color(color).size(11.0));
            }
        });
        if step_clicked {
            self.debugger_step();
        }
        if step_over_clicked {
            self.debugger_step_over();
        }
        if step_out_clicked {
            self.debugger_step_out();
        }
        if continue_clicked {
            self.debugger_continue();
        }

        // Current source location at PC (when DWARF line info is present).
        if !busy
            && let Some(pc) = self.debugger_pc()
            && let Some((file, line)) = self.debugger_source_at(pc)
        {
            let short = file.rsplit(['/', '\\']).next().unwrap_or(&file);
            ui.label(
                egui::RichText::new(format!("Source: {}:{}", short, line))
                    .size(10.0)
                    .color(egui::Color32::from_rgb(140, 170, 210)),
            );
        }

        // Source-line step: only meaningful when the current binary has DWARF
        // line info (DebugInfo populated `types.source_lines`). Reaches for
        // the next address whose (file, line) differs from the current one,
        // sets a software breakpoint, and triggers Continue.
        let mut step_source_clicked = false;
        if !busy
            && self
                .project
                .as_ref()
                .map(|p| !p.types.source_lines.is_empty())
                .unwrap_or(false)
            && ui.button("Step Source").clicked()
        {
            step_source_clicked = true;
        }
        if step_source_clicked {
            self.debugger_step_source_line();
        }

        ui.separator();

        // Breakpoint + watchpoint controls.
        let mut requested: Option<BreakpointKind> = None;
        ui.horizontal(|ui| {
            ui.label("BP @");
            ui.text_edit_singleline(&mut self.debugger_bp_input);
            if ui.button("+ Set").clicked() {
                requested = Some(BreakpointKind::Software);
            }
            if ui.button("+ Set HW").clicked() {
                requested = Some(BreakpointKind::Hardware);
            }
            if ui.button("+ Watch W").clicked() {
                requested = Some(BreakpointKind::WriteWatch);
            }
            if ui.button("+ Watch R").clicked() {
                requested = Some(BreakpointKind::ReadWatch);
            }
            if ui.button("+ Watch RW").clicked() {
                requested = Some(BreakpointKind::AccessWatch);
            }
            // Scope-to-thread checkbox; only visible when an active thread
            // is selected so single-thread targets don't see clutter.
            if self.debugger_active_thread.is_some() {
                ui.checkbox(&mut self.debugger_bp_scope_thread, "this thread");
            }
        });
        if let Some(kind) = requested {
            self.debugger_set_breakpoint_kind(kind);
        }
        // Active breakpoints list.
        let mut clear_addr: Option<u64> = None;
        let bps: Vec<(u64, BreakpointKind)> = self
            .debugger_remote
            .as_ref()
            .map(|d| d.breakpoints())
            .unwrap_or_default();
        if !bps.is_empty() {
            ui.label(
                egui::RichText::new("Active breakpoints:")
                    .size(10.0)
                    .color(egui::Color32::GRAY),
            );
            for (addr, kind) in bps {
                ui.horizontal(|ui| {
                    let kind_str = match kind {
                        BreakpointKind::Software => "sw",
                        BreakpointKind::Hardware => "hw",
                        BreakpointKind::WriteWatch => "wp-w",
                        BreakpointKind::ReadWatch => "wp-r",
                        BreakpointKind::AccessWatch => "wp-rw",
                    };
                    ui.monospace(
                        egui::RichText::new(format!("  [{}] 0x{:x}", kind_str, addr)).size(11.0),
                    );
                    if ui.small_button("x").clicked() {
                        clear_addr = Some(addr);
                    }
                });
            }
        }
        if let Some(addr) = clear_addr {
            self.debugger_remove_breakpoint(addr);
        }

        ui.separator();

        // Thread selector — only shown when the stub reports more than one.
        let threads: Vec<u64> = self
            .debugger_remote
            .as_ref()
            .map(|d| d.threads())
            .unwrap_or_default();
        if threads.len() > 1 {
            let mut selected = self.debugger_active_thread;
            ui.horizontal(|ui| {
                ui.label("Thread:");
                egui::ComboBox::from_id_salt("debugger_threads")
                    .selected_text(
                        selected
                            .map(|t| format!("0x{:x}", t))
                            .unwrap_or_else(|| "(any)".into()),
                    )
                    .show_ui(ui, |ui| {
                        for tid in &threads {
                            ui.selectable_value(&mut selected, Some(*tid), format!("0x{:x}", tid));
                        }
                    });
            });
            if selected != self.debugger_active_thread
                && let Some(tid) = selected
                && let Some(d) = self.debugger_remote.as_mut()
            {
                match d.set_active_thread(tid) {
                    Ok(()) => {
                        self.debugger_active_thread = Some(tid);
                        self.debugger_refresh();
                    }
                    Err(e) => self.add_toast(ToastKind::Error, format!("Set thread failed: {}", e)),
                }
            }
        }

        // Backtrace — DWARF first (works on optimized release builds), fall
        // back to the frame-pointer chain when no `.eh_frame` is available
        // for the current PC.
        let arch = self
            .project
            .as_ref()
            .map(|p| p.arch)
            .unwrap_or(re_core::arch::Architecture::X86_64);
        let (frames, source): (Vec<u64>, &str) = match (
            self.debugger_remote.as_ref(),
            self.debugger_unwinder.as_ref(),
        ) {
            (Some(d), Some(uw)) => {
                let regs = d.registers();
                let unwound =
                    uw.unwind(arch, &regs, 32, |addr, size| d.read_memory(addr, size).ok());
                if unwound.len() > 1 {
                    (unwound, "DWARF .eh_frame")
                } else {
                    (d.frame_pointer_backtrace(arch, 32), "frame-pointer")
                }
            }
            (Some(d), None) => (d.frame_pointer_backtrace(arch, 32), "frame-pointer"),
            _ => (Vec::new(), ""),
        };
        if !frames.is_empty() {
            ui.label(
                egui::RichText::new(format!("Backtrace ({}):", source))
                    .size(10.0)
                    .color(egui::Color32::GRAY),
            );
            let mut nav_target: Option<u64> = None;
            for (i, &addr) in frames.iter().enumerate() {
                // Resolve the enclosing function for a readable label.
                let func_name = self.project.as_ref().and_then(|p| {
                    p.functions
                        .find_function_containing(addr)
                        .and_then(|start| p.functions.get_function(start))
                        .map(|f| f.name.clone())
                });
                let label = match func_name {
                    Some(name) => format!("  #{:<2}  0x{:x}  {}", i, addr, name),
                    None => format!("  #{:<2}  0x{:x}", i, addr),
                };
                if ui
                    .add(egui::Link::new(
                        egui::RichText::new(label).monospace().size(11.0),
                    ))
                    .on_hover_text("Navigate disassembly to this frame")
                    .clicked()
                {
                    nav_target = Some(addr);
                }
            }
            ui.separator();
            if let Some(addr) = nav_target {
                self.debugger_navigate_to(addr);
            }
        }

        // Modules (shared libraries) — populated from the stub's svr4 library
        // list at refresh time. Empty (and hidden) when the stub doesn't
        // support enumeration.
        if !self.debugger_modules.is_empty() {
            let mut mod_nav: Option<u64> = None;
            egui::CollapsingHeader::new(format!("Modules ({})", self.debugger_modules.len()))
                .id_salt("debugger_modules")
                .show(ui, |ui| {
                    for (name, base) in &self.debugger_modules {
                        if ui
                            .add(egui::Link::new(
                                egui::RichText::new(format!("0x{:012x}  {}", base, name))
                                    .monospace()
                                    .size(11.0),
                            ))
                            .on_hover_text("Navigate to module base")
                            .clicked()
                        {
                            mod_nav = Some(*base);
                        }
                    }
                });
            if let Some(addr) = mod_nav {
                self.debugger_navigate_to(addr);
            }
            ui.separator();
        }

        // Register names are stable for a target, so a sorted snapshot taken
        // before the panel closures avoids borrowing `debugger_regs` while we
        // mutably edit `debugger_reg_edit`.
        let reg_names: Vec<String> = {
            let mut names: Vec<String> = self.debugger_regs.keys().cloned().collect();
            names.sort();
            names
        };
        // `None` value = the typed text failed to parse.
        let mut reg_write: Option<(String, Option<u64>)> = None;

        let avail = ui.available_size();
        ui.horizontal(|ui| {
            // Left: register dump (editable — commit with Enter).
            ui.vertical(|ui| {
                ui.set_width(avail.x * 0.35);
                ui.label(egui::RichText::new("Registers").strong().size(11.0));
                egui::ScrollArea::vertical()
                    .id_salt("debugger_regs")
                    .show(ui, |ui| {
                        if reg_names.is_empty() {
                            ui.label(
                                egui::RichText::new("(no register snapshot — click Refresh)")
                                    .size(10.0)
                                    .color(egui::Color32::GRAY),
                            );
                        } else {
                            for name in &reg_names {
                                ui.horizontal(|ui| {
                                    ui.monospace(
                                        egui::RichText::new(format!("{:>6} =", name)).size(11.0),
                                    );
                                    let text =
                                        self.debugger_reg_edit.entry(name.clone()).or_default();
                                    let resp = ui.add_enabled(
                                        !busy,
                                        egui::TextEdit::singleline(text)
                                            .desired_width(150.0)
                                            .font(egui::TextStyle::Monospace),
                                    );
                                    if resp.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    {
                                        reg_write = Some((name.clone(), parse_hex_or_dec(text)));
                                    }
                                });
                            }
                        }
                    });
            });
            ui.separator();

            // Right: memory inspector (read + write).
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Memory").strong().size(11.0));
                ui.horizontal(|ui| {
                    ui.label("Address:");
                    ui.text_edit_singleline(&mut self.debugger_mem_addr);
                    ui.label("Bytes:");
                    ui.add(egui::DragValue::new(&mut self.debugger_mem_size).range(1..=4096));
                    if ui.button("Read").clicked() {
                        self.debugger_read_memory();
                    }
                });
                // Write bar: space-or-comma separated hex bytes (e.g. "90 90 cc").
                ui.horizontal(|ui| {
                    ui.label("Write hex:");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.debugger_mem_write_input)
                            .desired_width(180.0)
                            .hint_text("90 90 cc"),
                    );
                    if ui.add_enabled(!busy, egui::Button::new("Write")).clicked() {
                        self.debugger_write_memory();
                    }
                });
                egui::ScrollArea::vertical()
                    .id_salt("debugger_mem")
                    .show(ui, |ui| {
                        if let Some(ref data) = self.debugger_mem_data {
                            let base = parse_hex_or_dec(&self.debugger_mem_addr).unwrap_or(0);
                            ui.monospace(
                                egui::RichText::new(format_hex_dump(data, base)).size(11.0),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("(no read yet)")
                                    .size(10.0)
                                    .color(egui::Color32::GRAY),
                            );
                        }
                    });
            });
        });

        if let Some((name, value)) = reg_write {
            match value {
                Some(v) => self.debugger_write_register(&name, v),
                None => self.add_toast(
                    ToastKind::Error,
                    format!("Register {} value must be hex (0x...) or decimal.", name),
                ),
            }
        }
    }

    /// The architecture to drive the connection with: the explicit override if
    /// set, otherwise the loaded project's arch (or the default).
    fn debugger_effective_arch(&self) -> Architecture {
        self.debugger_arch_override
            .unwrap_or_else(|| self.project.as_ref().map(|p| p.arch).unwrap_or_default())
    }

    fn debugger_connect(&mut self) {
        let arch = self.debugger_effective_arch();
        match re_core::debuggers::GdbRemoteDebugger::connect(
            self.debugger_addr_input.as_str(),
            arch,
        ) {
            Ok(d) => {
                self.add_toast(
                    ToastKind::Success,
                    format!("Connected to {}", self.debugger_addr_input),
                );
                self.debugger_remote = Some(d);
                self.debugger_refresh();
            }
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Connect failed: {}", e));
            }
        }
    }

    /// Connect to the stub at the address bar and attach to a user-supplied
    /// PID. The PID is intentionally transient — never saved in a profile.
    fn debugger_attach(&mut self) {
        let pid: u32 = match self.debugger_attach_pid.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.add_toast(ToastKind::Error, "Attach PID must be a number.".into());
                return;
            }
        };
        let arch = self.debugger_effective_arch();
        let addr = self.debugger_addr_input.clone();
        match re_core::debuggers::GdbRemoteDebugger::connect(addr.as_str(), arch) {
            Ok(mut d) => match d.attach(pid) {
                Ok(()) => {
                    self.add_toast(
                        ToastKind::Success,
                        format!("Attached to PID {} via {}", pid, addr),
                    );
                    self.debugger_remote = Some(d);
                    self.debugger_refresh();
                }
                Err(e) => self.add_toast(ToastKind::Error, format!("Attach failed: {}", e)),
            },
            Err(e) => self.add_toast(ToastKind::Error, format!("Connect failed: {}", e)),
        }
    }

    /// Spawn a local `gdbserver` child for the configured executable and
    /// connect to it. Linux-only (gated in the UI); the child is owned by the
    /// app and reaped on disconnect / drop.
    fn debugger_launch_local(&mut self) {
        let exe = self.debugger_launch_exe.trim().to_string();
        if exe.is_empty() {
            self.add_toast(ToastKind::Error, "Choose an executable to launch.".into());
            return;
        }
        let args: Vec<String> = self
            .debugger_launch_args
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let arch = self.debugger_effective_arch();
        match spawn_gdbserver(&exe, &args, arch) {
            Ok((child, dbg, port)) => {
                self.debugger_child = Some(child);
                self.debugger_remote = Some(dbg);
                self.debugger_addr_input = format!("127.0.0.1:{}", port);
                self.add_toast(
                    ToastKind::Success,
                    format!("Launched {} under gdbserver on port {}", exe, port),
                );
                self.debugger_refresh();
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Launch failed: {}", e)),
        }
    }

    /// Detach from the stub and reap any local gdbserver child.
    fn debugger_disconnect(&mut self) {
        if let Some(mut d) = self.debugger_remote.take() {
            let _ = d.detach();
        }
        if let Some(mut child) = self.debugger_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Profile selector + save/delete row. Reads/writes `project.debug_profiles`.
    fn show_debugger_profiles(&mut self, ui: &mut egui::Ui) {
        if self.project.is_none() {
            return;
        }
        let names: Vec<String> = self
            .project
            .as_ref()
            .map(|p| p.debug_profiles.iter().map(|x| x.name.clone()).collect())
            .unwrap_or_default();
        let mut load_name: Option<String> = None;
        let mut do_save = false;
        let mut do_delete = false;
        ui.horizontal(|ui| {
            ui.label("Profile:");
            egui::ComboBox::from_id_salt("dbg_profiles")
                .selected_text(if names.is_empty() {
                    "(none saved)".to_string()
                } else {
                    "select…".to_string()
                })
                .show_ui(ui, |ui| {
                    for n in &names {
                        if ui.selectable_label(false, n).clicked() {
                            load_name = Some(n.clone());
                        }
                    }
                });
            ui.separator();
            ui.label("Save as:");
            ui.add(
                egui::TextEdit::singleline(&mut self.debugger_profile_name).desired_width(110.0),
            );
            ui.checkbox(&mut self.debugger_profile_save_args, "save args");
            if ui.button("Save").clicked() {
                do_save = true;
            }
            if ui.button("Delete").clicked() {
                do_delete = true;
            }
        });
        if let Some(n) = load_name {
            self.debugger_load_profile(&n);
        }
        if do_save {
            self.debugger_save_profile();
        }
        if do_delete {
            self.debugger_delete_profile();
        }
    }

    fn debugger_save_profile(&mut self) {
        let name = self.debugger_profile_name.trim().to_string();
        if name.is_empty() {
            self.add_toast(ToastKind::Error, "Profile name required.".into());
            return;
        }
        let profile = DebugProfile {
            name: name.clone(),
            transport: self.debugger_transport,
            address: self.debugger_addr_input.clone(),
            exe_path: self.debugger_launch_exe.clone(),
            args: self
                .debugger_launch_args
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            arch_override: self.debugger_arch_override.map(|a| format!("{:?}", a)),
            save_args: self.debugger_profile_save_args,
        };
        if let Some(project) = self.project.as_mut() {
            project.debug_profiles.retain(|p| p.name != name);
            project.debug_profiles.push(profile.clone());
            // Write through to the live DB immediately so a saved profile
            // survives a crash / close-without-save, matching delete's
            // durability.
            if let Some(db) = project.db.as_ref()
                && let Err(e) = db.save_debug_profile(&profile)
            {
                self.add_toast(
                    ToastKind::Error,
                    format!("Profile save to DB failed: {}", e),
                );
                return;
            }
            self.add_toast(ToastKind::Success, format!("Saved profile '{}'", name));
        } else {
            self.add_toast(
                ToastKind::Error,
                "Open a project before saving profiles.".into(),
            );
        }
    }

    fn debugger_load_profile(&mut self, name: &str) {
        let Some(p) = self
            .project
            .as_ref()
            .and_then(|proj| proj.debug_profiles.iter().find(|x| x.name == name).cloned())
        else {
            return;
        };
        self.debugger_transport = p.transport;
        self.debugger_addr_input = p.address;
        self.debugger_launch_exe = p.exe_path;
        self.debugger_launch_args = p.args.join(" ");
        self.debugger_arch_override = p.arch_override.as_deref().and_then(arch_from_debug_name);
        self.debugger_profile_save_args = p.save_args;
        self.debugger_profile_name = p.name;
        self.add_toast(ToastKind::Success, format!("Loaded profile '{}'", name));
    }

    fn debugger_delete_profile(&mut self) {
        let name = self.debugger_profile_name.trim().to_string();
        if name.is_empty() {
            return;
        }
        let removed = if let Some(project) = self.project.as_mut() {
            let before = project.debug_profiles.len();
            project.debug_profiles.retain(|p| p.name != name);
            // Also drop it from the live DB so it doesn't reappear if the user
            // closes without a full save.
            if let Some(db) = project.db.as_ref() {
                let _ = db.delete_debug_profile(&name);
            }
            before != project.debug_profiles.len()
        } else {
            false
        };
        if removed {
            self.add_toast(ToastKind::Success, format!("Deleted profile '{}'", name));
        }
    }

    fn debugger_refresh(&mut self) {
        let Some(ref d) = self.debugger_remote else {
            return;
        };
        self.debugger_regs = d.registers();
        // Cache the module list (one qXfer round-trip per refresh, not per frame).
        self.debugger_modules = d.modules();
        // Repopulate the editable mirror so typed-but-uncommitted edits don't
        // linger across stops.
        self.debugger_reg_edit = self
            .debugger_regs
            .iter()
            .map(|(name, value)| (name.clone(), format!("0x{:x}", value)))
            .collect();
    }

    fn debugger_step(&mut self) {
        self.spawn_debugger_op(DebuggerOp::Step);
    }

    pub(crate) fn debugger_continue(&mut self) {
        self.spawn_debugger_op(DebuggerOp::Continue);
    }

    /// Move the debugger handle into a worker thread, run the blocking RSP
    /// exchange there, and ship the (debugger, result) pair back so the main
    /// thread can resume ownership next frame. Prevents the UI from freezing
    /// on a long-running inferior.
    fn spawn_debugger_op(&mut self, op: DebuggerOp) {
        if self.debugger_pending.is_some() {
            self.add_toast(ToastKind::Warning, "Debugger is already busy.".into());
            return;
        }
        // Capture a socket-sharing interrupt handle BEFORE the debugger moves
        // to the worker, so the Stop button can still halt the inferior.
        self.debugger_interrupt = self
            .debugger_remote
            .as_ref()
            .and_then(|d| d.interrupt_handle().ok());
        let Some(mut dbg) = self.debugger_remote.take() else {
            self.debugger_interrupt = None;
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = match op {
                DebuggerOp::Step => dbg.step(),
                DebuggerOp::Continue => dbg.continue_exec(),
            };
            let _ = tx.send((dbg, result));
        });
        self.debugger_pending = Some(PendingDebuggerOp { op, rx });
    }

    /// Per-frame poll. Reattaches the debugger handle once the worker thread
    /// finishes the blocking call and surfaces the stop reason.
    pub(crate) fn poll_debugger_op(&mut self) {
        let Some(pending) = self.debugger_pending.as_ref() else {
            return;
        };
        match pending.rx.try_recv() {
            Ok((dbg, result)) => {
                self.debugger_remote = Some(dbg);
                let op = pending.op;
                self.debugger_pending = None;
                self.debugger_interrupt = None;
                match result {
                    Ok(reason) => {
                        // Watchpoint stops carry a data address that's more
                        // useful than the PC — log it to the output panel so
                        // the analyst can pair it with the memory inspector.
                        if let StopReason::Watchpoint {
                            kind,
                            pc,
                            data_address,
                        } = &reason
                        {
                            let kind_str = match kind {
                                WatchpointHit::Write => "write",
                                WatchpointHit::Read => "read",
                                WatchpointHit::Access => "access",
                            };
                            self.output.push_str(&format!(
                                "Watchpoint ({}) at 0x{:x} accessed data 0x{:x}\n",
                                kind_str, pc, data_address
                            ));
                            self.debugger_mem_addr = format!("0x{:x}", data_address);
                        }
                        self.debugger_last_stop = Some(reason);
                        self.debugger_refresh();
                        self.debugger_clear_temp_breakpoints();
                        self.debugger_jump_disasm_to_pc();
                    }
                    Err(e) => self.add_toast(ToastKind::Error, format!("{:?} error: {}", op, e)),
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.debugger_pending = None;
                self.debugger_interrupt = None;
                self.add_toast(ToastKind::Error, "Debugger worker disconnected.".into());
            }
        }
    }

    /// Plant a one-shot software breakpoint at `addr` for a step-style action,
    /// recording it for later cleanup. If the user *already* has a breakpoint
    /// at `addr`, we rely on it and record nothing — so clearing temps never
    /// silently removes a user breakpoint that happens to share the address.
    /// Returns the stub error message on failure.
    pub(crate) fn debugger_plant_temp_breakpoint(
        &mut self,
        addr: u64,
    ) -> std::result::Result<(), String> {
        let Some(d) = self.debugger_remote.as_mut() else {
            return Err("not connected".into());
        };
        if d.breakpoints().iter().any(|(a, _)| *a == addr) {
            return Ok(());
        }
        d.set_breakpoint(addr, BreakpointKind::Software)
            .map_err(|e| e.to_string())?;
        self.debugger_temp_breakpoints.push(addr);
        Ok(())
    }

    /// Remove every breakpoint recorded in `debugger_temp_breakpoints` from
    /// the live stub. Called once per stop so single-shot source-step BPs
    /// don't pollute the user's breakpoint list.
    fn debugger_clear_temp_breakpoints(&mut self) {
        let temps = std::mem::take(&mut self.debugger_temp_breakpoints);
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        for addr in temps {
            // Try both kinds — we don't track the kind separately for temps.
            let _ = d.remove_breakpoint(addr, BreakpointKind::Software);
            let _ = d.remove_breakpoint(addr, BreakpointKind::Hardware);
        }
    }

    /// The current program counter, if a PC-like register is exposed. Reads
    /// the cached register snapshot (refreshed on every stop) rather than
    /// issuing a live `g` round-trip — this is called from per-frame render
    /// paths, so it must stay cheap and non-blocking.
    pub(crate) fn debugger_pc(&self) -> Option<u64> {
        self.debugger_remote.as_ref()?;
        let regs = &self.debugger_regs;
        regs.get("rip")
            .or_else(|| regs.get("eip"))
            .or_else(|| regs.get("pc"))
            .copied()
    }

    /// The source `(file, line)` mapped to `addr` via DWARF line info, if any
    /// (nearest entry at or below `addr`).
    pub(crate) fn debugger_source_at(&self, addr: u64) -> Option<(String, u32)> {
        let project = self.project.as_ref()?;
        let (_, info) = project.types.source_lines.range(..=addr).next_back()?;
        Some((info.file.clone(), info.line))
    }

    /// Disassemble a single instruction at `addr`, preferring the static image
    /// and falling back to a live memory read (for JIT / self-modifying code).
    fn debugger_disasm_at(&self, addr: u64) -> Option<re_core::disasm::Instruction> {
        let disasm = self.disasm.as_ref()?;
        if let Some(project) = self.project.as_ref()
            && let Ok(insn) = disasm.disassemble_one(&project.memory_map, addr)
        {
            return Some(insn);
        }
        let bytes = self.debugger_remote.as_ref()?.read_memory(addr, 15).ok()?;
        disasm
            .disassemble_bytes(&bytes, addr)
            .ok()?
            .into_iter()
            .next()
    }

    /// Navigate the disassembly / graph views to `addr`.
    fn debugger_navigate_to(&mut self, addr: u64) {
        self.current_address = addr;
        if let Some(ref mut project) = self.project {
            project.navigate_to(addr);
        }
        self.update_cfg();
    }

    /// After a stop, scroll the disassembly view to the current PC so the
    /// analyst sees what just stopped. Falls through silently when no PC
    /// register is exposed.
    fn debugger_jump_disasm_to_pc(&mut self) {
        if let Some(pc) = self.debugger_pc() {
            self.debugger_navigate_to(pc);
        }
    }

    /// Step over the instruction at PC: if it's a call, set a one-shot
    /// breakpoint at the return address and continue; otherwise a single
    /// instruction step is equivalent (and safe — blindly continuing past a
    /// taken branch would run away).
    fn debugger_step_over(&mut self) {
        let Some(pc) = self.debugger_pc() else {
            self.add_toast(ToastKind::Error, "PC unknown — Refresh first.".into());
            return;
        };
        let insn = self.debugger_disasm_at(pc);
        let is_call = insn
            .as_ref()
            .map(|i| i.groups.iter().any(|g| g == "call"))
            .unwrap_or(false);
        match (is_call, insn) {
            (true, Some(insn)) => {
                let ret = pc + insn.bytes.len() as u64;
                if let Err(e) = self.debugger_plant_temp_breakpoint(ret) {
                    self.add_toast(ToastKind::Error, format!("Step-over BP failed: {}", e));
                    return;
                }
                self.debugger_continue();
            }
            _ => self.debugger_step(),
        }
    }

    /// Step out of the current function: set a one-shot breakpoint at the
    /// caller's return address (frame #1 of the backtrace) and continue.
    fn debugger_step_out(&mut self) {
        let arch = self.project.as_ref().map(|p| p.arch).unwrap_or_default();
        let ret = {
            let Some(d) = self.debugger_remote.as_ref() else {
                return;
            };
            let regs = d.registers();
            // Same DWARF-first / frame-pointer-fallback as the backtrace panel.
            let frames = match self.debugger_unwinder.as_ref() {
                Some(uw) => {
                    let unwound = uw.unwind(arch, &regs, 32, |a, s| d.read_memory(a, s).ok());
                    if unwound.len() > 1 {
                        unwound
                    } else {
                        d.frame_pointer_backtrace(arch, 32)
                    }
                }
                None => d.frame_pointer_backtrace(arch, 32),
            };
            frames.get(1).copied()
        };
        let Some(ret) = ret else {
            self.add_toast(ToastKind::Warning, "No caller frame to return to.".into());
            return;
        };
        if let Err(e) = self.debugger_plant_temp_breakpoint(ret) {
            self.add_toast(ToastKind::Error, format!("Step-out BP failed: {}", e));
            return;
        }
        self.debugger_continue();
    }

    pub(crate) fn debugger_set_breakpoint(&mut self, hardware: bool) {
        let kind = if hardware {
            BreakpointKind::Hardware
        } else {
            BreakpointKind::Software
        };
        self.debugger_set_breakpoint_kind(kind);
    }

    fn debugger_set_breakpoint_kind(&mut self, kind: BreakpointKind) {
        let Some(addr) = parse_hex_or_dec(&self.debugger_bp_input) else {
            self.add_toast(
                ToastKind::Error,
                "Breakpoint address must be hex (0x...) or decimal.".into(),
            );
            return;
        };
        let scope_tid = if self.debugger_bp_scope_thread {
            self.debugger_active_thread
        } else {
            None
        };
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        let label = match kind {
            BreakpointKind::Software => "sw breakpoint",
            BreakpointKind::Hardware => "hw breakpoint",
            BreakpointKind::WriteWatch => "write watchpoint",
            BreakpointKind::ReadWatch => "read watchpoint",
            BreakpointKind::AccessWatch => "access watchpoint",
        };
        let result = match scope_tid {
            Some(tid) => d.set_breakpoint_for_thread(addr, kind, tid),
            None => d.set_breakpoint(addr, kind),
        };
        match result {
            Ok(()) => {
                let scope_note = scope_tid
                    .map(|t| format!(" (thread 0x{:x})", t))
                    .unwrap_or_default();
                self.add_toast(
                    ToastKind::Success,
                    format!("{} set at 0x{:x}{}", label, addr, scope_note),
                );
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Set {} failed: {}", label, e)),
        }
    }

    /// Find the next address that maps to a different source line than the
    /// current PC, set a temporary software breakpoint there, and resume.
    /// The address is recorded in `temp_breakpoints` so the next stop poll
    /// auto-clears it.
    fn debugger_step_source_line(&mut self) {
        let pc = self.debugger_remote.as_ref().and_then(|d| {
            let regs = d.registers();
            regs.get("rip")
                .or_else(|| regs.get("eip"))
                .or_else(|| regs.get("pc"))
                .copied()
        });
        let Some(pc) = pc else {
            self.add_toast(ToastKind::Error, "PC unknown — Refresh first.".into());
            return;
        };
        let next_addr = self.project.as_ref().and_then(|project| {
            let cur = project.types.source_lines.get(&pc);
            // Walk addresses ascending; find the first whose (file, line) differs.
            project
                .types
                .source_lines
                .range((pc + 1)..)
                .find(|(_, info)| match cur {
                    Some(c) => info.file != c.file || info.line != c.line,
                    None => true,
                })
                .map(|(&addr, _)| addr)
        });
        let Some(addr) = next_addr else {
            self.add_toast(
                ToastKind::Warning,
                "No further source line found (end of function?).".into(),
            );
            return;
        };
        if let Err(e) = self.debugger_plant_temp_breakpoint(addr) {
            self.add_toast(ToastKind::Error, format!("Set step BP failed: {}", e));
            return;
        }
        self.debugger_continue();
    }

    fn debugger_remove_breakpoint(&mut self, address: u64) {
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        // Try removing both kinds — the Vec dedupe is by (addr, kind).
        let _ = d.remove_breakpoint(address, BreakpointKind::Software);
        let _ = d.remove_breakpoint(address, BreakpointKind::Hardware);
    }

    fn debugger_write_register(&mut self, name: &str, value: u64) {
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.write_register(name, value) {
            Ok(()) => {
                self.add_toast(ToastKind::Success, format!("{} = 0x{:x}", name, value));
                // Re-read so the displayed value reflects what the stub stored
                // (it may mask reserved bits, e.g. in eflags).
                self.debugger_refresh();
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Write {} failed: {}", name, e)),
        }
    }

    fn debugger_write_memory(&mut self) {
        let Some(addr) = parse_hex_or_dec(&self.debugger_mem_addr) else {
            self.add_toast(
                ToastKind::Error,
                "Address must be a hex (0x...) or decimal number.".into(),
            );
            return;
        };
        let Some(bytes) = parse_hex_bytes(&self.debugger_mem_write_input) else {
            self.add_toast(
                ToastKind::Error,
                "Write value must be hex bytes, e.g. `90 90 cc` or `9090cc`.".into(),
            );
            return;
        };
        if bytes.is_empty() {
            return;
        }
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.write_memory(addr, &bytes) {
            Ok(()) => {
                self.add_toast(
                    ToastKind::Success,
                    format!("Wrote {} byte(s) at 0x{:x}", bytes.len(), addr),
                );
                self.debugger_mem_write_input.clear();
                // Re-read the window so the hex dump reflects the write.
                self.debugger_read_memory();
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Memory write failed: {}", e)),
        }
    }

    fn debugger_read_memory(&mut self) {
        let Some(ref d) = self.debugger_remote else {
            return;
        };
        let Some(addr) = parse_hex_or_dec(&self.debugger_mem_addr) else {
            self.add_toast(
                ToastKind::Error,
                "Address must be a hex (0x...) or decimal number.".into(),
            );
            return;
        };
        let size = self.debugger_mem_size.max(1) as usize;
        match d.read_memory(addr, size) {
            Ok(bytes) => self.debugger_mem_data = Some(bytes),
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Memory read failed: {}", e));
            }
        }
    }
}

fn stop_reason_summary(reason: &StopReason) -> (String, egui::Color32) {
    match reason {
        StopReason::Step => ("stepped".into(), egui::Color32::LIGHT_GRAY),
        StopReason::SoftwareBreakpoint(pc) => (
            format!("hit sw bp @ 0x{:x}", pc),
            egui::Color32::from_rgb(255, 200, 80),
        ),
        StopReason::HardwareBreakpoint(pc) => (
            format!("hit hw bp @ 0x{:x}", pc),
            egui::Color32::from_rgb(255, 200, 80),
        ),
        StopReason::Watchpoint {
            kind,
            pc,
            data_address,
        } => {
            let kind_str = match kind {
                WatchpointHit::Write => "write",
                WatchpointHit::Read => "read",
                WatchpointHit::Access => "access",
            };
            (
                format!(
                    "{} watch @ 0x{:x} (data 0x{:x})",
                    kind_str, pc, data_address
                ),
                egui::Color32::from_rgb(255, 170, 60),
            )
        }
        StopReason::Signal(sig) => (format!("signal {}", sig), egui::Color32::LIGHT_BLUE),
        StopReason::Exited(code) => (
            format!("exited ({})", code),
            egui::Color32::from_rgb(120, 200, 120),
        ),
        StopReason::Terminated(sig) => (
            format!("killed by signal {}", sig),
            egui::Color32::from_rgb(220, 80, 80),
        ),
        StopReason::Other(s) => (format!("stop: {}", s), egui::Color32::GRAY),
    }
}

fn transport_label(t: DebugTransport) -> &'static str {
    match t {
        DebugTransport::GdbRemote => "GDB Remote",
        DebugTransport::LocalLaunch => "Local launch",
    }
}

/// Parse an [`Architecture`] from its `Debug` name (how profiles store the
/// arch override). Returns `None` for an unknown name.
fn arch_from_debug_name(s: &str) -> Option<Architecture> {
    Some(match s {
        "X86" => Architecture::X86,
        "X86_64" => Architecture::X86_64,
        "Arm" => Architecture::Arm,
        "Arm64" => Architecture::Arm64,
        "Mips" => Architecture::Mips,
        "Mips64" => Architecture::Mips64,
        "RiscV32" => Architecture::RiscV32,
        "RiscV64" => Architecture::RiscV64,
        _ => return None,
    })
}

/// Ask the OS for a free loopback TCP port by binding to port 0 and reading
/// back the assigned port. The listener is dropped immediately; there is an
/// inherent (negligible, loopback-only) race before gdbserver rebinds it.
///
/// Only compiled where it is used: the Linux launch path and the test suite.
#[cfg(any(target_os = "linux", test))]
fn pick_free_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr().map(|a| a.port())
}

/// Spawn `gdbserver :<port> <exe> <args...>` and connect an RSP debugger to it,
/// retrying the connect until the stub is listening (~2s budget). On failure
/// the child is killed and reaped so it never orphans.
#[cfg(target_os = "linux")]
fn spawn_gdbserver(
    exe: &str,
    args: &[String],
    arch: Architecture,
) -> Result<
    (
        std::process::Child,
        re_core::debuggers::GdbRemoteDebugger,
        u16,
    ),
    String,
> {
    let port = pick_free_port().map_err(|e| format!("no free port: {}", e))?;
    let mut child = std::process::Command::new("gdbserver")
        .arg(format!(":{}", port))
        .arg(exe)
        .args(args)
        .spawn()
        .map_err(|e| format!("spawn gdbserver: {}", e))?;
    let addr = format!("127.0.0.1:{}", port);
    let mut last_err = String::new();
    for _ in 0..40 {
        match re_core::debuggers::GdbRemoteDebugger::connect(addr.as_str(), arch) {
            Ok(d) => return Ok((child, d, port)),
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(format!("gdbserver did not become ready: {}", last_err))
}

#[cfg(not(target_os = "linux"))]
fn spawn_gdbserver(
    _exe: &str,
    _args: &[String],
    _arch: Architecture,
) -> Result<
    (
        std::process::Child,
        re_core::debuggers::GdbRemoteDebugger,
        u16,
    ),
    String,
> {
    Err("local launch requires gdbserver (Linux only)".into())
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse a sequence of hex bytes from user text. Accepts space/comma
/// separators (`"90 90 cc"`, `"90,90,cc"`) or a contiguous even-length run
/// (`"9090cc"`). Returns `None` on any non-hex content or an odd contiguous
/// nibble count.
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    if trimmed.contains([' ', ',']) {
        trimmed
            .split([' ', ','])
            .filter(|tok| !tok.is_empty())
            .map(|tok| u8::from_str_radix(tok.trim_start_matches("0x"), 16).ok())
            .collect()
    } else {
        let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect()
    }
}

fn format_hex_dump(data: &[u8], base: u64) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base + (i as u64) * 16;
        out.push_str(&format!("{:08x}  ", addr));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 {
                out.push(' ');
            }
        }
        for j in chunk.len()..16 {
            out.push_str("   ");
            if j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for &b in chunk {
            if (0x20..=0x7E).contains(&b) {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_bytes_accepts_separated_and_contiguous() {
        assert_eq!(parse_hex_bytes("90 90 cc"), Some(vec![0x90, 0x90, 0xcc]));
        assert_eq!(parse_hex_bytes("90,90,cc"), Some(vec![0x90, 0x90, 0xcc]));
        assert_eq!(parse_hex_bytes("9090cc"), Some(vec![0x90, 0x90, 0xcc]));
        assert_eq!(parse_hex_bytes("0xde 0xad"), Some(vec![0xde, 0xad]));
        assert_eq!(parse_hex_bytes("   "), Some(vec![]));
    }

    #[test]
    fn parse_hex_bytes_rejects_malformed() {
        assert_eq!(parse_hex_bytes("9090c"), None); // odd contiguous nibbles
        assert_eq!(parse_hex_bytes("zz"), None); // non-hex
        assert_eq!(parse_hex_bytes("90 zz"), None); // non-hex token
    }

    #[test]
    fn pick_free_port_returns_nonzero() {
        let port = pick_free_port().expect("a free port should be available");
        assert_ne!(port, 0);
    }

    #[test]
    fn arch_round_trips_through_debug_name() {
        for a in ALL_DEBUG_ARCHES {
            assert_eq!(arch_from_debug_name(&format!("{:?}", a)), Some(*a));
        }
        assert_eq!(arch_from_debug_name("Sparc"), None);
    }
}
