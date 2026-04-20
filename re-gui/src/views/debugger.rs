//! Debugger panel.
//!
//! Connects to a `gdbserver`-compatible stub via the GDB Remote Serial
//! Protocol backend in `re-core`. Provides attach/detach/step/continue
//! controls, a register dump, and a memory inspector at a user-supplied
//! address. The actual transport lives in `re_core::debuggers::GdbRemoteDebugger`.

use eframe::egui;
use re_core::{BreakpointKind, Debugger, StopReason};

use crate::app::{PendingDebuggerOp, SleuthreApp, ToastKind};

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

        // Connection bar.
        ui.horizontal(|ui| {
            ui.label("Address:");
            ui.text_edit_singleline(&mut self.debugger_addr_input);
            if self.debugger_remote.is_none() {
                if ui.button("Connect").clicked() {
                    self.debugger_connect();
                }
            } else if ui.button("Disconnect").clicked()
                && let Some(mut d) = self.debugger_remote.take()
            {
                let _ = d.detach();
            }
        });

        if self.debugger_remote.is_none() {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Tip: launch `gdbserver :1234 ./prog` then connect to 127.0.0.1:1234.",
                )
                .size(10.0)
                .color(egui::Color32::GRAY),
            );
            return;
        }

        // Control bar. Disable Step/Continue while a previous async op is
        // still in flight so we don't double-issue RSP commands on the same
        // socket.
        let mut step_clicked = false;
        let mut continue_clicked = false;
        let busy = self.debugger_pending.is_some();
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("Step")).clicked() {
                step_clicked = true;
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
            // Stop button only meaningful while a continue is in flight; the
            // interrupt is sent over the same socket the worker thread is
            // already blocked reading on, so the worker returns shortly after.
            if busy
                && ui.button("Stop").clicked()
                && let Some(d) = self.debugger_remote.as_mut()
                && let Err(e) = d.interrupt()
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
        if continue_clicked {
            self.debugger_continue();
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
            for (i, addr) in frames.iter().enumerate() {
                ui.monospace(egui::RichText::new(format!("  #{:<2}  0x{:x}", i, addr)).size(11.0));
            }
            ui.separator();
        }

        let avail = ui.available_size();
        ui.horizontal(|ui| {
            // Left: register dump.
            ui.vertical(|ui| {
                ui.set_width(avail.x * 0.35);
                ui.label(egui::RichText::new("Registers").strong().size(11.0));
                egui::ScrollArea::vertical()
                    .id_salt("debugger_regs")
                    .show(ui, |ui| {
                        if self.debugger_regs.is_empty() {
                            ui.label(
                                egui::RichText::new("(no register snapshot — click Refresh)")
                                    .size(10.0)
                                    .color(egui::Color32::GRAY),
                            );
                        } else {
                            let mut sorted: Vec<_> = self.debugger_regs.iter().collect();
                            sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
                            for (name, value) in sorted {
                                ui.monospace(
                                    egui::RichText::new(format!("{:>6} = 0x{:016x}", name, value))
                                        .size(11.0),
                                );
                            }
                        }
                    });
            });
            ui.separator();

            // Right: memory inspector.
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
    }

    fn debugger_connect(&mut self) {
        let arch = self
            .project
            .as_ref()
            .map(|p| p.arch)
            .unwrap_or(re_core::arch::Architecture::X86_64);
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

    fn debugger_refresh(&mut self) {
        let Some(ref d) = self.debugger_remote else {
            return;
        };
        self.debugger_regs = d.registers();
    }

    fn debugger_step(&mut self) {
        self.spawn_debugger_op(DebuggerOp::Step);
    }

    fn debugger_continue(&mut self) {
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
        let Some(mut dbg) = self.debugger_remote.take() else {
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
                match result {
                    Ok(reason) => {
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
                self.add_toast(ToastKind::Error, "Debugger worker disconnected.".into());
            }
        }
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

    /// After a stop, scroll the disassembly view to the current PC so the
    /// analyst sees what just stopped. Falls through silently when no PC
    /// register is exposed.
    fn debugger_jump_disasm_to_pc(&mut self) {
        let Some(ref d) = self.debugger_remote else {
            return;
        };
        let regs = d.registers();
        let Some(&pc) = regs
            .get("rip")
            .or_else(|| regs.get("eip"))
            .or_else(|| regs.get("pc"))
        else {
            return;
        };
        self.current_address = pc;
        if let Some(ref mut project) = self.project {
            project.navigate_to(pc);
        }
        self.update_cfg();
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
        match d.set_breakpoint(addr, kind) {
            Ok(()) => self.add_toast(ToastKind::Success, format!("{} set at 0x{:x}", label, addr)),
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
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        if let Err(e) = d.set_breakpoint(addr, BreakpointKind::Software) {
            self.add_toast(ToastKind::Error, format!("Set step BP failed: {}", e));
            return;
        }
        self.debugger_temp_breakpoints.push(addr);
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

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse().ok()
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
