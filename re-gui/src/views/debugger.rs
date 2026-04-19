//! Debugger panel.
//!
//! Connects to a `gdbserver`-compatible stub via the GDB Remote Serial
//! Protocol backend in `re-core`. Provides attach/detach/step/continue
//! controls, a register dump, and a memory inspector at a user-supplied
//! address. The actual transport lives in `re_core::debuggers::GdbRemoteDebugger`.

use eframe::egui;
use re_core::{BreakpointKind, Debugger, StopReason};

use crate::app::{SleuthreApp, ToastKind};

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

        // Control bar.
        let mut step_clicked = false;
        let mut continue_clicked = false;
        ui.horizontal(|ui| {
            if ui.button("Step").clicked() {
                step_clicked = true;
            }
            if ui.button("Continue").clicked() {
                continue_clicked = true;
            }
            if ui.button("Refresh").clicked() {
                self.debugger_refresh();
            }
            if let Some(ref reason) = self.debugger_last_stop {
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

        ui.separator();

        // Breakpoint controls.
        let mut add_clicked = false;
        let mut clear_addr: Option<u64> = None;
        ui.horizontal(|ui| {
            ui.label("BP @");
            ui.text_edit_singleline(&mut self.debugger_bp_input);
            if ui.button("+ Set").clicked() {
                add_clicked = true;
            }
            if ui.button("+ Set HW").clicked() {
                add_clicked = true;
                self.debugger_bp_kind_hw = true;
            }
        });
        if add_clicked {
            let hw = self.debugger_bp_kind_hw;
            self.debugger_bp_kind_hw = false;
            self.debugger_set_breakpoint(hw);
        }
        // Active breakpoints list.
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
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.step() {
            Ok(reason) => {
                self.debugger_last_stop = Some(reason);
                self.debugger_refresh();
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Step error: {}", e)),
        }
    }

    fn debugger_continue(&mut self) {
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.continue_exec() {
            Ok(reason) => {
                self.debugger_last_stop = Some(reason);
                self.debugger_refresh();
            }
            Err(e) => self.add_toast(ToastKind::Error, format!("Continue error: {}", e)),
        }
    }

    fn debugger_set_breakpoint(&mut self, hardware: bool) {
        let Some(addr) = parse_hex_or_dec(&self.debugger_bp_input) else {
            self.add_toast(
                ToastKind::Error,
                "Breakpoint address must be hex (0x...) or decimal.".into(),
            );
            return;
        };
        let kind = if hardware {
            BreakpointKind::Hardware
        } else {
            BreakpointKind::Software
        };
        let Some(d) = self.debugger_remote.as_mut() else {
            return;
        };
        match d.set_breakpoint(addr, kind) {
            Ok(()) => self.add_toast(
                ToastKind::Success,
                format!("Breakpoint set at 0x{:x}", addr),
            ),
            Err(e) => self.add_toast(ToastKind::Error, format!("Set BP failed: {}", e)),
        }
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
