use eframe::egui;
use re_core::formats::bytecode::{OpcodeDefinition, OperandType, disassemble_with_table};

use crate::app::{SleuthreApp, ToastKind};

impl SleuthreApp {
    pub(crate) fn show_bytecode(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Bytecode Disassembly");
            ui.add_space(16.0);
            if ui.button("Load Bytecode File...").clicked() {
                self.load_bytecode_file();
            }
            if ui.button("Load Opcode Table (JSON)...").clicked() {
                self.load_bytecode_opcode_table();
            }
            if (!self.bytecode_insns.is_empty() || self.bytecode_bytes.is_some())
                && ui.button("Clear").clicked()
            {
                self.bytecode_bytes = None;
                self.bytecode_insns.clear();
                self.bytecode_format_name = None;
            }
        });
        ui.separator();

        if self.bytecode_insns.is_empty() {
            ui.label("Load a bytecode blob and (optionally) an opcode table JSON to disassemble.");
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Opcode JSON format: [{\"opcode\":1,\"mnemonic\":\"NOP\",\"operands\":[]}, ...]",
                )
                .size(10.0)
                .color(egui::Color32::GRAY),
            );
            return;
        }

        if let Some(ref name) = self.bytecode_format_name {
            ui.label(
                egui::RichText::new(format!("Format: {}", name))
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
        }
        ui.label(
            egui::RichText::new(format!("{} instructions", self.bytecode_insns.len())).size(11.0),
        );
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("bytecode_scroll")
            .show(ui, |ui| {
                egui::Grid::new("bytecode_grid")
                    .striped(true)
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Offset").strong().size(11.0));
                        ui.label(egui::RichText::new("Bytes").strong().size(11.0));
                        ui.label(egui::RichText::new("Mnemonic").strong().size(11.0));
                        ui.label(egui::RichText::new("Operands").strong().size(11.0));
                        ui.end_row();

                        for insn in &self.bytecode_insns {
                            let offset_color = if is_branch_mnemonic(&insn.mnemonic) {
                                egui::Color32::from_rgb(255, 200, 80)
                            } else {
                                egui::Color32::LIGHT_GRAY
                            };
                            ui.monospace(
                                egui::RichText::new(format!("{:08X}", insn.offset))
                                    .color(offset_color)
                                    .size(11.0),
                            );
                            let bytes: String = insn
                                .raw_bytes
                                .iter()
                                .map(|b| format!("{:02X}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            ui.monospace(egui::RichText::new(bytes).size(11.0));
                            let mnem_color = if is_branch_mnemonic(&insn.mnemonic) {
                                egui::Color32::from_rgb(255, 200, 80)
                            } else {
                                egui::Color32::from_rgb(120, 180, 255)
                            };
                            ui.monospace(
                                egui::RichText::new(&insn.mnemonic)
                                    .color(mnem_color)
                                    .size(11.0),
                            );
                            ui.monospace(egui::RichText::new(insn.operands.join(", ")).size(11.0));
                            ui.end_row();
                        }
                    });
            });
    }

    fn load_bytecode_file(&mut self) {
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Read error: {}", e));
                return;
            }
        };
        self.bytecode_bytes = Some(data);
        self.bytecode_insns.clear();
        self.bytecode_format_name = None;
        self.redisassemble_bytecode();
        self.add_toast(
            ToastKind::Info,
            "Loaded bytecode. Load an opcode table to disassemble.".into(),
        );
    }

    fn load_bytecode_opcode_table(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Opcode table (JSON)", &["json"])
            .pick_file()
        else {
            return;
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Read error: {}", e));
                return;
            }
        };
        match parse_opcode_table(&content) {
            Ok(table) => {
                self.bytecode_opcodes = table;
                self.bytecode_format_name =
                    path.file_name().map(|n| n.to_string_lossy().to_string());
                self.redisassemble_bytecode();
            }
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Opcode table parse error: {}", e));
            }
        }
    }

    fn redisassemble_bytecode(&mut self) {
        let Some(ref data) = self.bytecode_bytes else {
            return;
        };
        // Try registered plugin formats first.
        if let Some((insns, fmt)) = self.bytecode_registry.disassemble(data) {
            self.bytecode_insns = insns;
            self.bytecode_format_name = Some(fmt.name().to_string());
            return;
        }
        // Fallback: user-loaded opcode table.
        if self.bytecode_opcodes.is_empty() {
            return;
        }
        match disassemble_with_table(data, &self.bytecode_opcodes, 0) {
            Ok(insns) => self.bytecode_insns = insns,
            Err(e) => {
                self.add_toast(ToastKind::Error, format!("Disassembly failed: {}", e));
            }
        }
    }
}

fn is_branch_mnemonic(mnemonic: &str) -> bool {
    let m = mnemonic.to_ascii_uppercase();
    m.starts_with("J") || m.starts_with("CALL") || m == "BR" || m == "RET" || m == "GOTO"
}

fn parse_opcode_table(content: &str) -> Result<Vec<OpcodeDefinition>, String> {
    let parsed: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| "expected JSON array at top level".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item
            .as_object()
            .ok_or_else(|| "each opcode entry must be an object".to_string())?;
        let opcode = obj
            .get("opcode")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "missing 'opcode' field".to_string())?;
        let mnemonic = obj
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'mnemonic' field".to_string())?
            .to_string();
        let operands = obj.get("operands").and_then(|v| v.as_array());
        let mut op_types = Vec::new();
        if let Some(ops) = operands {
            for op in ops {
                let s = op
                    .as_str()
                    .ok_or_else(|| "operand entry must be a string".to_string())?;
                op_types.push(parse_operand_type(s)?);
            }
        }
        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(OpcodeDefinition {
            opcode: opcode as u8,
            mnemonic,
            operand_types: op_types,
            description,
        });
    }
    Ok(out)
}

fn parse_operand_type(s: &str) -> Result<OperandType, String> {
    match s {
        "u8" => Ok(OperandType::Uint8),
        "u16" => Ok(OperandType::Uint16),
        "u32" => Ok(OperandType::Uint32),
        "i8" => Ok(OperandType::Int8),
        "i16" => Ok(OperandType::Int16),
        "i32" => Ok(OperandType::Int32),
        "cstr" => Ok(OperandType::NullTermString),
        other => {
            if let Some(rest) = other.strip_prefix("str:")
                && let Ok(n) = rest.parse::<usize>()
            {
                return Ok(OperandType::FixedString(n));
            }
            Err(format!("unknown operand type '{}'", s))
        }
    }
}
