/// Defines a single opcode in a custom bytecode format.
#[derive(Debug, Clone)]
pub struct OpcodeDefinition {
    /// Opcode byte value.
    pub opcode: u8,
    /// Human-readable mnemonic (e.g., "GiveItem", "SetVariable").
    pub mnemonic: String,
    /// Operand types in order.
    pub operand_types: Vec<OperandType>,
    /// Description of what this opcode does.
    pub description: String,
}

/// Types of operands that follow an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    Uint8,
    Uint16,
    Uint32,
    Int8,
    Int16,
    Int32,
    /// Fixed-length string (length in bytes).
    FixedString(usize),
    /// Null-terminated string.
    NullTermString,
}

/// A single disassembled bytecode instruction.
#[derive(Debug, Clone)]
pub struct BytecodeInstruction {
    /// Byte offset within the bytecode stream.
    pub offset: u64,
    /// Opcode byte.
    pub opcode: u8,
    /// Mnemonic from the opcode table.
    pub mnemonic: String,
    /// Formatted operand strings.
    pub operands: Vec<String>,
    /// Raw bytes of this instruction.
    pub raw_bytes: Vec<u8>,
    /// Optional inline comment.
    pub comment: Option<String>,
    /// Total byte length of this instruction.
    pub length: usize,
}

/// Trait for custom bytecode format disassemblers.
pub trait BytecodeFormat: Send + Sync {
    /// Human-readable name (e.g., "MM7 EVT Events").
    fn name(&self) -> &str;
    /// Return `true` if this format can handle the data.
    fn matches(&self, header: &[u8]) -> bool;
    /// Return the opcode table for documentation/display.
    fn opcode_table(&self) -> Vec<OpcodeDefinition>;
    /// Disassemble a bytecode stream into instructions.
    fn disassemble(&self, data: &[u8]) -> Result<Vec<BytecodeInstruction>, String>;
}

/// Registry of bytecode format handlers.
#[derive(Default)]
pub struct BytecodeFormatRegistry {
    formats: Vec<Box<dyn BytecodeFormat>>,
}

impl BytecodeFormatRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, format: Box<dyn BytecodeFormat>) {
        self.formats.push(format);
    }

    /// Try to disassemble data using a matching format.
    pub fn disassemble(
        &self,
        data: &[u8],
    ) -> Option<(Vec<BytecodeInstruction>, &dyn BytecodeFormat)> {
        for fmt in &self.formats {
            if fmt.matches(data)
                && let Ok(insns) = fmt.disassemble(data)
            {
                return Some((insns, fmt.as_ref()));
            }
        }
        None
    }

    /// Disassemble data using a specific format by name.
    pub fn disassemble_as(
        &self,
        data: &[u8],
        format_name: &str,
    ) -> Option<Vec<BytecodeInstruction>> {
        self.formats
            .iter()
            .find(|f| f.name() == format_name)
            .and_then(|f| f.disassemble(data).ok())
    }

    pub fn format_names(&self) -> Vec<&str> {
        self.formats.iter().map(|f| f.name()).collect()
    }
}

/// Create default registry (empty — bytecode formats are contributed by plugins).
pub fn default_bytecode_registry() -> BytecodeFormatRegistry {
    BytecodeFormatRegistry::new()
}

/// Generic bytecode disassembler driven by an opcode table.
///
/// For formats where each instruction is: opcode(1 byte) + fixed operands,
/// this provides a reusable disassembly loop.
pub fn disassemble_with_table(
    data: &[u8],
    opcodes: &[OpcodeDefinition],
    base_offset: u64,
) -> Result<Vec<BytecodeInstruction>, String> {
    let opcode_map: std::collections::HashMap<u8, &OpcodeDefinition> =
        opcodes.iter().map(|o| (o.opcode, o)).collect();

    let mut instructions = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let op = data[pos];
        let inst_start = pos;

        let Some(def) = opcode_map.get(&op) else {
            // Unknown opcode — emit raw byte and advance
            instructions.push(BytecodeInstruction {
                offset: base_offset + pos as u64,
                opcode: op,
                mnemonic: format!("db 0x{:02X}", op),
                operands: Vec::new(),
                raw_bytes: vec![op],
                comment: Some("unknown opcode".to_string()),
                length: 1,
            });
            pos += 1;
            continue;
        };

        pos += 1; // skip opcode byte
        let mut operands = Vec::new();

        for operand_type in &def.operand_types {
            match operand_type {
                OperandType::Uint8 => {
                    if pos < data.len() {
                        operands.push(format!("{}", data[pos]));
                        pos += 1;
                    }
                }
                OperandType::Uint16 => {
                    if pos + 2 <= data.len() {
                        let val = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
                        operands.push(format!("{}", val));
                        pos += 2;
                    }
                }
                OperandType::Uint32 => {
                    if pos + 4 <= data.len() {
                        let val = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                        operands.push(format!("0x{:X}", val));
                        pos += 4;
                    }
                }
                OperandType::Int8 => {
                    if pos < data.len() {
                        operands.push(format!("{}", data[pos] as i8));
                        pos += 1;
                    }
                }
                OperandType::Int16 => {
                    if pos + 2 <= data.len() {
                        let val = i16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
                        operands.push(format!("{}", val));
                        pos += 2;
                    }
                }
                OperandType::Int32 => {
                    if pos + 4 <= data.len() {
                        let val = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                        operands.push(format!("{}", val));
                        pos += 4;
                    }
                }
                OperandType::FixedString(len) => {
                    let end = std::cmp::min(pos + len, data.len());
                    let s: String = data[pos..end]
                        .iter()
                        .take_while(|&&b| b != 0)
                        .map(|&b| b as char)
                        .collect();
                    operands.push(format!("\"{}\"", s));
                    pos = end;
                }
                OperandType::NullTermString => {
                    let start = pos;
                    while pos < data.len() && data[pos] != 0 {
                        pos += 1;
                    }
                    let s = String::from_utf8_lossy(&data[start..pos]).to_string();
                    if pos < data.len() {
                        pos += 1; // skip null terminator
                    }
                    operands.push(format!("\"{}\"", s));
                }
            }
        }

        let raw = data[inst_start..pos].to_vec();
        let length = raw.len();

        instructions.push(BytecodeInstruction {
            offset: base_offset + inst_start as u64,
            opcode: op,
            mnemonic: def.mnemonic.clone(),
            operands,
            raw_bytes: raw,
            comment: None,
            length,
        });
    }

    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disassemble_simple_table() {
        let opcodes = vec![
            OpcodeDefinition {
                opcode: 0x01,
                mnemonic: "NOP".to_string(),
                operand_types: vec![],
                description: "Do nothing".to_string(),
            },
            OpcodeDefinition {
                opcode: 0x02,
                mnemonic: "PUSH".to_string(),
                operand_types: vec![OperandType::Uint16],
                description: "Push u16".to_string(),
            },
            OpcodeDefinition {
                opcode: 0x03,
                mnemonic: "CALL".to_string(),
                operand_types: vec![OperandType::Uint32],
                description: "Call address".to_string(),
            },
        ];

        // NOP, PUSH 0x1234, CALL 0xDEADBEEF, NOP
        let data = [0x01, 0x02, 0x34, 0x12, 0x03, 0xEF, 0xBE, 0xAD, 0xDE, 0x01];
        let result = disassemble_with_table(&data, &opcodes, 0).unwrap();

        assert_eq!(result.len(), 4);
        assert_eq!(result[0].mnemonic, "NOP");
        assert_eq!(result[0].length, 1);
        assert_eq!(result[1].mnemonic, "PUSH");
        assert_eq!(result[1].operands[0], "4660"); // 0x1234
        assert_eq!(result[1].length, 3);
        assert_eq!(result[2].mnemonic, "CALL");
        assert_eq!(result[2].operands[0], "0xDEADBEEF");
        assert_eq!(result[2].length, 5);
        assert_eq!(result[3].mnemonic, "NOP");
    }

    #[test]
    fn unknown_opcodes_emit_db() {
        let opcodes = vec![OpcodeDefinition {
            opcode: 0x01,
            mnemonic: "NOP".to_string(),
            operand_types: vec![],
            description: "".to_string(),
        }];

        let data = [0xFF, 0x01, 0xAB];
        let result = disassemble_with_table(&data, &opcodes, 0x100).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].mnemonic, "db 0xFF");
        assert_eq!(result[0].offset, 0x100);
        assert!(result[0].comment.is_some());
        assert_eq!(result[1].mnemonic, "NOP");
        assert_eq!(result[1].offset, 0x101);
    }
}
