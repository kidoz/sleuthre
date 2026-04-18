use crate::formats::archive::default_registry as default_archive_registry;
use crate::formats::bytecode::{OpcodeDefinition, OperandType, disassemble_with_table};
use crate::import::symbols::{detect_format, parse_symbols};
use crate::project::Project;
use rhai::{Dynamic, Engine, EvalAltResult, Scope};
use std::cell::RefCell;
use std::rc::Rc;

/// Actions that scripts can request. Applied by the caller after eval.
#[derive(Debug, Clone)]
pub enum ScriptAction {
    Rename { address: u64, new_name: String },
    Comment { address: u64, text: String },
    Goto(u64),
    Print(String),
    ImportSymbols { path: String },
}

#[derive(Clone)]
pub struct BinaryFile {
    data: Rc<Vec<u8>>,
}

impl BinaryFile {
    pub fn read_u32_le(&mut self, offset: i64) -> Result<i64, Box<EvalAltResult>> {
        if offset < 0 || offset as usize + 4 > self.data.len() {
            return Err(Box::new(EvalAltResult::from("out of bounds")));
        }
        let val = u32::from_le_bytes(
            self.data[offset as usize..offset as usize + 4]
                .try_into()
                .unwrap(),
        );
        Ok(val as i64)
    }

    pub fn read_u16_le(&mut self, offset: i64) -> Result<i64, Box<EvalAltResult>> {
        if offset < 0 || offset as usize + 2 > self.data.len() {
            return Err(Box::new(EvalAltResult::from("out of bounds")));
        }
        let val = u16::from_le_bytes(
            self.data[offset as usize..offset as usize + 2]
                .try_into()
                .unwrap(),
        );
        Ok(val as i64)
    }

    pub fn read_string(&mut self, offset: i64, len: i64) -> Result<String, Box<EvalAltResult>> {
        if offset < 0 || len < 0 || offset as usize + len as usize > self.data.len() {
            return Err(Box::new(EvalAltResult::from("out of bounds")));
        }
        let slice = &self.data[offset as usize..offset as usize + len as usize];
        let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        Ok(String::from_utf8_lossy(&slice[..null_pos]).to_string())
    }

    pub fn len(&mut self) -> i64 {
        self.data.len() as i64
    }

    pub fn is_empty(&mut self) -> bool {
        self.data.is_empty()
    }
}

pub struct ScriptEngine {
    engine: Engine,
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // Register hex formatting helper
        engine.register_fn("hex", |n: i64| format!("0x{:x}", n));

        // Register BinaryFile type and methods
        engine.register_type_with_name::<BinaryFile>("BinaryFile");
        engine.register_fn(
            "open_binary",
            |path: rhai::ImmutableString| -> Result<BinaryFile, Box<EvalAltResult>> {
                let data = std::fs::read(path.as_str())
                    .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
                Ok(BinaryFile {
                    data: Rc::new(data),
                })
            },
        );
        engine.register_fn("read_u32_le", BinaryFile::read_u32_le);
        engine.register_fn("read_u16_le", BinaryFile::read_u16_le);
        engine.register_fn("read_string", BinaryFile::read_string);
        engine.register_fn("len", BinaryFile::len);

        // Archive APIs (read-only; auto-detects format by magic/extension).
        engine.register_fn(
            "open_archive",
            |path: rhai::ImmutableString| -> Result<rhai::Map, Box<EvalAltResult>> {
                let data = std::fs::read(path.as_str())
                    .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
                let ext = std::path::Path::new(path.as_str())
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let registry = default_archive_registry();
                let (dir, format) = registry
                    .open(&data, &ext)
                    .map_err(|e| Box::new(EvalAltResult::from(e)))?;
                let mut out = rhai::Map::new();
                out.insert("path".into(), Dynamic::from(path.to_string()));
                out.insert("format".into(), Dynamic::from(format.name().to_string()));
                out.insert("count".into(), Dynamic::from(dir.entries.len() as i64));
                Ok(out)
            },
        );
        engine.register_fn(
            "archive_entries",
            |path: rhai::ImmutableString| -> Result<rhai::Array, Box<EvalAltResult>> {
                let data = std::fs::read(path.as_str())
                    .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
                let ext = std::path::Path::new(path.as_str())
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let registry = default_archive_registry();
                let (dir, _fmt) = registry
                    .open(&data, &ext)
                    .map_err(|e| Box::new(EvalAltResult::from(e)))?;
                let arr: rhai::Array = dir
                    .entries
                    .iter()
                    .map(|e| {
                        let mut m = rhai::Map::new();
                        m.insert("name".into(), Dynamic::from(e.name.clone()));
                        m.insert("offset".into(), Dynamic::from(e.offset as i64));
                        m.insert("size".into(), Dynamic::from(e.decompressed_size as i64));
                        m.insert(
                            "compressed_size".into(),
                            Dynamic::from(e.compressed_size as i64),
                        );
                        m.insert("is_compressed".into(), Dynamic::from(e.is_compressed));
                        Dynamic::from(m)
                    })
                    .collect();
                Ok(arr)
            },
        );
        engine.register_fn(
            "archive_extract",
            |path: rhai::ImmutableString,
             entry_name: rhai::ImmutableString|
             -> Result<rhai::Blob, Box<EvalAltResult>> {
                let data = std::fs::read(path.as_str())
                    .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
                let ext = std::path::Path::new(path.as_str())
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let registry = default_archive_registry();
                let (dir, format) = registry
                    .open(&data, &ext)
                    .map_err(|e| Box::new(EvalAltResult::from(e)))?;
                let entry = dir
                    .entries
                    .iter()
                    .find(|e| e.name == entry_name.as_str())
                    .ok_or_else(|| {
                        Box::new(EvalAltResult::from(format!(
                            "entry '{}' not found",
                            entry_name
                        )))
                    })?;
                let bytes = format
                    .extract(&data, entry)
                    .map_err(|e| Box::new(EvalAltResult::from(e)))?;
                Ok(bytes)
            },
        );

        // Bytecode disassembly: run a user-supplied opcode table over a blob.
        // Each entry in `opcodes` must be a map with keys: opcode (i64), mnemonic (string),
        // operands (array of strings: "u8"|"u16"|"u32"|"i8"|"i16"|"i32"|"str:N"|"cstr").
        engine.register_fn(
            "disassemble_bytecode",
            |data: rhai::Blob, opcodes: rhai::Array| -> Result<rhai::Array, Box<EvalAltResult>> {
                let mut defs = Vec::with_capacity(opcodes.len());
                for item in opcodes {
                    let map = item.try_cast::<rhai::Map>().ok_or_else(|| {
                        Box::new(EvalAltResult::from("opcode entry must be a map"))
                    })?;
                    let opcode = map
                        .get("opcode")
                        .and_then(|v| v.clone().try_cast::<i64>())
                        .ok_or_else(|| {
                            Box::new(EvalAltResult::from("opcode.opcode missing/invalid"))
                        })? as u8;
                    let mnemonic = map
                        .get("mnemonic")
                        .and_then(|v| v.clone().try_cast::<rhai::ImmutableString>())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let operands_arr = map
                        .get("operands")
                        .and_then(|v| v.clone().try_cast::<rhai::Array>())
                        .unwrap_or_default();
                    let mut op_types = Vec::with_capacity(operands_arr.len());
                    for o in operands_arr {
                        let s = o.try_cast::<rhai::ImmutableString>().ok_or_else(|| {
                            Box::new(EvalAltResult::from("operand entry must be a string"))
                        })?;
                        op_types.push(parse_operand_type(s.as_str())?);
                    }
                    defs.push(OpcodeDefinition {
                        opcode,
                        mnemonic,
                        operand_types: op_types,
                        description: String::new(),
                    });
                }
                let insns = disassemble_with_table(&data, &defs, 0)
                    .map_err(|e| Box::new(EvalAltResult::from(e)))?;
                let arr: rhai::Array = insns
                    .into_iter()
                    .map(|ins| {
                        let mut m = rhai::Map::new();
                        m.insert("offset".into(), Dynamic::from(ins.offset as i64));
                        m.insert("opcode".into(), Dynamic::from(ins.opcode as i64));
                        m.insert("mnemonic".into(), Dynamic::from(ins.mnemonic));
                        m.insert("length".into(), Dynamic::from(ins.length as i64));
                        let ops: rhai::Array =
                            ins.operands.into_iter().map(Dynamic::from).collect();
                        m.insert("operands".into(), Dynamic::from(ops));
                        Dynamic::from(m)
                    })
                    .collect();
                Ok(arr)
            },
        );

        // Parse a symbol file and return the count of parsed entries (pure query).
        engine.register_fn(
            "parse_symbol_file",
            |path: rhai::ImmutableString| -> Result<i64, Box<EvalAltResult>> {
                let content = std::fs::read_to_string(path.as_str())
                    .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
                let fmt = detect_format(&content);
                let syms =
                    parse_symbols(&content, fmt).map_err(|e| Box::new(EvalAltResult::from(e)))?;
                Ok(syms.len() as i64)
            },
        );

        Self { engine }
    }

    /// Evaluate a script string with access to project data.
    /// Returns a list of actions to apply and any output text.
    pub fn eval(
        &mut self,
        script: &str,
        project: &mut Project,
    ) -> Result<ScriptResult, Box<EvalAltResult>> {
        let actions: Rc<RefCell<Vec<ScriptAction>>> = Rc::new(RefCell::new(Vec::new()));
        let mut scope = Scope::new();

        // Push project snapshot data into scope
        let func_list: Vec<Dynamic> = project
            .functions
            .functions
            .values()
            .map(|f| {
                let mut map = rhai::Map::new();
                map.insert("address".into(), Dynamic::from(f.start_address as i64));
                map.insert("name".into(), Dynamic::from(f.name.clone()));
                map.insert(
                    "size".into(),
                    Dynamic::from(
                        f.end_address
                            .map(|e| (e - f.start_address) as i64)
                            .unwrap_or(0),
                    ),
                );
                Dynamic::from(map)
            })
            .collect();
        scope.push("functions", func_list);

        let string_list: Vec<Dynamic> = project
            .strings
            .strings
            .iter()
            .map(|s| {
                let mut map = rhai::Map::new();
                map.insert("address".into(), Dynamic::from(s.address as i64));
                map.insert("value".into(), Dynamic::from(s.value.clone()));
                map.insert(
                    "encoding".into(),
                    Dynamic::from(format!("{:?}", s.encoding)),
                );
                Dynamic::from(map)
            })
            .collect();
        scope.push("strings", string_list);

        let comment_list: Vec<Dynamic> = project
            .comments
            .iter()
            .map(|(&addr, text)| {
                let mut map = rhai::Map::new();
                map.insert("address".into(), Dynamic::from(addr as i64));
                map.insert("text".into(), Dynamic::from(text.clone()));
                Dynamic::from(map)
            })
            .collect();
        scope.push("comments", comment_list);

        scope.push(
            "arch",
            Dynamic::from(project.arch.display_name().to_string()),
        );

        scope.push(
            "num_functions",
            Dynamic::from(project.functions.functions.len() as i64),
        );
        scope.push(
            "num_strings",
            Dynamic::from(project.strings.strings.len() as i64),
        );

        // Register action functions that capture shared state
        let actions_rename = actions.clone();
        self.engine
            .register_fn("rename", move |addr: i64, name: String| {
                actions_rename.borrow_mut().push(ScriptAction::Rename {
                    address: addr as u64,
                    new_name: name,
                });
            });

        let actions_comment = actions.clone();
        self.engine
            .register_fn("set_comment", move |addr: i64, text: String| {
                actions_comment.borrow_mut().push(ScriptAction::Comment {
                    address: addr as u64,
                    text,
                });
            });

        let actions_goto = actions.clone();
        self.engine.register_fn("goto", move |addr: i64| {
            actions_goto
                .borrow_mut()
                .push(ScriptAction::Goto(addr as u64));
        });

        let actions_print = actions.clone();
        self.engine.register_fn("println", move |msg: String| {
            actions_print.borrow_mut().push(ScriptAction::Print(msg));
        });

        let actions_import = actions.clone();
        self.engine
            .register_fn("import_symbols", move |path: rhai::ImmutableString| {
                actions_import
                    .borrow_mut()
                    .push(ScriptAction::ImportSymbols {
                        path: path.to_string(),
                    });
            });

        let result = self.engine.eval_with_scope::<Dynamic>(&mut scope, script)?;

        let collected_actions = actions.borrow().clone();
        let output = if result.is_unit() {
            String::new()
        } else {
            format!("{result}")
        };

        Ok(ScriptResult {
            output,
            actions: collected_actions,
        })
    }

    /// Evaluate a script file.
    pub fn eval_file(
        &mut self,
        path: &std::path::Path,
        project: &mut Project,
    ) -> Result<ScriptResult, Box<EvalAltResult>> {
        let script = std::fs::read_to_string(path)
            .map_err(|e| Box::new(EvalAltResult::from(e.to_string())))?;
        self.eval(&script, project)
    }
}

/// The result of running a script.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub output: String,
    pub actions: Vec<ScriptAction>,
}

fn parse_operand_type(s: &str) -> Result<OperandType, Box<EvalAltResult>> {
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
            Err(Box::new(EvalAltResult::from(format!(
                "unknown operand type '{}'",
                s
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn eval_simple_expression() {
        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));
        let result = engine.eval("40 + 2", &mut project).unwrap();
        assert_eq!(result.output, "42");
    }

    #[test]
    fn eval_hex_helper() {
        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));
        let result = engine.eval("hex(255)", &mut project).unwrap();
        assert_eq!(result.output, "0xff");
    }

    #[test]
    fn eval_rename_action() {
        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));
        let result = engine
            .eval("rename(0x1000, \"main\")", &mut project)
            .unwrap();
        assert_eq!(result.actions.len(), 1);
        assert!(matches!(
            &result.actions[0],
            ScriptAction::Rename { address: 0x1000, new_name } if new_name == "main"
        ));
    }

    #[test]
    fn eval_access_project_data() {
        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));
        let result = engine.eval("num_functions", &mut project).unwrap();
        assert_eq!(result.output, "0");
    }

    #[test]
    fn eval_print_action() {
        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));
        let result = engine
            .eval("println(\"hello world\")", &mut project)
            .unwrap();
        assert_eq!(result.actions.len(), 1);
        assert!(matches!(&result.actions[0], ScriptAction::Print(msg) if msg == "hello world"));
    }

    #[test]
    fn eval_binary_file() {
        use std::io::Write;

        let mut engine = ScriptEngine::new();
        let mut project = Project::new("test".into(), PathBuf::from("/tmp/test"));

        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_bin_file.bin");
        let mut file = std::fs::File::create(&file_path).unwrap();

        // Write data: [0x78, 0x56, 0x34, 0x12] = 0x12345678 u32
        // Write data: [0xef, 0xbe] = 0xbeef u16
        // Write data: "test\0"
        file.write_all(&[
            0x78, 0x56, 0x34, 0x12, 0xef, 0xbe, b't', b'e', b's', b't', 0x00,
        ])
        .unwrap();

        let path_str = file_path.to_str().unwrap().replace("\\", "\\\\");

        let script = format!(
            r#"
            let f = open_binary("{}");
            let len = f.len();
            let val32 = f.read_u32_le(0);
            let val16 = f.read_u16_le(4);
            let s = f.read_string(6, 4);
            println(len.to_string());
            println(val32.to_string());
            println(val16.to_string());
            println(s);
        "#,
            path_str
        );

        let result = engine.eval(&script, &mut project).unwrap();
        assert_eq!(result.actions.len(), 4);

        if let ScriptAction::Print(msg) = &result.actions[0] {
            assert_eq!(msg, "11");
        } else {
            panic!("expected print");
        }
        if let ScriptAction::Print(msg) = &result.actions[1] {
            assert_eq!(msg, "305419896");
        } else {
            panic!("expected print");
        } // 0x12345678
        if let ScriptAction::Print(msg) = &result.actions[2] {
            assert_eq!(msg, "48879");
        } else {
            panic!("expected print");
        } // 0xbeef
        if let ScriptAction::Print(msg) = &result.actions[3] {
            assert_eq!(msg, "test");
        } else {
            panic!("expected print");
        }

        std::fs::remove_file(file_path).unwrap();
    }
}
