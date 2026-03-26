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
                Ok(BinaryFile { data: Rc::new(data) })
            },
        );
        engine.register_fn("read_u32_le", BinaryFile::read_u32_le);
        engine.register_fn("read_u16_le", BinaryFile::read_u16_le);
        engine.register_fn("read_string", BinaryFile::read_string);
        engine.register_fn("len", BinaryFile::len);

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
        file.write_all(&[0x78, 0x56, 0x34, 0x12, 0xef, 0xbe, b't', b'e', b's', b't', 0x00]).unwrap();
        
        let path_str = file_path.to_str().unwrap().replace("\\", "\\\\");
        
        let script = format!(r#"
            let f = open_binary("{}");
            let len = f.len();
            let val32 = f.read_u32_le(0);
            let val16 = f.read_u16_le(4);
            let s = f.read_string(6, 4);
            println(len.to_string());
            println(val32.to_string());
            println(val16.to_string());
            println(s);
        "#, path_str);
        
        let result = engine.eval(&script, &mut project).unwrap();
        assert_eq!(result.actions.len(), 4);
        
        if let ScriptAction::Print(msg) = &result.actions[0] { assert_eq!(msg, "11"); } else { panic!("expected print"); }
        if let ScriptAction::Print(msg) = &result.actions[1] { assert_eq!(msg, "305419896"); } else { panic!("expected print"); } // 0x12345678
        if let ScriptAction::Print(msg) = &result.actions[2] { assert_eq!(msg, "48879"); } else { panic!("expected print"); } // 0xbeef
        if let ScriptAction::Print(msg) = &result.actions[3] { assert_eq!(msg, "test"); } else { panic!("expected print"); }
        
        std::fs::remove_file(file_path).unwrap();
    }
}
