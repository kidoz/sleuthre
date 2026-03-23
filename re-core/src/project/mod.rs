use crate::Result;
use crate::analysis::constants::ConstantScanner;
use crate::analysis::functions::FunctionManager;
use crate::analysis::strings::StringsManager;
use crate::analysis::xrefs::XrefManager;
use crate::arch::Architecture;
use crate::db::Database;
use crate::loader::{BinaryFormat, Export, Import, Symbol};
use crate::memory::MemoryMap;
use crate::typelib::TypeLibraryManager;
use crate::types::TypeManager;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionKind {
    Rename {
        address: u64,
        new_name: String,
        old_name: String,
    },
    Comment {
        address: u64,
        new_comment: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: uuid::Uuid,
    pub kind: ActionKind,
    pub rationale: String,
    pub confidence: f32,
}

/// A reversible command for the undo/redo system.
#[derive(Debug, Clone)]
pub enum UndoCommand {
    Rename {
        address: u64,
        old_name: String,
        new_name: String,
    },
    Comment {
        address: u64,
        old_comment: Option<String>,
        new_comment: Option<String>,
    },
    AddBookmark {
        address: u64,
        note: String,
    },
    RemoveBookmark {
        address: u64,
        note: String,
    },
    PatchMemory {
        address: u64,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
    },
    AddTag {
        address: u64,
        tag: String,
    },
    RemoveTag {
        address: u64,
        tag: String,
    },
}

pub struct Project {
    pub name: String,
    pub path: PathBuf,
    pub memory_map: MemoryMap,
    pub functions: FunctionManager,
    pub xrefs: XrefManager,
    pub strings: StringsManager,
    pub constants: ConstantScanner,
    pub comments: HashMap<u64, String>,
    pub pending_actions: Vec<PendingAction>,
    pub db: Option<Database>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub symbols: Vec<Symbol>,
    pub libraries: Vec<String>,
    pub types: TypeManager,
    pub bookmarks: BTreeMap<u64, String>,
    pub tags: BTreeMap<u64, Vec<String>>,
    pub decompilation_cache: HashMap<u64, crate::il::hlil::DecompiledCode>,
    pub nav_history: Vec<u64>,
    pub nav_position: usize,
    pub undo_stack: Vec<UndoCommand>,
    pub redo_stack: Vec<UndoCommand>,
    pub type_libs: TypeLibraryManager,
    pub arch: Architecture,
    pub binary_format: BinaryFormat,
}

impl Project {
    pub fn new(name: String, path: PathBuf) -> Self {
        Self {
            name,
            path,
            memory_map: MemoryMap::default(),
            functions: FunctionManager::default(),
            xrefs: XrefManager::new(),
            strings: StringsManager::default(),
            constants: ConstantScanner::default(),
            comments: HashMap::new(),
            pending_actions: Vec::new(),
            db: None,
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            libraries: Vec::new(),
            types: TypeManager::default(),
            bookmarks: BTreeMap::new(),
            tags: BTreeMap::new(),
            decompilation_cache: HashMap::new(),
            nav_history: Vec::new(),
            nav_position: 0,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            type_libs: TypeLibraryManager::default(),
            arch: Architecture::X86_64,
            binary_format: BinaryFormat::Raw,
        }
    }

    /// Execute a command and push it onto the undo stack, clearing redo.
    pub fn execute(&mut self, cmd: UndoCommand) {
        self.apply_command(&cmd, false);
        self.undo_stack.push(cmd);
        self.redo_stack.clear();
    }

    /// Undo the most recent command. Returns a description for the output log.
    pub fn undo(&mut self) -> Option<String> {
        let cmd = self.undo_stack.pop()?;
        let desc = self.apply_command(&cmd, true);
        self.redo_stack.push(cmd);
        Some(desc)
    }

    /// Redo the most recently undone command.
    pub fn redo(&mut self) -> Option<String> {
        let cmd = self.redo_stack.pop()?;
        let desc = self.apply_command(&cmd, false);
        self.undo_stack.push(cmd);
        Some(desc)
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Apply a command forward (undo=false) or in reverse (undo=true).
    fn apply_command(&mut self, cmd: &UndoCommand, undo: bool) -> String {
        match cmd {
            UndoCommand::Rename {
                address,
                old_name,
                new_name,
            } => {
                let name = if undo { old_name } else { new_name };
                if let Some(f) = self.functions.functions.get_mut(address) {
                    f.name = name.clone();
                }
                self.decompilation_cache.remove(address);

                // Invalidate callers too, as they might inline the function name
                if let Some(xrefs) = self.xrefs.to_address_xrefs.get(address) {
                    for xref in xrefs {
                        if xref.xref_type == crate::analysis::xrefs::XrefType::Call {
                            // Find function containing the call site
                            if let Some((&caller_addr, _)) = self
                                .functions
                                .functions
                                .range(..=xref.from_address)
                                .next_back()
                            {
                                self.decompilation_cache.remove(&caller_addr);
                            }
                        }
                    }
                }

                if undo {
                    format!("Undo rename at {:08X}", address)
                } else {
                    format!("Renamed {:08X} → {}", address, new_name)
                }
            }
            UndoCommand::Comment {
                address,
                old_comment,
                new_comment,
            } => {
                let comment = if undo { old_comment } else { new_comment };
                match comment {
                    Some(c) => {
                        self.comments.insert(*address, c.clone());
                    }
                    None => {
                        self.comments.remove(address);
                    }
                }
                self.decompilation_cache.remove(address);
                if undo {
                    format!("Undo comment at {:08X}", address)
                } else {
                    format!("Comment at {:08X}", address)
                }
            }
            UndoCommand::AddBookmark { address, note } => {
                if undo {
                    self.bookmarks.remove(address);
                    format!("Undo bookmark at {:08X}", address)
                } else {
                    self.bookmarks.insert(*address, note.clone());
                    format!("Bookmarked {:08X}", address)
                }
            }
            UndoCommand::RemoveBookmark { address, note } => {
                if undo {
                    self.bookmarks.insert(*address, note.clone());
                    format!("Undo remove bookmark at {:08X}", address)
                } else {
                    self.bookmarks.remove(address);
                    format!("Removed bookmark at {:08X}", address)
                }
            }
            UndoCommand::PatchMemory {
                address,
                old_bytes,
                new_bytes,
            } => {
                let bytes = if undo { old_bytes } else { new_bytes };
                // Best-effort write; if the address is invalid the undo/redo is
                // a no-op (the project state is already inconsistent).
                let _ = self.memory_map.write_data(*address, bytes);

                // Invalidate decompilation cache for any functions that overlap with this patch
                let patch_end = *address + bytes.len() as u64;
                let mut to_remove = Vec::new();
                for (&f_addr, f) in self.functions.functions.range(..patch_end) {
                    let f_end = f.end_address.unwrap_or(f_addr + 0x1000);
                    if *address < f_end {
                        to_remove.push(f_addr);
                    }
                }
                for f_addr in to_remove {
                    self.decompilation_cache.remove(&f_addr);
                }

                if undo {
                    format!("Undo patch at {:08X} ({} bytes)", address, old_bytes.len())
                } else {
                    format!("Patched {:08X} ({} bytes)", address, new_bytes.len())
                }
            }
            UndoCommand::AddTag { address, tag } => {
                if undo {
                    if let Some(tags) = self.tags.get_mut(address) {
                        tags.retain(|t| t != tag);
                        if tags.is_empty() {
                            self.tags.remove(address);
                        }
                    }
                    format!("Undo tag '{}' at {:08X}", tag, address)
                } else {
                    self.tags.entry(*address).or_default().push(tag.clone());
                    format!("Tagged {:08X} '{}'", address, tag)
                }
            }
            UndoCommand::RemoveTag { address, tag } => {
                if undo {
                    self.tags.entry(*address).or_default().push(tag.clone());
                    format!("Undo remove tag '{}' at {:08X}", tag, address)
                } else {
                    if let Some(tags) = self.tags.get_mut(address) {
                        tags.retain(|t| t != tag);
                        if tags.is_empty() {
                            self.tags.remove(address);
                        }
                    }
                    format!("Removed tag '{}' at {:08X}", tag, address)
                }
            }
        }
    }

    /// Get all unique tags used across the project.
    pub fn all_tags(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        for tags in self.tags.values() {
            for t in tags {
                set.insert(t.clone());
            }
        }
        set.into_iter().collect()
    }

    pub fn navigate_to(&mut self, address: u64) {
        // Trim forward history when navigating to a new address
        if self.nav_position < self.nav_history.len() {
            self.nav_history.truncate(self.nav_position);
        }
        self.nav_history.push(address);
        self.nav_position = self.nav_history.len();
    }

    pub fn navigate_back(&mut self) -> Option<u64> {
        if self.nav_position > 1 {
            self.nav_position -= 1;
            Some(self.nav_history[self.nav_position - 1])
        } else {
            None
        }
    }

    pub fn navigate_forward(&mut self) -> Option<u64> {
        if self.nav_position < self.nav_history.len() {
            self.nav_position += 1;
            Some(self.nav_history[self.nav_position - 1])
        } else {
            None
        }
    }

    pub fn save(&mut self, db_path: &std::path::Path) -> Result<()> {
        // Always open the target path so "Save As" to a new file works correctly.
        let needs_new_db = match &self.db {
            None => true,
            Some(db) => db.path() != db_path,
        };
        if needs_new_db {
            self.db = Some(Database::open(db_path)?);
        }
        let db = self.db.as_ref().unwrap();

        // Clear all tables before re-inserting to prevent stale rows.
        db.clear_all()?;

        for seg in &self.memory_map.segments {
            db.save_segment(seg)?;
        }
        for func in self.functions.functions.values() {
            db.save_function(func)?;
        }
        for (&addr, text) in &self.comments {
            db.set_comment(addr, text)?;
        }

        // Persist xrefs
        for xrefs in self.xrefs.to_address_xrefs.values() {
            for xref in xrefs {
                db.save_xref(xref)?;
            }
        }

        // Persist strings
        for s in &self.strings.strings {
            db.save_string(s)?;
        }

        // Persist constants
        for c in &self.constants.constants {
            db.save_constant(c)?;
        }

        // Persist imports/exports/symbols
        for import in &self.imports {
            db.save_import(import)?;
        }
        for export in &self.exports {
            db.save_export(export)?;
        }
        for sym in &self.symbols {
            db.save_symbol(sym)?;
        }

        // Persist types
        for ty in self.types.types.values() {
            db.save_type(ty)?;
        }
        for ann in self.types.annotations.values() {
            db.save_type_annotation(ann)?;
        }

        // Persist bookmarks
        for (&addr, note) in &self.bookmarks {
            db.save_bookmark(addr, note)?;
        }

        // Persist tags
        for (&addr, tags) in &self.tags {
            for tag in tags {
                db.save_tag(addr, tag)?;
            }
        }

        // Persist function signatures
        for (&addr, sig) in &self.types.function_signatures {
            db.save_function_signature(addr, sig)?;
        }

        // Persist global variables
        for (&addr, var) in &self.types.global_variables {
            db.save_global_variable(addr, var)?;
        }

        // Persist local variables
        for (&addr, vars) in &self.types.local_variables {
            db.save_local_variables(addr, vars)?;
        }

        // Persist source lines
        for (&addr, info) in &self.types.source_lines {
            db.save_source_line(addr, info)?;
        }

        // Persist decompilation cache
        for (&addr, code) in &self.decompilation_cache {
            db.save_decompiled_code(addr, code)?;
        }

        Ok(())
    }

    pub fn load(db_path: &std::path::Path) -> Result<Self> {
        let db = Database::open(db_path)?;
        let mut project = Project::new(
            db_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            db_path.to_path_buf(),
        );

        project.memory_map.segments = db.load_segments()?;
        for func in db.load_functions()? {
            project.functions.add_function(func);
        }
        project.comments = db.load_comments()?;

        // Restore xrefs
        for xref in db.load_xrefs()? {
            project.xrefs.add_xref(xref);
        }

        // Restore strings
        project.strings.strings = db.load_strings()?;

        // Restore constants
        project.constants.constants = db.load_constants()?;

        // Restore imports/exports/symbols
        project.imports = db.load_imports()?;
        project.exports = db.load_exports()?;
        project.symbols = db.load_symbols()?;

        // Restore types
        for ty in db.load_types()? {
            project.types.add_type(ty);
        }
        for ann in db.load_type_annotations()? {
            project.types.annotate(ann);
        }

        // Restore bookmarks
        project.bookmarks = db.load_bookmarks()?;

        // Restore tags
        project.tags = db.load_tags()?;

        // Restore function signatures
        project.types.function_signatures = db.load_function_signatures()?;

        // Restore global variables
        project.types.global_variables = db.load_global_variables()?;

        // Restore local variables
        project.types.local_variables = db.load_local_variables()?;

        // Restore source lines
        project.types.source_lines = db.load_source_lines()?;

        // Restore decompilation cache
        project.decompilation_cache = db.load_decompilation_cache()?;

        project.db = Some(db);
        Ok(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::{CallingConvention, Function};

    fn test_project() -> Project {
        let mut p = Project::new("test".into(), PathBuf::from("/tmp/test"));
        p.functions.add_function(Function {
            start_address: 0x1000,
            end_address: Some(0x1100),
            name: "sub_1000".into(),
            calling_convention: CallingConvention::default(),
            stack_frame_size: 0,
        });
        p
    }

    #[test]
    fn undo_redo_rename() {
        let mut p = test_project();
        p.execute(UndoCommand::Rename {
            address: 0x1000,
            old_name: "sub_1000".into(),
            new_name: "main".into(),
        });
        assert_eq!(p.functions.functions[&0x1000].name, "main");
        assert!(p.can_undo());
        assert!(!p.can_redo());

        p.undo();
        assert_eq!(p.functions.functions[&0x1000].name, "sub_1000");
        assert!(!p.can_undo());
        assert!(p.can_redo());

        p.redo();
        assert_eq!(p.functions.functions[&0x1000].name, "main");
    }

    #[test]
    fn undo_redo_comment() {
        let mut p = test_project();
        p.execute(UndoCommand::Comment {
            address: 0x1000,
            old_comment: None,
            new_comment: Some("entry point".into()),
        });
        assert_eq!(p.comments[&0x1000], "entry point");

        p.undo();
        assert!(!p.comments.contains_key(&0x1000));

        p.redo();
        assert_eq!(p.comments[&0x1000], "entry point");
    }

    #[test]
    fn undo_redo_bookmark() {
        let mut p = test_project();
        p.execute(UndoCommand::AddBookmark {
            address: 0x1000,
            note: "interesting".into(),
        });
        assert_eq!(p.bookmarks[&0x1000], "interesting");

        p.undo();
        assert!(!p.bookmarks.contains_key(&0x1000));

        p.redo();
        assert_eq!(p.bookmarks[&0x1000], "interesting");
    }

    #[test]
    fn new_command_clears_redo_stack() {
        let mut p = test_project();
        p.execute(UndoCommand::Comment {
            address: 0x1000,
            old_comment: None,
            new_comment: Some("first".into()),
        });
        p.undo();
        assert!(p.can_redo());

        // New command should clear redo
        p.execute(UndoCommand::Comment {
            address: 0x1000,
            old_comment: None,
            new_comment: Some("second".into()),
        });
        assert!(!p.can_redo());
        assert_eq!(p.comments[&0x1000], "second");
    }

    #[test]
    fn undo_redo_tag() {
        let mut p = test_project();
        p.execute(UndoCommand::AddTag {
            address: 0x1000,
            tag: "crypto".into(),
        });
        assert_eq!(p.tags[&0x1000], vec!["crypto"]);

        p.execute(UndoCommand::AddTag {
            address: 0x1000,
            tag: "suspicious".into(),
        });
        assert_eq!(p.tags[&0x1000], vec!["crypto", "suspicious"]);

        p.undo();
        assert_eq!(p.tags[&0x1000], vec!["crypto"]);

        p.redo();
        assert_eq!(p.tags[&0x1000], vec!["crypto", "suspicious"]);

        p.execute(UndoCommand::RemoveTag {
            address: 0x1000,
            tag: "crypto".into(),
        });
        assert_eq!(p.tags[&0x1000], vec!["suspicious"]);

        p.undo();
        assert_eq!(p.tags[&0x1000], vec!["suspicious", "crypto"]);
    }

    #[test]
    fn all_tags_returns_unique_sorted() {
        let mut p = test_project();
        p.tags
            .insert(0x1000, vec!["crypto".into(), "network".into()]);
        p.tags.insert(0x2000, vec!["crypto".into(), "vuln".into()]);
        let tags = p.all_tags();
        assert_eq!(tags, vec!["crypto", "network", "vuln"]);
    }

    #[test]
    fn undo_empty_returns_none() {
        let mut p = test_project();
        assert!(p.undo().is_none());
        assert!(p.redo().is_none());
    }

    #[test]
    fn undo_redo_patch_memory() {
        use crate::memory::{MemorySegment, Permissions};

        let mut p = test_project();

        // Set up a memory segment with known data
        let seg = MemorySegment {
            name: "text".to_string(),
            start: 0x1000,
            size: 8,
            data: vec![0x90; 8],
            permissions: Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
        };
        p.memory_map.add_segment(seg).unwrap();

        // Execute a patch command
        p.execute(UndoCommand::PatchMemory {
            address: 0x1000,
            old_bytes: vec![0x90, 0x90],
            new_bytes: vec![0xCC, 0xCC],
        });

        // Memory should contain patched bytes
        assert_eq!(p.memory_map.get_data(0x1000, 2).unwrap(), &[0xCC, 0xCC]);
        assert!(p.can_undo());

        // Undo should restore original bytes
        let msg = p.undo().unwrap();
        assert!(msg.contains("Undo"));
        assert_eq!(p.memory_map.get_data(0x1000, 2).unwrap(), &[0x90, 0x90]);
        assert!(p.can_redo());

        // Redo should re-apply the patch
        let msg = p.redo().unwrap();
        assert!(msg.contains("Patched"));
        assert_eq!(p.memory_map.get_data(0x1000, 2).unwrap(), &[0xCC, 0xCC]);
    }
}
