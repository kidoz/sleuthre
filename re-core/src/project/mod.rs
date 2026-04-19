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
    /// Dependency graph for surgical decompile-cache invalidation.
    pub cache_deps: CacheDependencyGraph,
    pub nav_history: Vec<u64>,
    pub nav_position: usize,
    pub undo_stack: Vec<UndoCommand>,
    pub redo_stack: Vec<UndoCommand>,
    pub type_libs: TypeLibraryManager,
    pub arch: Architecture,
    pub binary_format: BinaryFormat,
    pub struct_overlays: Vec<StructOverlay>,
}

/// Tracks which functions a cached decompilation depends on so a single edit
/// invalidates exactly the affected entries.
///
/// Two relationships are tracked:
///   * `func_to_called` — function F called callee G; renaming G invalidates F.
///   * `func_to_types` — function F referenced type T; editing T invalidates F.
///
/// The reverse direction (`called_to_funcs`, `type_to_funcs`) is maintained in
/// parallel so invalidation lookups are O(1).
#[derive(Debug, Clone, Default)]
pub struct CacheDependencyGraph {
    func_to_called: HashMap<u64, std::collections::HashSet<u64>>,
    called_to_funcs: HashMap<u64, std::collections::HashSet<u64>>,
    func_to_types: HashMap<u64, std::collections::HashSet<String>>,
    type_to_funcs: HashMap<String, std::collections::HashSet<u64>>,
}

impl CacheDependencyGraph {
    /// Replace the dependency set for a function in one shot, keeping the
    /// reverse indexes consistent.
    pub fn set_dependencies(
        &mut self,
        func: u64,
        callees: std::collections::HashSet<u64>,
        types: std::collections::HashSet<String>,
    ) {
        // Remove old reverse edges first.
        if let Some(old_callees) = self.func_to_called.remove(&func) {
            for c in old_callees {
                if let Some(set) = self.called_to_funcs.get_mut(&c) {
                    set.remove(&func);
                }
            }
        }
        if let Some(old_types) = self.func_to_types.remove(&func) {
            for t in old_types {
                if let Some(set) = self.type_to_funcs.get_mut(&t) {
                    set.remove(&func);
                }
            }
        }
        // Insert new edges.
        for c in &callees {
            self.called_to_funcs.entry(*c).or_default().insert(func);
        }
        for t in &types {
            self.type_to_funcs
                .entry(t.clone())
                .or_default()
                .insert(func);
        }
        self.func_to_called.insert(func, callees);
        self.func_to_types.insert(func, types);
    }

    /// Drop everything tracked for this function (e.g. when its cache entry is
    /// evicted independently of an edit).
    pub fn forget(&mut self, func: u64) {
        if let Some(callees) = self.func_to_called.remove(&func) {
            for c in callees {
                if let Some(set) = self.called_to_funcs.get_mut(&c) {
                    set.remove(&func);
                }
            }
        }
        if let Some(types) = self.func_to_types.remove(&func) {
            for t in types {
                if let Some(set) = self.type_to_funcs.get_mut(&t) {
                    set.remove(&func);
                }
            }
        }
    }

    /// Functions that should be re-decompiled when `callee` is renamed or has
    /// its signature changed. Includes `callee` itself.
    pub fn dependents_of_function(&self, callee: u64) -> std::collections::HashSet<u64> {
        let mut out = self
            .called_to_funcs
            .get(&callee)
            .cloned()
            .unwrap_or_default();
        out.insert(callee);
        out
    }

    /// Functions that should be re-decompiled when type `name` is renamed,
    /// has fields edited, or is deleted.
    pub fn dependents_of_type(&self, name: &str) -> std::collections::HashSet<u64> {
        self.type_to_funcs.get(name).cloned().unwrap_or_default()
    }
}

/// A named struct/type applied to a memory address, optionally as an array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructOverlay {
    pub address: u64,
    pub type_name: String,
    pub count: usize,
    pub label: String,
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
            cache_deps: CacheDependencyGraph::default(),
            nav_history: Vec::new(),
            nav_position: 0,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            type_libs: TypeLibraryManager::default(),
            arch: Architecture::X86_64,
            binary_format: BinaryFormat::Raw,
            struct_overlays: Vec::new(),
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
                // Invalidate exactly the function and any cached entry that
                // recorded a dependency on it; the dep-graph is more precise
                // than the xref-walk fallback because it understands inlined
                // names that don't carry call xrefs (e.g. function-pointer
                // tables).
                let mut to_invalidate = self.cache_deps.dependents_of_function(*address);
                if let Some(xrefs) = self.xrefs.to_address_xrefs.get(address) {
                    for xref in xrefs {
                        if xref.xref_type == crate::analysis::xrefs::XrefType::Call
                            && let Some((&caller_addr, _)) = self
                                .functions
                                .functions
                                .range(..=xref.from_address)
                                .next_back()
                        {
                            to_invalidate.insert(caller_addr);
                        }
                    }
                }
                for addr in to_invalidate {
                    self.decompilation_cache.remove(&addr);
                    self.cache_deps.forget(addr);
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

        // Update project path so auto-save targets the same file.
        self.path = db_path.with_extension("").to_path_buf();

        let db = self.db.as_ref().unwrap();

        // Wrap the entire clear + reinsert in a transaction so a mid-save
        // error leaves the previous data intact instead of an empty database.
        db.begin_transaction()?;

        let result = (|| -> Result<()> {
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

            // Persist struct overlays
            for overlay in &self.struct_overlays {
                db.save_struct_overlay(overlay)?;
            }

            Ok(())
        })();

        match result {
            Ok(()) => db.commit_transaction(),
            Err(e) => {
                let _ = db.rollback_transaction();
                Err(e)
            }
        }
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

        // Restore struct overlays
        project.struct_overlays = db.load_struct_overlays()?;

        project.db = Some(db);
        Ok(project)
    }

    /// Export the project's analyst-authored state as deterministic JSON Lines
    /// so that changes can be diffed and merged via git.
    ///
    /// Each line is an independent JSON document tagged with a `kind`. Lines
    /// are emitted in a stable order (addresses ascending, names alphabetical)
    /// so that semantically identical projects produce byte-identical output.
    /// Only human-editable data is exported — reproducible analysis artifacts
    /// (functions, xrefs, strings) are intentionally omitted so the export
    /// stays small and focused on user intent.
    pub fn export_jsonl(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        // 1. Metadata header (stable first line).
        let meta = serde_json::json!({
            "kind": "meta",
            "name": self.name,
            "arch": self.arch.display_name(),
            "format": format!("{:?}", self.binary_format),
            "version": 1,
        });
        let _ = writeln!(out, "{}", meta);

        // 2. Comments, ordered by address.
        let mut comments: Vec<_> = self.comments.iter().collect();
        comments.sort_by_key(|(a, _)| **a);
        for (&address, text) in comments {
            let rec = serde_json::json!({
                "kind": "comment",
                "address": format!("0x{:x}", address),
                "text": text,
            });
            let _ = writeln!(out, "{}", rec);
        }

        // 3. Function renames (only those diverging from auto-generated names).
        let mut funcs: Vec<_> = self.functions.functions.values().collect();
        funcs.sort_by_key(|f| f.start_address);
        for func in funcs {
            let auto = format!("sub_{:x}", func.start_address);
            if func.name != auto {
                let rec = serde_json::json!({
                    "kind": "rename",
                    "address": format!("0x{:x}", func.start_address),
                    "name": func.name,
                });
                let _ = writeln!(out, "{}", rec);
            }
        }

        // 4. Bookmarks.
        for (&address, note) in self.bookmarks.iter() {
            let rec = serde_json::json!({
                "kind": "bookmark",
                "address": format!("0x{:x}", address),
                "note": note,
            });
            let _ = writeln!(out, "{}", rec);
        }

        // 5. Tags.
        for (&address, tags) in self.tags.iter() {
            let mut sorted = tags.clone();
            sorted.sort();
            for tag in sorted {
                let rec = serde_json::json!({
                    "kind": "tag",
                    "address": format!("0x{:x}", address),
                    "tag": tag,
                });
                let _ = writeln!(out, "{}", rec);
            }
        }

        // 6. Struct overlays.
        let mut overlays = self.struct_overlays.clone();
        overlays.sort_by(|a, b| a.address.cmp(&b.address).then(a.label.cmp(&b.label)));
        for overlay in &overlays {
            let rec = serde_json::json!({
                "kind": "overlay",
                "address": format!("0x{:x}", overlay.address),
                "type_name": overlay.type_name,
                "count": overlay.count,
                "label": overlay.label,
            });
            let _ = writeln!(out, "{}", rec);
        }

        // 7. User-defined types, alphabetical.
        let mut type_names: Vec<&String> = self.types.types.keys().collect();
        type_names.sort();
        for name in type_names {
            if let Some(ty) = self.types.types.get(name) {
                let rec = serde_json::json!({
                    "kind": "type",
                    "name": name,
                    "definition": ty,
                });
                let _ = writeln!(out, "{}", rec);
            }
        }

        out
    }

    /// Import analyst-authored state from the JSON Lines format produced by
    /// [`export_jsonl`]. Unknown `kind` values are silently skipped so the
    /// format can grow forward-compatibly.
    pub fn import_jsonl(&mut self, content: &str) -> Result<ImportStats> {
        let mut stats = ImportStats::default();
        for (line_no, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let record: serde_json::Value = serde_json::from_str(line).map_err(|e| {
                crate::Error::Database(format!("jsonl line {}: {}", line_no + 1, e))
            })?;
            let kind = record.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let parse_addr = |value: Option<&serde_json::Value>| {
                value.and_then(|v| v.as_str()).and_then(|s| {
                    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(rest, 16).ok()
                    } else {
                        s.parse().ok()
                    }
                })
            };
            match kind {
                "meta" => {}
                "comment" => {
                    if let (Some(address), Some(text)) = (
                        parse_addr(record.get("address")),
                        record.get("text").and_then(|v| v.as_str()),
                    ) {
                        self.comments.insert(address, text.to_string());
                        stats.comments += 1;
                    }
                }
                "rename" => {
                    if let (Some(address), Some(name)) = (
                        parse_addr(record.get("address")),
                        record.get("name").and_then(|v| v.as_str()),
                    ) && let Some(func) = self.functions.functions.get_mut(&address)
                    {
                        func.name = name.to_string();
                        stats.renames += 1;
                    }
                }
                "bookmark" => {
                    if let (Some(address), Some(note)) = (
                        parse_addr(record.get("address")),
                        record.get("note").and_then(|v| v.as_str()),
                    ) {
                        self.bookmarks.insert(address, note.to_string());
                        stats.bookmarks += 1;
                    }
                }
                "tag" => {
                    if let (Some(address), Some(tag)) = (
                        parse_addr(record.get("address")),
                        record.get("tag").and_then(|v| v.as_str()),
                    ) {
                        self.tags.entry(address).or_default().push(tag.to_string());
                        stats.tags += 1;
                    }
                }
                "overlay" => {
                    if let (Some(address), Some(type_name), Some(count), Some(label)) = (
                        parse_addr(record.get("address")),
                        record.get("type_name").and_then(|v| v.as_str()),
                        record.get("count").and_then(|v| v.as_u64()),
                        record.get("label").and_then(|v| v.as_str()),
                    ) {
                        self.struct_overlays.push(StructOverlay {
                            address,
                            type_name: type_name.to_string(),
                            count: count as usize,
                            label: label.to_string(),
                        });
                        stats.overlays += 1;
                    }
                }
                "type" => {
                    if let Some(def) = record.get("definition")
                        && let Ok(ty) =
                            serde_json::from_value::<crate::types::CompoundType>(def.clone())
                    {
                        self.types.add_type(ty);
                        stats.types += 1;
                    }
                }
                _ => {}
            }
        }
        Ok(stats)
    }
}

/// Summary of an [`import_jsonl`] run. Useful for surfacing progress in UI.
#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    pub comments: usize,
    pub renames: usize,
    pub bookmarks: usize,
    pub tags: usize,
    pub overlays: usize,
    pub types: usize,
}

/// Outcome of a 3-way JSONL merge.
#[derive(Debug, Clone, Default)]
pub struct MergeResult {
    /// Merged JSONL output (deterministic ordering, ready to `import_jsonl`).
    pub merged: String,
    /// Number of records where both sides changed the same key in different
    /// ways. The merged output contains `kind: "conflict"` records describing
    /// each collision; the caller is expected to resolve them.
    pub conflict_count: usize,
    /// Records taken from `left` that `right` did not modify.
    pub left_adds: usize,
    /// Records taken from `right` that `left` did not modify.
    pub right_adds: usize,
    /// Records that both sides agreed to change in the same way.
    pub shared_changes: usize,
}

/// 3-way merge of three JSONL project exports — `base` is the common ancestor,
/// `left` and `right` are the divergent branches.
///
/// Each record is keyed by a tuple `(kind, primary_id)`; two edits to the
/// same key on opposite sides are a conflict unless the values match, in which
/// case the change is taken once.
///
/// Conflicts are not silently dropped: the merged stream includes a line like
/// `{ "kind": "conflict", "key": ..., "left": ..., "right": ... }` so the
/// downstream tooling (GUI, CLI) can surface them. Importers ignore `conflict`
/// kinds, matching the "ignore unknown kind" policy documented on
/// [`Project::import_jsonl`].
pub fn merge_jsonl_3way(base: &str, left: &str, right: &str) -> Result<MergeResult> {
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn load(content: &str) -> Result<BTreeMap<(String, String), Value>> {
        let mut map = BTreeMap::new();
        for (line_no, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let record: Value = serde_json::from_str(line).map_err(|e| {
                crate::Error::Database(format!("merge jsonl line {}: {}", line_no + 1, e))
            })?;
            let kind = record
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if kind == "meta" {
                // Meta lines are not merged — they describe the source, not
                // user edits.
                continue;
            }
            // Composite key chosen per kind so two sides editing the same
            // address produce the same key.
            let id = match kind.as_str() {
                "comment" | "rename" | "bookmark" | "overlay" => record
                    .get("address")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        if kind == "overlay" {
                            format!(
                                "{}::{}",
                                s,
                                record.get("label").and_then(|v| v.as_str()).unwrap_or("")
                            )
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_default(),
                "tag" => format!(
                    "{}::{}",
                    record.get("address").and_then(|v| v.as_str()).unwrap_or(""),
                    record.get("tag").and_then(|v| v.as_str()).unwrap_or("")
                ),
                "type" => record
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                _ => continue,
            };
            if !id.is_empty() {
                map.insert((kind, id), record);
            }
        }
        Ok(map)
    }

    let base_map = load(base)?;
    let left_map = load(left)?;
    let right_map = load(right)?;

    let mut stats = MergeResult::default();
    let mut out_records: Vec<(String, Value)> = Vec::new();

    let mut all_keys = std::collections::BTreeSet::new();
    all_keys.extend(base_map.keys().cloned());
    all_keys.extend(left_map.keys().cloned());
    all_keys.extend(right_map.keys().cloned());

    for key in all_keys {
        let b = base_map.get(&key);
        let l = left_map.get(&key);
        let r = right_map.get(&key);
        match (b, l, r) {
            (_, Some(lv), Some(rv)) if lv == rv => {
                // Count as a shared change if both sides modified an existing
                // record or both added a new one identically.
                match b {
                    Some(bv) if bv != lv => stats.shared_changes += 1,
                    None => stats.shared_changes += 1,
                    _ => {}
                }
                out_records.push((format!("{}::{}", key.0, key.1), lv.clone()));
            }
            (Some(bv), Some(lv), Some(rv)) => {
                if lv == bv {
                    out_records.push((format!("{}::{}", key.0, key.1), rv.clone()));
                    stats.right_adds += 1;
                } else if rv == bv {
                    out_records.push((format!("{}::{}", key.0, key.1), lv.clone()));
                    stats.left_adds += 1;
                } else {
                    // Both sides changed — real conflict.
                    let conflict = serde_json::json!({
                        "kind": "conflict",
                        "key": format!("{}::{}", key.0, key.1),
                        "base": bv,
                        "left": lv,
                        "right": rv,
                    });
                    out_records.push((format!("conflict::{}::{}", key.0, key.1), conflict));
                    stats.conflict_count += 1;
                }
            }
            (None, Some(lv), None) => {
                out_records.push((format!("{}::{}", key.0, key.1), lv.clone()));
                stats.left_adds += 1;
            }
            (None, None, Some(rv)) => {
                out_records.push((format!("{}::{}", key.0, key.1), rv.clone()));
                stats.right_adds += 1;
            }
            (Some(bv), Some(lv), None) => {
                if lv == bv {
                    // Right deleted, left unchanged → accept the delete.
                } else {
                    // Left modified, right deleted — conflict.
                    let conflict = serde_json::json!({
                        "kind": "conflict",
                        "key": format!("{}::{}", key.0, key.1),
                        "base": bv,
                        "left": lv,
                        "right": Value::Null,
                    });
                    out_records.push((format!("conflict::{}::{}", key.0, key.1), conflict));
                    stats.conflict_count += 1;
                }
            }
            (Some(bv), None, Some(rv)) => {
                if rv == bv {
                    // Left deleted, right unchanged → accept the delete.
                } else {
                    let conflict = serde_json::json!({
                        "kind": "conflict",
                        "key": format!("{}::{}", key.0, key.1),
                        "base": bv,
                        "left": Value::Null,
                        "right": rv,
                    });
                    out_records.push((format!("conflict::{}::{}", key.0, key.1), conflict));
                    stats.conflict_count += 1;
                }
            }
            (Some(_), None, None) => {
                // Both sides deleted.
            }
            (None, Some(lv), Some(rv)) => {
                // Both sides added the same key with different values — this is
                // an independent-addition conflict.
                let conflict = serde_json::json!({
                    "kind": "conflict",
                    "key": format!("{}::{}", key.0, key.1),
                    "base": Value::Null,
                    "left": lv,
                    "right": rv,
                });
                out_records.push((format!("conflict::{}::{}", key.0, key.1), conflict));
                stats.conflict_count += 1;
            }
            (None, None, None) => {}
        }
    }

    // Deterministic output ordering.
    out_records.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged = String::new();
    for (_, record) in out_records {
        merged.push_str(&record.to_string());
        merged.push('\n');
    }
    stats.merged = merged;
    Ok(stats)
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
    fn jsonl_merge_detects_and_resolves_changes() {
        // Base has a single comment; left renames a function; right adds a bookmark.
        // No conflict — the merge should pick up both divergent edits.
        let base = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"entry\"}\n";
        let left = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"entry\"}\n\
{\"kind\":\"rename\",\"address\":\"0x1000\",\"name\":\"main\"}\n";
        let right = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"entry\"}\n\
{\"kind\":\"bookmark\",\"address\":\"0x1020\",\"note\":\"check\"}\n";
        let result = merge_jsonl_3way(base, left, right).unwrap();
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.left_adds, 1);
        assert_eq!(result.right_adds, 1);
        assert!(result.merged.contains("\"name\":\"main\""));
        assert!(result.merged.contains("\"note\":\"check\""));
    }

    #[test]
    fn jsonl_merge_emits_conflict_on_divergent_edit() {
        let base = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"orig\"}\n";
        let left = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"from left\"}\n";
        let right = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"from right\"}\n";
        let result = merge_jsonl_3way(base, left, right).unwrap();
        assert_eq!(result.conflict_count, 1);
        assert!(result.merged.contains("\"kind\":\"conflict\""));
        assert!(result.merged.contains("from left"));
        assert!(result.merged.contains("from right"));
    }

    #[test]
    fn cache_dep_graph_invalidates_dependents() {
        let mut g = CacheDependencyGraph::default();
        // Function 0x1000 calls 0x2000 and references type Player.
        g.set_dependencies(
            0x1000,
            std::collections::HashSet::from([0x2000]),
            std::collections::HashSet::from(["Player".to_string()]),
        );
        // Function 0x1100 calls 0x2000 too.
        g.set_dependencies(
            0x1100,
            std::collections::HashSet::from([0x2000]),
            std::collections::HashSet::new(),
        );

        // Renaming 0x2000 should invalidate 0x1000, 0x1100, and 0x2000 itself.
        let dep = g.dependents_of_function(0x2000);
        assert!(dep.contains(&0x1000));
        assert!(dep.contains(&0x1100));
        assert!(dep.contains(&0x2000));

        // Editing Player should invalidate only 0x1000.
        let dep = g.dependents_of_type("Player");
        assert_eq!(dep.len(), 1);
        assert!(dep.contains(&0x1000));

        // After forgetting 0x1000 the type-side index is empty.
        g.forget(0x1000);
        assert!(g.dependents_of_type("Player").is_empty());
    }

    #[test]
    fn jsonl_merge_accepts_shared_change() {
        let base = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"orig\"}\n";
        let same = "\
{\"kind\":\"comment\",\"address\":\"0x1000\",\"text\":\"renamed\"}\n";
        let result = merge_jsonl_3way(base, same, same).unwrap();
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.shared_changes, 1);
        assert!(result.merged.contains("\"text\":\"renamed\""));
    }

    #[test]
    fn jsonl_export_import_roundtrip() {
        let mut src = test_project();
        src.comments.insert(0x1000, "entry point".into());
        src.bookmarks.insert(0x1020, "check me".into());
        src.tags.insert(0x1000, vec!["hot".into(), "crypto".into()]);
        src.struct_overlays.push(StructOverlay {
            address: 0x2000,
            type_name: "Player".into(),
            count: 4,
            label: "player_table".into(),
        });
        src.execute(UndoCommand::Rename {
            address: 0x1000,
            old_name: "sub_1000".into(),
            new_name: "main".into(),
        });
        let jsonl = src.export_jsonl();

        // Deterministic ordering: exporting the same project twice yields
        // byte-identical output.
        assert_eq!(jsonl, src.export_jsonl());

        // Reimport into a fresh project and verify every field round-trips.
        let mut dest = test_project();
        let stats = dest.import_jsonl(&jsonl).unwrap();
        assert_eq!(stats.comments, 1);
        assert_eq!(stats.renames, 1);
        assert_eq!(stats.bookmarks, 1);
        assert_eq!(stats.tags, 2);
        assert_eq!(stats.overlays, 1);

        assert_eq!(dest.comments.get(&0x1000), Some(&"entry point".to_string()));
        assert_eq!(dest.bookmarks.get(&0x1020), Some(&"check me".to_string()));
        assert_eq!(dest.functions.functions[&0x1000].name, "main");
        assert_eq!(dest.struct_overlays.len(), 1);
        assert_eq!(dest.struct_overlays[0].label, "player_table");
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
