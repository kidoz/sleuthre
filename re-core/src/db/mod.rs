use crate::Result;
use crate::analysis::constants::DiscoveredConstant;
use crate::analysis::functions::{CallingConvention, Function};
use crate::analysis::strings::{DiscoveredString, StringEncoding};
use crate::analysis::xrefs::{Xref, XrefType};
use crate::error::Error;
use crate::loader::{Export, Import, Symbol, SymbolKind};
use crate::memory::{MemorySegment, Permissions};
use crate::types::{
    CompoundType, FunctionSignature, SourceLineInfo, TypeAnnotation, TypeRef, VariableInfo,
};
use rusqlite::{Connection, params};
use std::path::Path;

pub struct Database {
    conn: Connection,
    db_path: std::path::PathBuf,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let db = Self {
            conn,
            db_path: path.to_path_buf(),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Return the filesystem path this database was opened from.
    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "BEGIN;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS segments (
                name TEXT,
                start INTEGER PRIMARY KEY,
                size INTEGER,
                data BLOB,
                permissions INTEGER
            );
            CREATE TABLE IF NOT EXISTS functions (
                start_address INTEGER PRIMARY KEY,
                name TEXT,
                end_address INTEGER
            );
            CREATE TABLE IF NOT EXISTS comments (
                address INTEGER PRIMARY KEY,
                text TEXT
            );
            CREATE TABLE IF NOT EXISTS xrefs (
                from_address INTEGER,
                to_address INTEGER,
                xref_type TEXT,
                PRIMARY KEY (from_address, to_address, xref_type)
            );
            CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_address);
            CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_address);
            CREATE TABLE IF NOT EXISTS strings (
                address INTEGER PRIMARY KEY,
                value TEXT,
                length INTEGER,
                section_name TEXT,
                encoding TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_strings_address ON strings(address);
            CREATE TABLE IF NOT EXISTS constants (
                address INTEGER PRIMARY KEY,
                value_hex TEXT,
                description TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_constants_address ON constants(address);
            CREATE TABLE IF NOT EXISTS imports (
                name TEXT,
                library TEXT,
                address INTEGER,
                PRIMARY KEY (name, library, address)
            );
            CREATE TABLE IF NOT EXISTS exports (
                name TEXT,
                address INTEGER PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS symbols (
                name TEXT,
                address INTEGER PRIMARY KEY,
                size INTEGER,
                kind TEXT
            );
            CREATE TABLE IF NOT EXISTS user_types (
                name TEXT PRIMARY KEY,
                kind TEXT,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS type_annotations (
                address INTEGER PRIMARY KEY,
                type_ref TEXT,
                name TEXT
            );
            CREATE TABLE IF NOT EXISTS bookmarks (
                address INTEGER PRIMARY KEY,
                note TEXT
            );
            CREATE TABLE IF NOT EXISTS function_signatures (
                address INTEGER PRIMARY KEY,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS global_variables (
                address INTEGER PRIMARY KEY,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS local_variables (
                function_address INTEGER PRIMARY KEY,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS source_lines (
                address INTEGER PRIMARY KEY,
                file TEXT,
                line INTEGER,
                column INTEGER
            );
            CREATE TABLE IF NOT EXISTS decompilation_cache (
                address INTEGER PRIMARY KEY,
                data TEXT
            );
            COMMIT;",
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn save_segment(&self, seg: &MemorySegment) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO segments (name, start, size, data, permissions) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seg.name, seg.start, seg.size, seg.data, seg.permissions.bits()],
        ).map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_segments(&self) -> Result<Vec<MemorySegment>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, start, size, data, permissions FROM segments")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let bits: u8 = row.get(4)?;
                Ok(MemorySegment {
                    name: row.get(0)?,
                    start: row.get(1)?,
                    size: row.get(2)?,
                    data: row.get(3)?,
                    permissions: Permissions::from_bits_truncate(bits),
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut segments = Vec::new();
        for row in rows {
            segments.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(segments)
    }

    pub fn set_comment(&self, address: u64, text: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO comments (address, text) VALUES (?1, ?2)",
                params![address, text],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_comments(&self) -> Result<std::collections::HashMap<u64, String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, text FROM comments")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut comments = std::collections::HashMap::new();
        for row in rows {
            let (addr, text) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            comments.insert(addr, text);
        }
        Ok(comments)
    }

    pub fn save_function(&self, func: &Function) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO functions (start_address, name, end_address) VALUES (?1, ?2, ?3)
                 ON CONFLICT(start_address) DO UPDATE SET name = excluded.name, end_address = excluded.end_address",
                params![func.start_address, func.name, func.end_address],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn set_name(&self, address: u64, name: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO functions (start_address, name) VALUES (?1, ?2)
             ON CONFLICT(start_address) DO UPDATE SET name = excluded.name",
                params![address, name],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_functions(&self) -> Result<Vec<Function>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, start_address, end_address FROM functions")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Function {
                    name: row.get(0)?,
                    start_address: row.get(1)?,
                    end_address: row.get(2)?,
                    calling_convention: CallingConvention::default(),
                    stack_frame_size: 0,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut functions = Vec::new();
        for row in rows {
            functions.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(functions)
    }

    pub fn save_xref(&self, xref: &Xref) -> Result<()> {
        let type_str = match xref.xref_type {
            XrefType::Call => "Call",
            XrefType::Jump => "Jump",
            XrefType::DataRead => "DataRead",
            XrefType::DataWrite => "DataWrite",
            XrefType::StringRef => "StringRef",
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO xrefs (from_address, to_address, xref_type) VALUES (?1, ?2, ?3)",
                params![xref.from_address, xref.to_address, type_str],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_xrefs(&self) -> Result<Vec<Xref>> {
        let mut stmt = self
            .conn
            .prepare("SELECT from_address, to_address, xref_type FROM xrefs")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let type_str: String = row.get(2)?;
                let xref_type = match type_str.as_str() {
                    "Call" => XrefType::Call,
                    "Jump" => XrefType::Jump,
                    "DataRead" => XrefType::DataRead,
                    "DataWrite" => XrefType::DataWrite,
                    "StringRef" => XrefType::StringRef,
                    _ => XrefType::Call,
                };
                Ok(Xref {
                    from_address: row.get(0)?,
                    to_address: row.get(1)?,
                    xref_type,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut xrefs = Vec::new();
        for row in rows {
            xrefs.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(xrefs)
    }

    pub fn save_string(&self, s: &DiscoveredString) -> Result<()> {
        let enc = match s.encoding {
            StringEncoding::Ascii => "Ascii",
            StringEncoding::Utf16Le => "Utf16Le",
            StringEncoding::Utf16Be => "Utf16Be",
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO strings (address, value, length, section_name, encoding) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![s.address, s.value, s.length, s.section_name, enc],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn clear_strings(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM strings", [])
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    /// Delete all rows from every data table. Call before a full re-save to
    /// prevent stale rows from accumulating.
    pub fn clear_all(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "DELETE FROM segments;
                 DELETE FROM functions;
                 DELETE FROM comments;
                 DELETE FROM xrefs;
                 DELETE FROM strings;
                 DELETE FROM constants;
                 DELETE FROM imports;
                 DELETE FROM exports;
                 DELETE FROM symbols;
                 DELETE FROM user_types;
                 DELETE FROM type_annotations;
                 DELETE FROM bookmarks;
                 DELETE FROM function_signatures;
                 DELETE FROM global_variables;
                 DELETE FROM local_variables;
                 DELETE FROM source_lines;
                 DELETE FROM decompilation_cache;",
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_strings(&self) -> Result<Vec<DiscoveredString>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, value, length, section_name, encoding FROM strings")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let enc_str: String = row.get(4)?;
                let encoding = match enc_str.as_str() {
                    "Utf16Le" => StringEncoding::Utf16Le,
                    "Utf16Be" => StringEncoding::Utf16Be,
                    _ => StringEncoding::Ascii,
                };
                Ok(DiscoveredString {
                    address: row.get(0)?,
                    value: row.get(1)?,
                    length: row.get(2)?,
                    section_name: row.get(3)?,
                    encoding,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut strings = Vec::new();
        for row in rows {
            strings.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(strings)
    }

    pub fn save_constant(&self, c: &DiscoveredConstant) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO constants (address, value_hex, description) VALUES (?1, ?2, ?3)",
                params![c.address, c.value_hex, c.description],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_constants(&self) -> Result<Vec<DiscoveredConstant>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, value_hex, description FROM constants")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DiscoveredConstant {
                    address: row.get(0)?,
                    value_hex: row.get(1)?,
                    description: row.get(2)?,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut constants = Vec::new();
        for row in rows {
            constants.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(constants)
    }

    // --- Import/Export/Symbol persistence ---

    pub fn save_import(&self, import: &Import) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO imports (name, library, address) VALUES (?1, ?2, ?3)",
                params![import.name, import.library, import.address],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_imports(&self) -> Result<Vec<Import>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, library, address FROM imports")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Import {
                    name: row.get(0)?,
                    library: row.get(1)?,
                    address: row.get(2)?,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut imports = Vec::new();
        for row in rows {
            imports.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(imports)
    }

    pub fn save_export(&self, export: &Export) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO exports (name, address) VALUES (?1, ?2)",
                params![export.name, export.address],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_exports(&self) -> Result<Vec<Export>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, address FROM exports")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Export {
                    name: row.get(0)?,
                    address: row.get(1)?,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut exports = Vec::new();
        for row in rows {
            exports.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(exports)
    }

    pub fn save_symbol(&self, sym: &Symbol) -> Result<()> {
        let kind_str = match sym.kind {
            SymbolKind::Function => "Function",
            SymbolKind::Object => "Object",
            SymbolKind::Other => "Other",
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO symbols (name, address, size, kind) VALUES (?1, ?2, ?3, ?4)",
                params![sym.name, sym.address, sym.size, kind_str],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    // --- Type persistence ---

    pub fn save_type(&self, ty: &CompoundType) -> Result<()> {
        let data =
            serde_json::to_string(ty).map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO user_types (name, kind, data) VALUES (?1, ?2, ?3)",
                params![ty.name(), ty.kind_name(), data],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_types(&self) -> Result<Vec<CompoundType>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM user_types")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut types = Vec::new();
        for row in rows {
            let data = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(ty) = serde_json::from_str::<CompoundType>(&data) {
                types.push(ty);
            }
        }
        Ok(types)
    }

    pub fn save_type_annotation(&self, ann: &TypeAnnotation) -> Result<()> {
        let type_ref_json = serde_json::to_string(&ann.type_ref)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO type_annotations (address, type_ref, name) VALUES (?1, ?2, ?3)",
                params![ann.address, type_ref_json, ann.name],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_type_annotations(&self) -> Result<Vec<TypeAnnotation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, type_ref, name FROM type_annotations")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let address: u64 = row.get(0)?;
                let type_ref_json: String = row.get(1)?;
                let name: String = row.get(2)?;
                Ok((address, type_ref_json, name))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut annotations = Vec::new();
        for row in rows {
            let (address, type_ref_json, name) =
                row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(type_ref) = serde_json::from_str::<TypeRef>(&type_ref_json) {
                annotations.push(TypeAnnotation {
                    address,
                    type_ref,
                    name,
                });
            }
        }
        Ok(annotations)
    }

    // --- Bookmark persistence ---

    pub fn save_bookmark(&self, address: u64, note: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO bookmarks (address, note) VALUES (?1, ?2)",
                params![address, note],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn delete_bookmark(&self, address: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM bookmarks WHERE address = ?1", params![address])
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_bookmarks(&self) -> Result<std::collections::BTreeMap<u64, String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, note FROM bookmarks")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut bookmarks = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, note) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            bookmarks.insert(addr, note);
        }
        Ok(bookmarks)
    }

    // --- Function signature persistence ---

    pub fn save_function_signature(&self, address: u64, sig: &FunctionSignature) -> Result<()> {
        let data = serde_json::to_string(sig)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO function_signatures (address, data) VALUES (?1, ?2)",
                params![address, data],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_function_signatures(
        &self,
    ) -> Result<std::collections::BTreeMap<u64, FunctionSignature>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, data FROM function_signatures")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, data) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(sig) = serde_json::from_str::<FunctionSignature>(&data) {
                result.insert(addr, sig);
            }
        }
        Ok(result)
    }

    // --- Global variable persistence ---

    pub fn save_global_variable(&self, address: u64, var: &VariableInfo) -> Result<()> {
        let data = serde_json::to_string(var)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO global_variables (address, data) VALUES (?1, ?2)",
                params![address, data],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_global_variables(&self) -> Result<std::collections::BTreeMap<u64, VariableInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, data FROM global_variables")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, data) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(var) = serde_json::from_str::<VariableInfo>(&data) {
                result.insert(addr, var);
            }
        }
        Ok(result)
    }

    // --- Local variable persistence ---

    pub fn save_local_variables(&self, function_address: u64, vars: &[VariableInfo]) -> Result<()> {
        let data = serde_json::to_string(vars)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO local_variables (function_address, data) VALUES (?1, ?2)",
                params![function_address, data],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_local_variables(
        &self,
    ) -> Result<std::collections::BTreeMap<u64, Vec<VariableInfo>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT function_address, data FROM local_variables")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, data) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(vars) = serde_json::from_str::<Vec<VariableInfo>>(&data) {
                result.insert(addr, vars);
            }
        }
        Ok(result)
    }

    // --- Source line persistence ---

    pub fn save_source_line(&self, address: u64, info: &SourceLineInfo) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO source_lines (address, file, line, column) VALUES (?1, ?2, ?3, ?4)",
                params![
                    address,
                    info.file,
                    info.line,
                    info.column.map(|c| c as i64)
                ],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_source_lines(&self) -> Result<std::collections::BTreeMap<u64, SourceLineInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, file, line, column FROM source_lines")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let col: Option<i64> = row.get(3)?;
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    col.map(|c| c as u32),
                ))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, file, line, column) =
                row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            result.insert(addr, SourceLineInfo { file, line, column });
        }
        Ok(result)
    }

    pub fn load_symbols(&self) -> Result<Vec<Symbol>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, address, size, kind FROM symbols")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let kind_str: String = row.get(3)?;
                let kind = match kind_str.as_str() {
                    "Function" => SymbolKind::Function,
                    "Object" => SymbolKind::Object,
                    _ => SymbolKind::Other,
                };
                Ok(Symbol {
                    name: row.get(0)?,
                    address: row.get(1)?,
                    size: row.get(2)?,
                    kind,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut symbols = Vec::new();
        for row in rows {
            symbols.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(symbols)
    }

    // --- Decompilation cache persistence ---

    pub fn save_decompiled_code(
        &self,
        address: u64,
        code: &crate::il::hlil::DecompiledCode,
    ) -> Result<()> {
        let data = serde_json::to_string(code)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO decompilation_cache (address, data) VALUES (?1, ?2)",
                params![address, data],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_decompilation_cache(
        &self,
    ) -> Result<std::collections::HashMap<u64, crate::il::hlil::DecompiledCode>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, data FROM decompilation_cache")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut result = std::collections::HashMap::new();
        for row in rows {
            let (addr, data) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            if let Ok(code) = serde_json::from_str::<crate::il::hlil::DecompiledCode>(&data) {
                result.insert(addr, code);
            }
        }
        Ok(result)
    }

    pub fn delete_decompiled_code(&self, address: u64) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM decompilation_cache WHERE address = ?1",
                params![address],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db() -> (Database, PathBuf) {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sleuthre_test_{}.db", uuid::Uuid::new_v4()));
        let db = Database::open(&path).unwrap();
        (db, path)
    }

    #[test]
    fn round_trip_functions() {
        let (db, path) = temp_db();
        let func = Function {
            name: "main".to_string(),
            start_address: 0x401000,
            end_address: Some(0x401100),
            calling_convention: CallingConvention::default(),
            stack_frame_size: 0,
        };
        db.save_function(&func).unwrap();
        let loaded = db.load_functions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "main");
        assert_eq!(loaded[0].start_address, 0x401000);
        assert_eq!(loaded[0].end_address, Some(0x401100));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_xrefs() {
        let (db, path) = temp_db();
        let xref = Xref {
            from_address: 0x401000,
            to_address: 0x402000,
            xref_type: XrefType::Call,
        };
        db.save_xref(&xref).unwrap();
        let loaded = db.load_xrefs().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].from_address, 0x401000);
        assert_eq!(loaded[0].to_address, 0x402000);
        assert_eq!(loaded[0].xref_type, XrefType::Call);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_strings() {
        let (db, path) = temp_db();
        let s = DiscoveredString {
            address: 0x500000,
            value: "hello".to_string(),
            length: 5,
            section_name: ".rodata".to_string(),
            encoding: StringEncoding::Ascii,
        };
        db.save_string(&s).unwrap();
        let loaded = db.load_strings().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].value, "hello");
        assert_eq!(loaded[0].encoding, StringEncoding::Ascii);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_constants() {
        let (db, path) = temp_db();
        let c = DiscoveredConstant {
            address: 0x600000,
            value_hex: "00000000".to_string(),
            description: "CRC32 table".to_string(),
        };
        db.save_constant(&c).unwrap();
        let loaded = db.load_constants().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].description, "CRC32 table");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_comments() {
        let (db, path) = temp_db();
        db.set_comment(0x401000, "entry point").unwrap();
        let comments = db.load_comments().unwrap();
        assert_eq!(comments.get(&0x401000).unwrap(), "entry point");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_imports() {
        let (db, path) = temp_db();
        let import = Import {
            name: "printf".to_string(),
            library: "libc.so.6".to_string(),
            address: 0x401000,
        };
        db.save_import(&import).unwrap();
        let loaded = db.load_imports().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "printf");
        assert_eq!(loaded[0].library, "libc.so.6");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_exports() {
        let (db, path) = temp_db();
        let export = Export {
            name: "my_func".to_string(),
            address: 0x402000,
        };
        db.save_export(&export).unwrap();
        let loaded = db.load_exports().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "my_func");
        assert_eq!(loaded[0].address, 0x402000);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_function_signatures() {
        use crate::types::{FunctionParameter, PrimitiveType, TypeRef};

        let (db, path) = temp_db();
        let sig = FunctionSignature {
            name: "main".to_string(),
            return_type: TypeRef::Primitive(PrimitiveType::I32),
            parameters: vec![FunctionParameter {
                name: "argc".to_string(),
                type_ref: TypeRef::Primitive(PrimitiveType::I32),
            }],
            calling_convention: "cdecl".to_string(),
            is_variadic: false,
        };
        db.save_function_signature(0x401000, &sig).unwrap();
        let loaded = db.load_function_signatures().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&0x401000].name, "main");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_global_variables() {
        use crate::types::{PrimitiveType, TypeRef, VariableInfo, VariableLocation};

        let (db, path) = temp_db();
        let var = VariableInfo {
            name: "g_counter".to_string(),
            type_ref: TypeRef::Primitive(PrimitiveType::U32),
            location: VariableLocation::Address(0x600000),
        };
        db.save_global_variable(0x600000, &var).unwrap();
        let loaded = db.load_global_variables().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&0x600000].name, "g_counter");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_source_lines() {
        use crate::types::SourceLineInfo;

        let (db, path) = temp_db();
        let info = SourceLineInfo {
            file: "main.c".to_string(),
            line: 42,
            column: Some(5),
        };
        db.save_source_line(0x401000, &info).unwrap();
        let loaded = db.load_source_lines().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&0x401000].file, "main.c");
        assert_eq!(loaded[&0x401000].line, 42);
        assert_eq!(loaded[&0x401000].column, Some(5));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn round_trip_symbols() {
        let (db, path) = temp_db();
        let sym = Symbol {
            name: "main".to_string(),
            address: 0x401000,
            size: 256,
            kind: SymbolKind::Function,
        };
        db.save_symbol(&sym).unwrap();
        let loaded = db.load_symbols().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "main");
        assert_eq!(loaded[0].kind, SymbolKind::Function);
        let _ = std::fs::remove_file(path);
    }
}
