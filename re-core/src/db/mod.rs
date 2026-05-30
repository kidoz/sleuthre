use crate::Result;
use crate::analysis::constants::DiscoveredConstant;
use crate::analysis::functions::Function;
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

/// SQLite stores every integer as a signed `i64`. Addresses, sizes, and lengths
/// in our model are unsigned (`u64`/`usize`), and the `u64 <-> i64` conversion
/// is a lossless bit reinterpretation (it round-trips even high addresses with
/// the top bit set, e.g. kernel pointers), which we opt into explicitly at this
/// boundary.
#[inline]
fn as_i64(v: u64) -> i64 {
    v as i64
}

/// Read column `idx` as the `i64` SQLite stores and reinterpret it as `u64`.
#[inline]
fn col_u64(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<u64> {
    Ok(row.get::<_, i64>(idx)? as u64)
}

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
                end_address INTEGER,
                calling_convention TEXT,
                stack_frame_size INTEGER
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
            CREATE TABLE IF NOT EXISTS tags (
                address INTEGER NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (address, tag)
            );
            CREATE INDEX IF NOT EXISTS idx_tags_address ON tags(address);
            CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);
            CREATE TABLE IF NOT EXISTS struct_overlays (
                address INTEGER NOT NULL,
                label TEXT NOT NULL,
                type_name TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (address, label)
            );
            CREATE TABLE IF NOT EXISTS classes (
                name TEXT PRIMARY KEY,
                base TEXT,
                vtable_label TEXT,
                vtable_address INTEGER
            );
            CREATE TABLE IF NOT EXISTS debug_profiles (
                name TEXT PRIMARY KEY,
                transport TEXT NOT NULL,
                address TEXT NOT NULL,
                exe_path TEXT NOT NULL,
                args TEXT NOT NULL,
                arch_override TEXT,
                save_args INTEGER NOT NULL
            );
            COMMIT;",
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        // Migrations for project files created before a column existed. SQLite
        // has no "ADD COLUMN IF NOT EXISTS", so each is guarded by a presence
        // check against PRAGMA table_info.
        self.ensure_column("functions", "calling_convention", "TEXT")?;
        self.ensure_column("functions", "stack_frame_size", "INTEGER")?;
        Ok(())
    }

    /// Add `column` (`<name> <sql-type>`) to `table` if it isn't already there.
    /// `table`/`column`/`decl` are fixed code literals, never user input.
    fn ensure_column(&self, table: &str, column: &str, decl: &str) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let existing = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let mut present = false;
        for name in existing {
            if name.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))? == column {
                present = true;
                break;
            }
        }
        if !present {
            self.conn
                .execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
                    [],
                )
                .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        }
        Ok(())
    }

    pub fn save_segment(&self, seg: &MemorySegment) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO segments (name, start, size, data, permissions) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seg.name, as_i64(seg.start), as_i64(seg.size), seg.data, seg.permissions.bits()],
        ).map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_segments(&self) -> Result<Vec<MemorySegment>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, start, size, data, permissions FROM segments ORDER BY start")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let bits: u8 = row.get(4)?;
                Ok(MemorySegment {
                    name: row.get(0)?,
                    start: col_u64(row, 1)?,
                    size: col_u64(row, 2)?,
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
                params![as_i64(address), text],
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
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut comments = std::collections::HashMap::new();
        for row in rows {
            let (addr, text) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            comments.insert(addr, text);
        }
        Ok(comments)
    }

    pub fn save_function(&self, func: &Function) -> Result<()> {
        let cc = serde_json::to_string(&func.calling_convention)
            .map_err(|e| Error::Database(e.to_string()))?;
        self.conn
            .execute(
                "INSERT INTO functions \
                 (start_address, name, end_address, calling_convention, stack_frame_size) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(start_address) DO UPDATE SET name = excluded.name, \
                 end_address = excluded.end_address, \
                 calling_convention = excluded.calling_convention, \
                 stack_frame_size = excluded.stack_frame_size",
                params![
                    as_i64(func.start_address),
                    func.name,
                    func.end_address.map(as_i64),
                    cc,
                    as_i64(func.stack_frame_size),
                ],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn set_name(&self, address: u64, name: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO functions (start_address, name) VALUES (?1, ?2)
             ON CONFLICT(start_address) DO UPDATE SET name = excluded.name",
                params![as_i64(address), name],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_functions(&self) -> Result<Vec<Function>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name, start_address, end_address, calling_convention, stack_frame_size \
                 FROM functions",
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                // calling_convention / stack_frame_size may be NULL in rows
                // written before these columns existed, or by `set_name`.
                let calling_convention = row
                    .get::<_, Option<String>>(3)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let stack_frame_size = row.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64;
                Ok(Function {
                    name: row.get(0)?,
                    start_address: col_u64(row, 1)?,
                    end_address: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                    calling_convention,
                    stack_frame_size,
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
                params![as_i64(xref.from_address), as_i64(xref.to_address), type_str],
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
                    from_address: col_u64(row, 0)?,
                    to_address: col_u64(row, 1)?,
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
                params![as_i64(s.address), s.value, s.length as i64, s.section_name, enc],
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

    pub fn begin_transaction(&self) -> Result<()> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn commit_transaction(&self) -> Result<()> {
        self.conn
            .execute_batch("COMMIT")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn rollback_transaction(&self) -> Result<()> {
        self.conn
            .execute_batch("ROLLBACK")
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
                 DELETE FROM decompilation_cache;
                 DELETE FROM tags;
                 DELETE FROM struct_overlays;
                 DELETE FROM classes;
                 DELETE FROM debug_profiles;",
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
                    address: col_u64(row, 0)?,
                    value: row.get(1)?,
                    length: row.get::<_, i64>(2)? as usize,
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
                params![as_i64(c.address), c.value_hex, c.description],
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
                    address: col_u64(row, 0)?,
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
                params![import.name, import.library, as_i64(import.address)],
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
                    address: col_u64(row, 2)?,
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
                params![export.name, as_i64(export.address)],
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
                    address: col_u64(row, 1)?,
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
                params![sym.name, as_i64(sym.address), as_i64(sym.size), kind_str],
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
                params![as_i64(ann.address), type_ref_json, ann.name],
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
                let address: u64 = col_u64(row, 0)?;
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
                params![as_i64(address), note],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn delete_bookmark(&self, address: u64) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM bookmarks WHERE address = ?1",
                params![as_i64(address)],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_bookmarks(&self) -> Result<std::collections::BTreeMap<u64, String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, note FROM bookmarks")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut bookmarks = std::collections::BTreeMap::new();
        for row in rows {
            let (addr, note) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            bookmarks.insert(addr, note);
        }
        Ok(bookmarks)
    }

    // --- Tag persistence ---

    pub fn save_tag(&self, address: u64, tag: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO tags (address, tag) VALUES (?1, ?2)",
                params![as_i64(address), tag],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_tags(&self) -> Result<std::collections::BTreeMap<u64, Vec<String>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, tag FROM tags ORDER BY address, tag")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut tags = std::collections::BTreeMap::<u64, Vec<String>>::new();
        for row in rows {
            let (addr, tag) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            tags.entry(addr).or_default().push(tag);
        }
        Ok(tags)
    }

    // --- Struct overlay persistence ---

    pub fn save_struct_overlay(&self, overlay: &crate::project::StructOverlay) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO struct_overlays (address, label, type_name, count) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    as_i64(overlay.address),
                    overlay.label,
                    overlay.type_name,
                    overlay.count as i64,
                ],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_struct_overlays(&self) -> Result<Vec<crate::project::StructOverlay>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, label, type_name, count FROM struct_overlays ORDER BY address, label")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(crate::project::StructOverlay {
                    address: col_u64(row, 0)?,
                    label: row.get::<_, String>(1)?,
                    type_name: row.get::<_, String>(2)?,
                    count: row.get::<_, i64>(3)? as usize,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;

        let mut overlays = Vec::new();
        for row in rows {
            overlays.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(overlays)
    }

    // --- Debugger profile persistence ---

    pub fn save_debug_profile(&self, profile: &crate::project::DebugProfile) -> Result<()> {
        use crate::project::DebugTransport;
        let transport = match profile.transport {
            DebugTransport::GdbRemote => "GdbRemote",
            DebugTransport::LocalLaunch => "LocalLaunch",
        };
        // Honour the "don't persist arguments" flag — args may carry secrets.
        let args_json = if profile.save_args {
            serde_json::to_string(&profile.args).map_err(|e| Error::Database(e.to_string()))?
        } else {
            "[]".to_string()
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO debug_profiles \
                 (name, transport, address, exe_path, args, arch_override, save_args) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    profile.name,
                    transport,
                    profile.address,
                    profile.exe_path,
                    args_json,
                    profile.arch_override,
                    profile.save_args as i64,
                ],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_debug_profiles(&self) -> Result<Vec<crate::project::DebugProfile>> {
        use crate::project::{DebugProfile, DebugTransport};
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name, transport, address, exe_path, args, arch_override, save_args \
                 FROM debug_profiles ORDER BY name",
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let transport = match row.get::<_, String>(1)?.as_str() {
                    "LocalLaunch" => DebugTransport::LocalLaunch,
                    _ => DebugTransport::GdbRemote,
                };
                let args: Vec<String> =
                    serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default();
                Ok(DebugProfile {
                    name: row.get::<_, String>(0)?,
                    transport,
                    address: row.get::<_, String>(2)?,
                    exe_path: row.get::<_, String>(3)?,
                    args,
                    arch_override: row.get::<_, Option<String>>(5)?,
                    save_args: row.get::<_, i64>(6)? != 0,
                })
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?);
        }
        Ok(profiles)
    }

    pub fn delete_debug_profile(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM debug_profiles WHERE name = ?1", params![name])
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    // --- ClassInfo persistence ---

    pub fn save_class(&self, name: &str, info: &crate::types::ClassInfo) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO classes (name, base, vtable_label, vtable_address) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    name,
                    info.base.as_deref(),
                    info.vtable_label.as_deref(),
                    info.vtable_address.map(|v| v as i64),
                ],
            )
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        Ok(())
    }

    pub fn load_classes(
        &self,
    ) -> Result<std::collections::BTreeMap<String, crate::types::ClassInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, base, vtable_label, vtable_address FROM classes ORDER BY name")
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let base: Option<String> = row.get(1)?;
                let vtable_label: Option<String> = row.get(2)?;
                let vtable_address: Option<i64> = row.get(3)?;
                Ok((
                    name,
                    crate::types::ClassInfo {
                        base,
                        vtable_label,
                        vtable_address: vtable_address.map(|v| v as u64),
                    },
                ))
            })
            .map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
        let mut out = std::collections::BTreeMap::new();
        for row in rows {
            let (n, info) = row.map_err(|e: rusqlite::Error| Error::Database(e.to_string()))?;
            out.insert(n, info);
        }
        Ok(out)
    }

    // --- Function signature persistence ---

    pub fn save_function_signature(&self, address: u64, sig: &FunctionSignature) -> Result<()> {
        let data = serde_json::to_string(sig)
            .map_err(|e| Error::Database(format!("JSON error: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO function_signatures (address, data) VALUES (?1, ?2)",
                params![as_i64(address), data],
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
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
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
                params![as_i64(address), data],
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
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
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
                params![as_i64(function_address), data],
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
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
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
                    as_i64(address),
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
                    col_u64(row, 0)?,
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
                    address: col_u64(row, 1)?,
                    size: col_u64(row, 2)?,
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
                params![as_i64(address), data],
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
            .query_map([], |row| Ok((col_u64(row, 0)?, row.get::<_, String>(1)?)))
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
                params![as_i64(address)],
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
        use crate::analysis::functions::CallingConvention;
        let (db, path) = temp_db();
        let func = Function {
            name: "main".to_string(),
            start_address: 0x401000,
            end_address: Some(0x401100),
            // Non-default so the test would catch silent loss of these fields.
            calling_convention: CallingConvention::Win64,
            stack_frame_size: 0x40,
        };
        db.save_function(&func).unwrap();
        let loaded = db.load_functions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "main");
        assert_eq!(loaded[0].start_address, 0x401000);
        assert_eq!(loaded[0].end_address, Some(0x401100));
        assert_eq!(loaded[0].calling_convention, CallingConvention::Win64);
        assert_eq!(loaded[0].stack_frame_size, 0x40);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn functions_table_migrates_from_pre_column_schema() {
        use crate::analysis::functions::CallingConvention;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sleuthre_migrate_{}.db", uuid::Uuid::new_v4()));
        // Simulate an old project file: a functions table without the
        // calling_convention / stack_frame_size columns, with one row.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE functions (start_address INTEGER PRIMARY KEY, name TEXT, end_address INTEGER);
                 INSERT INTO functions (start_address, name, end_address) VALUES (0x401000, 'old', NULL);",
            )
            .unwrap();
        }
        // Opening must add the new columns and still load the legacy row.
        let db = Database::open(&path).unwrap();
        let loaded = db.load_functions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "old");
        assert_eq!(loaded[0].calling_convention, CallingConvention::Unknown);
        assert_eq!(loaded[0].stack_frame_size, 0);
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

    #[test]
    fn round_trip_struct_overlays() {
        let (db, path) = temp_db();
        let overlays = [
            crate::project::StructOverlay {
                address: 0x500000,
                type_name: "Player".into(),
                count: 1,
                label: "player".into(),
            },
            crate::project::StructOverlay {
                address: 0x600000,
                type_name: "Monster".into(),
                count: 32,
                label: "monster_table".into(),
            },
        ];
        for o in &overlays {
            db.save_struct_overlay(o).unwrap();
        }
        let loaded = db.load_struct_overlays().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].address, 0x500000);
        assert_eq!(loaded[0].type_name, "Player");
        assert_eq!(loaded[0].count, 1);
        assert_eq!(loaded[0].label, "player");
        assert_eq!(loaded[1].address, 0x600000);
        assert_eq!(loaded[1].count, 32);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trip_debug_profiles() {
        use crate::project::{DebugProfile, DebugTransport};
        let (db, path) = temp_db();
        let remote = DebugProfile {
            name: "qemu".into(),
            transport: DebugTransport::GdbRemote,
            address: "127.0.0.1:1234".into(),
            exe_path: String::new(),
            args: vec![],
            arch_override: Some("Arm64".into()),
            save_args: true,
        };
        // save_args = false must drop the (potentially sensitive) args on disk.
        let launch = DebugProfile {
            name: "local".into(),
            transport: DebugTransport::LocalLaunch,
            address: String::new(),
            exe_path: "/bin/prog".into(),
            args: vec!["--token".into(), "secret".into()],
            arch_override: None,
            save_args: false,
        };
        db.save_debug_profile(&remote).unwrap();
        db.save_debug_profile(&launch).unwrap();

        let loaded = db.load_debug_profiles().unwrap();
        assert_eq!(loaded.len(), 2);
        // Ordered by name: "local", "qemu".
        assert_eq!(loaded[0].name, "local");
        assert_eq!(loaded[0].transport, DebugTransport::LocalLaunch);
        assert_eq!(loaded[0].exe_path, "/bin/prog");
        assert!(
            loaded[0].args.is_empty(),
            "args must not persist when save_args is false"
        );
        assert_eq!(loaded[1].name, "qemu");
        assert_eq!(loaded[1].transport, DebugTransport::GdbRemote);
        assert_eq!(loaded[1].address, "127.0.0.1:1234");
        assert_eq!(loaded[1].arch_override.as_deref(), Some("Arm64"));

        db.delete_debug_profile("local").unwrap();
        assert_eq!(db.load_debug_profiles().unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trip_classes() {
        let (db, path) = temp_db();
        let info = crate::types::ClassInfo {
            base: Some("Widget".into()),
            vtable_label: Some("vtable_Button".into()),
            vtable_address: Some(0x404010),
        };
        db.save_class("Button", &info).unwrap();
        let loaded = db.load_classes().unwrap();
        assert_eq!(loaded.len(), 1);
        let restored = loaded.get("Button").unwrap();
        assert_eq!(restored.base.as_deref(), Some("Widget"));
        assert_eq!(restored.vtable_label.as_deref(), Some("vtable_Button"));
        assert_eq!(restored.vtable_address, Some(0x404010));
        let _ = std::fs::remove_file(path);
    }
}
