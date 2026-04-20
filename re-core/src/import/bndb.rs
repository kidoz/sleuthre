//! Binary Ninja `.bndb` project importer.
//!
//! Reads symbols, comments, and function renames from a Binary Ninja database
//! (a SQLite file) and returns them as [`ImportedSymbol`] records that can be
//! applied to a sleuthre `Project` via the shared import pipeline.
//!
//! The schema varies slightly between BN versions; the subset used here is
//! stable from BN 4.x onwards and is documented in Vector35's public
//! `BinaryNinja.ProjectFile` reference. When a table or column is missing
//! we silently skip that category rather than fail — a BNDB that contains
//! only function names still imports cleanly.

use crate::import::symbols::ImportedSymbol;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Parse a `.bndb` file and return the symbols the analyst has added.
///
/// The database is opened read-only so the caller's copy is never modified.
/// Function renames, user comments, and non-default symbol names all surface
/// as [`ImportedSymbol`] entries so the existing rename/apply pipeline can
/// consume them without special-casing BN.
pub fn import_bndb(path: &Path) -> Result<Vec<ImportedSymbol>, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open bndb: {}", e))?;
    let mut out = Vec::new();
    collect_symbols(&conn, &mut out);
    collect_function_names(&conn, &mut out);
    collect_comments(&conn, &mut out);
    Ok(out)
}

/// Pull non-auto symbol names. BN's `symbol` table has `address`, `name`,
/// `auto` (boolean) — we ignore auto-generated entries because the analyst
/// already has them from the loader.
fn collect_symbols(conn: &Connection, out: &mut Vec<ImportedSymbol>) {
    let Ok(mut stmt) = conn.prepare("SELECT address, name FROM symbol WHERE auto = 0") else {
        return;
    };
    let rows = stmt.query_map([], |row| {
        let addr: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        Ok((addr as u64, name))
    });
    let Ok(rows) = rows else {
        return;
    };
    for row in rows.flatten() {
        out.push(ImportedSymbol {
            address: row.0,
            name: row.1,
            symbol_type: Some("symbol".into()),
            comment: None,
        });
    }
}

/// Pull function renames — rows in `function` where `name` has been edited
/// away from the disassembler default (`sub_...`).
fn collect_function_names(conn: &Connection, out: &mut Vec<ImportedSymbol>) {
    let Ok(mut stmt) = conn.prepare("SELECT start, name FROM function") else {
        return;
    };
    let rows = stmt.query_map([], |row| {
        let addr: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        Ok((addr as u64, name))
    });
    let Ok(rows) = rows else {
        return;
    };
    for row in rows.flatten() {
        // BN auto-names functions `sub_<addr>`; only import user renames.
        let auto = format!("sub_{:x}", row.0);
        if row.1 != auto && !row.1.is_empty() {
            out.push(ImportedSymbol {
                address: row.0,
                name: row.1,
                symbol_type: Some("function".into()),
                comment: None,
            });
        }
    }
}

/// BN stores comments in a `comment` table keyed by address.
fn collect_comments(conn: &Connection, out: &mut Vec<ImportedSymbol>) {
    let Ok(mut stmt) = conn.prepare("SELECT address, text FROM comment") else {
        return;
    };
    let rows = stmt.query_map([], |row| {
        let addr: i64 = row.get(0)?;
        let text: String = row.get(1)?;
        Ok((addr as u64, text))
    });
    let Ok(rows) = rows else {
        return;
    };
    for row in rows.flatten() {
        // Emit as a symbol with only a comment — the sleuthre applier drops
        // the name-side change when `name` matches the existing one.
        out.push(ImportedSymbol {
            address: row.0,
            name: String::new(),
            symbol_type: Some("comment".into()),
            comment: Some(row.1),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_bndb(sql: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("sleuthre_bndb_{}.db", uuid::Uuid::new_v4()));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
        path
    }

    #[test]
    fn imports_symbols_function_names_comments() {
        let path = scratch_bndb(
            "
            CREATE TABLE symbol (address INTEGER, name TEXT, auto INTEGER);
            INSERT INTO symbol VALUES (0x1000, 'my_sym', 0);
            INSERT INTO symbol VALUES (0x1004, 'auto_sym', 1);
            CREATE TABLE function (start INTEGER, name TEXT);
            INSERT INTO function VALUES (0x2000, 'main');
            INSERT INTO function VALUES (0x3000, 'sub_3000');
            CREATE TABLE comment (address INTEGER, text TEXT);
            INSERT INTO comment VALUES (0x1000, 'entry point');
            ",
        );
        let syms = import_bndb(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        // Expect: 1 user symbol (auto filtered), 1 renamed function, 1 comment.
        let kinds: Vec<_> = syms.iter().map(|s| s.symbol_type.as_deref()).collect();
        assert!(kinds.contains(&Some("symbol")));
        assert!(kinds.contains(&Some("function")));
        assert!(kinds.contains(&Some("comment")));
        assert_eq!(syms.len(), 3, "{:?}", syms);

        let func = syms
            .iter()
            .find(|s| s.symbol_type.as_deref() == Some("function"))
            .unwrap();
        assert_eq!(func.name, "main");
        assert_eq!(func.address, 0x2000);

        let cmt = syms
            .iter()
            .find(|s| s.symbol_type.as_deref() == Some("comment"))
            .unwrap();
        assert_eq!(cmt.comment.as_deref(), Some("entry point"));
    }

    #[test]
    fn missing_tables_do_not_fail_import() {
        let path = scratch_bndb(""); // Empty DB — no BN tables at all.
        let syms = import_bndb(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(syms.is_empty());
    }
}
