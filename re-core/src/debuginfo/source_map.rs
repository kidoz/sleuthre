use crate::types::SourceLineInfo;
use gimli::{Dwarf, Reader, Unit};
use std::collections::BTreeMap;

/// Upper bound on line-table rows collected across all compilation units —
/// a crafted `.debug_line` cannot balloon memory (mirrors `MAX_PDB_LINE_ROWS`
/// in the PDB parser).
pub(crate) const MAX_DWARF_LINE_ROWS: usize = 2_000_000;

/// Parse line number programs from a DWARF compilation unit. `line_budget`
/// is shared across units so the total row count stays bounded.
pub fn parse_source_lines<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    line_budget: &mut usize,
) -> BTreeMap<u64, SourceLineInfo> {
    let mut result = BTreeMap::new();

    let program = match unit.line_program.clone() {
        Some(p) => p,
        None => return result,
    };

    let mut rows = program.rows();
    while let Ok(Some((header, row))) = rows.next_row() {
        if *line_budget == 0 {
            break;
        }
        if !row.is_stmt() {
            continue;
        }

        let address = row.address();
        let line = match row.line() {
            Some(l) => l.get() as u32,
            None => continue,
        };
        let column = match row.column() {
            gimli::ColumnType::LeftEdge => None,
            gimli::ColumnType::Column(c) => Some(c.get() as u32),
        };

        let file_entry = match row.file(header) {
            Some(fe) => fe,
            None => continue,
        };

        let file = file_name_from_entry(dwarf, unit, header, file_entry);

        result.insert(address, SourceLineInfo { file, line, column });
        *line_budget -= 1;
    }

    result
}

fn file_name_from_entry<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    header: &gimli::LineProgramHeader<R>,
    file_entry: &gimli::FileEntry<R>,
) -> String {
    let mut path = String::new();

    // Get directory
    if let Some(dir) = file_entry.directory(header)
        && let Ok(dir_str) = dwarf.attr_string(unit, dir)
        && let Ok(s) = dir_str.to_string()
    {
        path.push_str(&s);
        if !path.ends_with('/') && !path.ends_with('\\') {
            path.push('/');
        }
    }

    // Get filename
    if let Ok(name_str) = dwarf.attr_string(unit, file_entry.path_name())
        && let Ok(s) = name_str.to_string()
    {
        path.push_str(&s);
    }

    path
}
