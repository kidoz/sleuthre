use crate::types::SourceLineInfo;
use gimli::{Dwarf, Reader, Unit};
use std::collections::BTreeMap;

/// Parse line number programs from a DWARF compilation unit.
pub fn parse_source_lines<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
) -> BTreeMap<u64, SourceLineInfo> {
    let mut result = BTreeMap::new();

    let program = match unit.line_program.clone() {
        Some(p) => p,
        None => return result,
    };

    let mut rows = program.rows();
    while let Ok(Some((header, row))) = rows.next_row() {
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

        let file = file_name_from_entry(dwarf, unit, file_entry);

        result.insert(address, SourceLineInfo { file, line, column });
    }

    result
}

fn file_name_from_entry<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    file_entry: &gimli::FileEntry<R>,
) -> String {
    let mut path = String::new();

    // Get directory
    if let Some(dir) = file_entry.directory(unit.line_program.as_ref().unwrap().header())
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
