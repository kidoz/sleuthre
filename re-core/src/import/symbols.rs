/// Supported symbol file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolFormat {
    /// Simple text: `0xADDRESS name` or `ADDRESS name` per line.
    TextMap,
    /// IDA Pro MAP file format.
    IdaMap,
    /// IDA IDC script with `MakeName()` / `MakeNameEx()` calls.
    IdaIdc,
    /// CSV: address,name[,type][,comment].
    Csv,
}

/// A single symbol parsed from an import file.
#[derive(Debug, Clone)]
pub struct ImportedSymbol {
    pub address: u64,
    pub name: String,
    /// Optional type hint such as "function" or "data".
    pub symbol_type: Option<String>,
    /// Optional comment carried alongside the symbol.
    pub comment: Option<String>,
}

/// Summary of an import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Auto-detect the symbol file format from its content.
pub fn detect_format(content: &str) -> SymbolFormat {
    // IDC: contains MakeName( or MakeNameEx(
    if content.contains("MakeName(") || content.contains("MakeNameEx(") {
        return SymbolFormat::IdaIdc;
    }

    // IDA MAP: contains characteristic header lines
    if content.contains("Publics by Value") || content.contains("Program entry point") {
        return SymbolFormat::IdaMap;
    }

    // CSV: first non-comment, non-empty line contains a comma
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains(',') {
            return SymbolFormat::Csv;
        }
        break;
    }

    SymbolFormat::TextMap
}

/// Parse symbols from file content in the given format.
pub fn parse_symbols(content: &str, format: SymbolFormat) -> Result<Vec<ImportedSymbol>, String> {
    match format {
        SymbolFormat::TextMap => parse_text_map(content),
        SymbolFormat::IdaMap => parse_ida_map(content),
        SymbolFormat::IdaIdc => parse_ida_idc(content),
        SymbolFormat::Csv => parse_csv(content),
    }
}

/// Parse text map format.
///
/// Each line: `0x004909F4 updateCharactersAndHirelingsEmotions`
/// or `004909F4 updateCharactersAndHirelingsEmotions`.
/// Blank lines and lines starting with `#` or `//` are skipped.
fn parse_text_map(content: &str) -> Result<Vec<ImportedSymbol>, String> {
    let mut symbols = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let addr_str = parts
            .next()
            .ok_or_else(|| format!("Line {}: missing address", line_no + 1))?;
        let name = parts
            .next()
            .ok_or_else(|| format!("Line {}: missing name", line_no + 1))?
            .trim();

        if name.is_empty() {
            return Err(format!("Line {}: empty name", line_no + 1));
        }

        let address = parse_hex_address(addr_str)
            .ok_or_else(|| format!("Line {}: invalid address '{}'", line_no + 1, addr_str))?;

        symbols.push(ImportedSymbol {
            address,
            name: name.to_string(),
            symbol_type: None,
            comment: None,
        });
    }

    Ok(symbols)
}

/// Parse IDA MAP format.
///
/// Looks for lines like `0001:000001A0   _init_engine` after the
/// `Publics by Value` header. Section 0001 typically maps to .text
/// with a base of 0x401000 for PE binaries. We use 0x401000 as the
/// default base for segment 0001 and 0x0 for others, but this is a
/// best-effort heuristic.
fn parse_ida_map(content: &str) -> Result<Vec<ImportedSymbol>, String> {
    let mut symbols = Vec::new();
    let mut in_publics = false;

    // Try to extract the entry point to infer base address.
    // Format: "Program entry point at SSSS:OOOOOOOO"
    let text_base: u64 = 0x401000; // Default PE .text base

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.contains("Publics by Value") {
            in_publics = true;
            continue;
        }

        if !in_publics {
            continue;
        }

        // Skip blank or header-like lines
        if trimmed.is_empty() || trimmed.starts_with("Address") {
            continue;
        }

        // Expect: SSSS:OOOOOOOO   name
        // Find the segment:offset pattern
        if let Some(colon_pos) = trimmed.find(':') {
            let seg_str = trimmed[..colon_pos].trim();
            // After colon, get offset and name
            let rest = &trimmed[colon_pos + 1..];
            let mut parts = rest.splitn(2, char::is_whitespace);
            let offset_str = match parts.next() {
                Some(s) => s.trim(),
                None => continue,
            };
            let name = match parts.next() {
                Some(s) => s.trim(),
                None => continue,
            };

            if name.is_empty() {
                continue;
            }

            let segment = u64::from_str_radix(seg_str, 16).unwrap_or(0);
            let offset = parse_hex_address(offset_str).unwrap_or(0);

            // Section 0001 = .text = base 0x401000 for PE
            // Section 0002+ we just use the offset as-is (data segments vary).
            let address = if segment == 1 {
                text_base + offset
            } else {
                offset
            };

            symbols.push(ImportedSymbol {
                address,
                name: name.to_string(),
                symbol_type: None,
                comment: None,
            });
        }
    }

    Ok(symbols)
}

/// Parse IDA IDC format.
///
/// Extracts `MakeName(0xADDR, "name")` and `MakeNameEx(0xADDR, "name", ...)` calls.
fn parse_ida_idc(content: &str) -> Result<Vec<ImportedSymbol>, String> {
    let mut symbols = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Match both MakeName( and MakeNameEx(
        let start = if let Some(pos) = trimmed.find("MakeName(") {
            pos + "MakeName(".len()
        } else if let Some(pos) = trimmed.find("MakeNameEx(") {
            pos + "MakeNameEx(".len()
        } else {
            continue;
        };

        let args_str = &trimmed[start..];

        // Find the closing paren for the full call
        let close = match args_str.find(')') {
            Some(p) => p,
            None => continue,
        };
        let args_str = &args_str[..close];

        // Split on first comma to get address and name
        let comma = match args_str.find(',') {
            Some(p) => p,
            None => continue,
        };

        let addr_str = args_str[..comma].trim();
        let rest = args_str[comma + 1..].trim();

        // Name is enclosed in quotes
        let name = extract_quoted_string(rest);
        if name.is_empty() {
            continue;
        }

        let address = match parse_hex_address(addr_str) {
            Some(a) => a,
            None => continue,
        };

        symbols.push(ImportedSymbol {
            address,
            name,
            symbol_type: None,
            comment: None,
        });
    }

    Ok(symbols)
}

/// Parse CSV format.
///
/// Columns: address, name, type (optional), comment (optional).
/// A header row is skipped if the first column does not look like a hex address.
fn parse_csv(content: &str) -> Result<Vec<ImportedSymbol>, String> {
    let mut symbols = Vec::new();
    let mut first = true;

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let fields: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if fields.len() < 2 {
            continue;
        }

        // Skip header row
        if first {
            first = false;
            if parse_hex_address(fields[0]).is_none() {
                // Looks like a header (e.g. "address,name,type,comment")
                continue;
            }
        }

        let address = match parse_hex_address(fields[0]) {
            Some(a) => a,
            None => {
                return Err(format!(
                    "Line {}: invalid address '{}'",
                    line_no + 1,
                    fields[0]
                ));
            }
        };

        let name = fields[1].trim_matches('"').to_string();
        if name.is_empty() {
            continue;
        }

        let symbol_type = fields.get(2).and_then(|s| {
            let s = s.trim_matches('"');
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        let comment = fields.get(3).and_then(|s| {
            let s = s.trim_matches('"');
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        symbols.push(ImportedSymbol {
            address,
            name,
            symbol_type,
            comment,
        });
    }

    Ok(symbols)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex address string, handling optional `0x` prefix.
fn parse_hex_address(s: &str) -> Option<u64> {
    let s = s.trim();
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(stripped, 16).ok()
}

/// Extract a double-quoted string value. Returns an empty string on failure.
fn extract_quoted_string(s: &str) -> String {
    let start = match s.find('"') {
        Some(p) => p + 1,
        None => return String::new(),
    };
    let end = match s[start..].find('"') {
        Some(p) => start + p,
        None => return String::new(),
    };
    s[start..end].to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_text_map() {
        let content = "0x004909F4 updateCharacters\n0x00401000 main\n";
        assert_eq!(detect_format(content), SymbolFormat::TextMap);
    }

    #[test]
    fn detect_idc() {
        let content = "MakeName(0x401000, \"main\");\nMakeNameEx(0x402000, \"foo\", 0);\n";
        assert_eq!(detect_format(content), SymbolFormat::IdaIdc);
    }

    #[test]
    fn detect_ida_map() {
        let content = " Program entry point at 0001:000CD7AE\n\n Address         Publics by Value\n 0001:00000000   _main\n";
        assert_eq!(detect_format(content), SymbolFormat::IdaMap);
    }

    #[test]
    fn detect_csv_format() {
        let content = "address,name,type\n0x401000,main,function\n";
        assert_eq!(detect_format(content), SymbolFormat::Csv);
    }

    #[test]
    fn parse_text_map_basic() {
        let content = "\
# comment line
0x004909F4 updateCharacters
004909F8 doSomething
// another comment

0x00401000 main
";
        let syms = parse_text_map(content).unwrap();
        assert_eq!(syms.len(), 3);
        assert_eq!(syms[0].address, 0x004909F4);
        assert_eq!(syms[0].name, "updateCharacters");
        assert_eq!(syms[1].address, 0x004909F8);
        assert_eq!(syms[1].name, "doSomething");
        assert_eq!(syms[2].address, 0x00401000);
        assert_eq!(syms[2].name, "main");
    }

    #[test]
    fn parse_idc_basic() {
        let content = "\
#include <idc.idc>
static main() {
    MakeName(0x401000, \"main\");
    MakeNameEx(0x402000, \"helper\", SN_CHECK);
}
";
        let syms = parse_ida_idc(content).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].address, 0x401000);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[1].address, 0x402000);
        assert_eq!(syms[1].name, "helper");
    }

    #[test]
    fn parse_ida_map_basic() {
        let content = "\
 Program entry point at 0001:000CD7AE

 Address         Publics by Value

 0001:00000000   _main
 0001:000001A0   _init_engine
";
        let syms = parse_ida_map(content).unwrap();
        assert_eq!(syms.len(), 2);
        // 0x401000 + 0x0 = 0x401000
        assert_eq!(syms[0].address, 0x401000);
        assert_eq!(syms[0].name, "_main");
        // 0x401000 + 0x1A0 = 0x4011A0
        assert_eq!(syms[1].address, 0x4011A0);
        assert_eq!(syms[1].name, "_init_engine");
    }

    #[test]
    fn parse_csv_with_header() {
        let content = "\
address,name,type,comment
0x401000,main,function,entry point
0x402000,global_data,data,
";
        let syms = parse_csv(content).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].address, 0x401000);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[0].symbol_type, Some("function".to_string()));
        assert_eq!(syms[0].comment, Some("entry point".to_string()));
        assert_eq!(syms[1].address, 0x402000);
        assert_eq!(syms[1].name, "global_data");
        assert_eq!(syms[1].symbol_type, Some("data".to_string()));
        assert_eq!(syms[1].comment, None);
    }

    #[test]
    fn parse_csv_no_header() {
        let content = "0x401000,main\n0x402000,helper\n";
        let syms = parse_csv(content).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[1].name, "helper");
    }

    #[test]
    fn parse_symbols_dispatches() {
        let content = "0x1000 foo\n0x2000 bar\n";
        let syms = parse_symbols(content, SymbolFormat::TextMap).unwrap();
        assert_eq!(syms.len(), 2);
    }

    #[test]
    fn parse_hex_address_variants() {
        assert_eq!(parse_hex_address("0x401000"), Some(0x401000));
        assert_eq!(parse_hex_address("0X401000"), Some(0x401000));
        assert_eq!(parse_hex_address("401000"), Some(0x401000));
        assert_eq!(parse_hex_address("  0x401000  "), Some(0x401000));
        assert_eq!(parse_hex_address("zzz"), None);
    }

    #[test]
    fn extract_quoted_string_basic() {
        assert_eq!(extract_quoted_string("\"hello\""), "hello");
        assert_eq!(extract_quoted_string("  \"world\" "), "world");
        assert_eq!(extract_quoted_string("no quotes"), "");
        assert_eq!(extract_quoted_string("\"unclosed"), "");
    }
}
