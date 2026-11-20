use object::read::macho::{MachHeader, Section, Segment};
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryMap, Permissions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredString {
    pub address: u64,
    pub value: String,
    pub length: usize,
    pub section_name: String,
    pub encoding: StringEncoding,
}

pub struct StringsManager {
    pub strings: Vec<DiscoveredString>,
    pub min_length: usize,
    /// Also scan executable segments. Off by default: arbitrary instruction
    /// bytes decode as short ASCII runs (`AUATUWVSH`, `D$ H`), which on a real
    /// binary bury the data-section strings under tens of thousands of false
    /// positives.
    pub scan_executable: bool,
}

impl Default for StringsManager {
    fn default() -> Self {
        Self {
            strings: Vec::new(),
            min_length: 4,
            scan_executable: false,
        }
    }
}

impl StringsManager {
    pub fn scan_memory(&mut self, memory: &MemoryMap) {
        self.strings.clear();
        for segment in &memory.segments {
            if !self.scan_executable && segment.permissions.contains(Permissions::EXECUTE) {
                continue;
            }
            self.scan_ascii(&segment.data, segment.start, &segment.name);
            self.scan_utf16le(segment);
            self.scan_utf16be(segment);
        }
        if !self.scan_executable {
            self.scan_macho_cstrings(memory);
        }
    }

    pub(crate) fn scan_macho_cstrings(&mut self, memory: &MemoryMap) {
        // Mach-O maps the header and C string literals alongside code in __TEXT.
        // Read section headers from the mapping so saved projects work without
        // the original binary or a second copy of the mapped sections.
        let Some(text) = memory
            .segments
            .iter()
            .find(|segment| segment.name == "__TEXT")
        else {
            return;
        };
        let data = text.data.as_slice();
        let original_len = self.strings.len();
        if let Ok(header) = object::macho::MachHeader64::<object::Endianness>::parse(data, 0) {
            self.scan_macho_cstring_sections(header, data, memory);
        } else if let Ok(header) = object::macho::MachHeader32::<object::Endianness>::parse(data, 0)
        {
            self.scan_macho_cstring_sections(header, data, memory);
        }
        if original_len > 0 && self.strings.len() > original_len {
            let mut literals = self.strings.split_off(original_len);
            let mut addresses: std::collections::HashSet<_> =
                self.strings.iter().map(|string| string.address).collect();
            literals.retain(|string| addresses.insert(string.address));
            self.strings.extend(literals);
        }
    }

    fn scan_macho_cstring_sections<M: MachHeader>(
        &mut self,
        header: &M,
        data: &[u8],
        memory: &MemoryMap,
    ) {
        let Ok(endian) = header.endian() else {
            return;
        };
        let Ok(mut commands) = header.load_commands(endian, data, 0) else {
            return;
        };
        let mut ranges = Vec::new();
        while let Ok(Some(command)) = commands.next() {
            let Ok(Some((segment, section_headers))) = M::Segment::from_command(command) else {
                continue;
            };
            let start = segment.vmaddr(endian).into();
            let Some(mapping) = memory.segment_at(start).filter(|mapping| {
                mapping.start == start && mapping.permissions.contains(Permissions::EXECUTE)
            }) else {
                continue;
            };
            let Ok(sections) = segment.sections(endian, section_headers) else {
                continue;
            };
            for section in sections {
                if section.flags(endian).typ() != object::macho::S_CSTRING_LITERALS {
                    continue;
                }
                let address = section.addr(endian).into();
                let size: u64 = section.size(endian).into();
                if let Some(offset) = address
                    .checked_sub(start)
                    .and_then(|offset| usize::try_from(offset).ok())
                    && (offset as u64)
                        .checked_add(size)
                        .is_some_and(|end| end <= mapping.size)
                    && let Ok(size) = usize::try_from(size)
                    && let Some(bytes) =
                        mapping.data.get(offset..).and_then(|tail| tail.get(..size))
                    && let Ok(name) = std::str::from_utf8(section.name())
                {
                    ranges.push((address, name, bytes));
                }
            }
        }
        // Bound scanning to the mapped data even if section headers overlap.
        ranges
            .sort_unstable_by_key(|&(address, _, bytes)| (address, std::cmp::Reverse(bytes.len())));
        let mut previous_end = 0;
        for (address, name, bytes) in ranges {
            if address >= previous_end {
                self.scan_ascii(bytes, address, name);
                previous_end = address + bytes.len() as u64;
            }
        }
    }

    fn is_printable_ascii(byte: u8) -> bool {
        (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
    }

    fn scan_ascii(&mut self, data: &[u8], base: u64, section_name: &str) {
        let mut run_start = 0usize;
        let mut in_run = false;

        for (offset, &byte) in data.iter().enumerate() {
            if Self::is_printable_ascii(byte) {
                if !in_run {
                    run_start = offset;
                    in_run = true;
                }
            } else if in_run {
                let run = &data[run_start..offset];
                if run.len() >= self.min_length
                    && let Ok(s) = std::str::from_utf8(run)
                {
                    self.strings.push(DiscoveredString {
                        address: base + run_start as u64,
                        value: s.to_string(),
                        length: run.len(),
                        section_name: section_name.to_owned(),
                        encoding: StringEncoding::Ascii,
                    });
                }
                in_run = false;
            }
        }

        // Flush at end of segment
        if in_run {
            let run = &data[run_start..];
            if run.len() >= self.min_length
                && let Ok(s) = std::str::from_utf8(run)
            {
                self.strings.push(DiscoveredString {
                    address: base + run_start as u64,
                    value: s.to_string(),
                    length: run.len(),
                    section_name: section_name.to_owned(),
                    encoding: StringEncoding::Ascii,
                });
            }
        }
    }

    fn scan_utf16le(&mut self, segment: &crate::memory::MemorySegment) {
        let data = &segment.data;
        if data.len() < 2 {
            return;
        }

        let mut chars = Vec::new();
        let mut start_addr = 0u64;

        let mut i = 0;
        while i + 1 < data.len() {
            let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);

            if (0x20..=0x7E).contains(&code_unit)
                || code_unit == 0x09
                || code_unit == 0x0A
                || code_unit == 0x0D
            {
                if chars.is_empty() {
                    start_addr = segment.start + i as u64;
                }
                chars.push(code_unit);
            } else {
                if chars.len() >= self.min_length {
                    let value = String::from_utf16_lossy(&chars);
                    self.strings.push(DiscoveredString {
                        address: start_addr,
                        value,
                        length: chars.len(),
                        section_name: segment.name.clone(),
                        encoding: StringEncoding::Utf16Le,
                    });
                }
                chars.clear();
            }
            i += 2;
        }

        // Flush at end
        if chars.len() >= self.min_length {
            let value = String::from_utf16_lossy(&chars);
            self.strings.push(DiscoveredString {
                address: start_addr,
                value,
                length: chars.len(),
                section_name: segment.name.clone(),
                encoding: StringEncoding::Utf16Le,
            });
        }
    }

    fn scan_utf16be(&mut self, segment: &crate::memory::MemorySegment) {
        let data = &segment.data;
        if data.len() < 2 {
            return;
        }

        let mut chars = Vec::new();
        let mut start_addr = 0u64;

        let mut i = 0;
        while i + 1 < data.len() {
            let code_unit = u16::from_be_bytes([data[i], data[i + 1]]);

            if (0x20..=0x7E).contains(&code_unit)
                || code_unit == 0x09
                || code_unit == 0x0A
                || code_unit == 0x0D
            {
                if chars.is_empty() {
                    start_addr = segment.start + i as u64;
                }
                chars.push(code_unit);
            } else {
                if chars.len() >= self.min_length {
                    let value = String::from_utf16_lossy(&chars);
                    self.strings.push(DiscoveredString {
                        address: start_addr,
                        value,
                        length: chars.len(),
                        section_name: segment.name.clone(),
                        encoding: StringEncoding::Utf16Be,
                    });
                }
                chars.clear();
            }
            i += 2;
        }

        if chars.len() >= self.min_length {
            let value = String::from_utf16_lossy(&chars);
            self.strings.push(DiscoveredString {
                address: start_addr,
                value,
                length: chars.len(),
                section_name: segment.name.clone(),
                encoding: StringEncoding::Utf16Be,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryMap, MemorySegment, Permissions};

    fn make_segment(name: &str, data: Vec<u8>) -> MemorySegment {
        let size = data.len() as u64;
        MemorySegment {
            name: name.to_string(),
            start: 0x1000,
            size,
            data,
            permissions: Permissions::READ,
        }
    }

    /// Code bytes routinely decode as short ASCII runs; those must not be
    /// reported as strings unless explicitly requested.
    #[test]
    fn executable_segments_are_skipped_by_default() {
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x1000,
            size: 16,
            data: b"\x00AUATUWVSH\x00\x00\x00\x00\x00\x00".to_vec(),
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
        map.add_segment(MemorySegment {
            name: ".rdata".to_string(),
            start: 0x2000,
            size: 16,
            data: b"\x00RealString\x00\x00\x00\x00\x00".to_vec(),
            permissions: Permissions::READ,
        })
        .unwrap();

        let mut mgr = StringsManager::default();
        mgr.scan_memory(&map);
        let values: Vec<&str> = mgr.strings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, vec!["RealString"]);

        mgr.scan_executable = true;
        mgr.scan_memory(&map);
        assert!(
            mgr.strings.iter().any(|s| s.value == "AUATUWVSH"),
            "opt-in must include executable segments"
        );
    }

    #[test]
    fn ascii_basic() {
        let mut mgr = StringsManager::default();
        let data = b"\x00\x00Hello World!\x00\x00".to_vec();
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("data", data)).unwrap();
        mgr.scan_memory(&map);

        let ascii: Vec<_> = mgr
            .strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].value, "Hello World!");
        assert_eq!(ascii[0].length, 12);
    }

    #[test]
    fn ascii_with_tab_newline() {
        let mut mgr = StringsManager::default();
        let data = b"\x00\x00Hi\tthere\n\x00\x00".to_vec();
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("data", data)).unwrap();
        mgr.scan_memory(&map);

        let ascii: Vec<_> = mgr
            .strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].value, "Hi\tthere\n");
    }

    #[test]
    fn utf16le_basic() {
        let mut mgr = StringsManager::default();
        // "Test" in UTF-16LE: T=0x0054, e=0x0065, s=0x0073, t=0x0074
        let data = vec![
            0x00, 0x00, // null
            0x54, 0x00, // T
            0x65, 0x00, // e
            0x73, 0x00, // s
            0x74, 0x00, // t
            0x00, 0x00, // null
        ];
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("data", data)).unwrap();
        mgr.scan_memory(&map);

        let utf16: Vec<_> = mgr
            .strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf16Le)
            .collect();
        assert_eq!(utf16.len(), 1);
        assert_eq!(utf16[0].value, "Test");
    }

    #[test]
    fn min_length_filter() {
        let mut mgr = StringsManager {
            min_length: 6,
            ..Default::default()
        };
        let data = b"\x00Hi\x00Hello World\x00".to_vec();
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("data", data)).unwrap();
        mgr.scan_memory(&map);

        let ascii: Vec<_> = mgr
            .strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].value, "Hello World");
    }

    #[test]
    fn end_of_segment_flush() {
        let mut mgr = StringsManager::default();
        // String at the very end of segment with no null terminator
        let data = b"\x00\x00TestEnd".to_vec();
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("data", data)).unwrap();
        mgr.scan_memory(&map);

        let ascii: Vec<_> = mgr
            .strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].value, "TestEnd");
    }
}
#[test]
fn test_macho_cstrings_in_executable_segment() {
    const BASE: u64 = 0x1000;
    const STRING_OFFSET: usize = 184;
    let mut data = vec![0; STRING_OFFSET];
    data.extend_from_slice(b"embedded literal\0unrelated code bytes\0");
    let mapped_size = data.len() as u64;

    // Header and one LC_SEGMENT_64 command with a single __cstring section.
    for (offset, value) in [
        (0, 0xfeed_facf_u32), // 64-bit magic
        (16, 1),              // one command
        (20, 152),            // segment command plus section header
        (32, 0x19),           // LC_SEGMENT_64
        (36, 152),            // command size
        (96, 1),              // one section
        (168, 2),             // S_CSTRING_LITERALS
    ] {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[40..46].copy_from_slice(b"__TEXT");
    data[56..64].copy_from_slice(&BASE.to_le_bytes());
    data[64..72].copy_from_slice(&mapped_size.to_le_bytes());
    data[104..113].copy_from_slice(b"__cstring");
    data[120..126].copy_from_slice(b"__TEXT");
    let address = BASE + STRING_OFFSET as u64;
    data[136..144].copy_from_slice(&address.to_le_bytes());
    data[144..152].copy_from_slice(&17_u64.to_le_bytes());

    let mut memory = MemoryMap::default();
    memory
        .add_segment(crate::memory::MemorySegment {
            name: "__TEXT".into(),
            start: BASE,
            size: mapped_size,
            data,
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
    let mut strings = StringsManager::default();
    strings.scan_memory(&memory);
    assert_eq!(strings.strings.len(), 1);
    assert_eq!(strings.strings[0].value, "embedded literal");
    assert_eq!(strings.strings[0].address, address);
    assert_eq!(strings.strings[0].section_name, "__cstring");

    strings.scan_macho_cstrings(&memory);
    assert_eq!(strings.strings.len(), 1);
}
