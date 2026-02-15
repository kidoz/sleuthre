use serde::{Deserialize, Serialize};

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
}

impl Default for StringsManager {
    fn default() -> Self {
        Self {
            strings: Vec::new(),
            min_length: 4,
        }
    }
}

impl StringsManager {
    pub fn scan_memory(&mut self, memory: &crate::memory::MemoryMap) {
        self.strings.clear();
        for segment in &memory.segments {
            self.scan_ascii(segment);
            self.scan_utf16le(segment);
            self.scan_utf16be(segment);
        }
    }

    fn is_printable_ascii(byte: u8) -> bool {
        (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
    }

    fn scan_ascii(&mut self, segment: &crate::memory::MemorySegment) {
        let mut current_string = Vec::new();
        let mut start_addr = 0u64;

        for (offset, &byte) in segment.data.iter().enumerate() {
            if Self::is_printable_ascii(byte) {
                if current_string.is_empty() {
                    start_addr = segment.start + offset as u64;
                }
                current_string.push(byte);
            } else {
                if current_string.len() >= self.min_length
                    && let Ok(value) = String::from_utf8(current_string.clone())
                {
                    self.strings.push(DiscoveredString {
                        address: start_addr,
                        value,
                        length: current_string.len(),
                        section_name: segment.name.clone(),
                        encoding: StringEncoding::Ascii,
                    });
                }
                current_string.clear();
            }
        }

        // Flush buffer at end of segment
        if current_string.len() >= self.min_length
            && let Ok(value) = String::from_utf8(current_string.clone())
        {
            self.strings.push(DiscoveredString {
                address: start_addr,
                value,
                length: current_string.len(),
                section_name: segment.name.clone(),
                encoding: StringEncoding::Ascii,
            });
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
