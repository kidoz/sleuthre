use serde::{Deserialize, Serialize};

use crate::memory::{MemoryMap, MemorySegment};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredConstant {
    pub address: u64,
    pub value_hex: String,
    pub description: String,
}

#[derive(Default)]
pub struct ConstantScanner {
    pub constants: Vec<DiscoveredConstant>,
}

// Standard CRC32 table first 4 entries (polynomial 0xEDB88320)
const CRC32_TABLE_HEAD: [u32; 4] = [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA];

// AES S-box first 16 bytes
const AES_SBOX_HEAD: [u8; 16] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
];

// AES inverse S-box first 16 bytes
const AES_INV_SBOX_HEAD: [u8; 16] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
];

impl ConstantScanner {
    pub fn scan(&mut self, memory: &MemoryMap) {
        self.constants.clear();
        for segment in &memory.segments {
            self.scan_crc32_table(segment);
            self.scan_aes_sbox(segment);
            self.scan_pointer_tables(segment, memory);
        }
    }

    fn scan_crc32_table(&mut self, segment: &MemorySegment) {
        let data = &segment.data;
        if data.len() < 16 {
            return;
        }
        for i in (0..data.len() - 15).step_by(4) {
            let mut matches = true;
            for (j, &expected) in CRC32_TABLE_HEAD.iter().enumerate() {
                let offset = i + j * 4;
                if offset + 4 > data.len() {
                    matches = false;
                    break;
                }
                let val = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                if val != expected {
                    matches = false;
                    break;
                }
            }
            if matches {
                self.constants.push(DiscoveredConstant {
                    address: segment.start + i as u64,
                    value_hex: format!("{:08X}", CRC32_TABLE_HEAD[0]),
                    description: "CRC32 lookup table (polynomial 0xEDB88320)".to_string(),
                });
            }
        }
    }

    fn scan_aes_sbox(&mut self, segment: &MemorySegment) {
        let data = &segment.data;
        if data.len() < 16 {
            return;
        }
        for i in 0..=data.len() - 16 {
            if data[i..i + 16] == AES_SBOX_HEAD {
                self.constants.push(DiscoveredConstant {
                    address: segment.start + i as u64,
                    value_hex: format!(
                        "{:02X}{:02X}{:02X}{:02X}",
                        data[i],
                        data[i + 1],
                        data[i + 2],
                        data[i + 3]
                    ),
                    description: "AES S-box".to_string(),
                });
            }
            if data[i..i + 16] == AES_INV_SBOX_HEAD {
                self.constants.push(DiscoveredConstant {
                    address: segment.start + i as u64,
                    value_hex: format!(
                        "{:02X}{:02X}{:02X}{:02X}",
                        data[i],
                        data[i + 1],
                        data[i + 2],
                        data[i + 3]
                    ),
                    description: "AES inverse S-box".to_string(),
                });
            }
        }
    }

    fn scan_pointer_tables(&mut self, segment: &MemorySegment, memory: &MemoryMap) {
        let data = &segment.data;
        // Try 8-byte pointers first then 4-byte
        for ptr_size in [8usize, 4] {
            if data.len() < ptr_size * 4 {
                continue;
            }
            let mut consecutive = 0u32;
            let mut table_start = 0usize;
            let mut i = 0;
            while i + ptr_size <= data.len() {
                let val = if ptr_size == 8 {
                    u64::from_le_bytes(data[i..i + 8].try_into().unwrap())
                } else {
                    u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as u64
                };

                if val != 0 && memory.contains_address(val) {
                    if consecutive == 0 {
                        table_start = i;
                    }
                    consecutive += 1;
                } else {
                    if consecutive >= 4 {
                        self.constants.push(DiscoveredConstant {
                            address: segment.start + table_start as u64,
                            value_hex: format!("{} entries, {}B pointers", consecutive, ptr_size),
                            description: format!(
                                "Pointer table ({} entries, {}-byte pointers)",
                                consecutive, ptr_size
                            ),
                        });
                    }
                    consecutive = 0;
                }
                i += ptr_size;
            }
            if consecutive >= 4 {
                self.constants.push(DiscoveredConstant {
                    address: segment.start + table_start as u64,
                    value_hex: format!("{} entries, {}B pointers", consecutive, ptr_size),
                    description: format!(
                        "Pointer table ({} entries, {}-byte pointers)",
                        consecutive, ptr_size
                    ),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    fn make_segment(start: u64, data: Vec<u8>) -> MemorySegment {
        let size = data.len() as u64;
        MemorySegment {
            name: "test".to_string(),
            start,
            size,
            data,
            permissions: Permissions::READ,
        }
    }

    #[test]
    fn crc32_detection() {
        let mut data = Vec::new();
        for &val in &CRC32_TABLE_HEAD {
            data.extend_from_slice(&val.to_le_bytes());
        }
        data.resize(32, 0);

        let mut map = MemoryMap::default();
        map.add_segment(make_segment(0x1000, data)).unwrap();

        let mut scanner = ConstantScanner::default();
        scanner.scan(&map);

        let crc = scanner
            .constants
            .iter()
            .filter(|c| c.description.contains("CRC32"))
            .count();
        assert_eq!(crc, 1);
        assert_eq!(scanner.constants[0].address, 0x1000);
    }

    #[test]
    fn aes_sbox_detection() {
        let mut data = AES_SBOX_HEAD.to_vec();
        data.resize(32, 0);

        let mut map = MemoryMap::default();
        map.add_segment(make_segment(0x2000, data)).unwrap();

        let mut scanner = ConstantScanner::default();
        scanner.scan(&map);

        let aes = scanner
            .constants
            .iter()
            .filter(|c| c.description.contains("AES S-box"))
            .count();
        assert_eq!(aes, 1);
    }

    #[test]
    fn pointer_table_detection() {
        // Create a segment that contains addresses, and another segment those addresses point to
        let mut map = MemoryMap::default();
        map.add_segment(make_segment(0x4000, vec![0u8; 0x100]))
            .unwrap();

        // Build a table of 5 pointers pointing into 0x4000..0x40FF
        let mut table_data = Vec::new();
        for i in 0..5u64 {
            table_data.extend_from_slice(&(0x4000 + i * 0x10).to_le_bytes());
        }
        table_data.resize(64, 0);

        map.add_segment(make_segment(0x5000, table_data)).unwrap();

        let mut scanner = ConstantScanner::default();
        scanner.scan(&map);

        let ptrs = scanner
            .constants
            .iter()
            .filter(|c| c.description.contains("Pointer table"))
            .count();
        assert!(
            ptrs >= 1,
            "Expected pointer table, got {:?}",
            scanner.constants
        );
    }
}
