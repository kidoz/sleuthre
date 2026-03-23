pub mod patch;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::arch::Endianness;
use crate::error::Error;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Permissions: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySegment {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub permissions: Permissions,
}

impl MemorySegment {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryMap {
    pub segments: Vec<MemorySegment>,
}

impl MemoryMap {
    pub fn add_segment(&mut self, segment: MemorySegment) -> Result<()> {
        let new_start = segment.start;
        let new_end = segment.start.checked_add(segment.size).ok_or_else(|| {
            Error::Loader(format!(
                "Segment '{}' at 0x{:x} with size 0x{:x} overflows address space",
                segment.name, segment.start, segment.size,
            ))
        })?;

        for existing in &self.segments {
            let ex_start = existing.start;
            let ex_end = existing.end();
            if new_start < ex_end && new_end > ex_start {
                return Err(Error::Loader(format!(
                    "Segment '{}' [0x{:x}..0x{:x}) overlaps with '{}' [0x{:x}..0x{:x})",
                    segment.name, new_start, new_end, existing.name, ex_start, ex_end,
                )));
            }
        }

        let pos = self
            .segments
            .binary_search_by_key(&new_start, |s| s.start)
            .unwrap_or_else(|i| i);
        self.segments.insert(pos, segment);
        Ok(())
    }

    /// Find the segment index containing `address` using binary search.
    /// Segments are kept sorted by `start` via `add_segment`.
    fn find_segment(&self, address: u64) -> Option<usize> {
        self.segments
            .binary_search_by(|s| {
                if address < s.start {
                    std::cmp::Ordering::Greater
                } else if address >= s.start.saturating_add(s.size) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }

    pub fn get_data(&self, address: u64, size: usize) -> Option<&[u8]> {
        let end = address.checked_add(size as u64)?;
        let idx = self.find_segment(address)?;
        let segment = &self.segments[idx];
        let seg_end = segment.start.saturating_add(segment.size);
        if end <= seg_end {
            let offset = (address - segment.start) as usize;
            Some(&segment.data[offset..offset + size])
        } else {
            None
        }
    }

    pub fn contains_address(&self, address: u64) -> bool {
        self.find_segment(address).is_some()
    }

    /// Read a u16 value with endianness awareness
    pub fn read_u16(&self, address: u64, endian: Endianness) -> Option<u16> {
        let data = self.get_data(address, 2)?;
        Some(endian.read_u16(data))
    }

    /// Read a u32 value with endianness awareness
    pub fn read_u32(&self, address: u64, endian: Endianness) -> Option<u32> {
        let data = self.get_data(address, 4)?;
        Some(endian.read_u32(data))
    }

    /// Read a u64 value with endianness awareness
    pub fn read_u64(&self, address: u64, endian: Endianness) -> Option<u64> {
        let data = self.get_data(address, 8)?;
        Some(endian.read_u64(data))
    }

    /// Search for a byte pattern in all segments. Wildcards represented as None.
    pub fn search_bytes(&self, pattern: &[Option<u8>]) -> Vec<u64> {
        let mut results = Vec::new();
        if pattern.is_empty() {
            return results;
        }
        for segment in &self.segments {
            if segment.data.len() < pattern.len() {
                continue;
            }
            for i in 0..=segment.data.len() - pattern.len() {
                let mut matched = true;
                for (j, p) in pattern.iter().enumerate() {
                    if let Some(byte) = p
                        && segment.data[i + j] != *byte
                    {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    results.push(segment.start + i as u64);
                }
            }
        }
        results
    }

    /// Write bytes at the given virtual address.
    ///
    /// Returns an error if the address range is not fully contained within a
    /// single segment.
    pub fn write_data(&mut self, address: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = address
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::Analysis("write_data: address overflow".to_string()))?;
        if let Some(idx) = self.find_segment(address) {
            let segment = &mut self.segments[idx];
            let seg_end = segment.start.saturating_add(segment.size);
            if end <= seg_end {
                let offset = (address - segment.start) as usize;
                segment.data[offset..offset + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(Error::Analysis(format!(
            "write_data: address range 0x{:x}..0x{:x} is not within any segment",
            address, end,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_segment(name: &str, start: u64, size: u64) -> MemorySegment {
        MemorySegment {
            name: name.to_string(),
            start,
            size,
            data: vec![0u8; size as usize],
            permissions: Permissions::READ,
        }
    }

    #[test]
    fn non_overlapping_segments() {
        let mut map = MemoryMap::default();
        assert!(map.add_segment(make_segment("a", 0x1000, 0x100)).is_ok());
        assert!(map.add_segment(make_segment("b", 0x2000, 0x100)).is_ok());
    }

    #[test]
    fn overlapping_segments_rejected() {
        let mut map = MemoryMap::default();
        assert!(map.add_segment(make_segment("a", 0x1000, 0x200)).is_ok());
        assert!(map.add_segment(make_segment("b", 0x1100, 0x200)).is_err());
    }

    #[test]
    fn sorted_insertion() {
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("c", 0x3000, 0x100)).unwrap();
        map.add_segment(make_segment("a", 0x1000, 0x100)).unwrap();
        map.add_segment(make_segment("b", 0x2000, 0x100)).unwrap();
        assert_eq!(map.segments[0].start, 0x1000);
        assert_eq!(map.segments[1].start, 0x2000);
        assert_eq!(map.segments[2].start, 0x3000);
    }

    #[test]
    fn get_data_works() {
        let mut map = MemoryMap::default();
        let mut seg = make_segment("test", 0x1000, 4);
        seg.data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        map.add_segment(seg).unwrap();

        let data = map.get_data(0x1000, 4).unwrap();
        assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);

        assert!(map.get_data(0x2000, 4).is_none());
    }

    #[test]
    fn contains_address_works() {
        let mut map = MemoryMap::default();
        map.add_segment(make_segment("test", 0x1000, 0x100))
            .unwrap();
        assert!(map.contains_address(0x1000));
        assert!(map.contains_address(0x10FF));
        assert!(!map.contains_address(0x1100));
        assert!(!map.contains_address(0x0FFF));
    }

    #[test]
    fn write_data_works() {
        let mut map = MemoryMap::default();
        let seg = make_segment("test", 0x1000, 8);
        map.add_segment(seg).unwrap();

        // Write some bytes and verify
        map.write_data(0x1000, &[0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(map.get_data(0x1000, 3).unwrap(), &[0xAA, 0xBB, 0xCC]);

        // Write at an offset within the segment
        map.write_data(0x1004, &[0xDD, 0xEE]).unwrap();
        assert_eq!(map.get_data(0x1004, 2).unwrap(), &[0xDD, 0xEE]);

        // Untouched bytes remain zero
        assert_eq!(map.get_data(0x1003, 1).unwrap(), &[0x00]);

        // Writing out of range should fail
        assert!(map.write_data(0x2000, &[0x01]).is_err());

        // Writing that extends past segment end should fail
        assert!(map.write_data(0x1006, &[0x01, 0x02, 0x03]).is_err());

        // Writing empty data should succeed trivially
        assert!(map.write_data(0x9999, &[]).is_ok());
    }
}
