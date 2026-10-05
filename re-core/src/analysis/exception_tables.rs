//! PE exception-directory (`.pdata`) function table recovery.
//!
//! On Windows x64 the linker emits a `RUNTIME_FUNCTION` entry for every
//! function that has unwind data — in practice nearly every function — giving
//! its exact `[begin, end)` range. This table is the authoritative function
//! list for such binaries: heuristic prologue sweeps both invent functions
//! inside real ones (matching prologue byte patterns mid-instruction) and miss
//! most real starts.
//!
//! Only the x86-64 table layout is decoded here: a flat array of 12-byte
//! entries (BeginAddress, EndAddress, UnwindInfoAddress), each an RVA relative
//! to the image base. ARM64 `.pdata` uses a different, 8-byte packed layout
//! and is intentionally not handled yet.

use crate::memory::MemoryMap;

/// One `RUNTIME_FUNCTION` entry, rebased to absolute addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub start: u64,
    /// Exclusive end address (`BeginAddress + size`).
    pub end: u64,
    /// Absolute address of the `.xdata` unwind info blob.
    pub unwind_info: u64,
}

/// Outcome of applying an exception table to a [`crate::analysis::functions::FunctionManager`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionTableStats {
    /// Entries decoded from `.pdata`.
    pub entries: usize,
    /// Functions created for a start that had no record yet.
    pub added: usize,
    /// Existing functions that gained an authoritative `end_address`.
    pub sized: usize,
    /// Heuristic functions dropped because they start inside a real function.
    pub removed: usize,
}

/// Decode the x86-64 `.pdata` table of a PE image into absolute ranges.
///
/// Entries are dropped unless the whole `[start, end)` range lies in
/// executable memory: some linkers emit a sentinel entry for the image base,
/// and a malformed table must not be trusted for addresses the loader never
/// mapped as code. Returns an empty vector when there is no `.pdata` segment.
pub fn parse_pe_x64_runtime_functions(memory: &MemoryMap, image_base: u64) -> Vec<RuntimeFunction> {
    let Some(segment) = memory
        .segments
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(".pdata"))
    else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for chunk in segment.data.as_chunks::<12>().0 {
        let begin_rva = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end_rva = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let unwind_rva = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);

        let (Some(start), Some(end)) = (
            image_base.checked_add(begin_rva as u64),
            image_base.checked_add(end_rva as u64),
        ) else {
            continue;
        };
        if end <= start {
            continue;
        }
        if !memory.is_executable(start) || !memory.is_executable(end - 1) {
            continue;
        }
        if !seen.insert(start) {
            continue;
        }

        entries.push(RuntimeFunction {
            start,
            end,
            unwind_info: image_base.wrapping_add(unwind_rva as u64),
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    /// Build a map with a `.text` segment at 0x401000 (exec) and a `.pdata`
    /// segment holding the given 12-byte entries.
    fn memory_with_pdata(entries: &[[u32; 3]]) -> MemoryMap {
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x401000,
            size: 0x1000,
            data: vec![0x90; 0x1000],
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();

        let mut pdata = Vec::new();
        for e in entries {
            for v in e {
                pdata.extend_from_slice(&v.to_le_bytes());
            }
        }
        map.add_segment(MemorySegment {
            name: ".pdata".to_string(),
            start: 0x600000,
            size: pdata.len() as u64,
            data: pdata,
            permissions: Permissions::READ,
        })
        .unwrap();
        map
    }

    #[test]
    fn rebases_rvas_and_keeps_executable_ranges() {
        // RVAs into the .text segment: [0x1100, 0x1200) and [0x1300, 0x1304).
        let map = memory_with_pdata(&[[0x1100, 0x1200, 0x9000], [0x1300, 0x1304, 0x9100]]);
        let entries = parse_pe_x64_runtime_functions(&map, 0x400000);
        assert_eq!(
            entries,
            vec![
                RuntimeFunction {
                    start: 0x401100,
                    end: 0x401200,
                    unwind_info: 0x409000,
                },
                RuntimeFunction {
                    start: 0x401300,
                    end: 0x401304,
                    unwind_info: 0x409100,
                },
            ]
        );
    }

    #[test]
    fn drops_sentinel_and_out_of_segment_entries() {
        let map = memory_with_pdata(&[
            [0, 0x1000, 0x9000],      // sentinel at image base: not executable
            [0x2000, 0x2100, 0x9000], // beyond .text: not executable
            [0x1400, 0x1400, 0x9000], // empty range
            [0x1000, 0x1010, 0x9000], // valid
        ]);
        let entries = parse_pe_x64_runtime_functions(&map, 0x400000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, 0x401000);
        assert_eq!(entries[0].end, 0x401010);
    }

    #[test]
    fn ignores_partial_trailing_chunk() {
        let mut map = memory_with_pdata(&[[0x1000, 0x1010, 0x9000]]);
        let pdata = map
            .segments
            .iter_mut()
            .find(|s| s.name == ".pdata")
            .unwrap();
        pdata.data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        pdata.size = pdata.data.len() as u64;
        let entries = parse_pe_x64_runtime_functions(&map, 0x400000);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn no_pdata_segment_yields_empty() {
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x1000,
            size: 0x100,
            data: vec![0x90; 0x100],
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
        assert!(parse_pe_x64_runtime_functions(&map, 0).is_empty());
    }
}
