use crate::arch::{Architecture, Endianness};
use crate::memory::MemoryMap;

/// A discovered vtable in the binary.
#[derive(Debug, Clone)]
pub struct VTable {
    /// Address of the vtable in memory
    pub address: u64,
    /// Ordered list of function pointers in the vtable
    pub entries: Vec<u64>,
    /// Matched COM/C++ interface name, if identified
    pub interface_name: Option<String>,
    /// Method names resolved from a known interface
    pub method_names: Vec<Option<String>>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

/// A known COM/C++ interface definition for matching.
#[derive(Debug, Clone)]
pub struct KnownInterface {
    pub name: String,
    pub method_names: Vec<String>,
    pub method_count: usize,
}

/// Result of vtable analysis.
#[derive(Debug, Default)]
pub struct VTableAnalysisResult {
    pub vtables: Vec<VTable>,
    pub resolved_calls: Vec<ResolvedIndirectCall>,
}

/// A resolved indirect call through a vtable.
#[derive(Debug, Clone)]
pub struct ResolvedIndirectCall {
    /// Address of the call instruction
    pub call_address: u64,
    /// The vtable used
    pub vtable_address: u64,
    /// Offset into the vtable
    pub vtable_offset: u64,
    /// Resolved target function address
    pub target_address: u64,
    /// Resolved method name if interface is known
    pub method_name: Option<String>,
}

/// Build the database of known COM interfaces for matching.
pub fn known_com_interfaces() -> Vec<KnownInterface> {
    vec![
        KnownInterface {
            name: "IUnknown".to_string(),
            method_names: vec!["QueryInterface".into(), "AddRef".into(), "Release".into()],
            method_count: 3,
        },
        KnownInterface {
            name: "IDirectDraw".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "Compact".into(),
                "CreateClipper".into(),
                "CreatePalette".into(),
                "CreateSurface".into(),
                "DuplicateSurface".into(),
                "EnumDisplayModes".into(),
                "EnumSurfaces".into(),
                "FlipToGDISurface".into(),
                "GetCaps".into(),
                "GetDisplayMode".into(),
                "GetFourCCCodes".into(),
                "GetGDISurface".into(),
                "GetMonitorFrequency".into(),
                "GetScanLine".into(),
                "GetVerticalBlankStatus".into(),
                "Initialize".into(),
                "RestoreDisplayMode".into(),
                "SetCooperativeLevel".into(),
                "SetDisplayMode".into(),
                "WaitForVerticalBlank".into(),
            ],
            method_count: 23,
        },
        KnownInterface {
            name: "IDirectDraw4".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "Compact".into(),
                "CreateClipper".into(),
                "CreatePalette".into(),
                "CreateSurface".into(),
                "DuplicateSurface".into(),
                "EnumDisplayModes".into(),
                "EnumSurfaces".into(),
                "FlipToGDISurface".into(),
                "GetCaps".into(),
                "GetDisplayMode".into(),
                "GetFourCCCodes".into(),
                "GetGDISurface".into(),
                "GetMonitorFrequency".into(),
                "GetScanLine".into(),
                "GetVerticalBlankStatus".into(),
                "Initialize".into(),
                "RestoreDisplayMode".into(),
                "SetCooperativeLevel".into(),
                "SetDisplayMode".into(),
                "WaitForVerticalBlank".into(),
                "GetAvailableVidMem".into(),
                "GetSurfaceFromDC".into(),
                "RestoreAllSurfaces".into(),
                "TestCooperativeLevel".into(),
                "GetDeviceIdentifier".into(),
            ],
            method_count: 28,
        },
        KnownInterface {
            name: "IDirectDrawSurface4".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "AddAttachedSurface".into(),
                "AddOverlayDirtyRect".into(),
                "Blt".into(),
                "BltBatch".into(),
                "BltFast".into(),
                "DeleteAttachedSurface".into(),
                "EnumAttachedSurfaces".into(),
                "EnumOverlayZOrders".into(),
                "Flip".into(),
                "GetAttachedSurface".into(),
                "GetBltStatus".into(),
                "GetCaps".into(),
                "GetClipper".into(),
                "GetColorKey".into(),
                "GetDC".into(),
                "GetFlipStatus".into(),
                "GetOverlayPosition".into(),
                "GetPalette".into(),
                "GetPixelFormat".into(),
                "GetSurfaceDesc".into(),
                "Initialize".into(),
                "IsLost".into(),
                "Lock".into(),
                "ReleaseDC".into(),
                "Restore".into(),
                "SetClipper".into(),
                "SetColorKey".into(),
                "SetOverlayPosition".into(),
                "SetPalette".into(),
                "Unlock".into(),
                "UpdateOverlay".into(),
                "UpdateOverlayDisplay".into(),
                "UpdateOverlayZOrder".into(),
                "GetDDInterface".into(),
                "PageLock".into(),
                "PageUnlock".into(),
                "SetSurfaceDesc".into(),
                "SetPrivateData".into(),
                "GetPrivateData".into(),
                "FreePrivateData".into(),
                "GetUniquenessValue".into(),
                "ChangeUniquenessValue".into(),
            ],
            method_count: 45,
        },
        KnownInterface {
            name: "IDirectSound".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "CreateSoundBuffer".into(),
                "GetCaps".into(),
                "DuplicateSoundBuffer".into(),
                "SetCooperativeLevel".into(),
                "Compact".into(),
                "GetSpeakerConfig".into(),
                "SetSpeakerConfig".into(),
                "Initialize".into(),
            ],
            method_count: 11,
        },
        KnownInterface {
            name: "IDirectSoundBuffer".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "GetCaps".into(),
                "GetCurrentPosition".into(),
                "GetFormat".into(),
                "GetVolume".into(),
                "GetPan".into(),
                "GetFrequency".into(),
                "GetStatus".into(),
                "Initialize".into(),
                "Lock".into(),
                "Play".into(),
                "SetCurrentPosition".into(),
                "SetFormat".into(),
                "SetVolume".into(),
                "SetPan".into(),
                "SetFrequency".into(),
                "Stop".into(),
                "Unlock".into(),
                "Restore".into(),
            ],
            method_count: 21,
        },
        KnownInterface {
            name: "IDirectInput".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "CreateDevice".into(),
                "EnumDevices".into(),
                "GetDeviceStatus".into(),
                "RunControlPanel".into(),
                "Initialize".into(),
            ],
            method_count: 8,
        },
        KnownInterface {
            name: "IDirectInputDevice".to_string(),
            method_names: vec![
                "QueryInterface".into(),
                "AddRef".into(),
                "Release".into(),
                "GetCapabilities".into(),
                "EnumObjects".into(),
                "GetProperty".into(),
                "SetProperty".into(),
                "Acquire".into(),
                "Unacquire".into(),
                "GetDeviceState".into(),
                "GetDeviceData".into(),
                "SetDataFormat".into(),
                "SetEventNotification".into(),
                "SetCooperativeLevel".into(),
                "GetObjectInfo".into(),
                "GetDeviceInfo".into(),
                "RunControlPanel".into(),
                "Initialize".into(),
            ],
            method_count: 18,
        },
    ]
}

/// Scan memory for potential vtables — arrays of code pointers in read-only data.
pub fn scan_for_vtables(memory: &MemoryMap, arch: Architecture) -> Vec<VTable> {
    let endian = arch.default_endianness();
    let ptr_size: u64 = match arch {
        Architecture::X86_64
        | Architecture::Arm64
        | Architecture::Mips64
        | Architecture::RiscV64 => 8,
        _ => 4,
    };
    let min_entries = 3u64; // minimum vtable size (IUnknown = 3)
    let max_entries = 256u64; // sanity limit

    // Find executable address ranges for validation
    let exec_ranges: Vec<(u64, u64)> = memory
        .segments
        .iter()
        .filter(|s| s.permissions.contains(crate::memory::Permissions::EXECUTE))
        .map(|s| (s.start, s.start + s.size))
        .collect();

    let is_code_ptr = |addr: u64| -> bool {
        exec_ranges
            .iter()
            .any(|(start, end)| addr >= *start && addr < *end)
    };

    // Scan read-only and data segments for arrays of code pointers
    let mut vtables = Vec::new();

    for segment in &memory.segments {
        // Skip executable segments (vtables live in .rdata/.data, not .text)
        if segment
            .permissions
            .contains(crate::memory::Permissions::EXECUTE)
        {
            continue;
        }

        let mut offset = 0u64;
        while offset + ptr_size <= segment.size {
            let addr = segment.start + offset;

            // Read pointer-sized value
            let ptr_val = read_ptr(memory, addr, ptr_size, endian);
            let Some(ptr_val) = ptr_val else {
                offset += ptr_size;
                continue;
            };

            if !is_code_ptr(ptr_val) {
                offset += ptr_size;
                continue;
            }

            // Found a code pointer — scan forward for consecutive code pointers
            let mut entries = vec![ptr_val];
            let mut scan_offset = offset + ptr_size;

            while scan_offset + ptr_size <= segment.size && (entries.len() as u64) < max_entries {
                let next_addr = segment.start + scan_offset;
                let Some(next_ptr) = read_ptr(memory, next_addr, ptr_size, endian) else {
                    break;
                };
                if !is_code_ptr(next_ptr) {
                    break;
                }
                entries.push(next_ptr);
                scan_offset += ptr_size;
            }

            if entries.len() as u64 >= min_entries {
                let confidence = if entries.len() >= 10 {
                    0.9
                } else if entries.len() >= 5 {
                    0.7
                } else {
                    0.5
                };

                vtables.push(VTable {
                    address: addr,
                    entries: entries.clone(),
                    interface_name: None,
                    method_names: vec![None; entries.len()],
                    confidence,
                });

                // Skip past this vtable to avoid overlapping detections
                offset = scan_offset;
            } else {
                offset += ptr_size;
            }
        }
    }

    vtables
}

/// Match discovered vtables against known COM interfaces.
pub fn match_interfaces(vtables: &mut [VTable], known: &[KnownInterface]) {
    for vtable in vtables.iter_mut() {
        for iface in known {
            if vtable.entries.len() == iface.method_count {
                // Exact method count match — high confidence
                vtable.interface_name = Some(iface.name.clone());
                vtable.method_names = iface.method_names.iter().map(|n| Some(n.clone())).collect();
                vtable.confidence = 0.95;
                break;
            } else if vtable.entries.len() > iface.method_count
                && iface.method_count >= 3
                && vtable.entries.len() <= iface.method_count + 5
            {
                // Close match — could be a derived interface
                // Only label the known methods
                vtable.interface_name = Some(format!("{}+", iface.name));
                vtable.method_names = (0..vtable.entries.len())
                    .map(|i| {
                        if i < iface.method_names.len() {
                            Some(iface.method_names[i].clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                vtable.confidence = 0.6;
                // Don't break — a better match might exist
            }
        }
    }
}

/// Resolve an indirect call `call [reg+offset]` if the vtable is known.
pub fn resolve_indirect_call(
    vtable: &VTable,
    offset: u64,
    ptr_size: u64,
) -> Option<ResolvedIndirectCall> {
    let index = (offset / ptr_size) as usize;
    if index >= vtable.entries.len() {
        return None;
    }
    Some(ResolvedIndirectCall {
        call_address: 0, // caller fills this in
        vtable_address: vtable.address,
        vtable_offset: offset,
        target_address: vtable.entries[index],
        method_name: vtable.method_names.get(index).cloned().flatten(),
    })
}

/// Run the full vtable analysis pass.
pub fn analyze_vtables(memory: &MemoryMap, arch: Architecture) -> VTableAnalysisResult {
    let mut vtables = scan_for_vtables(memory, arch);
    let known = known_com_interfaces();
    match_interfaces(&mut vtables, &known);

    VTableAnalysisResult {
        vtables,
        resolved_calls: Vec::new(),
    }
}

/// For every discovered vtable that matched a known interface (e.g.
/// `IDirectDraw7`) populate the corresponding `ClassInfo` entry's
/// `vtable_address` if it is not already set. Creates a fresh `ClassInfo` if
/// no class with that name is declared yet — analysts often discover the
/// vtable before they get around to declaring the class manually.
///
/// Returns the number of classes that were either linked or freshly created.
pub fn auto_link_vtables_to_classes(
    result: &VTableAnalysisResult,
    types: &mut crate::types::TypeManager,
) -> usize {
    let mut linked = 0usize;
    for vt in &result.vtables {
        let Some(ref iface) = vt.interface_name else {
            continue;
        };
        let entry = types.classes.entry(iface.clone()).or_default();
        if entry.vtable_address.is_none() {
            entry.vtable_address = Some(vt.address);
            entry.vtable_label = Some(format!("vtable_{}", iface));
            linked += 1;
        }
    }
    linked
}

fn read_ptr(memory: &MemoryMap, addr: u64, ptr_size: u64, endian: Endianness) -> Option<u64> {
    if ptr_size == 8 {
        memory.read_u64(addr, endian)
    } else {
        memory.read_u32(addr, endian).map(|v| v as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn known_com_interfaces_not_empty() {
        let ifaces = known_com_interfaces();
        assert!(!ifaces.is_empty());
        // IUnknown should always be first and have 3 methods
        assert_eq!(ifaces[0].name, "IUnknown");
        assert_eq!(ifaces[0].method_count, 3);
    }

    #[test]
    fn scan_finds_vtable_in_rdata() {
        let mut memory = MemoryMap::default();

        // .text segment with code addresses
        let text = MemorySegment {
            name: ".text".to_string(),
            start: 0x401000,
            size: 0x1000,
            data: vec![0xCC; 0x1000],
            permissions: Permissions::READ | Permissions::EXECUTE,
        };
        memory.add_segment(text).unwrap();

        // .rdata with a vtable: 5 pointers into .text
        let mut rdata_data = Vec::new();
        for i in 0u32..5 {
            rdata_data.extend_from_slice(&(0x401000u32 + i * 0x100).to_le_bytes());
        }
        // Followed by zero (non-code pointer) to terminate
        rdata_data.extend_from_slice(&[0u8; 4]);

        let rdata = MemorySegment {
            name: ".rdata".to_string(),
            start: 0x402000,
            size: rdata_data.len() as u64,
            data: rdata_data,
            permissions: Permissions::READ,
        };
        memory.add_segment(rdata).unwrap();

        let vtables = scan_for_vtables(&memory, Architecture::X86);
        assert!(!vtables.is_empty());
        assert_eq!(vtables[0].entries.len(), 5);
        assert_eq!(vtables[0].address, 0x402000);
    }

    #[test]
    fn match_iunknown() {
        let mut vtables = vec![VTable {
            address: 0x1000,
            entries: vec![0x2000, 0x2100, 0x2200],
            interface_name: None,
            method_names: vec![None; 3],
            confidence: 0.5,
        }];

        let known = known_com_interfaces();
        match_interfaces(&mut vtables, &known);

        assert_eq!(vtables[0].interface_name.as_deref(), Some("IUnknown"));
        assert_eq!(
            vtables[0].method_names[0].as_deref(),
            Some("QueryInterface")
        );
        assert_eq!(vtables[0].method_names[1].as_deref(), Some("AddRef"));
        assert_eq!(vtables[0].method_names[2].as_deref(), Some("Release"));
    }

    #[test]
    fn resolve_indirect_call_works() {
        let vtable = VTable {
            address: 0x1000,
            entries: vec![0x2000, 0x2100, 0x2200],
            interface_name: Some("IUnknown".to_string()),
            method_names: vec![
                Some("QueryInterface".into()),
                Some("AddRef".into()),
                Some("Release".into()),
            ],
            confidence: 0.95,
        };

        // call [reg+8] → index 2 with 4-byte pointers
        let result = resolve_indirect_call(&vtable, 8, 4).unwrap();
        assert_eq!(result.target_address, 0x2200);
        assert_eq!(result.method_name.as_deref(), Some("Release"));

        // Out of bounds
        assert!(resolve_indirect_call(&vtable, 12, 4).is_none());
    }

    #[test]
    fn auto_link_creates_or_updates_class_info() {
        let result = VTableAnalysisResult {
            vtables: vec![
                VTable {
                    address: 0x404010,
                    entries: vec![0x401000, 0x401010, 0x401020],
                    interface_name: Some("IUnknown".into()),
                    method_names: vec![None; 3],
                    confidence: 1.0,
                },
                VTable {
                    address: 0x404100,
                    entries: vec![],
                    interface_name: None, // unknown — should be skipped
                    method_names: vec![],
                    confidence: 0.5,
                },
            ],
            resolved_calls: Vec::new(),
        };
        let mut types = crate::types::TypeManager::default();
        let n = auto_link_vtables_to_classes(&result, &mut types);
        assert_eq!(n, 1, "only the matched vtable should produce a link");
        let cls = types.classes.get("IUnknown").unwrap();
        assert_eq!(cls.vtable_address, Some(0x404010));
        assert_eq!(cls.vtable_label.as_deref(), Some("vtable_IUnknown"));
    }

    #[test]
    fn auto_link_does_not_overwrite_existing_address() {
        let result = VTableAnalysisResult {
            vtables: vec![VTable {
                address: 0x500000,
                entries: vec![],
                interface_name: Some("IUnknown".into()),
                method_names: vec![],
                confidence: 1.0,
            }],
            resolved_calls: Vec::new(),
        };
        let mut types = crate::types::TypeManager::default();
        types.classes.insert(
            "IUnknown".into(),
            crate::types::ClassInfo {
                base: None,
                vtable_label: Some("user_label".into()),
                vtable_address: Some(0x123),
            },
        );
        let n = auto_link_vtables_to_classes(&result, &mut types);
        assert_eq!(n, 0, "user-supplied address must not be clobbered");
        assert_eq!(types.classes["IUnknown"].vtable_address, Some(0x123));
    }
}
