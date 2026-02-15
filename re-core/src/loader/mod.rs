use crate::Result;
use crate::arch::{Architecture, Endianness};
use crate::error::Error;
use crate::memory::{MemoryMap, MemorySegment, Permissions};
use goblin::{Object, elf, mach, pe};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The format of a loaded binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Object,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub library: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
}

#[derive(Debug)]
pub struct LoadedBinary {
    pub memory_map: MemoryMap,
    pub entry_point: u64,
    pub arch: Architecture,
    pub endianness: Endianness,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub libraries: Vec<String>,
    pub format: BinaryFormat,
    pub debug_info_path: Option<PathBuf>,
}

pub fn load_binary(path: &Path) -> Result<LoadedBinary> {
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    load_binary_from_bytes(&bytes)
}

pub fn load_binary_from_bytes(bytes: &[u8]) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Loader("Empty input".to_string()));
    }
    match Object::parse(bytes).map_err(|e| Error::Loader(e.to_string()))? {
        Object::Elf(elf) => load_elf(elf, bytes),
        Object::PE(pe) => load_pe(pe, bytes),
        Object::Mach(mach) => load_mach(mach, bytes),
        _ => Err(Error::Loader("Unsupported binary format".to_string())),
    }
}

fn detect_elf_arch(elf: &elf::Elf) -> Result<Architecture> {
    match elf.header.e_machine {
        elf::header::EM_386 => Ok(Architecture::X86),
        elf::header::EM_X86_64 => Ok(Architecture::X86_64),
        elf::header::EM_ARM => Ok(Architecture::Arm),
        elf::header::EM_AARCH64 => Ok(Architecture::Arm64),
        elf::header::EM_MIPS => {
            if elf.header.e_ident[elf::header::EI_CLASS] == elf::header::ELFCLASS64 {
                Ok(Architecture::Mips64)
            } else {
                Ok(Architecture::Mips)
            }
        }
        other => Err(Error::Loader(format!(
            "Unsupported ELF architecture: e_machine=0x{:x}",
            other
        ))),
    }
}

fn detect_pe_arch(pe: &pe::PE) -> Result<Architecture> {
    use goblin::pe::header::*;
    match pe.header.coff_header.machine {
        COFF_MACHINE_X86_64 => Ok(Architecture::X86_64),
        COFF_MACHINE_X86 => Ok(Architecture::X86),
        COFF_MACHINE_ARM64 => Ok(Architecture::Arm64),
        COFF_MACHINE_ARMNT => Ok(Architecture::Arm),
        other => Err(Error::Loader(format!(
            "Unsupported PE architecture: machine=0x{:x}",
            other
        ))),
    }
}

fn extract_elf_symbols(elf: &elf::Elf) -> Vec<Symbol> {
    let mut symbols = Vec::new();

    // Process both .symtab and .dynsym
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
            .unwrap_or("");
        if name.is_empty() || sym.st_value == 0 {
            continue;
        }
        let kind = match sym.st_type() {
            elf::sym::STT_FUNC => SymbolKind::Function,
            elf::sym::STT_OBJECT => SymbolKind::Object,
            _ => SymbolKind::Other,
        };
        symbols.push(Symbol {
            name: name.to_string(),
            address: sym.st_value,
            size: sym.st_size,
            kind,
        });
    }

    // Deduplicate by address, preferring Function kind
    symbols.sort_by_key(|s| s.address);
    symbols.dedup_by(|a, b| {
        if a.address == b.address {
            // Keep the one with better kind (Function > Object > Other)
            if a.kind == SymbolKind::Function {
                b.kind = SymbolKind::Function;
                b.name = a.name.clone();
            }
            true
        } else {
            false
        }
    });

    symbols
}

fn extract_elf_imports(elf: &elf::Elf) -> (Vec<Import>, Vec<String>) {
    let mut imports = Vec::new();
    let mut libraries = Vec::new();

    // Extract DT_NEEDED libraries
    for lib in &elf.libraries {
        libraries.push(lib.to_string());
    }

    // Extract imported symbols from .dynsym that are undefined (st_shndx == SHN_UNDEF)
    for (sym_index, sym) in elf.dynsyms.iter().enumerate() {
        if sym.st_shndx == 0usize && sym.st_type() == elf::sym::STT_FUNC {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            // Try to get PLT address from relocations
            let mut addr = sym.st_value;
            if addr == 0 {
                // Search relocations for this symbol by its dynsym index
                for reloc in elf.pltrelocs.iter() {
                    if reloc.r_sym == sym_index {
                        addr = reloc.r_offset;
                        break;
                    }
                }
            }
            imports.push(Import {
                name: name.to_string(),
                library: String::new(), // ELF doesn't directly associate imports with specific libs
                address: addr,
            });
        }
    }

    (imports, libraries)
}

fn extract_elf_exports(elf: &elf::Elf) -> Vec<Export> {
    let mut exports = Vec::new();

    // Dynamic symbols with global/weak binding that are defined (not UND)
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx != 0usize
            && (sym.st_bind() == elf::sym::STB_GLOBAL || sym.st_bind() == elf::sym::STB_WEAK)
            && sym.st_value != 0
        {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            exports.push(Export {
                name: name.to_string(),
                address: sym.st_value,
            });
        }
    }

    exports
}

fn detect_elf_endianness(elf: &elf::Elf) -> Endianness {
    if elf.header.e_ident[elf::header::EI_DATA] == elf::header::ELFDATA2MSB {
        Endianness::Big
    } else {
        Endianness::Little
    }
}

/// Maximum virtual segment size we'll allocate (256 MB).
const MAX_SEGMENT_SIZE: u64 = 256 * 1024 * 1024;

fn load_elf(elf: elf::Elf, bytes: &[u8]) -> Result<LoadedBinary> {
    let arch = detect_elf_arch(&elf)?;
    let endianness = detect_elf_endianness(&elf);
    let mut memory_map = MemoryMap::default();

    for header in elf.program_headers.iter() {
        if header.p_type == elf::program_header::PT_LOAD {
            let mut perms = Permissions::empty();
            if header.is_read() {
                perms.insert(Permissions::READ);
            }
            if header.is_write() {
                perms.insert(Permissions::WRITE);
            }
            if header.is_executable() {
                perms.insert(Permissions::EXECUTE);
            }

            let start = header.p_vaddr;
            let size = header.p_memsz;
            let file_offset = header.p_offset as usize;
            let file_size = header.p_filesz as usize;

            if size > MAX_SEGMENT_SIZE {
                return Err(Error::Loader(format!(
                    "ELF segment at 0x{:x} has virtual size 0x{:x} exceeding limit",
                    start, size,
                )));
            }

            let mut data = vec![0u8; size as usize];
            let end_offset = file_offset.saturating_add(file_size);
            if end_offset <= bytes.len() {
                data[..file_size].copy_from_slice(&bytes[file_offset..end_offset]);
            }

            memory_map.add_segment(MemorySegment {
                name: format!("segment_{:x}", start),
                start,
                size,
                data,
                permissions: perms,
            })?;
        }
    }

    let symbols = extract_elf_symbols(&elf);
    let (imports, libraries) = extract_elf_imports(&elf);
    let exports = extract_elf_exports(&elf);

    Ok(LoadedBinary {
        memory_map,
        entry_point: elf.entry,
        arch,
        endianness,
        symbols,
        imports,
        exports,
        libraries,
        format: BinaryFormat::Elf,
        debug_info_path: None,
    })
}

fn load_pe(pe: pe::PE, bytes: &[u8]) -> Result<LoadedBinary> {
    let arch = detect_pe_arch(&pe)?;
    let mut memory_map = MemoryMap::default();
    let image_base = pe.image_base as u64;

    for section in pe.sections.iter() {
        let mut perms = Permissions::empty();
        let characteristics = section.characteristics;
        if characteristics & pe::section_table::IMAGE_SCN_MEM_READ != 0 {
            perms.insert(Permissions::READ);
        }
        if characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
            perms.insert(Permissions::WRITE);
        }
        if characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
            perms.insert(Permissions::EXECUTE);
        }

        let start = image_base + section.virtual_address as u64;
        let virtual_size = section.virtual_size as usize;
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;

        let buf_size = virtual_size.max(raw_size);
        if buf_size as u64 > MAX_SEGMENT_SIZE {
            return Err(Error::Loader(format!(
                "PE section at 0x{:x} has size 0x{:x} exceeding limit",
                start, buf_size,
            )));
        }
        let mut buffer = vec![0u8; buf_size];

        let copy_size = raw_size.min(bytes.len().saturating_sub(raw_offset));
        if copy_size > 0 && raw_offset < bytes.len() {
            buffer[..copy_size].copy_from_slice(&bytes[raw_offset..raw_offset + copy_size]);
        }

        memory_map.add_segment(MemorySegment {
            name: section.name().unwrap_or("unknown").to_string(),
            start,
            size: buf_size as u64,
            data: buffer,
            permissions: perms,
        })?;
    }

    // Extract PE imports
    let mut imports = Vec::new();
    for import in &pe.imports {
        imports.push(Import {
            name: import.name.to_string(),
            library: import.dll.to_string(),
            address: image_base + import.rva as u64,
        });
    }

    // Extract PE exports
    let mut exports = Vec::new();
    for exp in &pe.exports {
        if let Some(ref name) = exp.name {
            exports.push(Export {
                name: name.to_string(),
                address: image_base + exp.rva as u64,
            });
        } else if let Some(offset) = exp.offset {
            exports.push(Export {
                name: format!("ordinal_{}", exp.rva),
                address: image_base + offset as u64,
            });
        }
    }

    // PE doesn't have a symbol table in the same way, but we can create symbols from exports
    let mut symbols = Vec::new();
    for exp in &exports {
        symbols.push(Symbol {
            name: exp.name.clone(),
            address: exp.address,
            size: 0,
            kind: SymbolKind::Function,
        });
    }

    // Extract library names from imports
    let mut libraries: Vec<String> = pe.imports.iter().map(|i| i.dll.to_string()).collect();
    libraries.sort();
    libraries.dedup();

    // Try to find PDB path from PE debug directory
    let pdb_path = extract_pe_pdb_path(&pe);

    Ok(LoadedBinary {
        memory_map,
        entry_point: pe.entry as u64 + image_base,
        arch,
        endianness: Endianness::Little, // PE is always little-endian
        symbols,
        imports,
        exports,
        libraries,
        format: BinaryFormat::Pe,
        debug_info_path: pdb_path,
    })
}

fn extract_pe_pdb_path(pe: &pe::PE) -> Option<PathBuf> {
    if let Some(ref debug_data) = pe.debug_data
        && let Some(ref codeview) = debug_data.codeview_pdb70_debug_info
    {
        let filename = String::from_utf8_lossy(codeview.filename);
        let filename = filename.trim_end_matches('\0');
        if !filename.is_empty() {
            return Some(PathBuf::from(filename));
        }
    }
    None
}

fn load_mach(mach: mach::Mach, bytes: &[u8]) -> Result<LoadedBinary> {
    match mach {
        mach::Mach::Binary(macho) => load_macho_single(macho, bytes),
        mach::Mach::Fat(fat) => {
            // For fat binaries, pick the first architecture
            for i in 0..fat.narches {
                if let Ok(mach::SingleArch::MachO(macho)) = fat.get(i) {
                    return load_macho_single(macho, bytes);
                }
            }
            Err(Error::Loader(
                "No usable architecture in fat binary".to_string(),
            ))
        }
    }
}

fn detect_macho_arch(macho: &mach::MachO) -> Result<Architecture> {
    use mach::cputype::*;
    match macho.header.cputype() {
        CPU_TYPE_X86 => Ok(Architecture::X86),
        CPU_TYPE_X86_64 => Ok(Architecture::X86_64),
        CPU_TYPE_ARM => Ok(Architecture::Arm),
        CPU_TYPE_ARM64 => Ok(Architecture::Arm64),
        other => Err(Error::Loader(format!(
            "Unsupported Mach-O architecture: cputype=0x{:x}",
            other
        ))),
    }
}

fn load_macho_single(macho: mach::MachO, bytes: &[u8]) -> Result<LoadedBinary> {
    let arch = detect_macho_arch(&macho)?;
    let endianness = if macho.little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };

    let mut memory_map = MemoryMap::default();

    // Load segments from load commands
    for seg in &macho.segments {
        let name = seg.name().unwrap_or("unknown").to_string();
        let vm_addr = seg.vmaddr;
        let vm_size = seg.vmsize;
        let file_off = seg.fileoff as usize;
        let file_size = seg.filesize as usize;

        let mut perms = Permissions::READ;
        let initprot = seg.initprot;
        if initprot & 0x2 != 0 {
            perms.insert(Permissions::WRITE);
        }
        if initprot & 0x4 != 0 {
            perms.insert(Permissions::EXECUTE);
        }

        if vm_size == 0 {
            continue;
        }
        if vm_size > MAX_SEGMENT_SIZE {
            // Skip __PAGEZERO or similar non-backed segments that are too large
            if file_size == 0 && initprot == 0 {
                continue;
            }
            return Err(Error::Loader(format!(
                "Mach-O segment '{}' at 0x{:x} has virtual size 0x{:x} exceeding limit",
                name, vm_addr, vm_size,
            )));
        }

        let mut data = vec![0u8; vm_size as usize];
        let copy_size = file_size.min(bytes.len().saturating_sub(file_off));
        if copy_size > 0 && file_off < bytes.len() {
            data[..copy_size].copy_from_slice(&bytes[file_off..file_off + copy_size]);
        }

        memory_map.add_segment(MemorySegment {
            name,
            start: vm_addr,
            size: vm_size,
            data,
            permissions: perms,
        })?;
    }

    // Extract symbols
    let mut symbols = Vec::new();
    if let Some(ref symtab) = macho.symbols {
        for (name, nlist) in symtab.iter().flatten() {
            if name.is_empty() || nlist.n_value == 0 {
                continue;
            }
            let kind = if nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT {
                // Could be function or data — we'll default to Function for simplicity
                SymbolKind::Function
            } else {
                SymbolKind::Other
            };
            symbols.push(Symbol {
                name: name.to_string(),
                address: nlist.n_value,
                size: 0,
                kind,
            });
        }
    }

    // Extract imports
    let mut imports = Vec::new();
    for import in &macho.imports().unwrap_or_default() {
        imports.push(Import {
            name: import.name.to_string(),
            library: import.dylib.to_string(),
            address: import.address,
        });
    }

    // Extract exports
    let mut exports = Vec::new();
    for export in &macho.exports().unwrap_or_default() {
        exports.push(Export {
            name: export.name.clone(),
            address: export.offset,
        });
    }

    // Extract library dependencies
    let mut libraries: Vec<String> = macho.libs.iter().map(|l| l.to_string()).collect();
    libraries.sort();
    libraries.dedup();

    Ok(LoadedBinary {
        memory_map,
        entry_point: macho.entry,
        arch,
        endianness,
        symbols,
        imports,
        exports,
        libraries,
        format: BinaryFormat::MachO,
        debug_info_path: None,
    })
}

/// Load a raw binary file with user-specified parameters.
///
/// This creates a single memory segment containing the entire file contents,
/// mapped at the given base address with full RWX permissions.
pub fn load_raw_binary(
    data: &[u8],
    base_address: u64,
    arch: Architecture,
    entry_point: Option<u64>,
) -> Result<LoadedBinary> {
    if data.is_empty() {
        return Err(Error::Loader("Empty input".to_string()));
    }

    let mut memory_map = MemoryMap::default();
    memory_map.add_segment(MemorySegment {
        name: "raw".to_string(),
        start: base_address,
        size: data.len() as u64,
        data: data.to_vec(),
        permissions: Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
    })?;

    Ok(LoadedBinary {
        memory_map,
        entry_point: entry_point.unwrap_or(base_address),
        arch,
        endianness: arch.default_endianness(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        libraries: Vec::new(),
        format: BinaryFormat::Raw,
        debug_info_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_error() {
        let result = load_binary_from_bytes(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Empty input"), "got: {}", err);
    }

    #[test]
    fn unsupported_format_error() {
        let result = load_binary_from_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn load_raw_binary_basic() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let loaded = load_raw_binary(&data, 0x1000, Architecture::Arm64, None).unwrap();
        assert_eq!(loaded.arch, Architecture::Arm64);
        assert_eq!(loaded.entry_point, 0x1000);
        assert_eq!(loaded.endianness, Endianness::Little);
        assert!(loaded.symbols.is_empty());
        assert!(loaded.imports.is_empty());
        assert!(loaded.exports.is_empty());
        assert!(loaded.libraries.is_empty());
        assert_eq!(loaded.memory_map.segments.len(), 1);
        assert_eq!(loaded.memory_map.segments[0].name, "raw");
        assert_eq!(loaded.memory_map.segments[0].start, 0x1000);
        assert_eq!(loaded.memory_map.segments[0].size, 8);
        assert_eq!(loaded.memory_map.segments[0].data, data);
        assert!(
            loaded.memory_map.segments[0]
                .permissions
                .contains(Permissions::READ)
        );
        assert!(
            loaded.memory_map.segments[0]
                .permissions
                .contains(Permissions::WRITE)
        );
        assert!(
            loaded.memory_map.segments[0]
                .permissions
                .contains(Permissions::EXECUTE)
        );
    }

    #[test]
    fn load_raw_binary_custom_entry() {
        let data = vec![0xAA; 16];
        let loaded = load_raw_binary(&data, 0x8000, Architecture::X86_64, Some(0x8004)).unwrap();
        assert_eq!(loaded.entry_point, 0x8004);
        assert_eq!(loaded.arch, Architecture::X86_64);
    }

    #[test]
    fn load_raw_binary_empty_error() {
        let result = load_raw_binary(&[], 0x1000, Architecture::Arm64, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Empty input"), "got: {}", err);
    }

    #[test]
    fn load_raw_binary_memory_readable() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let loaded = load_raw_binary(&data, 0x2000, Architecture::Arm, None).unwrap();
        let read_back = loaded.memory_map.get_data(0x2000, 4).unwrap();
        assert_eq!(read_back, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn load_raw_binary_mips_big_endian() {
        let data = vec![0x00; 4];
        let loaded = load_raw_binary(&data, 0, Architecture::Mips, None).unwrap();
        assert_eq!(loaded.endianness, Endianness::Big);
    }
}
