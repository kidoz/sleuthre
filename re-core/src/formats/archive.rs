use std::collections::HashMap;
use std::io::Read;

/// Describes a single entry inside an archive.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Name or path of the file within the archive.
    pub name: String,
    /// Absolute byte offset of the entry data in the archive file.
    pub offset: u64,
    /// Size of the data as stored (may be compressed).
    pub compressed_size: u64,
    /// Size of the data after decompression. Equal to `compressed_size` if not compressed.
    pub decompressed_size: u64,
    /// Whether the entry data is compressed.
    pub is_compressed: bool,
    /// Entry type.
    pub entry_type: ArchiveEntryType,
    /// Extra metadata (format-specific).
    pub metadata: HashMap<String, String>,
}

/// Whether an archive entry is a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveEntryType {
    File,
    Directory,
}

/// Parsed archive directory listing.
#[derive(Debug, Clone, Default)]
pub struct ArchiveDirectory {
    pub entries: Vec<ArchiveEntry>,
    /// Human-readable format description.
    pub format_name: String,
    /// Extra metadata about the archive itself.
    pub metadata: HashMap<String, String>,
}

/// Trait implemented by archive format parsers.
///
/// Each format (LOD, WAD, PAK, VPK, ...) implements this trait. Formats are
/// registered in a [`FormatRegistry`] and selected by magic bytes.
pub trait ArchiveFormat: Send + Sync {
    /// Human-readable name of the format (e.g., "MM6/7/8 LOD Archive").
    fn name(&self) -> &str;

    /// Return `true` if this format can handle the given data. `extension` is
    /// the lowercased file extension (e.g., `"lod"`).
    fn matches(&self, header: &[u8], extension: &str) -> bool;

    /// Parse the archive data and return a directory of entries.
    fn parse(&self, data: &[u8]) -> Result<ArchiveDirectory, String>;

    /// Extract raw (decompressed) bytes for a single entry.
    fn extract(&self, data: &[u8], entry: &ArchiveEntry) -> Result<Vec<u8>, String>;
}

/// Registry of known archive formats.
#[derive(Default)]
pub struct FormatRegistry {
    formats: Vec<Box<dyn ArchiveFormat>>,
}

impl FormatRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new archive format handler.
    pub fn register(&mut self, format: Box<dyn ArchiveFormat>) {
        self.formats.push(format);
    }

    /// Try to detect which registered format matches the given data.
    pub fn detect(&self, data: &[u8], extension: &str) -> Option<&dyn ArchiveFormat> {
        self.formats
            .iter()
            .find(|f| f.matches(data, extension))
            .map(|f| f.as_ref())
    }

    /// Open an archive file, auto-detecting the format.
    pub fn open(
        &self,
        data: &[u8],
        extension: &str,
    ) -> Result<(ArchiveDirectory, &dyn ArchiveFormat), String> {
        let format = self
            .detect(data, extension)
            .ok_or_else(|| "Unknown archive format".to_string())?;
        let dir = format.parse(data)?;
        Ok((dir, format))
    }

    /// Return all registered format names.
    pub fn format_names(&self) -> Vec<&str> {
        self.formats.iter().map(|f| f.name()).collect()
    }
}

/// Create a default registry with all built-in archive format handlers.
pub fn default_registry() -> FormatRegistry {
    let mut reg = FormatRegistry::new();
    reg.register(Box::new(LodArchiveFormat));
    reg.register(Box::new(VidArchiveFormat));
    reg.register(Box::new(SndArchiveFormat));
    reg
}

// ---------------------------------------------------------------------------
// Built-in: MM6/7/8 LOD Archive Format
// ---------------------------------------------------------------------------

pub struct LodArchiveFormat;

impl ArchiveFormat for LodArchiveFormat {
    fn name(&self) -> &str {
        "MM6/7/8 LOD Archive"
    }

    fn matches(&self, header: &[u8], extension: &str) -> bool {
        extension == "lod" || (header.len() >= 4 && &header[0..4] == b"LOD\0")
    }

    fn parse(&self, data: &[u8]) -> Result<ArchiveDirectory, String> {
        if data.len() < 0x104 + 32 {
            return Err("File too small for LOD header".to_string());
        }
        if &data[0..4] != b"LOD\0" {
            return Err("Invalid LOD signature".to_string());
        }

        let version = read_cstring(&data[4..84]);
        let description = read_cstring(&data[0x58..0xD8]);

        // Directory entry at offset 0x104
        let dir_offset = u32::from_le_bytes(data[0x114..0x118].try_into().unwrap()) as u64;
        let num_items = u16::from_le_bytes(data[0x120..0x122].try_into().unwrap()) as usize;

        if dir_offset as usize + num_items * 32 > data.len() {
            return Err("Directory extends beyond file".to_string());
        }

        let mut entries = Vec::with_capacity(num_items);
        for i in 0..num_items {
            let entry_base = dir_offset as usize + i * 32;
            if entry_base + 32 > data.len() {
                break;
            }
            let name = read_cstring(&data[entry_base..entry_base + 16]);
            let file_offset =
                u32::from_le_bytes(data[entry_base + 16..entry_base + 20].try_into().unwrap())
                    as u64;
            let file_size =
                u32::from_le_bytes(data[entry_base + 20..entry_base + 24].try_into().unwrap())
                    as u64;

            if name.is_empty() {
                continue;
            }

            // Check if data has compression header
            let abs_offset = file_offset;
            let (is_compressed, decompressed_size) = if abs_offset as usize + 16 <= data.len() {
                check_lod_compression(&data[abs_offset as usize..])
            } else {
                (false, file_size)
            };

            entries.push(ArchiveEntry {
                name,
                offset: abs_offset,
                compressed_size: file_size,
                decompressed_size,
                is_compressed,
                entry_type: ArchiveEntryType::File,
                metadata: HashMap::new(),
            });
        }

        let mut meta = HashMap::new();
        meta.insert("version".to_string(), version);
        meta.insert("description".to_string(), description);

        Ok(ArchiveDirectory {
            entries,
            format_name: "LOD Archive".to_string(),
            metadata: meta,
        })
    }

    fn extract(&self, data: &[u8], entry: &ArchiveEntry) -> Result<Vec<u8>, String> {
        let start = entry.offset as usize;
        if start >= data.len() {
            return Err("Entry offset beyond file".to_string());
        }

        if entry.is_compressed {
            // Skip the 16-byte compression header
            let comp_start = start + 16;
            let comp_end = comp_start + entry.compressed_size as usize;
            if comp_end > data.len() {
                // Try without header offset
                let raw =
                    &data[start..std::cmp::min(start + entry.compressed_size as usize, data.len())];
                return decompress_zlib(raw, entry.decompressed_size as usize);
            }
            let compressed = &data[comp_start..comp_end];
            decompress_zlib(compressed, entry.decompressed_size as usize)
        } else {
            let end = std::cmp::min(start + entry.compressed_size as usize, data.len());
            Ok(data[start..end].to_vec())
        }
    }
}

fn check_lod_compression(data: &[u8]) -> (bool, u64) {
    if data.len() < 16 {
        return (false, 0);
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let sig = &data[4..8];
    let decompressed = u32::from_le_bytes(data[12..16].try_into().unwrap()) as u64;

    if version == 91969 && sig == b"mvii" && decompressed > 0 {
        (true, decompressed)
    } else {
        (false, 0)
    }
}

fn decompress_zlib(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(expected_size);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(decompressed)
}

// ---------------------------------------------------------------------------
// Built-in: MM6/7/8 VID Container
// ---------------------------------------------------------------------------

pub struct VidArchiveFormat;

impl ArchiveFormat for VidArchiveFormat {
    fn name(&self) -> &str {
        "MM6/7/8 VID Video Container"
    }

    fn matches(&self, header: &[u8], extension: &str) -> bool {
        if extension == "vid" {
            return true;
        }
        if header.len() < 48 {
            return false;
        }
        // Heuristic: first 4 bytes = small count, then 40 bytes of printable ASCII name
        let count = u32::from_le_bytes(header[0..4].try_into().unwrap_or([0; 4]));
        count > 0
            && count < 10000
            && header[4..44]
                .iter()
                .all(|&b| b == 0 || (0x20..=0x7E).contains(&b))
    }

    fn parse(&self, data: &[u8]) -> Result<ArchiveDirectory, String> {
        if data.len() < 4 {
            return Err("File too small".to_string());
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if 4 + count * 44 > data.len() {
            return Err("Directory extends beyond file".to_string());
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 44;
            let name = read_cstring(&data[base..base + 40]);
            let offset = u32::from_le_bytes(data[base + 40..base + 44].try_into().unwrap()) as u64;

            // Calculate size from next entry's offset or file end
            let next_offset = if i + 1 < count {
                u32::from_le_bytes(
                    data[4 + (i + 1) * 44 + 40..4 + (i + 1) * 44 + 44]
                        .try_into()
                        .unwrap(),
                ) as u64
            } else {
                data.len() as u64
            };
            let size = next_offset.saturating_sub(offset);

            entries.push(ArchiveEntry {
                name,
                offset,
                compressed_size: size,
                decompressed_size: size,
                is_compressed: false,
                entry_type: ArchiveEntryType::File,
                metadata: HashMap::new(),
            });
        }

        Ok(ArchiveDirectory {
            entries,
            format_name: "VID Container".to_string(),
            metadata: HashMap::new(),
        })
    }

    fn extract(&self, data: &[u8], entry: &ArchiveEntry) -> Result<Vec<u8>, String> {
        let start = entry.offset as usize;
        let end = std::cmp::min(start + entry.compressed_size as usize, data.len());
        if start >= data.len() {
            return Err("Entry offset beyond file".to_string());
        }
        Ok(data[start..end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Built-in: MM6/7/8 SND Container
// ---------------------------------------------------------------------------

pub struct SndArchiveFormat;

impl ArchiveFormat for SndArchiveFormat {
    fn name(&self) -> &str {
        "MM6/7/8 SND Sound Container"
    }

    fn matches(&self, header: &[u8], extension: &str) -> bool {
        if extension == "snd" {
            return true;
        }
        if header.len() < 56 {
            return false;
        }
        let count = u32::from_le_bytes(header[0..4].try_into().unwrap_or([0; 4]));
        count > 0
            && count < 50000
            && header[4..44]
                .iter()
                .all(|&b| b == 0 || (0x20..=0x7E).contains(&b))
    }

    fn parse(&self, data: &[u8]) -> Result<ArchiveDirectory, String> {
        if data.len() < 4 {
            return Err("File too small".to_string());
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if 4 + count * 52 > data.len() {
            return Err("Directory extends beyond file".to_string());
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 52;
            let name = read_cstring(&data[base..base + 40]);
            let offset = u32::from_le_bytes(data[base + 40..base + 44].try_into().unwrap()) as u64;
            let size = u32::from_le_bytes(data[base + 44..base + 48].try_into().unwrap()) as u64;
            let decompressed =
                u32::from_le_bytes(data[base + 48..base + 52].try_into().unwrap()) as u64;

            let is_compressed = decompressed > 0 && decompressed != size;

            entries.push(ArchiveEntry {
                name,
                offset,
                compressed_size: size,
                decompressed_size: if is_compressed { decompressed } else { size },
                is_compressed,
                entry_type: ArchiveEntryType::File,
                metadata: HashMap::new(),
            });
        }

        Ok(ArchiveDirectory {
            entries,
            format_name: "SND Container".to_string(),
            metadata: HashMap::new(),
        })
    }

    fn extract(&self, data: &[u8], entry: &ArchiveEntry) -> Result<Vec<u8>, String> {
        let start = entry.offset as usize;
        let end = std::cmp::min(start + entry.compressed_size as usize, data.len());
        if start >= data.len() {
            return Err("Entry offset beyond file".to_string());
        }
        let raw = &data[start..end];

        if entry.is_compressed {
            decompress_zlib(raw, entry.decompressed_size as usize)
        } else {
            Ok(raw.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lod_format_matches() {
        let f = LodArchiveFormat;
        assert!(f.matches(b"LOD\0rest_of_header", "lod"));
        assert!(f.matches(b"LOD\0rest_of_header", "other"));
        assert!(!f.matches(b"NOTLOD", "other"));
        assert!(f.matches(b"", "lod")); // extension match
    }

    #[test]
    fn default_registry_has_formats() {
        let reg = default_registry();
        assert_eq!(reg.format_names().len(), 3);
    }

    #[test]
    fn read_cstring_works() {
        assert_eq!(read_cstring(b"hello\0world"), "hello");
        assert_eq!(read_cstring(b"no_null"), "no_null");
        assert_eq!(read_cstring(b"\0empty"), "");
    }
}
