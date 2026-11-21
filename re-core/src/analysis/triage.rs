//! Reproducible static evidence from the original sample bytes.

use std::io::Write;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};

use super::pipeline::AnalysisResult;
use crate::Result;
use crate::analysis::constants::{ConstantScanner, DiscoveredConstant};
use crate::analysis::entropy::shannon_entropy;
use crate::analysis::strings::{DiscoveredString, StringEncoding, StringsManager};
use crate::arch::{Architecture, Endianness};
use crate::loader::{BinaryFormat, Import, LoadedBinary, RawFileMapping, load_binary_from_bytes};
use crate::memory::{MemoryMap, Permissions};

/// A virtual address, encoded losslessly in JSON even for JavaScript consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReportAddress(pub u64);

impl Serialize for ReportAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:#x}", self.0))
    }
}

impl<'de> Deserialize<'de> for ReportAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| de::Error::custom("expected a 0x-prefixed report address"))?;
        u64::from_str_radix(digits, 16)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSegment {
    pub name: String,
    pub start: ReportAddress,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    pub permissions: Permissions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportImport {
    pub name: String,
    pub library: String,
    pub address: Option<ReportAddress>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    String {
        encoding: StringEncoding,
        value: String,
    },
    Constant {
        description: String,
        value: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportFinding {
    pub address: ReportAddress,
    #[serde(flatten)]
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Markdown,
}

impl std::str::FromStr for ReportFormat {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "json" => Ok(Self::Json),
            "markdown" => Ok(Self::Markdown),
            _ => Err("expected json or markdown"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TriageReport {
    pub schema_version: u32,
    pub sha256: String,
    pub format: BinaryFormat,
    pub architecture: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_order: Option<Endianness>,
    pub entry_point: ReportAddress,
    /// Shannon entropy of the entire file, in bits per byte, rounded to six decimals.
    pub entropy: f64,
    pub segments: Vec<ReportSegment>,
    pub imports: Vec<ReportImport>,
    pub findings: Vec<ReportFinding>,
}

impl TriageReport {
    pub(crate) const SCHEMA_VERSION: u32 = 1;

    /// Hash, load, and scan one snapshot, so a concurrent file edit cannot mix inputs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_loaded(bytes, load_binary_from_bytes(bytes)?))
    }

    /// Scan the supplied mapping. Pass the complete file bytes used to load
    /// it so the digest and entropy also cover any unmapped parts of the file.
    pub fn from_loaded(bytes: &[u8], binary: LoadedBinary) -> Self {
        let mut strings = StringsManager::default();
        strings.scan_memory(&binary.memory_map);
        let mut constants = ConstantScanner::default();
        constants.scan(&binary.memory_map);

        Self::header(bytes, binary.format, binary.arch, binary.entry_point).with_evidence(
            &binary.memory_map,
            binary.raw_source.as_ref().map(|s| (s, binary.endianness)),
            binary.imports.into_iter(),
            strings.strings.into_iter(),
            constants.constants.into_iter(),
        )
    }

    /// The preset pipeline has already scanned both strings and constants.
    pub(super) fn from_analysis(bytes: &[u8], analysis: &AnalysisResult) -> Self {
        let p = &analysis.project;
        Self::header(bytes, p.binary_format, p.arch, analysis.entry_point).with_evidence(
            &p.memory_map,
            p.raw_mapping.as_ref().map(|m| (&m.source, m.endianness)),
            p.imports.iter().cloned(),
            p.strings.strings.iter().cloned(),
            p.constants.constants.iter().cloned(),
        )
    }

    fn header(bytes: &[u8], format: BinaryFormat, arch: Architecture, entry: u64) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            sha256: hex::encode(Sha256::digest(bytes)),
            format,
            architecture: arch.display_name().into(),
            byte_order: None,
            entry_point: ReportAddress(entry),
            entropy: (shannon_entropy(bytes) * 1_000_000.0).round() / 1_000_000.0,
            segments: Vec::new(),
            imports: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn with_evidence(
        mut self,
        memory: &MemoryMap,
        raw_mapping: Option<(&RawFileMapping, Endianness)>,
        imports: impl Iterator<Item = Import>,
        strings: impl Iterator<Item = DiscoveredString>,
        constants: impl Iterator<Item = DiscoveredConstant>,
    ) -> Self {
        self.findings.extend(strings.map(|s| ReportFinding {
            address: ReportAddress(s.address),
            evidence: Evidence::String {
                encoding: s.encoding,
                value: s.value,
            },
        }));
        self.findings.extend(constants.map(|c| ReportFinding {
            address: ReportAddress(c.address),
            evidence: Evidence::Constant {
                description: c.description,
                value: c.value_hex,
            },
        }));
        self.findings.sort_by_key(|f| f.address);
        self.imports.extend(imports.map(|i| ReportImport {
            name: i.name,
            library: i.library,
            address: (i.address != 0).then_some(ReportAddress(i.address)),
        }));
        self.imports.sort_by(|a, b| {
            (a.address, &a.library, &a.name).cmp(&(b.address, &b.library, &b.name))
        });
        self.byte_order = raw_mapping.map(|(_, order)| order);
        self.segments
            .extend(memory.segments.iter().map(|s| ReportSegment {
                name: s.name.clone(),
                start: ReportAddress(s.start),
                size: s.size,
                file_offset:
                    raw_mapping.and_then(|(source, _)| source.file_offsets.get(&s.start).copied()),
                permissions: s.permissions,
            }));
        self
    }

    /// Write the canonical UTF-8 JSON export, including its final line feed.
    pub fn write_json(&self, mut out: impl Write) -> serde_json::Result<()> {
        serde_json::to_writer_pretty(&mut out, self)?;
        out.write_all(b"\n").map_err(serde_json::Error::io)
    }

    pub fn write(&self, format: ReportFormat, out: impl Write) -> std::io::Result<()> {
        match format {
            ReportFormat::Json => self.write_json(out).map_err(std::io::Error::from),
            ReportFormat::Markdown => self.write_markdown(out),
        }
    }

    fn write_markdown(&self, mut out: impl Write) -> std::io::Result<()> {
        writeln!(out, "# Triage report\n")?;
        writeln!(out, "- Report version: {}", self.schema_version)?;
        writeln!(out, "- SHA-256: `{}`", self.sha256)?;
        writeln!(out, "- Format: {:?} ({})", self.format, self.architecture)?;
        if let Some(order) = self.byte_order {
            writeln!(out, "- Byte order: {order:?}")?;
        }
        writeln!(out, "- Entry point: `{:#x}`", self.entry_point.0)?;
        writeln!(out, "- Entropy: {:.6} bits per byte", self.entropy)?;
        // Indented code blocks keep sample text literal. Debug-quoting each
        // string escapes embedded newlines so samples cannot start a new block.
        writeln!(out, "\n## Segments ({})\n", self.segments.len())?;
        for s in &self.segments {
            write!(
                out,
                "    {:#x}  {:?}  {} bytes  {}",
                s.start.0,
                s.name,
                s.size,
                s.permissions
                    .iter_names()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
                    .join(" | ")
            )?;
            if let Some(offset) = s.file_offset {
                write!(out, "  file offset {offset:#x}")?;
            }
            writeln!(out)?;
        }
        writeln!(out, "\n## Imports ({})\n", self.imports.len())?;
        for i in &self.imports {
            let address = i
                .address
                .map_or_else(|| "unresolved".into(), |a| format!("{:#x}", a.0));
            writeln!(out, "    {address}  {:?}  {:?}", i.library, i.name)?;
        }
        writeln!(out, "\n## Findings ({})\n", self.findings.len())?;
        for f in &self.findings {
            let addr = f.address.0;
            match &f.evidence {
                Evidence::String { encoding, value } => {
                    writeln!(out, "    {addr:#x}  {encoding:?} string  {value:?}")?
                }
                Evidence::Constant { description, value } => {
                    writeln!(out, "    {addr:#x}  Constant  {description:?}  {value:?}")?
                }
            }
        }
        Ok(())
    }
}
