use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;

use re_core::analysis::pipeline;
use re_core::arch::{Architecture, Endianness};
use re_core::disasm::Disassembler;
use re_core::loader;

#[derive(Parser)]
#[command(name = "re-cli")]
#[command(about = "sleuthre CLI — headless binary analysis tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Export a reproducible triage report as JSON or Markdown
    Triage {
        /// Path to the binary file
        binary: PathBuf,
        /// Report format (json or markdown)
        #[arg(long, default_value = "json")]
        format: re_core::analysis::triage::ReportFormat,
    },
    /// Load a binary, run full analysis, and print a summary
    Analyze {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Disassemble N instructions starting at an address
    Disasm {
        /// Path to the binary file
        binary: PathBuf,
        /// Start address (hex, e.g. 0x1000)
        #[arg(long, value_parser = parse_hex_address)]
        address: u64,
        /// Number of instructions to disassemble
        #[arg(long, default_value_t = 16)]
        count: usize,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Decompile a function at an address
    Decompile {
        /// Path to the binary file
        binary: PathBuf,
        /// Address of the function (hex)
        #[arg(long, value_parser = parse_hex_address)]
        address: u64,
    },
    /// List all discovered functions
    Functions {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// List all discovered strings
    Strings {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// List exports
    Exports {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// List imports
    Imports {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print binary metadata (architecture, entry point, segments)
    Info {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Load a raw binary file (firmware, shellcode, etc.) and disassemble it
    Raw(RawArgs),
    /// Run analysis plugins
    Plugins {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args)]
struct RawArgs {
    /// Path to the raw binary file
    binary: PathBuf,
    /// Architecture (x86, x86_64, arm, arm64, mips, mips64, riscv32, riscv64)
    #[arg(long)]
    arch: String,
    /// Map the whole file at this address
    #[arg(long, value_parser = parse_hex_address, default_value = "0x0", conflicts_with = "regions")]
    base: u64,
    /// Map a named file slice. Repeat for each region. Numbers accept decimal or 0x hex.
    #[arg(long = "region", value_name = "NAME:FILE_OFFSET:LENGTH:START", value_parser = parse_raw_region)]
    regions: Vec<loader::RawRegion>,
    /// Byte order (little or big). Regions default to the architecture's order.
    /// Whole-file disassembly defaults to little-endian for compatibility.
    #[arg(long, visible_alias = "endian", value_parser = parse_byte_order)]
    byte_order: Option<Endianness>,
    /// Entry address. Defaults to the base or the start of the first supplied region.
    #[arg(long, value_parser = parse_hex_address)]
    entry: Option<u64>,
    /// Number of instructions to disassemble
    #[arg(long, default_value_t = 32)]
    count: usize,
    /// Output the instructions as JSON
    #[arg(long)]
    json: bool,
}

fn parse_byte_order(value: &str) -> Result<Endianness, String> {
    match value {
        "little" => Ok(Endianness::Little),
        "big" => Ok(Endianness::Big),
        _ => Err("expected little or big".into()),
    }
}

fn parse_raw_region(spec: &str) -> Result<loader::RawRegion, String> {
    let fields: Vec<_> = spec.splitn(5, ':').map(str::trim).collect();
    let [name, offset, length, start] = fields[..] else {
        return Err("expected NAME:FILE_OFFSET:LENGTH:START".into());
    };
    if name.is_empty() {
        return Err("region name is empty".into());
    }
    let number = |text, field| parse_hex_address(text).map_err(|e| format!("invalid {field}: {e}"));
    let file_offset =
        usize::try_from(number(offset, "file offset")?).map_err(|_| "file offset is too large")?;
    let length =
        usize::try_from(number(length, "length")?).map_err(|_| "region length is too large")?;
    Ok(loader::RawRegion {
        name: name.into(),
        file_offset,
        length,
        start: number(start, "virtual start")?,
    })
}

fn parse_hex_address(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        // Try decimal first, then hex
        s.parse::<u64>()
            .or_else(|_| u64::from_str_radix(s, 16))
            .map_err(|e| e.to_string())
    }
}

fn run_analysis(path: &Path) -> Result<pipeline::AnalysisResult> {
    Ok(pipeline::analyze_binary(path, |stage| {
        eprintln!("[*] {stage}")
    })?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Triage { binary, format } => {
            let bytes = std::fs::read(&binary)
                .with_context(|| format!("Failed to read {}", binary.display()))?;
            let report = re_core::analysis::triage::TriageReport::from_bytes(&bytes)
                .with_context(|| format!("Failed to triage {}", binary.display()))?;
            report
                .write(format, std::io::stdout().lock())
                .context("Failed to write triage report")
        }
        Commands::Analyze { binary, json } => cmd_analyze(&binary, json),
        Commands::Disasm {
            binary,
            address,
            count,
            json,
        } => cmd_disasm(&binary, address, count, json),
        Commands::Decompile { binary, address } => cmd_decompile(&binary, address),
        Commands::Functions { binary, json } => cmd_functions(&binary, json),
        Commands::Strings { binary, json } => cmd_strings(&binary, json),
        Commands::Exports { binary, json } => cmd_exports(&binary, json),
        Commands::Imports { binary, json } => cmd_imports(&binary, json),
        Commands::Info { binary, json } => cmd_info(&binary, json),
        Commands::Raw(args) => cmd_raw(args),
        Commands::Plugins { binary, json } => cmd_plugins(&binary, json),
    }
}

// -- plugins ------------------------------------------------------------------

#[derive(Serialize)]
struct PluginFindingEntry {
    address: String,
    category: String,
    message: String,
    severity: f64,
}

fn cmd_plugins(path: &Path, json: bool) -> Result<()> {
    let mut result = run_analysis(path)?;

    let mut pm = re_core::plugin::PluginManager::default();
    pm.register_analysis_pass(Box::new(re_core::analysis::passes::SuspiciousNamePass));
    pm.register_analysis_pass(Box::new(
        re_core::analysis::struct_inference::StructInferencePass::new(result.project.arch),
    ));

    let findings = pm.run_all_analysis_passes(
        &result.project.memory_map,
        &mut result.project.functions,
        &result.project.xrefs,
        &result.project.strings,
    )?;

    let entries: Vec<PluginFindingEntry> = findings
        .into_iter()
        .map(|f| PluginFindingEntry {
            address: format!("0x{:x}", f.address),
            category: format!("{:?}", f.category),
            message: f.message,
            severity: f.severity,
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        println!("Analysis Plugin Findings");
        println!("========================");
        if entries.is_empty() {
            println!("No findings.");
        } else {
            let h_addr = "ADDRESS";
            let h_cat = "CATEGORY";
            let h_sev = "SEV";
            println!("{h_addr:<14} {h_cat:<14} {h_sev:<5} MESSAGE");
            println!("{}", "-".repeat(80));
            for e in &entries {
                println!(
                    "{:<14} {:<14} {:<5.2} {}",
                    e.address, e.category, e.severity, e.message
                );
            }
        }
    }

    Ok(())
}

// -- analyze ------------------------------------------------------------------

#[derive(Serialize)]
struct AnalyzeSummary {
    arch: String,
    entry_point: String,
    functions_count: usize,
    strings_count: usize,
    imports_count: usize,
    exports_count: usize,
    libraries: Vec<String>,
}

fn cmd_analyze(path: &Path, json: bool) -> Result<()> {
    let result = run_analysis(path)?;

    let summary = AnalyzeSummary {
        arch: result.project.arch.display_name().to_string(),
        entry_point: format!("0x{:x}", result.entry_point),
        functions_count: result.project.functions.functions.len(),
        strings_count: result.project.strings.strings.len(),
        imports_count: result.project.imports.len(),
        exports_count: result.project.exports.len(),
        libraries: result.project.libraries.clone(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("Binary Analysis Summary");
        println!("=======================");
        println!("Architecture:  {}", summary.arch);
        println!("Entry point:   {}", summary.entry_point);
        println!("Functions:     {}", summary.functions_count);
        println!("Strings:       {}", summary.strings_count);
        println!("Imports:       {}", summary.imports_count);
        println!("Exports:       {}", summary.exports_count);
        if !summary.libraries.is_empty() {
            println!("Libraries:");
            for lib in &summary.libraries {
                println!("  - {lib}");
            }
        }
    }

    Ok(())
}

// -- disasm -------------------------------------------------------------------

#[derive(Serialize)]
struct DisasmEntry {
    address: String,
    bytes: String,
    mnemonic: String,
    operands: String,
}

fn cmd_disasm(path: &Path, address: u64, count: usize, json: bool) -> Result<()> {
    let binary = loader::load_binary(path)
        .with_context(|| format!("Failed to load binary: {}", path.display()))?;

    let disasm = Disassembler::new(binary.arch)
        .with_context(|| format!("Failed to create disassembler for {}", binary.arch))?;

    print_disassembly(&disasm, &binary.memory_map, address, count, json)
}

fn print_disassembly(
    disasm: &Disassembler,
    memory: &re_core::memory::MemoryMap,
    address: u64,
    count: usize,
    json: bool,
) -> Result<()> {
    let mut entries = Vec::new();
    let mut addr = address;
    for _ in 0..count {
        match disasm.disassemble_one(memory, addr) {
            Ok(insn) => {
                let next = insn.address + insn.bytes.len() as u64;
                entries.push(DisasmEntry {
                    address: format!("0x{:x}", insn.address),
                    bytes: insn
                        .bytes
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                    mnemonic: insn.mnemonic,
                    operands: insn.op_str,
                });
                addr = next;
            }
            Err(_) => break,
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for e in &entries {
            println!(
                "{:<14} {:<24} {} {}",
                e.address, e.bytes, e.mnemonic, e.operands
            );
        }
    }

    Ok(())
}

// -- decompile ----------------------------------------------------------------

fn cmd_decompile(path: &Path, address: u64) -> Result<()> {
    let mut project = run_analysis(path)?.project;
    if project.functions.get_function(address).is_some() {
        let disasm = Disassembler::new(project.arch)?;
        println!("{}", project.decompile_at(&disasm, address)?.text);
    } else {
        println!("No function found at address 0x{:x}", address);
    }

    Ok(())
}

// -- functions ----------------------------------------------------------------

#[derive(Serialize)]
struct FunctionEntry {
    address: String,
    name: String,
    size: Option<u64>,
}

fn cmd_functions(path: &Path, json: bool) -> Result<()> {
    let result = run_analysis(path)?;

    let entries: Vec<FunctionEntry> = result
        .project
        .functions
        .functions
        .values()
        .map(|f| {
            let size = f
                .end_address
                .map(|end: u64| end.saturating_sub(f.start_address));
            FunctionEntry {
                address: format!("0x{:x}", f.start_address),
                name: f.name.clone(),
                size,
            }
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let h_addr = "ADDRESS";
        let h_size = "SIZE";
        println!("{h_addr:<14} {h_size:<8} NAME");
        println!("{}", "-".repeat(50));
        for e in &entries {
            let size_str = match e.size {
                Some(s) => format!("{s}"),
                None => "?".to_string(),
            };
            println!("{:<14} {:<8} {}", e.address, size_str, e.name);
        }
        println!("\nTotal: {} functions", entries.len());
    }

    Ok(())
}

// -- strings ------------------------------------------------------------------

#[derive(Serialize)]
struct StringEntry {
    address: String,
    length: usize,
    encoding: String,
    section: String,
    value: String,
}

fn cmd_strings(path: &Path, json: bool) -> Result<()> {
    let result = run_analysis(path)?;

    let entries: Vec<StringEntry> = result
        .project
        .strings
        .strings
        .iter()
        .map(|s| StringEntry {
            address: format!("0x{:x}", s.address),
            length: s.length,
            encoding: format!("{:?}", s.encoding),
            section: s.section_name.clone(),
            value: s.value.clone(),
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let h_addr = "ADDRESS";
        let h_len = "LEN";
        let h_enc = "ENCODING";
        println!("{h_addr:<14} {h_len:<6} {h_enc:<10} VALUE");
        println!("{}", "-".repeat(70));
        for e in &entries {
            // Truncate very long strings for display
            let display_val = if e.value.len() > 80 {
                format!("{}...", &e.value[..77])
            } else {
                e.value.clone()
            };
            println!(
                "{:<14} {:<6} {:<10} {}",
                e.address, e.length, e.encoding, display_val
            );
        }
        println!("\nTotal: {} strings", entries.len());
    }

    Ok(())
}

// -- exports ------------------------------------------------------------------

#[derive(Serialize)]
struct ExportEntry {
    address: String,
    name: String,
}

fn cmd_exports(path: &Path, json: bool) -> Result<()> {
    let binary = loader::load_binary(path)
        .with_context(|| format!("Failed to load binary: {}", path.display()))?;

    let entries: Vec<ExportEntry> = binary
        .exports
        .iter()
        .map(|e| ExportEntry {
            address: format!("0x{:x}", e.address),
            name: e.name.clone(),
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let h_addr = "ADDRESS";
        println!("{h_addr:<14} NAME");
        println!("{}", "-".repeat(40));
        for e in &entries {
            println!("{:<14} {}", e.address, e.name);
        }
        println!("\nTotal: {} exports", entries.len());
    }

    Ok(())
}

// -- imports ------------------------------------------------------------------

#[derive(Serialize)]
struct ImportEntry {
    address: String,
    name: String,
    library: String,
}

fn cmd_imports(path: &Path, json: bool) -> Result<()> {
    let binary = loader::load_binary(path)
        .with_context(|| format!("Failed to load binary: {}", path.display()))?;

    let entries: Vec<ImportEntry> = binary
        .imports
        .iter()
        .map(|i| ImportEntry {
            address: format!("0x{:x}", i.address),
            name: i.name.clone(),
            library: i.library.clone(),
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let h_addr = "ADDRESS";
        let h_name = "NAME";
        println!("{h_addr:<14} {h_name:<30} LIBRARY");
        println!("{}", "-".repeat(60));
        for e in &entries {
            println!("{:<14} {:<30} {}", e.address, e.name, e.library);
        }
        println!("\nTotal: {} imports", entries.len());
    }

    Ok(())
}

// -- info ---------------------------------------------------------------------

#[derive(Serialize)]
struct BinaryInfo {
    arch: String,
    endianness: String,
    entry_point: String,
    segments: Vec<SegmentInfo>,
    pointer_size: usize,
}

#[derive(Serialize)]
struct SegmentInfo {
    name: String,
    start: String,
    size: u64,
    permissions: String,
}

fn cmd_info(path: &Path, json: bool) -> Result<()> {
    let binary = loader::load_binary(path)
        .with_context(|| format!("Failed to load binary: {}", path.display()))?;

    let segments: Vec<SegmentInfo> = binary
        .memory_map
        .segments
        .iter()
        .map(|s| SegmentInfo {
            name: s.name.clone(),
            start: format!("0x{:x}", s.start),
            size: s.size,
            permissions: format!("{:?}", s.permissions),
        })
        .collect();

    let info = BinaryInfo {
        arch: binary.arch.display_name().to_string(),
        endianness: format!("{:?}", binary.endianness),
        entry_point: format!("0x{:x}", binary.entry_point),
        segments,
        pointer_size: binary.arch.pointer_size(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Binary Information");
        println!("==================");
        println!("Architecture:  {}", info.arch);
        println!("Endianness:    {}", info.endianness);
        println!("Entry point:   {}", info.entry_point);
        println!("Pointer size:  {} bytes", info.pointer_size);
        println!();
        println!("Segments ({}):", info.segments.len());
        let h_name = "NAME";
        let h_start = "START";
        let h_size = "SIZE";
        println!("  {h_name:<20} {h_start:<14} {h_size:<10} PERMISSIONS");
        println!("  {}", "-".repeat(60));
        for seg in &info.segments {
            println!(
                "  {:<20} {:<14} {:<10} {}",
                seg.name, seg.start, seg.size, seg.permissions
            );
        }
    }

    Ok(())
}

// -- raw ----------------------------------------------------------------------

fn parse_arch(s: &str) -> Result<Architecture> {
    match s.to_lowercase().as_str() {
        "x86" | "i386" => Ok(Architecture::X86),
        "x86_64" | "x86-64" | "x64" | "amd64" => Ok(Architecture::X86_64),
        "arm" | "arm32" => Ok(Architecture::Arm),
        "arm64" | "aarch64" => Ok(Architecture::Arm64),
        "mips" | "mips32" => Ok(Architecture::Mips),
        "mips64" => Ok(Architecture::Mips64),
        "riscv" | "riscv32" | "rv32" => Ok(Architecture::RiscV32),
        "riscv64" | "rv64" => Ok(Architecture::RiscV64),
        _ => anyhow::bail!(
            "Unknown architecture '{}'. Supported: x86, x86_64, arm, arm64, mips, mips64, riscv32, riscv64",
            s
        ),
    }
}

fn cmd_raw(args: RawArgs) -> Result<()> {
    use std::io::Write;

    let arch = parse_arch(&args.arch)?;
    let data = std::fs::read(&args.binary)
        .with_context(|| format!("Failed to read file: {}", args.binary.display()))?;
    let whole_file = args.regions.is_empty();
    let order = args.byte_order.unwrap_or(if whole_file {
        Endianness::Little
    } else {
        arch.default_endianness()
    });
    let regions = if whole_file {
        vec![loader::RawRegion {
            name: "raw".into(),
            file_offset: 0,
            length: data.len(),
            start: args.base,
        }]
    } else {
        args.regions
    };
    let binary = loader::load_raw_regions(&data, &regions, arch, order, args.entry)
        .context("Failed to create raw binary mapping")?;
    let disasm = Disassembler::with_endianness(binary.arch, binary.endianness)
        .with_context(|| format!("Failed to create disassembler for {}", binary.arch))?;

    let ep = binary.entry_point;
    {
        let mut output: Box<dyn Write> = if args.json {
            Box::new(std::io::stderr().lock())
        } else {
            Box::new(std::io::stdout().lock())
        };
        write!(output, "Raw binary: {} bytes, {arch}, ", data.len())?;
        if whole_file {
            write!(output, "base={:#x}, ", args.base)?;
        }
        writeln!(output, "entry={ep:#x}, byte order={order:?}")?;
        if !whole_file {
            for region in &regions {
                writeln!(
                    output,
                    "  {}: file offset {:#x}, length {:#x}, start {:#x}",
                    region.name, region.file_offset, region.length, region.start
                )?;
            }
        }
    }

    print_disassembly(&disasm, &binary.memory_map, ep, args.count, args.json)
}
