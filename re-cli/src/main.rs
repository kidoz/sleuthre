use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;

use re_core::analysis::pipeline;
use re_core::analysis::type_propagation::FunctionTypeInfo;
use re_core::arch::Architecture;
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
    Raw {
        /// Path to the raw binary file
        binary: PathBuf,
        /// Architecture: x86, x86_64, arm, arm64, mips, mips64
        #[arg(long)]
        arch: String,
        /// Base address to map the binary at (hex, e.g. 0x1000)
        #[arg(long, value_parser = parse_hex_address, default_value = "0x0")]
        base: u64,
        /// Entry point address (hex); defaults to base address
        #[arg(long, value_parser = parse_hex_address)]
        entry: Option<u64>,
        /// Number of instructions to disassemble
        #[arg(long, default_value_t = 32)]
        count: usize,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Run analysis plugins
    Plugins {
        /// Path to the binary file
        binary: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
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

/// Result of the full analysis pipeline.
struct AnalysisResult {
    project: re_core::project::Project,
    type_info: HashMap<u64, FunctionTypeInfo>,
    entry_point: u64,
}

/// Run the full analysis pipeline using the shared `re_core::analysis::pipeline`.
fn run_analysis(path: &Path) -> Result<AnalysisResult> {
    let pipeline_result = pipeline::analyze_binary(path, |stage| {
        eprintln!("[*] {}", stage);
    })
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    let type_info: HashMap<u64, FunctionTypeInfo> = pipeline_result
        .project
        .types
        .function_signatures
        .iter()
        .map(|(&addr, sig)| {
            (
                addr,
                FunctionTypeInfo {
                    signature: Some(sig.clone()),
                    var_types: Default::default(),
                },
            )
        })
        .collect();

    Ok(AnalysisResult {
        project: pipeline_result.project,
        type_info,
        entry_point: pipeline_result.entry_point,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
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
        Commands::Raw {
            binary,
            arch,
            base,
            entry,
            count,
            json,
        } => cmd_raw(&binary, &arch, base, entry, count, json),
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

    let mut entries = Vec::new();
    let mut addr = address;
    for _ in 0..count {
        match disasm.disassemble_one(&binary.memory_map, addr) {
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
    let result = run_analysis(path)?;

    if let Some(func) = result.project.functions.functions.get(&address) {
        // Disassemble the function first
        let size = func
            .end_address
            .unwrap_or(address + 0x100)
            .saturating_sub(address);
        // Limit size to avoid huge functions if something goes wrong
        let size = size.min(0x10000) as usize;

        let disasm = Disassembler::new(result.project.arch).with_context(|| {
            format!("Failed to create disassembler for {}", result.project.arch)
        })?;

        let instructions = disasm.disassemble_range(&result.project.memory_map, address, size)?;

        // Build symbol map for resolution
        let mut symbols = HashMap::new();
        // 1. Functions
        for f in result.project.functions.functions.values() {
            symbols.insert(f.start_address, f.name.clone());
        }
        // 2. Imports/Symbols from binary
        for sym in &result.project.symbols {
            symbols.insert(sym.address, sym.name.clone());
        }
        for imp in &result.project.imports {
            symbols.insert(imp.address, imp.name.clone());
        }

        let code = re_core::il::structuring::decompile(
            &func.name,
            &instructions,
            result.project.arch,
            &symbols,
            result.type_info.get(&address),
            &re_core::types::TypeManager::default(),
            &result.project.memory_map,
        );

        println!("{}", code.text);
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

fn cmd_raw(
    path: &Path,
    arch_str: &str,
    base: u64,
    entry: Option<u64>,
    count: usize,
    json: bool,
) -> Result<()> {
    let arch = parse_arch(arch_str)?;
    let data =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

    let binary = loader::load_raw_binary(&data, base, arch, entry)
        .with_context(|| "Failed to create raw binary mapping")?;

    let disasm = Disassembler::new(binary.arch)
        .with_context(|| format!("Failed to create disassembler for {}", binary.arch))?;

    let ep = binary.entry_point;
    println!(
        "Raw binary: {} bytes, {}, base=0x{:x}, entry=0x{:x}",
        data.len(),
        arch,
        base,
        ep,
    );

    let mut entries = Vec::new();
    let mut addr = ep;
    for _ in 0..count {
        match disasm.disassemble_one(&binary.memory_map, addr) {
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
