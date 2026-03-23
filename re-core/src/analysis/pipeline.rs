use std::collections::HashMap;
use std::path::Path;

use crate::Result;
use crate::analysis::passes::{HeuristicNamePass, SignaturePass, SuspiciousNamePass};
use crate::analysis::type_propagation::TypePropagator;
use crate::arch::Architecture;
use crate::debuginfo;
use crate::disasm::Disassembler;
use crate::loader::{self, BinaryFormat, LoadedBinary};
use crate::plugin::{AnalysisFinding, PluginManager};
use crate::project::Project;
use crate::signatures::SignatureDatabase;

/// Describes which stage the analysis pipeline is currently executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisStage {
    LoadingBinary,
    DiscoveringFunctions,
    RecursiveDescent,
    ScanningXrefs,
    ScanningStrings,
    StringXrefs,
    ScanningConstants,
    ExtractingDebugInfo,
    TypePropagation,
    RunningAnalysisPasses,
    Done,
}

impl std::fmt::Display for AnalysisStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadingBinary => write!(f, "Loading binary..."),
            Self::DiscoveringFunctions => write!(f, "Discovering functions..."),
            Self::RecursiveDescent => write!(f, "Recursive descent..."),
            Self::ScanningXrefs => write!(f, "Scanning cross-references..."),
            Self::ScanningStrings => write!(f, "Scanning strings..."),
            Self::StringXrefs => write!(f, "Scanning string references..."),
            Self::ScanningConstants => write!(f, "Scanning constants..."),
            Self::ExtractingDebugInfo => write!(f, "Extracting debug info..."),
            Self::TypePropagation => write!(f, "Propagating types..."),
            Self::RunningAnalysisPasses => write!(f, "Running analysis passes..."),
            Self::Done => write!(f, "Done"),
        }
    }
}

/// The complete result of the analysis pipeline.
pub struct AnalysisResult {
    pub project: Project,
    pub findings: Vec<AnalysisFinding>,
    pub func_xref_counts: HashMap<u64, (usize, usize)>,
    pub entry_point: u64,
    pub summary: String,
}

fn platform_string(arch: Architecture, format: BinaryFormat) -> String {
    let os = match format {
        BinaryFormat::Elf => "linux",
        BinaryFormat::Pe => "windows",
        BinaryFormat::MachO => "macos",
        BinaryFormat::Raw => "unknown",
    };
    let arch_str = match arch {
        Architecture::X86_64 => "x86_64",
        Architecture::X86 => "x86",
        Architecture::Arm64 => "arm64",
        Architecture::Arm => "arm",
        Architecture::Mips => "mips",
        Architecture::Mips64 => "mips64",
        Architecture::RiscV32 => "riscv32",
        Architecture::RiscV64 => "riscv64",
    };
    format!("{}_{}", os, arch_str)
}

/// Run the full analysis pipeline on a binary file.
///
/// `on_progress` is called at each stage; pass `|_| {}` to ignore progress.
/// The `Disassembler` (which wraps the `!Send` Capstone) is created and
/// dropped entirely within this function, so callers on background threads
/// never need to send it across thread boundaries.
pub fn analyze_binary(
    path: &Path,
    mut on_progress: impl FnMut(AnalysisStage),
) -> Result<AnalysisResult> {
    // --- Load ---
    on_progress(AnalysisStage::LoadingBinary);
    let loaded = loader::load_binary(path)?;

    analyze_loaded(path, loaded, on_progress)
}

/// Run the full analysis pipeline on an already-loaded binary.
/// Useful when the caller already has `LoadedBinary` (e.g. raw binaries).
pub fn analyze_loaded(
    path: &Path,
    loaded: LoadedBinary,
    mut on_progress: impl FnMut(AnalysisStage),
) -> Result<AnalysisResult> {
    let mut project = Project::new(
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        path.to_path_buf(),
    );
    project.memory_map = loaded.memory_map;
    project.imports = loaded.imports;
    project.exports = loaded.exports;
    project.symbols.clone_from(&loaded.symbols);
    project.libraries = loaded.libraries;
    project.arch = loaded.arch;
    project.binary_format = loaded.format;

    // --- Disassembler (created and dropped in this scope) ---
    let disasm = Disassembler::new(loaded.arch).ok();

    // --- Function discovery ---
    on_progress(AnalysisStage::DiscoveringFunctions);
    if let Some(ref ds) = disasm {
        let _ = project.functions.discover_functions(
            &project.memory_map,
            ds,
            loaded.entry_point,
            loaded.arch,
        );
        project.functions.apply_symbols(&loaded.symbols);

        on_progress(AnalysisStage::RecursiveDescent);
        let _ = project
            .functions
            .discover_functions_recursive(&project.memory_map, ds);

        on_progress(AnalysisStage::ScanningXrefs);
        let _ = project
            .xrefs
            .scan_xrefs(&project.memory_map, ds, &project.functions);
    }

    // --- Strings ---
    on_progress(AnalysisStage::ScanningStrings);
    project.strings.scan_memory(&project.memory_map);

    if let Some(ref ds) = disasm {
        on_progress(AnalysisStage::StringXrefs);
        let _ = project.xrefs.scan_string_xrefs(
            &project.memory_map,
            ds,
            &project.functions,
            &project.strings.strings,
        );
    }

    // --- Constants ---
    on_progress(AnalysisStage::ScanningConstants);
    project.constants.scan(&project.memory_map);

    // --- Debug info ---
    on_progress(AnalysisStage::ExtractingDebugInfo);
    let bytes = std::fs::read(path).unwrap_or_default();
    let debug_info = debuginfo::extract_debug_info(&bytes, loaded.arch).unwrap_or_default();

    let pdb_debug = if let Some(ref pdb_path) = loaded.debug_info_path {
        let pdb_candidate = path
            .parent()
            .map(|dir| dir.join(pdb_path.file_name().unwrap_or_default()))
            .unwrap_or_else(|| pdb_path.clone());
        if pdb_candidate.exists() {
            debuginfo::extract_pdb_info(&pdb_candidate, loaded.arch).unwrap_or_default()
        } else if pdb_path.exists() {
            debuginfo::extract_pdb_info(pdb_path, loaded.arch).unwrap_or_default()
        } else {
            Default::default()
        }
    } else {
        Default::default()
    };

    let mut debug_type_count = 0usize;
    let mut debug_sig_count = 0usize;
    for di in [&debug_info, &pdb_debug] {
        for ty in &di.types {
            project.types.add_type(ty.clone());
            debug_type_count += 1;
        }
        for (&addr, sig) in &di.function_signatures {
            project.types.function_signatures.insert(addr, sig.clone());
            debug_sig_count += 1;
            if let Some(func) = project.functions.functions.get_mut(&addr)
                && func.name.starts_with("sub_")
            {
                func.name.clone_from(&sig.name);
            }
        }
        for (&addr, var) in &di.global_variables {
            project.types.global_variables.insert(addr, var.clone());
        }
        for (&addr, vars) in &di.local_variables {
            project.types.local_variables.insert(addr, vars.clone());
        }
        for (&addr, line_info) in &di.source_lines {
            project.types.source_lines.insert(addr, line_info.clone());
        }
    }

    // --- Type libraries ---
    let platform = platform_string(loaded.arch, loaded.format);
    project.type_libs.load_for_platform(&platform);

    // --- Type propagation ---
    on_progress(AnalysisStage::TypePropagation);
    let propagator = TypePropagator::new(
        &project.functions,
        &project.xrefs,
        &project.type_libs,
        &project.imports,
    );
    let type_info = propagator.propagate(&debug_info, &project.types);
    for (&addr, info) in &type_info {
        if let Some(ref sig) = info.signature {
            project
                .types
                .function_signatures
                .entry(addr)
                .or_insert_with(|| sig.clone());
            if let Some(func) = project.functions.functions.get_mut(&addr)
                && func.name.starts_with("sub_")
            {
                func.name.clone_from(&sig.name);
            }
        }
    }

    // --- Analysis passes ---
    on_progress(AnalysisStage::RunningAnalysisPasses);
    let mut pm = PluginManager::default();
    pm.register_analysis_pass(Box::new(SuspiciousNamePass));
    pm.register_analysis_pass(Box::new(HeuristicNamePass));

    let sig_db = match loaded.arch {
        Architecture::X86_64 => SignatureDatabase::builtin_x86_64(),
        Architecture::Arm64 => SignatureDatabase::builtin_arm64(),
        _ => SignatureDatabase::new(),
    };
    pm.register_analysis_pass(Box::new(SignaturePass::new(sig_db)));

    let findings = pm
        .run_all_analysis_passes(
            &project.memory_map,
            &mut project.functions,
            &project.xrefs,
            &project.strings,
        )
        .unwrap_or_default();

    // --- Build xref counts ---
    let mut func_xref_counts = HashMap::new();
    for &addr in project.functions.functions.keys() {
        let xrefs_in = project
            .xrefs
            .to_address_xrefs
            .get(&addr)
            .map(|v| v.len())
            .unwrap_or(0);
        let xrefs_out = project
            .xrefs
            .from_address_xrefs
            .get(&addr)
            .map(|v| v.len())
            .unwrap_or(0);
        func_xref_counts.insert(addr, (xrefs_in, xrefs_out));
    }

    // --- Summary ---
    let func_count = project.functions.functions.len();
    let import_count = project.imports.len();
    let export_count = project.exports.len();
    let sym_count = loaded.symbols.len();
    let lib_count = project.libraries.len();

    let mut summary = format!(
        "Loaded '{}': {} functions, {} symbols, {} imports, {} exports, {} libraries",
        path.display(),
        func_count,
        sym_count,
        import_count,
        export_count,
        lib_count,
    );
    if debug_sig_count > 0 || debug_type_count > 0 {
        summary.push_str(&format!(
            ", {} debug signatures, {} debug types",
            debug_sig_count, debug_type_count
        ));
    }

    on_progress(AnalysisStage::Done);

    Ok(AnalysisResult {
        project,
        findings,
        func_xref_counts,
        entry_point: loaded.entry_point,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_display() {
        assert_eq!(
            AnalysisStage::LoadingBinary.to_string(),
            "Loading binary..."
        );
        assert_eq!(AnalysisStage::Done.to_string(), "Done");
    }
}
