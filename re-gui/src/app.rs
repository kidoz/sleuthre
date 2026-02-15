use re_core::analysis::cfg::ControlFlowGraph;
use re_core::analysis::type_propagation::TypePropagator;
use re_core::debuginfo;
use re_core::disasm::Disassembler;
use re_core::loader::load_binary;
use re_core::plugin::{AnalysisFinding, PluginManager};
use re_core::project::{ActionKind, PendingAction, Project};
use uuid::Uuid;

use re_core::analysis::passes::SuspiciousNamePass;
use crate::theme::{SyntaxColors, ThemeMode};

pub(crate) struct SleuthreApp {
    pub(crate) project: Option<Project>,
    pub(crate) disasm: Option<Disassembler>,
    pub(crate) current_cfg: Option<ControlFlowGraph>,
    pub(crate) output: String,
    pub(crate) function_filter: String,
    pub(crate) string_filter: String,
    pub(crate) active_tab: Tab,
    pub(crate) current_address: u64,

    pub(crate) rename_active: bool,
    pub(crate) rename_input: String,
    pub(crate) comment_active: bool,
    pub(crate) comment_input: String,
    pub(crate) xref_active: bool,
    pub(crate) focused_address: Option<u64>,

    pub(crate) approval_queue_open: bool,
    pub(crate) decompiled_code: String,
    pub(crate) trigger_decompile: bool,

    pub(crate) command_input: String,
    pub(crate) import_filter: String,
    pub(crate) export_filter: String,

    pub(crate) goto_active: bool,
    pub(crate) goto_input: String,

    pub(crate) bookmark_active: bool,
    pub(crate) bookmark_input: String,

    pub(crate) search_active: bool,
    pub(crate) search_input: String,
    pub(crate) search_results: Vec<(u64, String)>,
    pub(crate) search_mode: SearchMode,

    pub(crate) structure_filter: String,
    pub(crate) call_graph_filter: String,

    // Graph view state
    pub(crate) graph_zoom: f32,

    // Theme
    pub(crate) theme_mode: ThemeMode,
    pub(crate) syntax: SyntaxColors,
    pub(crate) theme_changed: bool,

    // Plugins
    pub(crate) plugin_manager: PluginManager,
    pub(crate) plugin_findings: Vec<AnalysisFinding>,
    pub(crate) show_findings_window: bool,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum Tab {
    Disassembly,
    Graph,
    Decompiler,
    HexView,
    Strings,
    Imports,
    Exports,
    Structures,
    CallGraph,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum SearchMode {
    Address,
    HexPattern,
    String,
}

impl Default for SleuthreApp {
    fn default() -> Self {
        Self {
            project: None,
            disasm: None,
            current_cfg: None,
            output: "Sleuthre v0.1.0 started.\n\
                     Analysis subsystem has been initialized.\n\
                     Hotkeys: F5 decompile, Space graph, N rename, ; comment, X xrefs,\n\
                     Ctrl+G goto, Ctrl+D bookmark, Ctrl+F search, Alt+Left/Right navigate.\n"
                .to_owned(),
            function_filter: String::new(),
            string_filter: String::new(),
            active_tab: Tab::Disassembly,
            current_address: 0,
            rename_active: false,
            rename_input: String::new(),
            comment_active: false,
            comment_input: String::new(),
            xref_active: false,
            focused_address: None,
            approval_queue_open: false,
            decompiled_code: "// Press F5 to decompile".to_string(),
            trigger_decompile: false,
            command_input: String::new(),
            import_filter: String::new(),
            export_filter: String::new(),
            goto_active: false,
            goto_input: String::new(),
            bookmark_active: false,
            bookmark_input: String::new(),
            search_active: false,
            search_input: String::new(),
            search_results: Vec::new(),
            search_mode: SearchMode::String,
            structure_filter: String::new(),
            call_graph_filter: String::new(),
            graph_zoom: 1.0,
            theme_mode: ThemeMode::Dark,
            syntax: SyntaxColors::for_theme(ThemeMode::Dark),
            theme_changed: true, // Apply on first frame
            plugin_manager: {
                let mut pm = PluginManager::default();
                pm.register_analysis_pass(Box::new(SuspiciousNamePass));
                pm
            },
            plugin_findings: Vec::new(),
            show_findings_window: false,
        }
    }
}

impl SleuthreApp {
    pub(crate) fn open_binary(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Executables", &["elf", "exe", "dll", "so", "bin"])
            .pick_file()
        {
            match load_binary(&path) {
                Ok(loaded) => {
                    let mut project = Project::new(
                        path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        path.clone(),
                    );
                    project.memory_map = loaded.memory_map;
                    project.imports = loaded.imports;
                    project.exports = loaded.exports;
                    project.symbols.clone_from(&loaded.symbols);
                    project.libraries = loaded.libraries;

                    let disasm = Disassembler::new(loaded.arch).ok();
                    if let Some(ref ds) = disasm {
                        let _ = project.functions.discover_functions(
                            &project.memory_map,
                            ds,
                            loaded.entry_point,
                            loaded.arch,
                        );
                        project.functions.apply_symbols(&loaded.symbols);
                        let _ = project
                            .functions
                            .discover_functions_recursive(&project.memory_map, ds);
                        let _ =
                            project
                                .xrefs
                                .scan_xrefs(&project.memory_map, ds, &project.functions);
                    }
                    project.strings.scan_memory(&project.memory_map);
                    if let Some(ref ds) = disasm {
                        let _ = project.xrefs.scan_string_xrefs(
                            &project.memory_map,
                            ds,
                            &project.functions,
                            &project.strings.strings,
                        );
                    }
                    project.constants.scan(&project.memory_map);

                    // Store arch and format
                    project.arch = loaded.arch;
                    project.binary_format = loaded.format;

                    // Extract debug info from the binary
                    let bytes = std::fs::read(&path).unwrap_or_default();
                    let debug_info = debuginfo::extract_debug_info(&bytes).unwrap_or_default();

                    // Also try PDB if available
                    let pdb_debug = if let Some(ref pdb_path) = loaded.debug_info_path {
                        // Try relative to binary directory
                        let pdb_candidate = path
                            .parent()
                            .map(|dir| dir.join(pdb_path.file_name().unwrap_or_default()))
                            .unwrap_or_else(|| pdb_path.clone());
                        if pdb_candidate.exists() {
                            debuginfo::extract_pdb_info(&pdb_candidate).unwrap_or_default()
                        } else if pdb_path.exists() {
                            debuginfo::extract_pdb_info(pdb_path).unwrap_or_default()
                        } else {
                            Default::default()
                        }
                    } else {
                        Default::default()
                    };

                    // Merge debug info into project
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
                            // Update function names from debug info
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

                    // Load type libraries
                    let platform = platform_string(loaded.arch, loaded.format);
                    project.type_libs.load_for_platform(&platform);

                    // Type propagation
                    let propagator = TypePropagator::new(
                        &project.functions,
                        &project.xrefs,
                        &project.type_libs,
                        &project.imports,
                    );
                    let type_info = propagator.propagate(&debug_info, &project.types);
                    // Apply propagated signatures back
                    for (&addr, info) in &type_info {
                        if let Some(ref sig) = info.signature {
                            project
                                .types
                                .function_signatures
                                .entry(addr)
                                .or_insert_with(|| sig.clone());
                            // Update function names from type propagation
                            if let Some(func) = project.functions.functions.get_mut(&addr)
                                && func.name.starts_with("sub_")
                            {
                                func.name.clone_from(&sig.name);
                            }
                        }
                    }

                    let func_count = project.functions.functions.len();
                    let import_count = project.imports.len();
                    let export_count = project.exports.len();
                    let sym_count = loaded.symbols.len();
                    let lib_count = project.libraries.len();

                    self.current_address = loaded.entry_point;
                    self.disasm = disasm;
                    self.project = Some(project);
                    self.update_cfg();
                    self.output.push_str(&format!(
                        "Loaded '{}': {} functions, {} symbols, {} imports, {} exports, {} libraries",
                        path.display(), func_count, sym_count, import_count, export_count, lib_count
                    ));
                    if debug_sig_count > 0 || debug_type_count > 0 {
                        self.output.push_str(&format!(
                            ", {} debug signatures, {} debug types",
                            debug_sig_count, debug_type_count
                        ));
                    }
                    self.output.push('\n');
                }
                Err(e) => self.output.push_str(&format!("Error: {}\n", e)),
            }
        }
    }

    pub(crate) fn save_project(&mut self) {
        if self.project.is_none() {
            self.output.push_str("No project to save.\n");
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Sleuthre Project", &["slre"])
            .save_file()
            && let Some(ref mut project) = self.project
        {
            match project.save(&path) {
                Ok(()) => self
                    .output
                    .push_str(&format!("Project saved to '{}'.\n", path.display())),
                Err(e) => self.output.push_str(&format!("Save error: {}\n", e)),
            }
        }
    }

    pub(crate) fn load_project(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Sleuthre Project", &["slre"])
            .pick_file()
        {
            match Project::load(&path) {
                Ok(project) => {
                    self.output
                        .push_str(&format!("Project loaded from '{}'.\n", path.display()));
                    self.disasm = Disassembler::new(project.arch).ok();
                    self.project = Some(project);
                    self.update_cfg();
                }
                Err(e) => self.output.push_str(&format!("Load error: {}\n", e)),
            }
        }
    }

    pub(crate) fn update_cfg(&mut self) {
        if let (Some(project), Some(disasm)) = (&self.project, &self.disasm) {
            let mut cfg = ControlFlowGraph::new();
            let _ = cfg.build_for_function(&project.memory_map, disasm, self.current_address);
            self.current_cfg = Some(cfg);
        }
        if self.active_tab == Tab::Decompiler {
            self.decompile_current_function();
        }
    }

    pub(crate) fn decompile_current_function(&mut self) {
        let (project, disasm) = match (&self.project, &self.disasm) {
            (Some(p), Some(d)) => (p, d),
            _ => return,
        };

        if let Ok(insns) = disasm.disassemble_range(&project.memory_map, self.current_address, 500)
        {
            let func_name = project
                .functions
                .functions
                .get(&self.current_address)
                .map(|f| f.name.as_str())
                .unwrap_or("sub_unknown");
            let arch = self
                .disasm
                .as_ref()
                .map(|d| d.arch)
                .unwrap_or(re_core::arch::Architecture::X86_64);
            self.decompiled_code = re_core::il::structuring::decompile(func_name, &insns, arch);
        }
    }

    pub(crate) fn run_ai_naming_heuristics(&mut self) {
        if let Some(ref mut project) = self.project
            && let Some(s) = project
                .strings
                .strings
                .iter()
                .find(|s| s.value.contains("Bink") || s.value.contains("Smack"))
        {
            project.pending_actions.push(PendingAction {
                id: Uuid::new_v4(),
                kind: ActionKind::Rename {
                    address: self.current_address,
                    new_name: "decode_bink_frame".to_string(),
                    old_name: "sub_401000".to_string(),
                },
                rationale: format!(
                    "Function at {:X} references string '{}'",
                    self.current_address, s.value
                ),
                confidence: 0.9,
            });
            self.approval_queue_open = true;
        }
    }

    pub(crate) fn any_modal_active(&self) -> bool {
        self.rename_active
            || self.comment_active
            || self.xref_active
            || self.approval_queue_open
            || self.goto_active
            || self.bookmark_active
            || self.search_active
    }
}

fn platform_string(
    arch: re_core::arch::Architecture,
    format: re_core::loader::BinaryFormat,
) -> String {
    let os = match format {
        re_core::loader::BinaryFormat::Elf => "linux",
        re_core::loader::BinaryFormat::Pe => "windows",
        re_core::loader::BinaryFormat::MachO => "macos",
        re_core::loader::BinaryFormat::Raw => "unknown",
    };
    let arch_str = match arch {
        re_core::arch::Architecture::X86_64 => "x86_64",
        re_core::arch::Architecture::X86 => "x86",
        re_core::arch::Architecture::Arm64 => "arm64",
        re_core::arch::Architecture::Arm => "arm",
        re_core::arch::Architecture::Mips => "mips",
        re_core::arch::Architecture::Mips64 => "mips64",
    };
    format!("{}_{}", os, arch_str)
}
