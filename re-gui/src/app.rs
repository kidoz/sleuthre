use re_core::analysis::cfg::ControlFlowGraph;
use re_core::analysis::type_propagation::{FunctionTypeInfo, TypePropagator};
use re_core::debuginfo;
use re_core::disasm::Disassembler;
use re_core::loader::load_binary;
use re_core::plugin::{AnalysisFinding, PluginManager};
use re_core::project::{ActionKind, PendingAction, Project};
use std::collections::HashMap;
use uuid::Uuid;

use crate::theme::{SyntaxColors, ThemeMode};
use re_core::analysis::passes::{HeuristicNamePass, SignaturePass, SuspiciousNamePass};
use re_core::signatures::SignatureDatabase;

pub(crate) struct SleuthreApp {
    pub(crate) project: Option<Project>,
    pub(crate) disasm: Option<Disassembler>,
    pub(crate) current_cfg: Option<ControlFlowGraph>,
    pub(crate) output: String,
    pub(crate) function_filter: String,
    pub(crate) string_filter: String,
    pub(crate) active_tab: Tab,
    pub(crate) dock_state: egui_dock::DockState<Tab>,
    pub(crate) current_address: u64,

    pub(crate) rename_active: bool,
    pub(crate) rename_input: String,
    pub(crate) comment_active: bool,
    pub(crate) comment_input: String,
    pub(crate) xref_active: bool,
    pub(crate) focused_address: Option<u64>,

    pub(crate) approval_queue_open: bool,
    pub(crate) decompiled_code: re_core::il::hlil::DecompiledCode,
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
    pub(crate) xref_filter: String,

    // Graph view state
    pub(crate) graph_zoom: f32,
    pub(crate) graph_options: GraphOptions,

    // Theme
    pub(crate) theme_mode: ThemeMode,
    pub(crate) syntax: SyntaxColors,
    pub(crate) theme_changed: bool,

    // Plugins
    pub(crate) plugin_manager: PluginManager,
    pub(crate) plugin_findings: Vec<AnalysisFinding>,
    pub(crate) show_findings_window: bool,

    // Structure creation
    pub(crate) create_struct_active: bool,
    pub(crate) new_struct_name: String,
    pub(crate) editing_struct: Option<String>,
    pub(crate) new_field_name: String,
    pub(crate) new_field_offset: String,
    pub(crate) new_field_type: String,

    // Hex view editing
    pub(crate) hex_selected_addr: Option<u64>,
    pub(crate) hex_edit_buffer: String,

    // Toasts
    pub(crate) toasts: Vec<Toast>,

    // Debugger
    pub(crate) debugger: Box<dyn re_core::Debugger>,

    // Scripting
    pub(crate) script_engine: re_core::scripting::ScriptEngine,
    pub(crate) script_input: String,

    // Auto-save
    pub(crate) last_save_time: f64,

    // Output panel
    pub(crate) output_panel_visible: bool,
    pub(crate) output_panel_height: f32,

    // Functions list sorting/filtering
    pub(crate) func_sort_column: FunctionSortColumn,
    pub(crate) func_sort_ascending: bool,
    pub(crate) func_type_filter: FunctionTypeFilter,
    pub(crate) func_xref_counts: HashMap<u64, (usize, usize)>,

    // Navigation band layer
    pub(crate) nav_band_layer: NavBandLayer,

    // Command bar
    pub(crate) command_bar_input: String,
    pub(crate) command_bar_results: Vec<CommandBarResult>,
    pub(crate) command_bar_selected: usize,
    pub(crate) command_bar_active: bool,
}

pub(crate) struct Toast {
    pub(crate) kind: ToastKind,
    pub(crate) message: String,
    pub(crate) expires_at: f64,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
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
    Xrefs,
}

impl std::fmt::Display for Tab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tab::Disassembly => write!(f, "Disassembly"),
            Tab::Graph => write!(f, "Graph"),
            Tab::Decompiler => write!(f, "Pseudocode"),
            Tab::HexView => write!(f, "Hex View"),
            Tab::Strings => write!(f, "Strings"),
            Tab::Imports => write!(f, "Imports"),
            Tab::Exports => write!(f, "Exports"),
            Tab::Structures => write!(f, "Structures"),
            Tab::CallGraph => write!(f, "Call Graph"),
            Tab::Xrefs => write!(f, "Cross References"),
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum SearchMode {
    Address,
    HexPattern,
    String,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum FunctionSortColumn {
    Address,
    Name,
    Size,
    XrefsIn,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum FunctionTypeFilter {
    All,
    User,
    Library,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum NavBandLayer {
    Segments,
    Functions,
    AnalysisState,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum GraphLayoutMode {
    Hierarchical,
    Compact,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) struct GraphOptions {
    pub(crate) layout_mode: GraphLayoutMode,
    pub(crate) show_edge_labels: bool,
    pub(crate) show_minimap: bool,
}

#[derive(Clone)]
pub(crate) struct CommandBarResult {
    pub(crate) label: String,
    pub(crate) address: u64,
    pub(crate) kind: CommandBarResultKind,
}

#[derive(Clone, PartialEq)]
pub(crate) enum CommandBarResultKind {
    Function,
    Import,
    Export,
    StringRef,
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
            dock_state: egui_dock::DockState::new(vec![Tab::Disassembly]),
            current_address: 0,
            rename_active: false,
            rename_input: String::new(),
            comment_active: false,
            comment_input: String::new(),
            xref_active: false,
            focused_address: None,
            approval_queue_open: false,
            decompiled_code: re_core::il::hlil::DecompiledCode {
                text: "// Press F5 to decompile".to_string(),
                annotations: vec![],
            },
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
            xref_filter: String::new(),
            graph_zoom: 1.0,
            graph_options: GraphOptions {
                layout_mode: GraphLayoutMode::Hierarchical,
                show_edge_labels: true,
                show_minimap: true,
            },
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
            create_struct_active: false,
            new_struct_name: String::new(),
            editing_struct: None,
            new_field_name: String::new(),
            new_field_offset: String::new(),
            new_field_type: String::new(),
            hex_selected_addr: None,
            hex_edit_buffer: String::new(),
            toasts: Vec::new(),
            debugger: Box::new(re_core::MockDebugger::default()),
            script_engine: re_core::scripting::ScriptEngine::new(),
            script_input: String::new(),
            last_save_time: 0.0,
            output_panel_visible: true,
            output_panel_height: 150.0,
            func_sort_column: FunctionSortColumn::Address,
            func_sort_ascending: true,
            func_type_filter: FunctionTypeFilter::All,
            func_xref_counts: HashMap::new(),
            nav_band_layer: NavBandLayer::Segments,
            command_bar_input: String::new(),
            command_bar_results: Vec::new(),
            command_bar_selected: 0,
            command_bar_active: false,
        }
    }
}

impl SleuthreApp {
    pub(crate) fn add_toast(&mut self, kind: ToastKind, message: String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        self.toasts.push(Toast {
            kind,
            message,
            expires_at: now + 5.0, // Default 5 seconds
        });
    }

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
                    let debug_info =
                        debuginfo::extract_debug_info(&bytes, loaded.arch).unwrap_or_default();

                    // Also try PDB if available
                    let pdb_debug = if let Some(ref pdb_path) = loaded.debug_info_path {
                        // Try relative to binary directory
                        let pdb_candidate = path
                            .parent()
                            .map(|dir| dir.join(pdb_path.file_name().unwrap_or_default()))
                            .unwrap_or_else(|| pdb_path.clone());
                        if pdb_candidate.exists() {
                            debuginfo::extract_pdb_info(&pdb_candidate, loaded.arch)
                                .unwrap_or_default()
                        } else if pdb_path.exists() {
                            debuginfo::extract_pdb_info(pdb_path, loaded.arch).unwrap_or_default()
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

                    // Configure analysis passes based on architecture
                    self.plugin_manager.clear_analysis_passes();
                    self.plugin_manager
                        .register_analysis_pass(Box::new(SuspiciousNamePass));
                    self.plugin_manager
                        .register_analysis_pass(Box::new(HeuristicNamePass));

                    let sig_db = match loaded.arch {
                        re_core::arch::Architecture::X86_64 => SignatureDatabase::builtin_x86_64(),
                        re_core::arch::Architecture::Arm64 => SignatureDatabase::builtin_arm64(),
                        _ => SignatureDatabase::new(),
                    };
                    self.plugin_manager
                        .register_analysis_pass(Box::new(SignaturePass::new(sig_db)));

                    // Run analysis passes automatically
                    if let Ok(findings) = self.plugin_manager.run_all_analysis_passes(
                        &project.memory_map,
                        &mut project.functions,
                        &project.xrefs,
                        &project.strings,
                    ) {
                        self.plugin_findings = findings;
                        if !self.plugin_findings.is_empty() {
                            self.add_toast(
                                ToastKind::Success,
                                format!("Analysis found {} items", self.plugin_findings.len()),
                            );
                        }
                    }

                    // Build xref counts cache
                    self.func_xref_counts.clear();
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
                        self.func_xref_counts.insert(addr, (xrefs_in, xrefs_out));
                    }

                    self.current_address = loaded.entry_point;
                    self.disasm = disasm;
                    self.project = Some(project);
                    self.update_cfg();
                    let msg = format!(
                        "Loaded '{}': {} functions, {} symbols, {} imports, {} exports, {} libraries",
                        path.display(),
                        func_count,
                        sym_count,
                        import_count,
                        export_count,
                        lib_count
                    );
                    self.add_toast(ToastKind::Success, format!("Loaded '{}'", path.display()));
                    self.output.push_str(&msg);
                    if debug_sig_count > 0 || debug_type_count > 0 {
                        self.output.push_str(&format!(
                            ", {} debug signatures, {} debug types",
                            debug_sig_count, debug_type_count
                        ));
                    }
                    self.output.push('\n');
                }
                Err(e) => {
                    self.add_toast(ToastKind::Error, format!("Load error: {}", e));
                    self.output.push_str(&format!("Error: {}\n", e));
                }
            }
        }
    }

    pub(crate) fn save_project(&mut self) {
        if self.project.is_none() {
            self.add_toast(ToastKind::Warning, "No project to save.".into());
            return;
        }

        let file_dialog = rfd::FileDialog::new().add_filter("Sleuthre Project", &["slre"]);
        if let Some(path) = file_dialog.save_file()
            && let Some(ref mut project) = self.project
        {
            match project.save(&path) {
                Ok(()) => {
                    self.add_toast(
                        ToastKind::Success,
                        format!("Project saved to '{}'", path.display()),
                    );
                    self.output
                        .push_str(&format!("Project saved to '{}'.\n", path.display()));
                }
                Err(e) => {
                    self.add_toast(ToastKind::Error, format!("Save error: {}", e));
                    self.output.push_str(&format!("Save error: {}\n", e));
                }
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
                    self.add_toast(
                        ToastKind::Success,
                        format!("Project loaded from '{}'", path.display()),
                    );
                    self.output
                        .push_str(&format!("Project loaded from '{}'.\n", path.display()));
                    self.disasm = Disassembler::new(project.arch).ok();
                    self.project = Some(project);
                    self.update_cfg();
                }
                Err(e) => {
                    self.add_toast(ToastKind::Error, format!("Load error: {}", e));
                    self.output.push_str(&format!("Load error: {}\n", e));
                }
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
        let (project, disasm) = match (&mut self.project, &self.disasm) {
            (Some(p), Some(d)) => (p, d),
            _ => return,
        };

        // Check cache first
        if let Some(cached) = project.decompilation_cache.get(&self.current_address) {
            self.decompiled_code = cached.clone();
            return;
        }

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

            // Build symbol map
            let mut symbols = HashMap::new();
            for f in project.functions.functions.values() {
                symbols.insert(f.start_address, f.name.clone());
            }
            for sym in &project.symbols {
                symbols.insert(sym.address, sym.name.clone());
            }
            for imp in &project.imports {
                symbols.insert(imp.address, imp.name.clone());
            }

            // Build type info for the current function
            let type_info = project
                .types
                .function_signatures
                .get(&self.current_address)
                .map(|sig| FunctionTypeInfo {
                    signature: Some(sig.clone()),
                    var_types: Default::default(),
                });

            let code = re_core::il::structuring::decompile(
                func_name,
                &insns,
                arch,
                &symbols,
                type_info.as_ref(),
                &project.types,
                &project.memory_map,
            );

            // Cache it
            project
                .decompilation_cache
                .insert(self.current_address, code.clone());
            self.decompiled_code = code;
        }
    }

    pub(crate) fn run_ai_naming_heuristics(&mut self) {
        let arch = self.project.as_ref().map(|p| p.arch);
        let current_addr = self.current_address;

        let mut toast = None;
        if let Some(ref mut project) = self.project {
            // 1. Run Signature-based matching
            let sig_db = match arch.unwrap_or(re_core::arch::Architecture::X86_64) {
                re_core::arch::Architecture::X86_64 => {
                    re_core::signatures::SignatureDatabase::builtin_x86_64()
                }
                re_core::arch::Architecture::Arm64 => {
                    re_core::signatures::SignatureDatabase::builtin_arm64()
                }
                _ => re_core::signatures::SignatureDatabase::new(),
            };

            let matches = sig_db.scan_and_apply(&project.memory_map, &mut project.functions);
            if !matches.is_empty() {
                toast = Some((
                    ToastKind::Success,
                    format!(
                        "Identified {} library functions via signatures.",
                        matches.len()
                    ),
                ));
            }

            // 2. Original hardcoded heuristic (refined)
            if let Some(s) = project
                .strings
                .strings
                .iter()
                .find(|s| s.value.contains("Bink") || s.value.contains("Smack"))
            {
                project.pending_actions.push(PendingAction {
                    id: Uuid::new_v4(),
                    kind: ActionKind::Rename {
                        address: current_addr,
                        new_name: "decode_bink_frame".to_string(),
                        old_name: "sub_401000".to_string(),
                    },
                    rationale: format!(
                        "Function at {:X} references string '{}'",
                        current_addr, s.value
                    ),
                    confidence: 0.9,
                });
                self.approval_queue_open = true;
            }
        }

        if let Some((kind, msg)) = toast {
            self.add_toast(kind, msg);
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

    pub(crate) fn focus_or_open_tab(&mut self, tab: Tab) {
        if let Some((surface, node, tab_idx)) = self.dock_state.find_tab(&tab) {
            self.dock_state
                .set_focused_node_and_surface((surface, node));
            self.dock_state.set_active_tab((surface, node, tab_idx));
        } else {
            self.dock_state.push_to_focused_leaf(tab);
        }
        self.active_tab = tab;
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
        re_core::arch::Architecture::RiscV32 => "riscv32",
        re_core::arch::Architecture::RiscV64 => "riscv64",
    };
    format!("{}_{}", os, arch_str)
}
