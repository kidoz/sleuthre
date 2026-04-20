use eframe::egui;
use re_core::analysis::cfg::ControlFlowGraph;
use re_core::analysis::type_propagation::FunctionTypeInfo;
use re_core::disasm::Disassembler;
use re_core::plugin::{AnalysisFinding, PluginManager};
use re_core::project::{ActionKind, PendingAction, Project};
use std::collections::HashMap;
use uuid::Uuid;

use crate::theme::{SyntaxColors, ThemeMode};
use re_core::analysis::passes::{MsvcPatternPass, SuspiciousNamePass};

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

    // Struct field editing
    pub(crate) edit_field_active: bool,
    pub(crate) edit_field_struct: String,
    pub(crate) edit_field_index: usize,
    pub(crate) edit_field_name: String,
    pub(crate) edit_field_offset: String,
    pub(crate) edit_field_type: String,

    // Type rename
    pub(crate) rename_type_active: bool,
    pub(crate) rename_type_old: String,
    pub(crate) rename_type_new: String,

    // Enum creation
    pub(crate) create_enum_active: bool,
    pub(crate) new_enum_name: String,
    pub(crate) new_enum_variants: Vec<(String, String)>,

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

    // Tags
    pub(crate) func_tag_filter: Option<String>,
    pub(crate) tag_active: bool,
    pub(crate) tag_input: String,
    pub(crate) cached_func_tag_filter: Option<String>,

    // Cached sorted/filtered function list (addresses only).
    // Rebuilt only when filter/sort/type changes or functions are modified.
    pub(crate) cached_func_list: Vec<u64>,
    pub(crate) cached_func_list_dirty: bool,
    // Snapshot of the inputs that produced the cache, for invalidation.
    pub(crate) cached_func_filter: String,
    pub(crate) cached_func_sort_col: FunctionSortColumn,
    pub(crate) cached_func_sort_asc: bool,
    pub(crate) cached_func_type_filter: FunctionTypeFilter,
    pub(crate) cached_func_count: usize,

    // Cached disassembly for the visible window
    pub(crate) disasm_cache: Vec<re_core::disasm::Instruction>,
    pub(crate) disasm_cache_base: u64,

    // Command bar
    pub(crate) command_bar_input: String,
    pub(crate) command_bar_results: Vec<CommandBarResult>,
    pub(crate) command_bar_selected: usize,
    pub(crate) command_bar_active: bool,

    // Background loading
    pub(crate) load_receiver: Option<std::sync::mpsc::Receiver<LoadProgress>>,
    pub(crate) load_stage: Option<String>,

    // Entropy
    pub(crate) entropy_map: Option<re_core::analysis::entropy::EntropyMap>,

    // Re-analysis
    pub(crate) reanalyze_active: bool,
    pub(crate) reanalyze_config: re_core::analysis::pipeline::AnalysisConfig,

    // Binary diff
    pub(crate) diff_project_b: Option<re_core::project::Project>,
    pub(crate) diff_result: Option<re_core::analysis::diff::DiffResult>,
    pub(crate) diff_filter: String,
    pub(crate) diff_selected: Option<usize>,
    pub(crate) diff_lines: Vec<re_core::analysis::diff::DiffLine>,

    // Signature manager
    pub(crate) user_sig_db: re_core::signatures::SignatureDatabase,
    pub(crate) sig_filter: String,
    pub(crate) new_sig_name: String,
    pub(crate) new_sig_pattern: String,
    pub(crate) new_sig_library: String,

    // Archive browser
    pub(crate) archive_registry: re_core::formats::archive::FormatRegistry,
    pub(crate) archive_image_registry: re_core::formats::image::ImageDecoderRegistry,
    pub(crate) archive_data: Option<Vec<u8>>,
    pub(crate) archive_dir: Option<re_core::formats::archive::ArchiveDirectory>,
    pub(crate) archive_format: Option<String>,
    pub(crate) archive_selected: Option<usize>,
    pub(crate) archive_preview: Option<Vec<u8>>,
    pub(crate) archive_image_texture: Option<(egui::TextureHandle, f32, f32)>,
    pub(crate) archive_filter: String,

    // Data inspector (struct overlays)
    pub(crate) overlay_add_active: bool,
    pub(crate) overlay_add_address: String,
    pub(crate) overlay_add_type: String,
    pub(crate) overlay_add_count: String,
    pub(crate) overlay_add_label: String,

    // Source compare
    pub(crate) source_compare_dir: Option<std::path::PathBuf>,
    pub(crate) source_compare_files: Vec<(String, String)>,
    pub(crate) source_compare_mappings: Vec<SourceMapping>,
    pub(crate) source_compare_selected: Option<usize>,
    pub(crate) source_compare_scroll_y: f32,

    // Tabular viewer
    pub(crate) tabular_data: Option<TabularData>,
    pub(crate) tabular_filter: String,
    pub(crate) tabular_sort_col: Option<usize>,
    pub(crate) tabular_sort_asc: bool,

    // Import symbols dialog
    pub(crate) import_symbols_active: bool,
    pub(crate) import_symbols_path: String,
    pub(crate) import_symbols_preview: Option<(
        re_core::import::symbols::SymbolFormat,
        Vec<re_core::import::symbols::ImportedSymbol>,
    )>,

    // Image preview pane
    pub(crate) image_preview_slots: Vec<ImagePreviewSlot>,
    pub(crate) image_preview_selected: Option<usize>,
    pub(crate) image_zoom: f32,
    pub(crate) image_pan: egui::Vec2,

    // Bytecode view
    pub(crate) bytecode_registry: re_core::formats::bytecode::BytecodeFormatRegistry,
    pub(crate) bytecode_bytes: Option<Vec<u8>>,
    pub(crate) bytecode_opcodes: Vec<re_core::formats::bytecode::OpcodeDefinition>,
    pub(crate) bytecode_insns: Vec<re_core::formats::bytecode::BytecodeInstruction>,
    pub(crate) bytecode_format_name: Option<String>,

    // Class editor
    pub(crate) class_edit_active: bool,
    pub(crate) class_edit_target: String,
    pub(crate) class_edit_base: String,
    pub(crate) class_edit_vtable_label: String,
    pub(crate) class_edit_vtable_addr: String,

    // Plugin registry (Rhai scripts hot-reloaded from a user directory).
    pub(crate) plugins: re_core::scripting::PluginRegistry,
    pub(crate) plugin_runner: re_core::scripting::AsyncPluginRunner,

    // Live collaboration broadcaster.
    pub(crate) collab_broadcaster: Option<re_core::collab::CollabBroadcaster>,
    pub(crate) collab_status: Option<String>,
    pub(crate) collab_dialog_active: bool,
    pub(crate) collab_port_input: String,
    /// High-water mark of `project.undo_stack` indices already published over
    /// the collab broadcaster.
    pub(crate) last_published_undo_idx: usize,

    // Debugger panel
    pub(crate) debugger_remote: Option<re_core::debuggers::GdbRemoteDebugger>,
    pub(crate) debugger_addr_input: String,
    pub(crate) debugger_regs: std::collections::HashMap<String, u64>,
    pub(crate) debugger_mem_addr: String,
    pub(crate) debugger_mem_size: u32,
    pub(crate) debugger_mem_data: Option<Vec<u8>>,
    pub(crate) debugger_bp_input: String,
    pub(crate) debugger_last_stop: Option<re_core::StopReason>,
    /// Async operation currently in flight on the debugger; the handle is
    /// borrowed to a worker thread and returned via the channel when the
    /// blocking RSP exchange completes.
    pub(crate) debugger_pending: Option<PendingDebuggerOp>,
    /// Deferred breakpoint set from a disassembly context-menu click — the
    /// scroll-area closure can't call `&mut self` methods directly so the
    /// click stashes intent here for the post-closure handler.
    pub(crate) pending_bp_set: Option<(u64, bool)>,
    /// Active thread ID selected in the debugger panel; `None` until the
    /// user picks one from the thread selector.
    pub(crate) debugger_active_thread: Option<u64>,
    /// DWARF stack-unwinder built once when a binary is loaded; used by the
    /// debugger panel to walk frames without requiring frame pointers.
    pub(crate) debugger_unwinder: Option<re_core::debuginfo::unwind::StackUnwinder>,
    /// Software breakpoints set transiently by step-source / step-over and
    /// removed on the next stop reply.
    pub(crate) debugger_temp_breakpoints: Vec<u64>,
    /// When `true`, the next BP set targets only `debugger_active_thread`.
    pub(crate) debugger_bp_scope_thread: bool,
}

/// Async operation in flight on the debugger.
pub(crate) struct PendingDebuggerOp {
    pub(crate) op: crate::views::debugger::DebuggerOp,
    pub(crate) rx: std::sync::mpsc::Receiver<(
        re_core::debuggers::GdbRemoteDebugger,
        re_core::Result<re_core::StopReason>,
    )>,
}

pub(crate) use crate::views::image_preview::ImagePreviewSlot;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceMatchStatus {
    Matched,
    Divergent,
    Unmatched,
}

#[derive(Clone)]
pub(crate) struct SourceMapping {
    pub(crate) address: u64,
    pub(crate) binary_name: String,
    pub(crate) source_function: Option<String>,
    pub(crate) source_file: Option<String>,
    pub(crate) status: SourceMatchStatus,
}

#[derive(Clone, Default)]
pub(crate) struct TabularData {
    pub(crate) headers: Vec<String>,
    pub(crate) rows: Vec<Vec<String>>,
    pub(crate) source_name: String,
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
    Entropy,
    Signatures,
    Diff,
    Archives,
    DataInspector,
    SourceCompare,
    Tabular,
    ImagePreview,
    Bytecode,
    Debugger,
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
            Tab::Entropy => write!(f, "Entropy"),
            Tab::Signatures => write!(f, "Signatures"),
            Tab::Diff => write!(f, "Binary Diff"),
            Tab::Archives => write!(f, "Archives"),
            Tab::DataInspector => write!(f, "Data Inspector"),
            Tab::SourceCompare => write!(f, "Source Compare"),
            Tab::Tabular => write!(f, "Tabular"),
            Tab::ImagePreview => write!(f, "Images"),
            Tab::Bytecode => write!(f, "Bytecode"),
            Tab::Debugger => write!(f, "Debugger"),
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
    Entropy,
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

pub(crate) enum LoadProgress {
    Stage(String),
    Done(std::result::Result<Box<re_core::analysis::pipeline::AnalysisResult>, String>),
}

impl Default for SleuthreApp {
    fn default() -> Self {
        Self {
            project: None,
            disasm: None,
            current_cfg: None,
            output: "Sleuthre v0.3.0 started.\n\
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
                pm.register_analysis_pass(Box::new(MsvcPatternPass));
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
            edit_field_active: false,
            edit_field_struct: String::new(),
            edit_field_index: 0,
            edit_field_name: String::new(),
            edit_field_offset: String::new(),
            edit_field_type: String::new(),
            rename_type_active: false,
            rename_type_old: String::new(),
            rename_type_new: String::new(),
            create_enum_active: false,
            new_enum_name: String::new(),
            new_enum_variants: Vec::new(),
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
            func_tag_filter: None,
            tag_active: false,
            tag_input: String::new(),
            cached_func_tag_filter: None,
            cached_func_list: Vec::new(),
            cached_func_list_dirty: true,
            cached_func_filter: String::new(),
            cached_func_sort_col: FunctionSortColumn::Address,
            cached_func_sort_asc: true,
            cached_func_type_filter: FunctionTypeFilter::All,
            cached_func_count: 0,
            disasm_cache: Vec::new(),
            disasm_cache_base: u64::MAX,
            command_bar_input: String::new(),
            command_bar_results: Vec::new(),
            command_bar_selected: 0,
            command_bar_active: false,
            load_receiver: None,
            load_stage: None,
            entropy_map: None,
            diff_project_b: None,
            diff_result: None,
            diff_filter: String::new(),
            diff_selected: None,
            diff_lines: Vec::new(),
            reanalyze_active: false,
            reanalyze_config: re_core::analysis::pipeline::AnalysisConfig::default(),
            user_sig_db: re_core::signatures::SignatureDatabase::new(),
            sig_filter: String::new(),
            new_sig_name: String::new(),
            new_sig_pattern: String::new(),
            new_sig_library: "user".into(),
            archive_registry: re_core::formats::archive::default_registry(),
            archive_image_registry: re_core::formats::image::default_image_registry(),
            archive_data: None,
            archive_dir: None,
            archive_format: None,
            archive_selected: None,
            archive_preview: None,
            archive_image_texture: None,
            archive_filter: String::new(),
            overlay_add_active: false,
            overlay_add_address: String::new(),
            overlay_add_type: String::new(),
            overlay_add_count: "1".into(),
            overlay_add_label: String::new(),
            source_compare_dir: None,
            source_compare_files: Vec::new(),
            source_compare_mappings: Vec::new(),
            source_compare_selected: None,
            source_compare_scroll_y: 0.0,
            tabular_data: None,
            tabular_filter: String::new(),
            tabular_sort_col: None,
            tabular_sort_asc: true,
            import_symbols_active: false,
            import_symbols_path: String::new(),
            import_symbols_preview: None,
            image_preview_slots: Vec::new(),
            image_preview_selected: None,
            image_zoom: 1.0,
            image_pan: egui::Vec2::ZERO,
            bytecode_registry: re_core::formats::bytecode::default_bytecode_registry(),
            bytecode_bytes: None,
            bytecode_opcodes: Vec::new(),
            bytecode_insns: Vec::new(),
            bytecode_format_name: None,
            class_edit_active: false,
            class_edit_target: String::new(),
            class_edit_base: String::new(),
            class_edit_vtable_label: String::new(),
            class_edit_vtable_addr: String::new(),
            plugins: {
                let mut reg = re_core::scripting::PluginRegistry::new();
                if let Some(dir) = re_core::scripting::PluginRegistry::default_user_dir() {
                    reg.set_dir(dir);
                    let _ = reg.reload_changed();
                }
                reg
            },
            plugin_runner: re_core::scripting::AsyncPluginRunner::new(),
            collab_broadcaster: None,
            collab_status: None,
            collab_dialog_active: false,
            collab_port_input: String::new(),
            last_published_undo_idx: 0,
            debugger_remote: None,
            debugger_addr_input: "127.0.0.1:1234".into(),
            debugger_regs: std::collections::HashMap::new(),
            debugger_mem_addr: "0x0".into(),
            debugger_mem_size: 64,
            debugger_mem_data: None,
            debugger_bp_input: "0x0".into(),
            debugger_last_stop: None,
            debugger_pending: None,
            pending_bp_set: None,
            debugger_active_thread: None,
            debugger_unwinder: None,
            debugger_temp_breakpoints: Vec::new(),
            debugger_bp_scope_thread: false,
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

    pub(crate) fn open_binary(&mut self, ctx: &eframe::egui::Context) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Executables", &["elf", "exe", "dll", "so", "bin"])
            .pick_file()
        else {
            return;
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let ctx_clone = ctx.clone();

        std::thread::spawn(move || {
            let result = re_core::analysis::pipeline::analyze_binary(&path, |stage| {
                let _ = tx.send(LoadProgress::Stage(stage.to_string()));
                ctx_clone.request_repaint();
            });
            let _ = tx.send(LoadProgress::Done(
                result.map(Box::new).map_err(|e| e.to_string()),
            ));
            ctx_clone.request_repaint();
        });

        self.load_receiver = Some(rx);
        self.load_stage = Some("Loading...".into());
    }

    /// Poll the background loader for progress/completion.
    pub(crate) fn poll_load(&mut self) {
        let Some(ref rx) = self.load_receiver else {
            return;
        };

        while let Ok(msg) = rx.try_recv() {
            match msg {
                LoadProgress::Stage(s) => {
                    self.load_stage = Some(s);
                }
                LoadProgress::Done(Ok(result)) => {
                    // Create a fresh Disassembler on the main thread
                    // (Capstone is !Send so it cannot come from the worker)
                    self.disasm = Disassembler::new(result.project.arch).ok();
                    self.current_address = result.entry_point;
                    self.func_xref_counts = result.func_xref_counts;
                    if !result.findings.is_empty() {
                        self.add_toast(
                            ToastKind::Success,
                            format!("Analysis found {} items", result.findings.len()),
                        );
                    }
                    self.plugin_findings = result.findings;
                    self.add_toast(
                        ToastKind::Success,
                        format!("Loaded '{}'", result.project.name),
                    );
                    self.output.push_str(&result.summary);
                    self.output.push('\n');
                    self.project = Some(result.project);
                    self.cached_func_list_dirty = true;
                    // Compute entropy map
                    if let Some(ref project) = self.project {
                        self.entropy_map = Some(re_core::analysis::entropy::compute_entropy_map(
                            &project.memory_map,
                            256,
                            256,
                        ));
                    }
                    // Build the DWARF stack-unwinder from the binary so the
                    // debugger panel can walk frames without requiring frame
                    // pointers. Best-effort: a binary without `.eh_frame`
                    // simply leaves the option as `None`.
                    if let Some(ref project) = self.project
                        && let Ok(bytes) = std::fs::read(&project.path)
                    {
                        self.debugger_unwinder =
                            re_core::debuginfo::unwind::StackUnwinder::from_bytes(&bytes);
                    }
                    self.update_cfg();
                    self.load_receiver = None;
                    self.load_stage = None;
                    return;
                }
                LoadProgress::Done(Err(e)) => {
                    self.add_toast(ToastKind::Error, format!("Load error: {}", e));
                    self.output.push_str(&format!("Error: {}\n", e));
                    self.load_receiver = None;
                    self.load_stage = None;
                    return;
                }
            }
        }
    }

    pub(crate) fn is_loading(&self) -> bool {
        self.load_receiver.is_some()
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
                    self.cached_func_list_dirty = true;
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
        // Invalidate disassembly cache on navigation
        self.disasm_cache_base = u64::MAX;
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

            // Cache it and record what it referenced so a future rename or
            // type edit invalidates this entry without a project-wide clear.
            let (callees, types) = code.dependencies();
            project
                .cache_deps
                .set_dependencies(self.current_address, callees, types);
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
            || self.tag_active
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
