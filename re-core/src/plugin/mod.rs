//! Plugin API for extending sleuthre with custom analysis passes and loaders.
//!
//! This module provides a trait-based plugin system that allows third-party code to:
//! - Register custom analysis passes that run over loaded binaries
//! - Register custom binary loaders for unsupported formats
//! - Integrate with the core engine through well-defined interfaces

use std::collections::HashMap;

use crate::Result;
use crate::analysis::functions::FunctionManager;
use crate::loader::LoadedBinary;
use crate::memory::MemoryMap;

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

/// Descriptive metadata for a plugin.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Human-readable plugin name (must be unique within a `PluginManager`).
    pub name: String,
    /// Semantic version string (e.g. "0.1.0").
    pub version: String,
    /// Author or organization.
    pub author: String,
    /// Short description of what the plugin does.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Core Plugin trait
// ---------------------------------------------------------------------------

/// Base trait that every plugin must implement.
///
/// Provides lifecycle hooks so the host can initialize and tear down
/// plugin-owned resources.
pub trait Plugin: Send + Sync {
    /// Return metadata describing this plugin.
    fn info(&self) -> PluginInfo;

    /// Called once when the plugin is registered with the manager.
    /// Use this for one-time initialization.
    fn on_load(&mut self) -> Result<()>;

    /// Called when the plugin is unregistered or the manager is dropped.
    /// Use this to release resources.
    fn on_unload(&mut self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Analysis findings
// ---------------------------------------------------------------------------

/// Broad category for an analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    /// Potential security vulnerability.
    Vulnerability,
    /// Recognized code/data pattern.
    Pattern,
    /// Something that deviates from the norm.
    Anomaly,
    /// Neutral informational note.
    Info,
}

/// A single result produced by an analysis pass.
#[derive(Debug, Clone)]
pub struct AnalysisFinding {
    /// Virtual address the finding relates to.
    pub address: u64,
    /// Classification of the finding.
    pub category: FindingCategory,
    /// Human-readable explanation.
    pub message: String,
    /// Confidence / importance score in the range `[0.0, 1.0]`.
    /// A value of `0.0` means lowest severity; `1.0` means highest.
    pub severity: f64,
}

impl AnalysisFinding {
    /// Create a new finding, clamping `severity` to `[0.0, 1.0]`.
    pub fn new(address: u64, category: FindingCategory, message: String, severity: f64) -> Self {
        Self {
            address,
            category,
            message,
            severity: severity.clamp(0.0, 1.0),
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisPass trait
// ---------------------------------------------------------------------------

/// A plugin that performs an analysis pass over a binary's memory and
/// function map, producing zero or more [`AnalysisFinding`]s.
pub trait AnalysisPass: Send + Sync {
    /// Short, unique name for this pass (used in logs and UI).
    fn name(&self) -> &str;

    /// Execute the pass. Implementations may inspect `memory` and mutate
    /// `functions` (e.g. rename, annotate, or add new entries).
    fn run_analysis(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
    ) -> Result<Vec<AnalysisFinding>>;
}

// ---------------------------------------------------------------------------
// LoaderPlugin trait
// ---------------------------------------------------------------------------

/// A plugin that can recognize and load a specific binary format.
pub trait LoaderPlugin: Send + Sync {
    /// Short, unique name for this loader.
    fn name(&self) -> &str;

    /// Quickly decide whether `data` looks like a format this loader
    /// supports (e.g. check magic bytes). Must be side-effect-free.
    fn can_load(&self, data: &[u8]) -> bool;

    /// Parse `data` into a [`LoadedBinary`].
    fn load(&self, data: &[u8]) -> Result<LoadedBinary>;
}

// ---------------------------------------------------------------------------
// PluginManager
// ---------------------------------------------------------------------------

/// Central registry that owns plugin instances and dispatches operations.
pub struct PluginManager {
    /// General-purpose plugins keyed by their `PluginInfo::name`.
    plugins: HashMap<String, Box<dyn Plugin>>,
    /// Registered analysis passes.
    analysis_passes: Vec<Box<dyn AnalysisPass>>,
    /// Registered loader plugins.
    loader_plugins: Vec<Box<dyn LoaderPlugin>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    /// Create an empty manager with no plugins registered.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            analysis_passes: Vec::new(),
            loader_plugins: Vec::new(),
        }
    }

    // -- General plugins ----------------------------------------------------

    /// Register a general-purpose plugin.
    ///
    /// Calls [`Plugin::on_load`] during registration.
    /// Returns an error if a plugin with the same name is already registered
    /// or if `on_load` fails.
    pub fn register_plugin(&mut self, mut plugin: Box<dyn Plugin>) -> Result<()> {
        let info = plugin.info();
        if self.plugins.contains_key(&info.name) {
            return Err(crate::error::Error::Analysis(format!(
                "Plugin '{}' is already registered",
                info.name,
            )));
        }
        plugin.on_load()?;
        self.plugins.insert(info.name, plugin);
        Ok(())
    }

    /// Unregister a plugin by name, calling [`Plugin::on_unload`].
    ///
    /// Returns an error if the plugin is not found or if `on_unload` fails.
    pub fn unregister_plugin(&mut self, name: &str) -> Result<()> {
        let mut plugin = self
            .plugins
            .remove(name)
            .ok_or_else(|| crate::error::Error::Analysis(format!("Plugin '{}' not found", name)))?;
        plugin.on_unload()
    }

    /// List metadata for all registered general-purpose plugins.
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.values().map(|p| p.info()).collect()
    }

    // -- Analysis passes ----------------------------------------------------

    /// Register an analysis pass.
    pub fn register_analysis_pass(&mut self, pass: Box<dyn AnalysisPass>) {
        self.analysis_passes.push(pass);
    }

    /// Run every registered analysis pass, collecting all findings.
    pub fn run_all_analysis_passes(
        &self,
        memory: &MemoryMap,
        functions: &mut FunctionManager,
    ) -> Result<Vec<AnalysisFinding>> {
        let mut all_findings = Vec::new();
        for pass in &self.analysis_passes {
            let findings = pass.run_analysis(memory, functions)?;
            all_findings.extend(findings);
        }
        Ok(all_findings)
    }

    /// Return the names of all registered analysis passes.
    pub fn list_analysis_passes(&self) -> Vec<&str> {
        self.analysis_passes.iter().map(|p| p.name()).collect()
    }

    // -- Loader plugins -----------------------------------------------------

    /// Register a loader plugin.
    pub fn register_loader(&mut self, loader: Box<dyn LoaderPlugin>) {
        self.loader_plugins.push(loader);
    }

    /// Find the first loader that claims it can handle `data`, and load it.
    ///
    /// Returns `None` if no loader matches.
    pub fn try_load(&self, data: &[u8]) -> Option<Result<LoadedBinary>> {
        for loader in &self.loader_plugins {
            if loader.can_load(data) {
                return Some(loader.load(data));
            }
        }
        None
    }

    /// Return the names of all registered loader plugins.
    pub fn list_loaders(&self) -> Vec<&str> {
        self.loader_plugins.iter().map(|l| l.name()).collect()
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        // Best-effort: call on_unload for every plugin still registered.
        for (_name, plugin) in self.plugins.iter_mut() {
            let _ = plugin.on_unload();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::Function;
    use crate::arch::{Architecture, Endianness};
    use crate::loader::LoadedBinary;
    use crate::memory::{MemoryMap, MemorySegment, Permissions};

    // -- Helpers / stub implementations -------------------------------------

    /// A trivial plugin used in tests.
    struct StubPlugin {
        loaded: bool,
    }

    impl StubPlugin {
        fn new() -> Self {
            Self { loaded: false }
        }
    }

    impl Plugin for StubPlugin {
        fn info(&self) -> PluginInfo {
            PluginInfo {
                name: "stub".to_string(),
                version: "0.1.0".to_string(),
                author: "test".to_string(),
                description: "A stub plugin for testing".to_string(),
            }
        }

        fn on_load(&mut self) -> Result<()> {
            self.loaded = true;
            Ok(())
        }

        fn on_unload(&mut self) -> Result<()> {
            self.loaded = false;
            Ok(())
        }
    }

    /// An analysis pass that flags every function whose name starts with
    /// "dangerous_".
    struct DangerousNamePass;

    impl AnalysisPass for DangerousNamePass {
        fn name(&self) -> &str {
            "dangerous-name-detector"
        }

        fn run_analysis(
            &self,
            _memory: &MemoryMap,
            functions: &mut FunctionManager,
        ) -> Result<Vec<AnalysisFinding>> {
            let findings: Vec<AnalysisFinding> = functions
                .functions
                .values()
                .filter(|f| f.name.starts_with("dangerous_"))
                .map(|f| {
                    AnalysisFinding::new(
                        f.start_address,
                        FindingCategory::Vulnerability,
                        format!("Function '{}' has a suspicious name", f.name),
                        0.7,
                    )
                })
                .collect();
            Ok(findings)
        }
    }

    /// A trivial loader that recognises a custom 4-byte magic.
    struct CustomLoader;

    const CUSTOM_MAGIC: &[u8] = b"CUST";

    impl LoaderPlugin for CustomLoader {
        fn name(&self) -> &str {
            "custom-loader"
        }

        fn can_load(&self, data: &[u8]) -> bool {
            data.len() >= 4 && data[..4] == *CUSTOM_MAGIC
        }

        fn load(&self, data: &[u8]) -> Result<LoadedBinary> {
            if !self.can_load(data) {
                return Err(crate::error::Error::Loader(
                    "Not a custom format".to_string(),
                ));
            }
            let mut memory_map = MemoryMap::default();
            memory_map.add_segment(MemorySegment {
                name: "custom_seg".to_string(),
                start: 0x1000,
                size: (data.len() - 4) as u64,
                data: data[4..].to_vec(),
                permissions: Permissions::READ | Permissions::EXECUTE,
            })?;
            Ok(LoadedBinary {
                memory_map,
                entry_point: 0x1000,
                arch: Architecture::X86_64,
                endianness: Endianness::Little,
                symbols: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
                libraries: Vec::new(),
                format: crate::loader::BinaryFormat::Raw,
                debug_info_path: None,
            })
        }
    }

    fn make_memory_map() -> MemoryMap {
        let mut map = MemoryMap::default();
        map.add_segment(MemorySegment {
            name: ".text".to_string(),
            start: 0x1000,
            size: 16,
            data: vec![0xCC; 16],
            permissions: Permissions::READ | Permissions::EXECUTE,
        })
        .unwrap();
        map
    }

    fn make_function_manager() -> FunctionManager {
        let mut mgr = FunctionManager::default();
        mgr.add_function(Function {
            name: "main".to_string(),
            start_address: 0x1000,
            end_address: Some(0x1010),
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });
        mgr.add_function(Function {
            name: "dangerous_eval".to_string(),
            start_address: 0x2000,
            end_address: None,
            calling_convention: Default::default(),
            stack_frame_size: 0,
        });
        mgr
    }

    // -- Plugin registration / lifecycle ------------------------------------

    #[test]
    fn register_and_list_plugin() {
        let mut mgr = PluginManager::new();
        mgr.register_plugin(Box::new(StubPlugin::new())).unwrap();
        let list = mgr.list_plugins();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "stub");
    }

    #[test]
    fn duplicate_plugin_rejected() {
        let mut mgr = PluginManager::new();
        mgr.register_plugin(Box::new(StubPlugin::new())).unwrap();
        let result = mgr.register_plugin(Box::new(StubPlugin::new()));
        assert!(result.is_err());
    }

    #[test]
    fn unregister_plugin() {
        let mut mgr = PluginManager::new();
        mgr.register_plugin(Box::new(StubPlugin::new())).unwrap();
        mgr.unregister_plugin("stub").unwrap();
        assert!(mgr.list_plugins().is_empty());
    }

    #[test]
    fn unregister_missing_plugin_errors() {
        let mut mgr = PluginManager::new();
        let result = mgr.unregister_plugin("nonexistent");
        assert!(result.is_err());
    }

    // -- Analysis passes ----------------------------------------------------

    #[test]
    fn analysis_pass_detects_findings() {
        let mut mgr = PluginManager::new();
        mgr.register_analysis_pass(Box::new(DangerousNamePass));

        let memory = make_memory_map();
        let mut functions = make_function_manager();
        let findings = mgr
            .run_all_analysis_passes(&memory, &mut functions)
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].address, 0x2000);
        assert_eq!(findings[0].category, FindingCategory::Vulnerability);
        assert!(findings[0].message.contains("dangerous_eval"));
    }

    #[test]
    fn no_analysis_passes_returns_empty() {
        let mgr = PluginManager::new();
        let memory = make_memory_map();
        let mut functions = make_function_manager();
        let findings = mgr
            .run_all_analysis_passes(&memory, &mut functions)
            .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn list_analysis_passes() {
        let mut mgr = PluginManager::new();
        mgr.register_analysis_pass(Box::new(DangerousNamePass));
        let names = mgr.list_analysis_passes();
        assert_eq!(names, vec!["dangerous-name-detector"]);
    }

    // -- Loader plugins -----------------------------------------------------

    #[test]
    fn loader_recognises_magic() {
        let mut mgr = PluginManager::new();
        mgr.register_loader(Box::new(CustomLoader));

        let mut data = CUSTOM_MAGIC.to_vec();
        data.extend_from_slice(&[0x90; 8]);

        let result = mgr.try_load(&data);
        assert!(result.is_some());
        let loaded = result.unwrap().unwrap();
        assert_eq!(loaded.entry_point, 0x1000);
        assert_eq!(loaded.arch, Architecture::X86_64);
    }

    #[test]
    fn loader_rejects_unknown() {
        let mut mgr = PluginManager::new();
        mgr.register_loader(Box::new(CustomLoader));

        let data = b"NOT_CUSTOM_FORMAT";
        let result = mgr.try_load(data);
        assert!(result.is_none());
    }

    #[test]
    fn list_loaders() {
        let mut mgr = PluginManager::new();
        mgr.register_loader(Box::new(CustomLoader));
        let names = mgr.list_loaders();
        assert_eq!(names, vec!["custom-loader"]);
    }

    // -- AnalysisFinding severity clamping ----------------------------------

    #[test]
    fn severity_clamped_to_valid_range() {
        let f1 = AnalysisFinding::new(0, FindingCategory::Info, "low".into(), -0.5);
        assert!((f1.severity - 0.0).abs() < f64::EPSILON);

        let f2 = AnalysisFinding::new(0, FindingCategory::Info, "high".into(), 1.5);
        assert!((f2.severity - 1.0).abs() < f64::EPSILON);

        let f3 = AnalysisFinding::new(0, FindingCategory::Info, "mid".into(), 0.5);
        assert!((f3.severity - 0.5).abs() < f64::EPSILON);
    }

    // -- Default / new equivalence ------------------------------------------

    #[test]
    fn plugin_manager_default_is_empty() {
        let mgr = PluginManager::default();
        assert!(mgr.list_plugins().is_empty());
        assert!(mgr.list_analysis_passes().is_empty());
        assert!(mgr.list_loaders().is_empty());
    }
}
