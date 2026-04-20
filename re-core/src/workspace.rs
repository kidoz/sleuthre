//! Multi-binary workspace scaffolding.
//!
//! A [`Workspace`] owns a collection of named [`Project`]s — typically the
//! executable plus its dynamic libraries — so cross-binary navigation and
//! import resolution can be expressed in one place. This is the 0.4.0
//! library-only foundation: the GUI still operates on a single `Project` at a
//! time, but headless tooling (MCP, plugins, the CLI) can load a whole target
//! set and query symbols across all of them in one pass.
//!
//! What this layer is *not*: it does not yet share memory between binaries,
//! fold call graphs across DLL boundaries, or persist to disk as a single
//! bundle. Those belong to a later release once the data model has settled.

use crate::project::Project;
use std::collections::HashMap;
use std::path::PathBuf;

/// A named project inside a [`Workspace`]. The `name` is the display label
/// (usually the binary's basename) and is the key callers pass to look the
/// project up again.
pub struct WorkspaceBinary {
    pub name: String,
    pub path: PathBuf,
    pub project: Project,
}

/// Collection of related binaries analysed together. Binaries are keyed by
/// name; inserting a second entry with the same name replaces the first.
#[derive(Default)]
pub struct Workspace {
    binaries: Vec<WorkspaceBinary>,
    by_name: HashMap<String, usize>,
}

/// Where a matching symbol was found. Returned by [`Workspace::resolve_symbol`]
/// so callers can jump across binaries without re-scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolHit {
    /// Name of the binary the symbol belongs to.
    pub binary: String,
    /// Address within that binary.
    pub address: u64,
    /// Kind label (`"function"`, `"export"`, `"symbol"`) — informational only.
    pub kind: &'static str,
}

impl Workspace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a project under `name`. If a project with that name already exists
    /// it is replaced and the old one dropped.
    pub fn add(&mut self, name: impl Into<String>, path: PathBuf, project: Project) {
        let name = name.into();
        let entry = WorkspaceBinary {
            name: name.clone(),
            path,
            project,
        };
        if let Some(&idx) = self.by_name.get(&name) {
            self.binaries[idx] = entry;
        } else {
            self.by_name.insert(name, self.binaries.len());
            self.binaries.push(entry);
        }
    }

    pub fn remove(&mut self, name: &str) -> Option<WorkspaceBinary> {
        let idx = self.by_name.remove(name)?;
        let removed = self.binaries.remove(idx);
        // Rebuild indices — cheap for the handful of binaries a workspace holds.
        self.by_name.clear();
        for (i, b) in self.binaries.iter().enumerate() {
            self.by_name.insert(b.name.clone(), i);
        }
        Some(removed)
    }

    pub fn len(&self) -> usize {
        self.binaries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.binaries.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.binaries.iter().map(|b| b.name.as_str())
    }

    pub fn get(&self, name: &str) -> Option<&WorkspaceBinary> {
        self.by_name.get(name).map(|&i| &self.binaries[i])
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut WorkspaceBinary> {
        let idx = *self.by_name.get(name)?;
        Some(&mut self.binaries[idx])
    }

    pub fn iter(&self) -> impl Iterator<Item = &WorkspaceBinary> {
        self.binaries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut WorkspaceBinary> {
        self.binaries.iter_mut()
    }

    /// Find every binary that exposes `name` — as a function, export, or
    /// symbol. Results are returned in workspace insertion order so a primary
    /// binary listed first shadows its DLLs in any "first hit" lookup.
    pub fn resolve_symbol(&self, name: &str) -> Vec<SymbolHit> {
        let mut out = Vec::new();
        for b in &self.binaries {
            for func in b.project.functions.functions.values() {
                if func.name == name {
                    out.push(SymbolHit {
                        binary: b.name.clone(),
                        address: func.start_address,
                        kind: "function",
                    });
                }
            }
            for exp in &b.project.exports {
                if exp.name == name {
                    out.push(SymbolHit {
                        binary: b.name.clone(),
                        address: exp.address,
                        kind: "export",
                    });
                }
            }
            for sym in &b.project.symbols {
                if sym.name == name {
                    out.push(SymbolHit {
                        binary: b.name.clone(),
                        address: sym.address,
                        kind: "symbol",
                    });
                }
            }
        }
        out
    }

    /// Resolve an unresolved import in `importer` by searching the other
    /// binaries' exports. Returns the first match (or `None`). Callers that
    /// want every match should iterate [`Workspace::resolve_symbol`] instead.
    pub fn resolve_import(&self, importer: &str, symbol: &str) -> Option<SymbolHit> {
        for b in &self.binaries {
            if b.name == importer {
                continue;
            }
            for exp in &b.project.exports {
                if exp.name == symbol {
                    return Some(SymbolHit {
                        binary: b.name.clone(),
                        address: exp.address,
                        kind: "export",
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Export;

    fn project_with_export(name: &str, addr: u64) -> Project {
        let mut p = Project::new("dummy".into(), PathBuf::from("/tmp/x"));
        p.exports.push(Export {
            name: name.into(),
            address: addr,
        });
        p
    }

    #[test]
    fn add_and_lookup() {
        let mut ws = Workspace::new();
        ws.add(
            "app",
            "/tmp/app".into(),
            Project::new("app".into(), "/tmp/app".into()),
        );
        ws.add(
            "libc.so",
            "/tmp/libc".into(),
            project_with_export("malloc", 0x1000),
        );
        assert_eq!(ws.len(), 2);
        assert!(ws.get("app").is_some());
        assert!(ws.get("libc.so").is_some());
        assert!(ws.get("missing").is_none());
    }

    #[test]
    fn resolves_cross_binary_import() {
        let mut ws = Workspace::new();
        ws.add(
            "app",
            "/tmp/app".into(),
            Project::new("app".into(), "/tmp/app".into()),
        );
        ws.add(
            "libc.so",
            "/tmp/libc".into(),
            project_with_export("malloc", 0x2000),
        );
        let hit = ws.resolve_import("app", "malloc").unwrap();
        assert_eq!(hit.binary, "libc.so");
        assert_eq!(hit.address, 0x2000);
        assert_eq!(hit.kind, "export");
    }

    #[test]
    fn resolve_import_skips_self() {
        let mut ws = Workspace::new();
        // Binary re-exports its own symbol — must not resolve to itself.
        ws.add("self", "/tmp/self".into(), project_with_export("foo", 0x1));
        assert!(ws.resolve_import("self", "foo").is_none());
    }

    #[test]
    fn resolve_symbol_finds_all_matches() {
        let mut ws = Workspace::new();
        ws.add("a", "/tmp/a".into(), project_with_export("foo", 0x10));
        ws.add("b", "/tmp/b".into(), project_with_export("foo", 0x20));
        let hits = ws.resolve_symbol("foo");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].binary, "a");
        assert_eq!(hits[1].binary, "b");
    }

    #[test]
    fn remove_keeps_index_consistent() {
        let mut ws = Workspace::new();
        ws.add(
            "a",
            "/tmp/a".into(),
            Project::new("a".into(), "/tmp/a".into()),
        );
        ws.add(
            "b",
            "/tmp/b".into(),
            Project::new("b".into(), "/tmp/b".into()),
        );
        ws.add(
            "c",
            "/tmp/c".into(),
            Project::new("c".into(), "/tmp/c".into()),
        );
        ws.remove("b");
        assert_eq!(ws.len(), 2);
        assert!(ws.get("a").is_some());
        assert!(ws.get("b").is_none());
        assert!(ws.get("c").is_some());
    }
}
