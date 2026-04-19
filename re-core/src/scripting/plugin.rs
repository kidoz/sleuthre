//! Plugin discovery and hot-reload for Rhai scripts.
//!
//! On startup the registry scans a single directory (defaults to
//! `~/.sleuthre/plugins/`) for `*.rhai` files and remembers each script's
//! mtime and source text. Callers periodically invoke
//! [`PluginRegistry::reload_changed`] — typically once per UI frame at low
//! cost — to pick up any external edits without restarting the host.
//!
//! Polling avoids a hard dependency on the `notify` crate, which historically
//! has had cross-platform reliability issues on macOS and Linux container
//! runtimes; a single `metadata()` syscall per plugin per second is cheap
//! and reliable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One discovered plugin script.
#[derive(Debug, Clone)]
pub struct PluginScript {
    /// Absolute path to the source file.
    pub path: PathBuf,
    /// Identifier — the file name without extension.
    pub name: String,
    /// Cached source text. Updated by [`PluginRegistry::reload_changed`].
    pub source: String,
    /// File mtime at the moment `source` was read.
    pub mtime: SystemTime,
}

/// Outcome of a hot-reload pass.
#[derive(Debug, Clone, Default)]
pub struct ReloadReport {
    /// Plugin file paths that were freshly loaded (new since last scan).
    pub added: Vec<PathBuf>,
    /// Plugin file paths whose source was refreshed because the mtime advanced.
    pub updated: Vec<PathBuf>,
    /// Plugin file paths that disappeared since the last scan.
    pub removed: Vec<PathBuf>,
}

impl ReloadReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty()
    }
}

/// In-memory registry of discovered plugin scripts.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    dir: Option<PathBuf>,
    scripts: HashMap<PathBuf, PluginScript>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the directory the registry scans on each reload pass.
    pub fn set_dir<P: Into<PathBuf>>(&mut self, dir: P) {
        self.dir = Some(dir.into());
    }

    /// Default discovery directory — `~/.sleuthre/plugins/`.
    pub fn default_user_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".sleuthre").join("plugins"))
    }

    /// All currently loaded plugin scripts, ordered by path.
    pub fn scripts(&self) -> Vec<&PluginScript> {
        let mut out: Vec<_> = self.scripts.values().collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Look up a plugin by its name (file stem).
    pub fn get(&self, name: &str) -> Option<&PluginScript> {
        self.scripts.values().find(|s| s.name == name)
    }

    /// Clear all loaded plugins (for tests / explicit reset).
    pub fn clear(&mut self) {
        self.scripts.clear();
    }

    /// Re-scan the configured directory and refresh any changed scripts.
    /// Returns a report enumerating what changed so the host can log or
    /// render a toast.
    pub fn reload_changed(&mut self) -> ReloadReport {
        let mut report = ReloadReport::default();
        let Some(ref dir) = self.dir else {
            return report;
        };
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => {
                // Missing directory is not an error — silently treat as empty
                // so creating the dir mid-session "just works" once it appears.
                let removed: Vec<_> = self.scripts.keys().cloned().collect();
                self.scripts.clear();
                report.removed = removed;
                return report;
            }
        };

        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rhai") {
                continue;
            }
            seen.insert(path.clone());

            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);

            match self.scripts.get(&path) {
                Some(existing) if existing.mtime == mtime => {
                    // Up to date.
                }
                Some(_) => {
                    if let Ok(source) = std::fs::read_to_string(&path) {
                        let name = file_stem(&path);
                        self.scripts.insert(
                            path.clone(),
                            PluginScript {
                                path: path.clone(),
                                name,
                                source,
                                mtime,
                            },
                        );
                        report.updated.push(path);
                    }
                }
                None => {
                    if let Ok(source) = std::fs::read_to_string(&path) {
                        let name = file_stem(&path);
                        self.scripts.insert(
                            path.clone(),
                            PluginScript {
                                path: path.clone(),
                                name,
                                source,
                                mtime,
                            },
                        );
                        report.added.push(path);
                    }
                }
            }
        }

        // Drop scripts that disappeared since the last scan.
        let removed: Vec<PathBuf> = self
            .scripts
            .keys()
            .filter(|p| !seen.contains(*p))
            .cloned()
            .collect();
        for p in &removed {
            self.scripts.remove(p);
        }
        report.removed = removed;
        report
    }
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sleuthre_plugins_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn discovers_new_scripts() {
        let dir = temp_dir();
        write_script(&dir, "hello.rhai", "// hello");
        let mut reg = PluginRegistry::new();
        reg.set_dir(&dir);

        let report = reg.reload_changed();
        assert_eq!(report.added.len(), 1);
        assert_eq!(reg.scripts().len(), 1);
        assert_eq!(reg.get("hello").unwrap().source, "// hello");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_modified_script() {
        let dir = temp_dir();
        let path = write_script(&dir, "edit.rhai", "// v1");
        let mut reg = PluginRegistry::new();
        reg.set_dir(&dir);
        reg.reload_changed();

        // Bump mtime by overwriting with new content; sleep one second so the
        // filesystem records a fresh timestamp on macOS HFS/APFS where mtime
        // resolution is per-second.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"// v2").unwrap();
        drop(f);

        let report = reg.reload_changed();
        assert_eq!(
            report.updated.len(),
            1,
            "expected the v2 source to be reloaded"
        );
        assert_eq!(reg.get("edit").unwrap().source, "// v2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drops_removed_scripts() {
        let dir = temp_dir();
        let path = write_script(&dir, "doomed.rhai", "// rip");
        let mut reg = PluginRegistry::new();
        reg.set_dir(&dir);
        reg.reload_changed();
        std::fs::remove_file(&path).unwrap();

        let report = reg.reload_changed();
        assert_eq!(report.removed.len(), 1);
        assert!(reg.get("doomed").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
