use super::{Project, StructOverlay};
use crate::types::CompoundType;
use crate::{Error, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Key = (String, String);
type Records = BTreeMap<Key, Value>;

/// Outcome of a 3-way JSONL merge.
#[derive(Debug, Clone, Default)]
pub struct MergeResult {
    /// Merged JSONL output (deterministic ordering, ready to `import_jsonl`).
    pub merged: String,
    /// Number of records where both sides changed the same key in different
    /// ways. The merged output contains `kind: "conflict"` records describing
    /// each collision; the caller is expected to resolve them.
    pub conflict_count: usize,
    /// Records taken from `left` that `right` did not modify.
    pub left_adds: usize,
    /// Records taken from `right` that `left` did not modify.
    pub right_adds: usize,
    /// Records that both sides agreed to change in the same way.
    pub shared_changes: usize,
}

/// 3-way merge of three JSONL project exports — `base` is the common ancestor,
/// `left` and `right` are the divergent branches.
///
/// Each record is keyed by a tuple `(kind, primary_id)`; two edits to the
/// same key on opposite sides are a conflict unless the values match, in which
/// case the change is taken once.
///
/// Conflicts are not silently dropped: the merged stream includes a line like
/// `{ "kind": "conflict", "key": ..., "left": ..., "right": ... }` so the
/// downstream tooling (GUI, CLI) can surface them. Importers ignore `conflict`
/// kinds, matching the "ignore unknown kind" policy documented on
/// [`Project::import_jsonl`].
pub fn merge_jsonl_3way(base: &str, left: &str, right: &str) -> Result<MergeResult> {
    let merged = combine(
        &load(base, false)?,
        &load(left, false)?,
        &load(right, false)?,
    );
    let mut lines = BTreeMap::new();
    for ((kind, id), record) in merged.records {
        lines.insert(format!("{kind}::{id}"), record);
    }
    let conflict_count = merged.conflicts.len();
    for conflict in merged.conflicts {
        let key = format!("{}::{}", conflict.key.0, conflict.key.1);
        lines.insert(format!("conflict::{key}"), serde_json::json!({
            "kind":"conflict", "key":key, "base":conflict.base, "left":conflict.current, "right":conflict.incoming
        }));
    }
    let mut output = String::new();
    for value in lines.into_values() {
        output.push_str(&value.to_string());
        output.push('\n');
    }
    Ok(MergeResult {
        merged: output,
        conflict_count,
        left_adds: merged.left_adds,
        right_adds: merged.right_adds,
        shared_changes: merged.shared_changes,
    })
}

fn load(content: &str, review: bool) -> Result<Records> {
    let mut map = BTreeMap::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut record: Value = serde_json::from_str(line).map_err(|e| {
            crate::Error::Database(format!("merge jsonl line {}: {}", line_no + 1, e))
        })?;
        let kind = record
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if kind == "meta" {
            // Meta lines are not merged — they describe the source, not
            // user edits.
            continue;
        }
        if review {
            validate_record(&mut record).map_err(|e| {
                crate::Error::Database(format!("merge JSONL line {}: {e}", line_no + 1))
            })?;
        }
        // Composite key chosen per kind so two sides editing the same
        // address produce the same key.
        let id = match kind.as_str() {
            "comment" | "rename" | "bookmark" | "overlay" => record
                .get("address")
                .and_then(|v| v.as_str())
                .map(|s| {
                    if kind == "overlay" {
                        format!(
                            "{}::{}",
                            s,
                            record.get("label").and_then(|v| v.as_str()).unwrap_or("")
                        )
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_default(),
            "tag" => format!(
                "{}::{}",
                record.get("address").and_then(|v| v.as_str()).unwrap_or(""),
                record.get("tag").and_then(|v| v.as_str()).unwrap_or("")
            ),
            "type" => record
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            _ => continue,
        };
        if id.is_empty() {
            continue;
        }
        let key = (kind, id);
        if review && let Some(previous) = map.get(&key) {
            if previous != &record {
                return Err(Error::Database(format!(
                    "Conflicting {} records at {}",
                    key.0, key.1
                )));
            }
            continue;
        }
        map.insert(key, record);
    }
    Ok(map)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeSide {
    Current,
    Incoming,
}

pub struct MergeConflict {
    key: Key,
    pub base: Option<Value>,
    pub current: Option<Value>,
    pub incoming: Option<Value>,
    pub choice: Option<MergeSide>,
}

impl MergeConflict {
    pub fn kind(&self) -> &str {
        &self.key.0
    }
    pub fn identifier(&self) -> &str {
        &self.key.1
    }
}

#[derive(Default)]
struct Combined {
    records: Records,
    conflicts: Vec<MergeConflict>,
    left_adds: usize,
    right_adds: usize,
    shared_changes: usize,
    automatic: Vec<Key>,
}

fn combine(base: &Records, left: &Records, right: &Records) -> Combined {
    let mut merged = Combined::default();
    let keys: BTreeSet<_> = base.keys().chain(left.keys()).chain(right.keys()).collect();
    for key in keys {
        let (b, l, r) = (base.get(key), left.get(key), right.get(key));
        let chosen = if l == r {
            merged.shared_changes += usize::from(l.is_some() && l != b);
            l
        } else if l == b {
            merged.automatic.push(key.clone());
            merged.right_adds += usize::from(r.is_some());
            r
        } else if r == b {
            merged.left_adds += usize::from(l.is_some());
            l
        } else {
            merged.conflicts.push(MergeConflict {
                key: key.clone(),
                base: b.cloned(),
                current: l.cloned(),
                incoming: r.cloned(),
                choice: None,
            });
            continue;
        };
        if let Some(value) = chosen {
            merged.records.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// A preview against a specific export of the open project. Decisions affect
/// only this object until all changes have passed preflight in apply().
pub struct MergeReview {
    original: String,
    local: Records,
    merged: Combined,
}

impl MergeReview {
    pub fn prepare(base: &str, current_export: String, incoming: &str) -> Result<Self> {
        let read = |role, text: &str| {
            load(text, true).map_err(|e| Error::Database(format!("{role}: {e}")))
        };
        let local = read("Current branch", &current_export)?;
        let merged = combine(
            &read("Common ancestor", base)?,
            &local,
            &read("Incoming branch", incoming)?,
        );
        Ok(Self {
            original: current_export,
            local,
            merged,
        })
    }

    pub fn conflicts(&self) -> &[MergeConflict] {
        &self.merged.conflicts
    }
    pub fn choose(&mut self, index: usize, side: MergeSide) {
        if let Some(conflict) = self.merged.conflicts.get_mut(index) {
            conflict.choice = Some(side);
        }
    }

    /// Incoming changes that can be applied without choosing a branch.
    pub fn automatic_changes(&self) -> impl ExactSizeIterator<Item = (&str, &str, Option<&Value>)> {
        self.merged
            .automatic
            .iter()
            .map(|key| (key.0.as_str(), key.1.as_str(), self.merged.records.get(key)))
    }

    pub fn apply(&self, project: &mut Project) -> Result<usize> {
        if project.export_jsonl() != self.original {
            return Err(Error::Analysis(
                "The project changed during review. Preview the merge again.".into(),
            ));
        }
        let mut resolved: BTreeMap<_, _> = self.merged.records.iter().collect();
        for conflict in self.conflicts() {
            let selected = match conflict.choice {
                Some(MergeSide::Current) => &conflict.current,
                Some(MergeSide::Incoming) => &conflict.incoming,
                None => {
                    return Err(Error::Analysis(
                        "Choose a branch for every conflict.".into(),
                    ));
                }
            };
            if let Some(record) = selected {
                resolved.insert(&conflict.key, record);
            }
        }
        // Decode the complete delta before mutating project state. An absent
        // record is a deletion, including restoring an automatic function name.
        let mut edits = Vec::new();
        for key in self
            .local
            .keys()
            .chain(resolved.keys().copied())
            .collect::<BTreeSet<_>>()
        {
            let before = self.local.get(key);
            let after = resolved.get(key).copied();
            if before == after {
                continue;
            }
            let value = after
                .or(before)
                .expect("key comes from local or resolved records");
            let edit = Edit::decode(value)?;
            if let Edit::Rename(address, _) = &edit
                && project.functions.get_function(*address).is_none()
            {
                return Err(Error::Analysis(format!(
                    "No function at {address:#x} for merged rename"
                )));
            }
            edits.push((edit, after.is_some()));
        }
        let layout_changed = edits
            .iter()
            .any(|(e, _)| matches!(e, Edit::Type(_) | Edit::Overlay(_)));
        if layout_changed {
            check_layout(&resolved, project.arch)?;
        }
        let changed = edits.len();
        for (edit, present) in edits {
            edit.apply(project, present);
        }
        if changed > 0 {
            project.redo_stack.clear();
            if layout_changed {
                project.sync_overlay_globals();
            } else {
                project.decompilation_cache.clear();
                project.cache_deps = Default::default();
            }
        }
        Ok(changed)
    }
}

fn address(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

fn validate_record(record: &mut Value) -> Result<()> {
    if let Some(value) = record.get_mut("address") {
        let addr = value
            .as_str()
            .and_then(address)
            .ok_or_else(|| Error::Database("Invalid record address".into()))?;
        *value = Value::String(format!("{addr:#x}"));
    }
    Edit::decode(record).map(|_| ())
}

// The desktop uses these dimensions for array indexing and field addresses.
// Validate the final combination: a type and its overlay can come from different branches.
fn check_layout(records: &BTreeMap<&Key, &Value>, arch: crate::arch::Architecture) -> Result<()> {
    use crate::types::TypeRef;

    fn size(ty: &TypeRef, arch: crate::arch::Architecture) -> Option<usize> {
        match ty {
            TypeRef::Array { element, count } => size(element, arch)?.checked_mul(*count),
            TypeRef::Const(inner) | TypeRef::Volatile(inner) => size(inner, arch),
            _ => Some(ty.size(arch)),
        }
    }

    let mut layouts = BTreeMap::new();
    for ((kind, name), record) in records {
        if kind != "type" {
            continue;
        }
        let Edit::Type(ty) = Edit::decode(record)? else {
            unreachable!("type key")
        };
        let invalid = || Error::Database(format!("Type layout overflows for {name}"));
        let (stride, extent) = match ty {
            CompoundType::Struct {
                fields,
                size: stride,
                ..
            }
            | CompoundType::Union {
                fields,
                size: stride,
                ..
            } => {
                let mut extent = stride;
                for field in fields {
                    let width = size(&field.type_ref, arch).ok_or_else(invalid)?;
                    extent = extent.max(field.offset.checked_add(width).ok_or_else(invalid)?);
                }
                (stride, extent)
            }
            CompoundType::Typedef { target, .. } => {
                let width = size(&target, arch).ok_or_else(invalid)?;
                (width, width)
            }
            CompoundType::Enum { size, .. } => (size, size),
        };
        layouts.insert(name, (stride, extent));
    }
    for ((kind, _), record) in records {
        if kind != "overlay" {
            continue;
        }
        let Edit::Overlay(overlay) = Edit::decode(record)? else {
            unreachable!("overlay key")
        };
        if let Some(&(stride, extent)) = layouts.get(&overlay.type_name)
            && overlay
                .count
                .saturating_sub(1)
                .checked_mul(stride)
                .and_then(|offset| offset.checked_add(extent))
                .and_then(|bytes| overlay.address.checked_add(bytes as u64))
                .is_none()
        {
            return Err(Error::Database(format!(
                "Overlay '{}' exceeds the address space",
                overlay.label
            )));
        }
    }
    Ok(())
}

enum Edit {
    Comment(u64, String),
    Rename(u64, String),
    Bookmark(u64, String),
    Tag(u64, String),
    Overlay(StructOverlay),
    Type(CompoundType),
}

impl Edit {
    fn decode(record: &Value) -> Result<Self> {
        let text = |key: &str| {
            record[key]
                .as_str()
                .ok_or_else(|| Error::Database(format!("Expected a string for {key}")))
        };
        let addr =
            || address(text("address")?).ok_or_else(|| Error::Database("Invalid address".into()));
        Ok(match text("kind")? {
            "comment" => Self::Comment(addr()?, text("text")?.into()),
            "rename" => Self::Rename(addr()?, text("name")?.into()),
            "bookmark" => Self::Bookmark(addr()?, text("note")?.into()),
            "tag" => Self::Tag(addr()?, text("tag")?.into()),
            "overlay" => Self::Overlay(StructOverlay {
                address: addr()?,
                label: text("label")?.into(),
                type_name: text("type_name")?.into(),
                count: record["count"]
                    .as_u64()
                    .filter(|&n| n > 0 && i64::try_from(n).is_ok())
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(|| Error::Database("Invalid overlay count".into()))?,
            }),
            "type" => {
                let ty: CompoundType = serde_json::from_value(record["definition"].clone())
                    .map_err(|e| Error::Database(format!("Invalid type definition: {e}")))?;
                if text("name")? != ty.name() || ty.name().is_empty() {
                    return Err(Error::Database(
                        "Type name must match its definition".into(),
                    ));
                }
                Self::Type(ty)
            }
            kind => {
                return Err(Error::Database(format!(
                    "Unsupported merge record kind '{kind}'"
                )));
            }
        })
    }

    fn apply(self, p: &mut Project, present: bool) {
        match self {
            Self::Comment(addr, text) => {
                if present {
                    p.comments.insert(addr, text);
                } else {
                    p.comments.remove(&addr);
                }
            }
            Self::Bookmark(addr, note) => {
                if present {
                    p.bookmarks.insert(addr, note);
                } else {
                    p.bookmarks.remove(&addr);
                }
            }
            Self::Rename(addr, name) => {
                let function = p
                    .functions
                    .functions
                    .get_mut(&addr)
                    .expect("merge preflight verified rename targets");
                function.name = if present {
                    name
                } else {
                    format!("sub_{addr:x}")
                };
            }
            Self::Tag(addr, tag) => {
                if present {
                    p.tags.entry(addr).or_default().push(tag);
                } else if let Some(tags) = p.tags.get_mut(&addr) {
                    tags.retain(|t| t != &tag);
                    if tags.is_empty() {
                        p.tags.remove(&addr);
                    }
                }
            }
            Self::Overlay(overlay) => {
                let index = p
                    .struct_overlays
                    .iter()
                    .position(|o| o.address == overlay.address && o.label == overlay.label);
                match (index, present) {
                    (Some(i), true) => p.struct_overlays[i] = overlay,
                    (Some(i), false) => {
                        p.struct_overlays.remove(i);
                    }
                    (None, true) => p.struct_overlays.push(overlay),
                    (None, false) => {}
                }
            }
            Self::Type(ty) => {
                if present {
                    p.types.add_type(ty);
                } else {
                    p.types.remove_type(ty.name());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_edit_conflict_and_uncontested_deletions_are_applied_once() {
        let mut project = Project::new("sample".into(), "sample.bin".into());
        project.tags.insert(16, vec!["old".into()]);
        project.comments.insert(16, "ancestor".into());
        project.bookmarks.insert(16, "remove".into());
        let base = project.export_jsonl();
        project.comments.insert(16, "current".into());
        let incoming = r#"{"kind":"tag","address":"0x10","tag":"new"}"#;
        let mut review = MergeReview::prepare(&base, project.export_jsonl(), incoming).unwrap();
        assert_eq!(review.conflicts().len(), 1);
        assert!(review.conflicts()[0].incoming.is_none());
        review.choose(0, MergeSide::Incoming);
        review.apply(&mut project).unwrap();
        assert!(project.comments.is_empty());
        assert!(project.bookmarks.is_empty());
        assert_eq!(project.tags[&16], vec!["new"]);
    }

    #[test]
    fn merge_checks_combined_layout_before_replacing_an_overlay() {
        let mut p = Project::new("sample".into(), "sample.bin".into());
        p.types.add_type(CompoundType::Struct {
            name: "Packet".into(),
            size: 4,
            fields: vec![],
        });
        let base = p.export_jsonl();
        let valid = format!(
            "{base}{}\n",
            serde_json::json!({
                "kind":"overlay","address":"0x20","type_name":"Packet","count":2,"label":"packets"
            })
        );
        let invalid = valid.replace("0x20", "0xfffffffffffffffe");
        let draft = MergeReview::prepare(&base, base.clone(), &invalid).unwrap();
        assert!(draft.apply(&mut p).is_err());
        assert_eq!(p.export_jsonl(), base);

        MergeReview::prepare(&base, base.clone(), &valid)
            .unwrap()
            .apply(&mut p)
            .unwrap();
        assert_eq!(p.types.global_variables[&32].name, "packets");
        let current = p.export_jsonl();
        MergeReview::prepare(&current, current.clone(), &base)
            .unwrap()
            .apply(&mut p)
            .unwrap();
        assert!(p.struct_overlays.is_empty());
        assert!(!p.types.global_variables.contains_key(&32));
    }

    #[test]
    fn failed_apply_preserves_other_edits_and_detects_a_stale_preview() {
        let mut project = Project::new("sample".into(), "sample.bin".into());
        let original = project.export_jsonl();
        let incoming = concat!(
            "{\"kind\":\"comment\",\"address\":\"0x10\",\"text\":\"pending\"}\n",
            "{\"kind\":\"rename\",\"address\":\"0x20\",\"name\":\"missing\"}\n"
        );
        let review = MergeReview::prepare("", original.clone(), incoming).unwrap();
        assert!(
            review
                .apply(&mut project)
                .unwrap_err()
                .to_string()
                .contains("No function")
        );
        assert_eq!(project.export_jsonl(), original);
        project.comments.insert(32, "new local edit".into());
        let updated = project.export_jsonl();
        assert!(
            review
                .apply(&mut project)
                .unwrap_err()
                .to_string()
                .contains("changed during review")
        );
        assert_eq!(project.export_jsonl(), updated);
    }
}
