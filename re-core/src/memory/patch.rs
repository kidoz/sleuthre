use serde::{Deserialize, Serialize};

use crate::Result;
use crate::error::Error;

use super::MemoryMap;

/// A single binary patch: stores the original and replacement bytes at a given address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub patched_bytes: Vec<u8>,
    pub description: String,
    pub applied: bool,
}

/// Manages a collection of binary patches that can be applied to and reverted from a [`MemoryMap`].
#[derive(Debug, Default)]
pub struct PatchManager {
    patches: Vec<Patch>,
}

impl PatchManager {
    /// Create a new patch, immediately applying it to `memory`.
    ///
    /// Returns the index of the newly created patch.
    pub fn add_patch(
        &mut self,
        memory: &mut MemoryMap,
        address: u64,
        new_bytes: &[u8],
        description: &str,
    ) -> Result<usize> {
        let original_bytes = memory
            .get_data(address, new_bytes.len())
            .ok_or_else(|| {
                Error::Analysis(format!(
                    "add_patch: address range 0x{:x}..0x{:x} is not within any segment",
                    address,
                    address + new_bytes.len() as u64,
                ))
            })?
            .to_vec();

        memory.write_data(address, new_bytes)?;

        let index = self.patches.len();
        self.patches.push(Patch {
            address,
            original_bytes,
            patched_bytes: new_bytes.to_vec(),
            description: description.to_string(),
            applied: true,
        });

        Ok(index)
    }

    /// Revert a previously applied patch, restoring the original bytes in memory.
    pub fn revert_patch(&mut self, memory: &mut MemoryMap, index: usize) -> Result<()> {
        let patch = self.patches.get_mut(index).ok_or_else(|| {
            Error::Analysis(format!("revert_patch: patch index {index} out of range"))
        })?;

        if !patch.applied {
            return Err(Error::Analysis(format!(
                "revert_patch: patch {index} is already reverted"
            )));
        }

        memory.write_data(patch.address, &patch.original_bytes)?;
        patch.applied = false;
        Ok(())
    }

    /// Re-apply a previously reverted patch.
    pub fn reapply_patch(&mut self, memory: &mut MemoryMap, index: usize) -> Result<()> {
        let patch = self.patches.get_mut(index).ok_or_else(|| {
            Error::Analysis(format!("reapply_patch: patch index {index} out of range"))
        })?;

        if patch.applied {
            return Err(Error::Analysis(format!(
                "reapply_patch: patch {index} is already applied"
            )));
        }

        memory.write_data(patch.address, &patch.patched_bytes)?;
        patch.applied = true;
        Ok(())
    }

    /// Revert all currently applied patches (in reverse order of creation).
    pub fn revert_all(&mut self, memory: &mut MemoryMap) -> Result<()> {
        for i in (0..self.patches.len()).rev() {
            if self.patches[i].applied {
                memory.write_data(self.patches[i].address, &self.patches[i].original_bytes)?;
                self.patches[i].applied = false;
            }
        }
        Ok(())
    }

    /// Return a read-only view of all patches.
    pub fn list_patches(&self) -> &[Patch] {
        &self.patches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    fn make_test_memory() -> MemoryMap {
        let mut map = MemoryMap::default();
        let seg = MemorySegment {
            name: "text".to_string(),
            start: 0x1000,
            size: 16,
            data: vec![0x90; 16], // fill with NOP-like bytes
            permissions: Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
        };
        map.add_segment(seg).unwrap();
        map
    }

    #[test]
    fn add_patch_applies_and_stores_original() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        let idx = pm
            .add_patch(&mut mem, 0x1000, &[0xCC, 0xCC], "breakpoint")
            .unwrap();
        assert_eq!(idx, 0);

        // Memory should now contain patched bytes
        assert_eq!(mem.get_data(0x1000, 2).unwrap(), &[0xCC, 0xCC]);

        // Patch should record originals
        let patches = pm.list_patches();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].original_bytes, &[0x90, 0x90]);
        assert_eq!(patches[0].patched_bytes, &[0xCC, 0xCC]);
        assert!(patches[0].applied);
    }

    #[test]
    fn revert_patch_restores_original() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        let idx = pm.add_patch(&mut mem, 0x1000, &[0xCC], "bp").unwrap();
        pm.revert_patch(&mut mem, idx).unwrap();

        assert_eq!(mem.get_data(0x1000, 1).unwrap(), &[0x90]);
        assert!(!pm.list_patches()[0].applied);
    }

    #[test]
    fn reapply_patch_after_revert() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        let idx = pm
            .add_patch(&mut mem, 0x1000, &[0xEB, 0x10], "jump")
            .unwrap();
        pm.revert_patch(&mut mem, idx).unwrap();
        assert_eq!(mem.get_data(0x1000, 2).unwrap(), &[0x90, 0x90]);

        pm.reapply_patch(&mut mem, idx).unwrap();
        assert_eq!(mem.get_data(0x1000, 2).unwrap(), &[0xEB, 0x10]);
        assert!(pm.list_patches()[0].applied);
    }

    #[test]
    fn revert_already_reverted_fails() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        let idx = pm.add_patch(&mut mem, 0x1000, &[0xCC], "bp").unwrap();
        pm.revert_patch(&mut mem, idx).unwrap();
        assert!(pm.revert_patch(&mut mem, idx).is_err());
    }

    #[test]
    fn reapply_already_applied_fails() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        let idx = pm.add_patch(&mut mem, 0x1000, &[0xCC], "bp").unwrap();
        assert!(pm.reapply_patch(&mut mem, idx).is_err());
    }

    #[test]
    fn revert_all_restores_everything() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();

        pm.add_patch(&mut mem, 0x1000, &[0xAA], "p1").unwrap();
        pm.add_patch(&mut mem, 0x1004, &[0xBB, 0xCC], "p2").unwrap();

        pm.revert_all(&mut mem).unwrap();

        assert_eq!(mem.get_data(0x1000, 1).unwrap(), &[0x90]);
        assert_eq!(mem.get_data(0x1004, 2).unwrap(), &[0x90, 0x90]);
        assert!(pm.list_patches().iter().all(|p| !p.applied));
    }

    #[test]
    fn add_patch_out_of_range_fails() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();
        assert!(pm.add_patch(&mut mem, 0x9000, &[0xCC], "bad").is_err());
    }

    #[test]
    fn invalid_index_fails() {
        let mut mem = make_test_memory();
        let mut pm = PatchManager::default();
        assert!(pm.revert_patch(&mut mem, 42).is_err());
        assert!(pm.reapply_patch(&mut mem, 42).is_err());
    }
}
