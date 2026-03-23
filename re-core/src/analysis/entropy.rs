//! Entropy analysis for binary data.
//!
//! Computes Shannon entropy over sliding windows to identify regions of
//! interest: packed/encrypted data (high entropy), code (medium), and
//! structured data (low).

use crate::memory::MemoryMap;

/// A single entropy sample for a region of the binary.
#[derive(Debug, Clone)]
pub struct EntropySample {
    pub address: u64,
    pub entropy: f64,
    pub size: usize,
}

/// Result of full-binary entropy analysis.
#[derive(Debug, Clone, Default)]
pub struct EntropyMap {
    pub samples: Vec<EntropySample>,
    pub min_address: u64,
    pub max_address: u64,
}

/// Compute Shannon entropy (0.0–8.0) for a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compute entropy map over the entire binary memory using a sliding window.
///
/// `window_size` controls the granularity (256 is a good default).
/// `step` controls how many bytes to advance between samples (defaults to window_size for non-overlapping).
pub fn compute_entropy_map(memory: &MemoryMap, window_size: usize, step: usize) -> EntropyMap {
    let window_size = window_size.max(1);
    let step = step.max(1);
    let mut samples = Vec::new();
    let mut min_address = u64::MAX;
    let mut max_address = 0u64;

    for segment in &memory.segments {
        if segment.data.is_empty() {
            continue;
        }
        let seg_start = segment.start;
        let seg_end = seg_start + segment.size;
        min_address = min_address.min(seg_start);
        max_address = max_address.max(seg_end);

        let mut offset = 0;
        while offset < segment.data.len() {
            let end = (offset + window_size).min(segment.data.len());
            let window = &segment.data[offset..end];
            let entropy = shannon_entropy(window);
            samples.push(EntropySample {
                address: seg_start + offset as u64,
                entropy,
                size: window.len(),
            });
            offset += step;
        }
    }

    EntropyMap {
        samples,
        min_address,
        max_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySegment, Permissions};

    #[test]
    fn entropy_of_zeros_is_zero() {
        let data = vec![0u8; 256];
        assert!((shannon_entropy(&data) - 0.0).abs() < 0.001);
    }

    #[test]
    fn entropy_of_uniform_is_eight() {
        let data: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 0.001);
    }

    #[test]
    fn entropy_map_segments() {
        let mut memory = MemoryMap::default();
        memory
            .add_segment(MemorySegment {
                name: "text".into(),
                start: 0x1000,
                size: 512,
                data: vec![0x90; 512],
                permissions: Permissions::READ | Permissions::EXECUTE,
            })
            .unwrap();
        let map = compute_entropy_map(&memory, 256, 256);
        assert_eq!(map.samples.len(), 2);
        // All 0x90 bytes → very low entropy
        assert!(map.samples[0].entropy < 0.1);
    }

    #[test]
    fn entropy_empty_memory() {
        let memory = MemoryMap::default();
        let map = compute_entropy_map(&memory, 256, 256);
        assert!(map.samples.is_empty());
    }
}
