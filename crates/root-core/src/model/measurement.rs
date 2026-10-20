use serde::{Deserialize, Serialize};

/// Precise disk storage measurement for a file or directory tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMeasurement {
    /// Apparent (logical) size in bytes.
    pub bytes: u64,
    /// Physical allocated size on disk (accounting for filesystem block size).
    pub allocated_bytes: u64,
    /// Whether the file is sparse (allocated_bytes significantly less than apparent bytes).
    pub is_sparse: bool,
    /// Whether this file shares its inode with other directory entries (`st_nlink > 1`).
    pub is_multi_link: bool,
    /// Number of hard links referencing this inode.
    pub link_count: u64,
    /// Shared bytes (bytes shared with other hard links or deduplicated store).
    pub shared_bytes: u64,
    /// Unique bytes freed if this specific entry's inode is unlinked completely.
    pub unique_bytes: u64,
}

impl StorageMeasurement {
    pub fn zero() -> Self {
        Self {
            bytes: 0,
            allocated_bytes: 0,
            is_sparse: false,
            is_multi_link: false,
            link_count: 1,
            shared_bytes: 0,
            unique_bytes: 0,
        }
    }

    pub fn from_raw(bytes: u64, allocated_blocks: u64, link_count: u64) -> Self {
        // Standard Linux block size in stat is 512 bytes (POSIX standard for st_blocks)
        let allocated_bytes = allocated_blocks * 512;
        let is_sparse = bytes > allocated_bytes && allocated_bytes > 0;
        let is_multi_link = link_count > 1;
        let (shared_bytes, unique_bytes) = if is_multi_link {
            (bytes, 0)
        } else {
            (0, bytes)
        };

        Self {
            bytes,
            allocated_bytes,
            is_sparse,
            is_multi_link,
            link_count,
            shared_bytes,
            unique_bytes,
        }
    }
}

/// Granular process memory measurements distinguishing shared from private memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMeasurement {
    /// Resident Set Size in bytes (physical pages currently mapped; includes shared).
    pub rss_bytes: u64,
    /// Proportional Set Size in bytes (RSS scaled by sharing count from `/proc/[pid]/smaps_rollup`).
    pub pss_bytes: Option<u64>,
    /// Unique Set Size in bytes (private clean + private dirty exclusively mapped to this process).
    pub uss_bytes: Option<u64>,
    /// Memory currently paged out to swap in bytes.
    pub swap_bytes: u64,
}

impl MemoryMeasurement {
    pub fn new(
        rss_bytes: u64,
        pss_bytes: Option<u64>,
        uss_bytes: Option<u64>,
        swap_bytes: u64,
    ) -> Self {
        Self {
            rss_bytes,
            pss_bytes,
            uss_bytes,
            swap_bytes,
        }
    }
}

/// Host system physical and virtual memory distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMemorySummary {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub cached_bytes: u64,
    pub free_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

/// Pressure Stall Information (PSI) metrics from Linux kernel 4.20+.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PressureMetrics {
    /// Percentage of time processes were stalled waiting for memory over last 10 seconds.
    pub some_10s_pct: f32,
    /// Percentage of time processes were stalled waiting for memory over last 60 seconds.
    pub some_60s_pct: f32,
    /// Percentage of time processes were stalled waiting for memory over last 300 seconds.
    pub some_300s_pct: f32,
    /// Percentage of time all non-idle tasks were completely stalled waiting for memory (thrashing).
    pub full_10s_pct: f32,
}

/// Overall filesystem capacity, free space, and inode accounting from kernel statvfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FilesystemUsage {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
}
