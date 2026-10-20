use root_core::{
    error::Result,
    model::{
        MemoryMeasurement, PlatformCapabilities, PressureMetrics, ProcessCandidate,
        ResourceMetadata, SystemMemorySummary,
    },
};
use std::path::{Path, PathBuf};

/// Interface for querying standard user and environment paths.
pub trait EnvironmentProvider: Send + Sync {
    fn config_dir(&self) -> PathBuf;
    fn data_dir(&self) -> PathBuf;
    fn cache_dir(&self) -> PathBuf;
    fn state_dir(&self) -> PathBuf;
    fn runtime_dir(&self) -> Option<PathBuf>;
    fn home_dir(&self) -> PathBuf;
    fn current_uid(&self) -> u32;
    fn current_gid(&self) -> u32;
}

/// Interface for read-only filesystem metadata inspection.
pub trait FilesystemProvider: Send + Sync {
    /// Obtains metadata without following symbolic links (equivalent to lstat).
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata>;
    fn canonicalize(&self, path: &Path) -> Result<PathBuf>;
    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;
    fn get_device_id(&self, path: &Path) -> Result<u64>;
    fn get_inode(&self, path: &Path) -> Result<u64>;
}

/// Interface for read-only process inspection.
pub trait ProcessProvider: Send + Sync {
    fn list_pids(&self) -> Result<Vec<u32>>;
    fn inspect_process(&self, pid: u32) -> Result<Option<ProcessCandidate>>;
    fn get_process_memory(&self, pid: u32) -> Result<Option<MemoryMeasurement>>;
}

/// Interface for system-wide memory, pressure, and platform capabilities.
pub trait ResourceAccountant: Send + Sync {
    fn get_system_memory(&self) -> Result<SystemMemorySummary>;
    fn get_pressure_metrics(&self) -> Result<Option<PressureMetrics>>;
    fn get_capabilities(&self) -> Result<PlatformCapabilities>;
}

/// Stub interface for future event-based monitoring (Mode C).
pub trait FilesystemWatcher: Send + Sync {
    fn is_supported(&self) -> bool;
}
