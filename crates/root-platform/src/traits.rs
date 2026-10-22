use root_core::{
    error::Result,
    model::{
        DegradedReason, FileIdentity, FilesystemUsage, LiveFsEvent, MemoryMeasurement,
        PlatformCapabilities, PressureMetrics, ProcessCandidate, ResourceMetadata,
        ScheduleInterval, SystemMemorySummary,
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
    /// Platform-neutral identity. The default derives a POSIX identity from the legacy accessors;
    /// platforms whose identity is not a device/inode pair (Windows) must override it.
    fn get_file_identity(&self, path: &Path) -> Result<FileIdentity> {
        Ok(FileIdentity::posix(
            self.get_device_id(path)?,
            self.get_inode(path)?,
        ))
    }
    fn get_filesystem_usage(&self, path: &Path) -> Result<FilesystemUsage>;
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

/// Source of filesystem change events for the live monitor (Mode C).
///
/// Implementations differ in semantics (kernel queue, coalesced stream, or snapshot polling) and
/// must say so through `backend_name`; callers must not assume event-for-event equivalence.
pub trait FilesystemWatcher: Send + Sync {
    fn is_supported(&self) -> bool;
}

/// A started, bounded, cancellable filesystem event source.
pub trait FsEventSource {
    /// Short description of the mechanism, for example `inotify` or `metadata polling`.
    fn backend_name(&self) -> &'static str;

    /// Registers a directory tree, recording degradation (watch limit, permission) instead of
    /// failing the session.
    fn add_tree(&mut self, root: &Path, degraded: &mut Vec<DegradedReason>) -> Result<usize>;

    /// Returns events observed since the previous call without blocking.
    fn poll(
        &mut self,
        agent_filter: Option<&str>,
        degraded: &mut Vec<DegradedReason>,
    ) -> Result<Vec<LiveFsEvent>>;

    fn active_watches(&self) -> usize;
}

/// User-level scheduler adapter (systemd user timer, launchd LaunchAgent, Task Scheduler task).
///
/// Disabled by default: nothing is installed until the caller explicitly invokes `install`.
/// Adapters never use privileged locations and refuse to overwrite definitions Root did not create.
pub trait Scheduler {
    /// Human-readable backend name, for example `systemd user timer`.
    fn backend_name(&self) -> &'static str;

    /// Whether the backend can be driven on this host right now.
    fn backend_available(&self) -> bool;

    /// Validates and installs the definition transactionally. Does not activate it.
    fn install(
        &self,
        exec_path: &Path,
        interval: &ScheduleInterval,
        catch_up: bool,
        ac_power_only: bool,
    ) -> Result<()>;

    /// Removes only Root-owned artifacts.
    fn uninstall(&self) -> Result<()>;

    fn enable(&self) -> Result<()>;
    fn disable(&self) -> Result<()>;
    fn is_active(&self) -> bool;
    fn next_trigger(&self) -> Option<String>;

    /// Files the adapter owns, for status output and tests.
    fn artifact_paths(&self) -> Vec<PathBuf>;

    /// `None` when the platform cannot report AC power state.
    fn ac_power_connected(&self) -> Option<bool>;

    /// `None` when the platform has no memory pressure signal Root supports.
    fn memory_pressure_high(&self, stall_threshold_pct: f64) -> Option<bool>;
}
