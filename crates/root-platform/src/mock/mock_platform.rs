use root_core::{
    error::{Result, RootError},
    model::{
        FileType, MemoryMeasurement, PlatformCapabilities, PressureMetrics, ProcessCandidate,
        ProcessIdentity, ProcessState, ResourceMetadata, StorageMeasurement, SystemMemorySummary,
    },
};
use std::path::{Path, PathBuf};

use crate::traits::{EnvironmentProvider, FilesystemProvider, ProcessProvider, ResourceAccountant};

#[derive(Debug, Clone)]
pub struct MockPlatform {
    pub base_dir: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

impl MockPlatform {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            uid: 1000,
            gid: 1000,
        }
    }
}

impl EnvironmentProvider for MockPlatform {
    fn home_dir(&self) -> PathBuf {
        self.base_dir.join("home")
    }

    fn config_dir(&self) -> PathBuf {
        self.home_dir().join(".config")
    }

    fn data_dir(&self) -> PathBuf {
        self.home_dir().join(".local/share")
    }

    fn cache_dir(&self) -> PathBuf {
        self.home_dir().join(".cache")
    }

    fn state_dir(&self) -> PathBuf {
        self.home_dir().join(".local/state")
    }

    fn runtime_dir(&self) -> Option<PathBuf> {
        Some(self.base_dir.join("run"))
    }

    fn current_uid(&self) -> u32 {
        self.uid
    }

    fn current_gid(&self) -> u32 {
        self.gid
    }
}

impl FilesystemProvider for MockPlatform {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        if !path.exists() {
            return Err(RootError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "mock not found"),
            });
        }
        Ok(ResourceMetadata {
            file_type: if path.is_dir() {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            storage: StorageMeasurement::from_raw(1024, 2, 1),
            permissions_mode: 0o755,
            mtime_epoch_secs: 1700000000,
            atime_epoch_secs: 1700000000,
            ctime_epoch_secs: 1700000000,
        })
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn read_dir(&self, _path: &Path) -> Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    fn get_device_id(&self, _path: &Path) -> Result<u64> {
        Ok(1)
    }

    fn get_inode(&self, _path: &Path) -> Result<u64> {
        Ok(42)
    }

    fn get_filesystem_usage(&self, _path: &Path) -> Result<root_core::model::FilesystemUsage> {
        Ok(root_core::model::FilesystemUsage {
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            available_bytes: 450_000_000_000,
            total_inodes: 60_000_000,
            free_inodes: 50_000_000,
        })
    }
}

impl ProcessProvider for MockPlatform {
    fn list_pids(&self) -> Result<Vec<u32>> {
        Ok(vec![101, 102])
    }

    fn inspect_process(&self, pid: u32) -> Result<Option<ProcessCandidate>> {
        if pid == 101 {
            Ok(Some(ProcessCandidate {
                identity: ProcessIdentity {
                    pid: 101,
                    ppid: 1,
                    real_uid: self.uid,
                    name: "mock-abandoned-lsp".to_string(),
                    executable: Some(PathBuf::from("/usr/bin/node")),
                    cmdline: vec!["node".into(), "tsserver.js".into()],
                    start_time_ticks: 123456,
                    tty_nr: 0,
                },
                state: ProcessState::Sleeping,
                memory: MemoryMeasurement::new(50_000_000, Some(35_000_000), Some(30_000_000), 0),
                is_reparented_to_init: true,
                is_abandoned: true,
                associated_agent: Some("TypeScript Server".to_string()),
            }))
        } else {
            Ok(None)
        }
    }

    fn get_process_memory(&self, pid: u32) -> Result<Option<MemoryMeasurement>> {
        if pid == 101 {
            Ok(Some(MemoryMeasurement::new(
                50_000_000,
                Some(35_000_000),
                Some(30_000_000),
                0,
            )))
        } else {
            Ok(None)
        }
    }
}

impl ResourceAccountant for MockPlatform {
    fn get_system_memory(&self) -> Result<SystemMemorySummary> {
        Ok(SystemMemorySummary {
            total_bytes: 16_000_000_000,
            available_bytes: 8_000_000_000,
            cached_bytes: 4_000_000_000,
            free_bytes: 2_000_000_000,
            swap_total_bytes: 4_000_000_000,
            swap_free_bytes: 3_500_000_000,
        })
    }

    fn get_pressure_metrics(&self) -> Result<Option<PressureMetrics>> {
        Ok(Some(PressureMetrics {
            some_10s_pct: 0.05,
            some_60s_pct: 0.02,
            some_300s_pct: 0.01,
            full_10s_pct: 0.0,
        }))
    }

    fn get_capabilities(&self) -> Result<PlatformCapabilities> {
        Ok(PlatformCapabilities {
            os_name: "Mock OS".to_string(),
            kernel_version: "6.1.0-mock".to_string(),
            is_linux: true,
            user_uid: self.uid,
            user_gid: self.gid,
            proc_fs: root_core::model::CapabilityStatus::SupportedAndAccessible,
            proc_meminfo: root_core::model::CapabilityStatus::SupportedAndAccessible,
            proc_pressure_memory: root_core::model::CapabilityStatus::SupportedAndAccessible,
            proc_smaps_rollup: root_core::model::CapabilityStatus::SupportedAndAccessible,
            cgroups_v2: root_core::model::CapabilityStatus::SupportedAndAccessible,
            pidfd: root_core::model::CapabilityStatus::SupportedAndAccessible,
            openat2: root_core::model::CapabilityStatus::SupportedAndAccessible,
            statx: root_core::model::CapabilityStatus::SupportedAndAccessible,
        })
    }
}
