use std::{env, os::unix::fs::MetadataExt, path::PathBuf};

use crate::traits::EnvironmentProvider;

#[derive(Debug, Default, Clone)]
pub struct LinuxEnvironment;

impl LinuxEnvironment {
    pub fn new() -> Self {
        Self
    }
}

impl EnvironmentProvider for LinuxEnvironment {
    fn home_dir(&self) -> PathBuf {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"))
    }

    fn config_dir(&self) -> PathBuf {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join(".config"))
    }

    fn data_dir(&self) -> PathBuf {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join(".local/share"))
    }

    fn cache_dir(&self) -> PathBuf {
        env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join(".cache"))
    }

    fn state_dir(&self) -> PathBuf {
        env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join(".local/state"))
    }

    fn runtime_dir(&self) -> Option<PathBuf> {
        env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
    }

    fn current_uid(&self) -> u32 {
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(1000)
    }

    fn current_gid(&self) -> u32 {
        std::fs::metadata("/proc/self")
            .map(|m| m.gid())
            .unwrap_or(1000)
    }
}
