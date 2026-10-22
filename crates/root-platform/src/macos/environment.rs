use std::{env, path::PathBuf};

use crate::traits::EnvironmentProvider;

/// macOS standard locations. Honors `HOME`; XDG variables are intentionally ignored because
/// macOS applications use `~/Library`.
#[derive(Debug, Clone, Default)]
pub struct MacEnvironment {
    home_override: Option<PathBuf>,
}

impl MacEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an environment rooted at an explicit home directory (used by tests).
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home_override: Some(home.into()),
        }
    }

    pub fn launch_agents_dir(&self) -> PathBuf {
        self.home_dir().join("Library").join("LaunchAgents")
    }
}

impl EnvironmentProvider for MacEnvironment {
    fn home_dir(&self) -> PathBuf {
        if let Some(home) = &self.home_override {
            return home.clone();
        }
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/empty"))
    }

    fn config_dir(&self) -> PathBuf {
        self.home_dir().join("Library").join("Application Support")
    }

    fn data_dir(&self) -> PathBuf {
        self.home_dir().join("Library").join("Application Support")
    }

    fn cache_dir(&self) -> PathBuf {
        self.home_dir().join("Library").join("Caches")
    }

    /// macOS has no XDG state directory; Application Support is the conventional location.
    fn state_dir(&self) -> PathBuf {
        self.home_dir().join("Library").join("Application Support")
    }

    /// No per-user runtime directory equivalent to `XDG_RUNTIME_DIR` is assumed.
    fn runtime_dir(&self) -> Option<PathBuf> {
        None
    }

    fn current_uid(&self) -> u32 {
        unsafe { libc::geteuid() }
    }

    fn current_gid(&self) -> u32 {
        unsafe { libc::getegid() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_layout() {
        let env = MacEnvironment::with_home("/Users/dev");
        assert_eq!(
            env.config_dir(),
            PathBuf::from("/Users/dev/Library/Application Support")
        );
        assert_eq!(env.cache_dir(), PathBuf::from("/Users/dev/Library/Caches"));
        assert_eq!(
            env.launch_agents_dir(),
            PathBuf::from("/Users/dev/Library/LaunchAgents")
        );
        assert!(env.runtime_dir().is_none());
    }
}
