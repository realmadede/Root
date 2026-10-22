use std::{collections::HashMap, env, path::PathBuf};

use crate::traits::EnvironmentProvider;

/// Windows standard locations resolved from `%USERPROFILE%`, `%APPDATA%`, and `%LOCALAPPDATA%`.
///
/// Variables can be injected so the layout is testable on any host. POSIX uid and gid do not
/// exist on Windows; both accessors return the sentinel `0` and the `posix_ownership` capability
/// reports `Unsupported`.
#[derive(Debug, Clone, Default)]
pub struct WindowsEnvironment {
    vars: Option<HashMap<String, String>>,
}

impl WindowsEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_vars(vars: HashMap<String, String>) -> Self {
        Self { vars: Some(vars) }
    }

    fn var(&self, name: &str) -> Option<String> {
        match &self.vars {
            Some(map) => map.get(name).cloned(),
            None => env::var(name).ok(),
        }
        .filter(|v| !v.is_empty())
    }
}

impl EnvironmentProvider for WindowsEnvironment {
    fn home_dir(&self) -> PathBuf {
        self.var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Users\\Default"))
    }

    /// Roaming application data.
    fn config_dir(&self) -> PathBuf {
        self.var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join("AppData").join("Roaming"))
    }

    fn data_dir(&self) -> PathBuf {
        self.local_app_data()
    }

    fn cache_dir(&self) -> PathBuf {
        self.local_app_data()
    }

    fn state_dir(&self) -> PathBuf {
        self.local_app_data()
    }

    fn runtime_dir(&self) -> Option<PathBuf> {
        None
    }

    fn current_uid(&self) -> u32 {
        0
    }

    fn current_gid(&self) -> u32 {
        0
    }
}

impl WindowsEnvironment {
    fn local_app_data(&self) -> PathBuf {
        self.var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home_dir().join("AppData").join("Local"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(pairs: &[(&str, &str)]) -> WindowsEnvironment {
        WindowsEnvironment::with_vars(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn uses_app_data_variables() {
        let e = env_with(&[
            ("USERPROFILE", "C:\\Users\\dev"),
            ("APPDATA", "D:\\Roaming"),
            ("LOCALAPPDATA", "D:\\Local"),
        ]);
        assert_eq!(e.home_dir(), PathBuf::from("C:\\Users\\dev"));
        assert_eq!(e.config_dir(), PathBuf::from("D:\\Roaming"));
        assert_eq!(e.state_dir(), PathBuf::from("D:\\Local"));
        assert!(e.runtime_dir().is_none());
    }

    #[test]
    fn falls_back_to_profile_relative_locations() {
        let e = env_with(&[("USERPROFILE", "C:\\Users\\dev")]);
        assert!(e.cache_dir().ends_with("Local"));
        assert!(e.config_dir().ends_with("Roaming"));
    }

    #[test]
    fn empty_variables_are_ignored() {
        let e = env_with(&[("USERPROFILE", ""), ("LOCALAPPDATA", "")]);
        assert_eq!(e.home_dir(), PathBuf::from("C:\\Users\\Default"));
    }
}
