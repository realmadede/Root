use crate::model::state::ThemePreference;
use serde::{Deserialize, Serialize};

/// Application settings view-model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsViewModel {
    // Appearance
    pub theme: ThemePreference,

    // Inspection Limits
    pub max_traversal_depth: usize,
    pub max_entries_limit: usize,
    pub traversal_timeout_seconds: u64,

    // Privacy & Security Invariants (Read-Only)
    pub metadata_only_enforced: bool,
    pub credential_redaction_enforced: bool,
    pub telemetry_free_enforced: bool,
    pub zero_ai_dependencies_enforced: bool,
    pub unprivileged_user_enforced: bool,

    // Notifications
    pub notifications_enabled: bool,
    pub notification_service_available: bool,

    // About
    pub app_name: &'static str,
    pub app_version: &'static str,
    pub license: &'static str,
    pub repository_url: &'static str,
    pub target_platform: &'static str,
}

impl Default for SettingsViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsViewModel {
    pub fn new() -> Self {
        Self {
            theme: ThemePreference::SystemDefault,
            max_traversal_depth: 16,
            max_entries_limit: 50_000,
            traversal_timeout_seconds: 60,

            metadata_only_enforced: true,
            credential_redaction_enforced: true,
            telemetry_free_enforced: true,
            zero_ai_dependencies_enforced: true,
            unprivileged_user_enforced: true,

            notifications_enabled: true,
            notification_service_available: true,

            app_name: "Root",
            app_version: env!("CARGO_PKG_VERSION"),
            license: "MIT",
            repository_url: "https://github.com/realmadede/Root",
            target_platform: "Linux (x86_64 / aarch64)",
        }
    }

    /// Sets theme preference.
    pub fn set_theme(&mut self, theme: ThemePreference) {
        self.theme = theme;
    }

    /// Updates traversal budgets within validated safety boundaries.
    pub fn set_inspection_budgets(
        &mut self,
        depth: usize,
        entries: usize,
        timeout: u64,
    ) -> Result<(), &'static str> {
        if !(2..=64).contains(&depth) {
            return Err("Traversal depth must be between 2 and 64.");
        }
        if !(1_000..=250_000).contains(&entries) {
            return Err("Entries limit must be between 1,000 and 250,000.");
        }
        if !(5..=300).contains(&timeout) {
            return Err("Timeout must be between 5s and 300s.");
        }

        self.max_traversal_depth = depth;
        self.max_entries_limit = entries;
        self.traversal_timeout_seconds = timeout;
        Ok(())
    }

    /// Toggles desktop notifications.
    pub fn set_notifications_enabled(&mut self, enabled: bool) {
        self.notifications_enabled = enabled;
    }
}
