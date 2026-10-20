use super::navigation::NavigationState;
use root_core::discovery::LifecycleState;
use root_core::model::ProtectionTier;
use serde::{Deserialize, Serialize};

/// High-level scanning execution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanExecutionState {
    /// Scanner is idle.
    Idle,
    /// Background inspection is active.
    Scanning {
        generation: u64,
        current_path: String,
        entries_examined: usize,
    },
    /// Scan completed successfully.
    Completed {
        generation: u64,
        total_items: usize,
        total_bytes: u64,
        duration_ms: u64,
    },
    /// Scan was cancelled by user.
    Cancelled { generation: u64 },
    /// Scan failed with a non-fatal error.
    Failed { generation: u64, error: String },
}

/// Sort criteria for resource lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ResourceSortField {
    #[default]
    Size,
    Name,
    Category,
    ProtectionTier,
    Lifecycle,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    #[default]
    Descending,
}

/// Comprehensive filter criteria for resource exploration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceFilter {
    pub search_query: String,
    pub category: Option<String>,
    pub protection_tier: Option<ProtectionTier>,
    pub lifecycle: Option<LifecycleState>,
    pub min_size_bytes: Option<u64>,
}

impl ResourceFilter {
    /// Returns true if the filter is in its default state (no filtering applied).
    pub fn is_empty(&self) -> bool {
        self.search_query.is_empty()
            && self.category.is_none()
            && self.protection_tier.is_none()
            && self.lifecycle.is_none()
            && self.min_size_bytes.is_none()
    }

    /// Resets all filter fields to default.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// UI theme preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemePreference {
    /// Follow system GNOME / Freedesktop preference.
    #[default]
    SystemDefault,
    /// Force light appearance.
    ForceLight,
    /// Force dark appearance.
    ForceDark,
}

/// Central application state coordinator.
#[derive(Debug, Clone)]
pub struct AppState {
    pub navigation: NavigationState,
    pub scan_state: ScanExecutionState,
    pub current_generation: u64,
    pub active_error: Option<String>,
    pub theme: ThemePreference,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            navigation: NavigationState::default(),
            scan_state: ScanExecutionState::Idle,
            current_generation: 0,
            active_error: None,
            theme: ThemePreference::SystemDefault,
        }
    }
}

impl AppState {
    /// Advances generation ID to prevent stale asynchronous results from overwriting newer state.
    pub fn next_generation(&mut self) -> u64 {
        self.current_generation += 1;
        self.current_generation
    }

    /// Checks if a result from a specific generation is still valid and not superseded.
    pub fn is_generation_current(&self, gen: u64) -> bool {
        self.current_generation == gen
    }
}
