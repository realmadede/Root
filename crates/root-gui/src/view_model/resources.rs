use crate::model::presentation::{
    badge_for_lifecycle, badge_for_protection_tier, format_bytes_tabular, format_path_middle,
    LifecycleBadge, ProtectionBadge,
};
use crate::model::state::{ResourceFilter, ResourceSortField, SortDirection};
use root_core::discovery::{DiscoveryFinding, LifecycleState, ProcessAttribution};
use root_core::model::ProtectionTier;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Individual resource row item in the explorer view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceItemViewModel {
    pub id: String,
    pub target_name: String,
    pub category: String,
    pub path: PathBuf,
    pub apparent_size_bytes: u64,
    pub allocated_blocks: u64,
    pub protection_tier: ProtectionTier,
    pub lifecycle: LifecycleState,
    pub lifecycle_attribution: ProcessAttribution,
    pub evidence_confidence: String,
    pub rule_id: String,
    pub provenance_facts: Vec<String>,
    pub guardian_decision: String,
    pub known_limitations: Vec<String>,
    pub is_sparse: bool,
    pub is_multi_link: bool,
}

impl ResourceItemViewModel {
    pub fn from_finding(finding: &DiscoveryFinding) -> Self {
        let is_sparse = finding.metadata.storage.is_sparse;
        let is_multi_link = finding.metadata.storage.is_multi_link;

        let guardian_decision = match finding.protection_tier {
            ProtectionTier::StrictlyProtected => "Preserve: resource is strictly protected",
            ProtectionTier::UserConfirmRequired => "Preserve: requires explicit operator review",
            ProtectionTier::ObsoleteTransient => "Preserve (Read-Only Policy)",
            ProtectionTier::SafeRecoverable => "Preserve (Read-Only Policy)",
            ProtectionTier::NonActionable => "Preserve: resource is non-actionable",
        }
        .to_string();

        let mut facts = Vec::new();
        facts.push(format!("Rule ID: {}", finding.rule_id));
        facts.push(format!("Confidence: {:?}", finding.confidence));
        facts.push(format!("Inode: {}", finding.location.inode));
        facts.push(format!("Device: {}", finding.location.device_id));
        facts.push(format!(
            "Link Count: {}",
            finding.metadata.storage.link_count
        ));
        facts.push(finding.evidence_explanation.clone());

        facts.push(format!(
            "Process Attribution: {}",
            finding.lifecycle.attribution.display_badge()
        ));
        if is_sparse {
            facts.push(format!(
                "Sparse Allocation: {} physical bytes",
                finding.metadata.storage.allocated_bytes
            ));
        }
        if is_multi_link {
            facts.push(format!(
                "Hard Links: {} directory references share this inode",
                finding.metadata.storage.link_count
            ));
        }

        let limitations = if finding.limitations.is_empty() {
            Vec::new()
        } else {
            vec![finding.limitations.clone()]
        };

        Self {
            id: format!("{}:{}", finding.location.device_id, finding.location.inode),
            target_name: finding.target_name.clone(),
            category: format!("{:?}", finding.category),
            path: finding.location.path.clone(),
            apparent_size_bytes: finding.metadata.storage.bytes,
            allocated_blocks: finding.metadata.storage.allocated_bytes / 512,
            protection_tier: finding.protection_tier,
            lifecycle: finding.lifecycle.state,
            lifecycle_attribution: finding.lifecycle.attribution,
            evidence_confidence: format!("{:?}", finding.confidence),
            rule_id: finding.rule_id.clone(),
            provenance_facts: facts,
            guardian_decision,
            known_limitations: limitations,
            is_sparse,
            is_multi_link,
        }
    }

    pub fn protection_badge(&self) -> ProtectionBadge {
        badge_for_protection_tier(self.protection_tier)
    }

    pub fn lifecycle_badge(&self) -> LifecycleBadge {
        badge_for_lifecycle(self.lifecycle)
    }

    pub fn size_display(&self) -> String {
        format_bytes_tabular(self.apparent_size_bytes)
    }

    pub fn path_middle_display(&self, max_chars: usize) -> String {
        format_path_middle(&self.path, max_chars)
    }
}

/// Resource explorer view-model with filtering, sorting, and bounded list presentation.
#[derive(Debug, Clone, Default)]
pub struct ResourcesViewModel {
    all_items: Vec<ResourceItemViewModel>,
    filtered_items: Vec<ResourceItemViewModel>,
    filter: ResourceFilter,
    sort_field: ResourceSortField,
    sort_direction: SortDirection,
    selected_index: Option<usize>,
    max_visible_items: usize,
}

impl ResourcesViewModel {
    pub fn new() -> Self {
        Self {
            all_items: Vec::new(),
            filtered_items: Vec::new(),
            filter: ResourceFilter::default(),
            sort_field: ResourceSortField::Size,
            sort_direction: SortDirection::Descending,
            selected_index: None,
            max_visible_items: 500, // Bound GTK list rows to avoid layout lag
        }
    }

    /// Loads findings into the view-model.
    pub fn load_findings(&mut self, findings: &[DiscoveryFinding]) {
        self.all_items = findings
            .iter()
            .map(ResourceItemViewModel::from_finding)
            .collect();
        self.apply_filter_and_sort();
    }

    /// Sets the maximum items rendered in the list model.
    pub fn set_max_visible_items(&mut self, limit: usize) {
        self.max_visible_items = limit;
        self.apply_filter_and_sort();
    }

    /// Returns the active filter criteria.
    pub fn filter(&self) -> &ResourceFilter {
        &self.filter
    }

    /// Sets a new filter and updates the filtered list.
    pub fn set_filter(&mut self, filter: ResourceFilter) {
        self.filter = filter;
        self.apply_filter_and_sort();
    }

    /// Updates the text search query.
    pub fn set_search_query(&mut self, query: &str) {
        self.filter.search_query = query.to_string();
        self.apply_filter_and_sort();
    }

    /// Sets the sort field and direction.
    pub fn set_sorting(&mut self, field: ResourceSortField, direction: SortDirection) {
        self.sort_field = field;
        self.sort_direction = direction;
        self.apply_filter_and_sort();
    }

    /// Selects an item by index in the filtered list.
    pub fn select_item(&mut self, index: usize) -> bool {
        if index < self.filtered_items.len() {
            self.selected_index = Some(index);
            true
        } else {
            self.selected_index = None;
            false
        }
    }

    /// Returns the currently selected resource item, if any.
    pub fn selected_item(&self) -> Option<&ResourceItemViewModel> {
        self.selected_index
            .and_then(|idx| self.filtered_items.get(idx))
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected_index = None;
    }

    /// Returns visible items in the filtered, sorted list.
    pub fn items(&self) -> &[ResourceItemViewModel] {
        &self.filtered_items
    }

    /// Total count of items matching the filter (before bounded clipping).
    pub fn total_matching_count(&self) -> usize {
        self.filtered_items.len()
    }

    /// Total count of all loaded items.
    pub fn total_unfiltered_count(&self) -> usize {
        self.all_items.len()
    }

    /// Total byte size of all items currently displayed in the filtered list.
    pub fn total_filtered_bytes(&self) -> u64 {
        self.filtered_items
            .iter()
            .map(|item| item.apparent_size_bytes)
            .sum()
    }

    /// Internal helper applying active filter and sort rules.
    fn apply_filter_and_sort(&mut self) {
        let query = self.filter.search_query.to_lowercase();

        let mut filtered: Vec<ResourceItemViewModel> = self
            .all_items
            .iter()
            .filter(|item| {
                // Search query match
                if !query.is_empty() {
                    let path_str = item.path.to_string_lossy().to_lowercase();
                    let target_str = item.target_name.to_lowercase();
                    let rule_str = item.rule_id.to_lowercase();
                    if !path_str.contains(&query)
                        && !target_str.contains(&query)
                        && !rule_str.contains(&query)
                    {
                        return false;
                    }
                }

                // Category match
                if let Some(ref cat) = self.filter.category {
                    if !item.category.eq_ignore_ascii_case(cat) {
                        return false;
                    }
                }

                // Protection tier match
                if let Some(tier) = self.filter.protection_tier {
                    if item.protection_tier != tier {
                        return false;
                    }
                }

                // Lifecycle match
                if let Some(lifecycle) = self.filter.lifecycle {
                    if item.lifecycle != lifecycle {
                        return false;
                    }
                }

                // Minimum size match
                if let Some(min_bytes) = self.filter.min_size_bytes {
                    if item.apparent_size_bytes < min_bytes {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Sort
        filtered.sort_by(|a, b| {
            let cmp = match self.sort_field {
                ResourceSortField::Size => a.apparent_size_bytes.cmp(&b.apparent_size_bytes),
                ResourceSortField::Name => a.target_name.cmp(&b.target_name),
                ResourceSortField::Category => a.category.cmp(&b.category),
                ResourceSortField::ProtectionTier => {
                    (a.protection_tier as u8).cmp(&(b.protection_tier as u8))
                }
                ResourceSortField::Lifecycle => (a.lifecycle as u8).cmp(&(b.lifecycle as u8)),
            };

            match self.sort_direction {
                SortDirection::Ascending => cmp,
                SortDirection::Descending => cmp.reverse(),
            }
        });

        if filtered.len() > self.max_visible_items {
            filtered.truncate(self.max_visible_items);
        }

        self.filtered_items = filtered;

        // Reset or clamp selection
        if let Some(idx) = self.selected_index {
            if idx >= self.filtered_items.len() {
                self.selected_index = if self.filtered_items.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
        }
    }
}
