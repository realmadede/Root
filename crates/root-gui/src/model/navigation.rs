use serde::{Deserialize, Serialize};

/// Supported top-level navigation destinations in Root's native interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NavigationItem {
    /// System health, memory, PSI pressure, and storage overview.
    Overview,
    /// Bounded resource explorer with category filtering and sorting.
    Resources,
    /// AI coding agent and developer toolchain footprint discovery.
    Agents,
    /// Unprivileged process inspection and attribution.
    Processes,
    /// Mode C real-time live event monitoring.
    Activity,
    /// Mode B scheduled inspections and systemd user timers.
    Schedule,
    /// Application settings, inspection budgets, and privacy controls.
    Settings,
}

impl NavigationItem {
    /// Returns all available navigation items in standard tab order.
    pub const ALL: [NavigationItem; 7] = [
        NavigationItem::Overview,
        NavigationItem::Resources,
        NavigationItem::Agents,
        NavigationItem::Processes,
        NavigationItem::Activity,
        NavigationItem::Schedule,
        NavigationItem::Settings,
    ];

    /// Returns the human-readable display title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Resources => "Resources",
            Self::Agents => "Agents",
            Self::Processes => "Processes",
            Self::Activity => "Activity",
            Self::Schedule => "Schedule",
            Self::Settings => "Settings",
        }
    }

    /// Returns the libadwaita/Freedesktop icon name.
    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::Overview => "view-dashboard-symbolic",
            Self::Resources => "drive-harddisk-symbolic",
            Self::Agents => "system-run-symbolic",
            Self::Processes => "application-x-executable-symbolic",
            Self::Activity => "utilities-system-monitor-symbolic",
            Self::Schedule => "alarm-symbolic",
            Self::Settings => "emblem-system-symbolic",
        }
    }

    /// Returns the internal stack page identifier for GTK/libadwaita view stacks.
    pub fn page_id(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Resources => "resources",
            Self::Agents => "agents",
            Self::Processes => "processes",
            Self::Activity => "activity",
            Self::Schedule => "schedule",
            Self::Settings => "settings",
        }
    }

    /// Returns the keyboard accelerator shortcut (e.g. "`<Control>1`").
    pub fn accelerator(&self) -> &'static str {
        match self {
            Self::Overview => "<Control>1",
            Self::Resources => "<Control>2",
            Self::Agents => "<Control>3",
            Self::Processes => "<Control>4",
            Self::Activity => "<Control>5",
            Self::Schedule => "<Control>6",
            Self::Settings => "<Control>7",
        }
    }

    /// Returns the index of this item in the navigation bar.
    pub fn index(&self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Resources => 1,
            Self::Agents => 2,
            Self::Processes => 3,
            Self::Activity => 4,
            Self::Schedule => 5,
            Self::Settings => 6,
        }
    }

    /// Resolves a navigation item from its page identifier.
    pub fn from_page_id(id: &str) -> Option<Self> {
        match id {
            "overview" => Some(Self::Overview),
            "resources" => Some(Self::Resources),
            "agents" => Some(Self::Agents),
            "processes" => Some(Self::Processes),
            "activity" => Some(Self::Activity),
            "schedule" => Some(Self::Schedule),
            "settings" => Some(Self::Settings),
            _ => None,
        }
    }
}

/// Navigation state tracker supporting forward/backward history and active tab changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationState {
    current: NavigationItem,
    history: Vec<NavigationItem>,
    max_history: usize,
}

impl Default for NavigationState {
    fn default() -> Self {
        Self {
            current: NavigationItem::Overview,
            history: Vec::new(),
            max_history: 32,
        }
    }
}

impl NavigationState {
    /// Creates a new navigation state starting at the specified item.
    pub fn new(initial: NavigationItem) -> Self {
        Self {
            current: initial,
            history: Vec::new(),
            max_history: 32,
        }
    }

    /// Returns the currently active navigation item.
    pub fn current(&self) -> NavigationItem {
        self.current
    }

    /// Navigates to a new item, recording previous item in history.
    pub fn navigate_to(&mut self, item: NavigationItem) {
        if self.current != item {
            self.history.push(self.current);
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }
            self.current = item;
        }
    }

    /// Navigates back to the previously active navigation item, if any.
    pub fn navigate_back(&mut self) -> bool {
        if let Some(prev) = self.history.pop() {
            self.current = prev;
            true
        } else {
            false
        }
    }

    /// Returns true if backwards navigation is possible.
    pub fn can_navigate_back(&self) -> bool {
        !self.history.is_empty()
    }
}
