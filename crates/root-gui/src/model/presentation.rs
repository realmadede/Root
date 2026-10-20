use root_core::discovery::LifecycleState;
use root_core::model::ProtectionTier;
use std::path::Path;

/// Formats a byte count with binary prefixes and tabular figures layout.
/// Adheres to Designing-Skills requirement: numeric measurements must not horizontally jitter.
pub fn format_bytes_tabular(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    let b = bytes as f64;
    if b < KIB {
        format!("{} B", bytes)
    } else if b < MIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.2} MiB", b / MIB)
    } else if b < TIB {
        format!("{:.2} GiB", b / GIB)
    } else {
        format!("{:.2} TiB", b / TIB)
    }
}

/// Formats a byte count wrapped in Pango markup with tabular digits (`tnum=1`).
pub fn format_bytes_pango(bytes: u64) -> String {
    format!(
        "<span font_features=\"tnum=1\">{}</span>",
        format_bytes_tabular(bytes)
    )
}

/// Truncates a long filesystem path in the middle preserving the beginning origin and ending components.
/// Prevents Break-UI layout overflow while maintaining user context.
pub fn format_path_middle(path: &Path, max_chars: usize) -> String {
    let s = path.to_string_lossy();
    if s.chars().count() <= max_chars || max_chars < 12 {
        return s.into_owned();
    }

    let chars: Vec<char> = s.chars().collect();
    let total = chars.len();
    let keep_side = (max_chars - 3) / 2;

    let prefix: String = chars[..keep_side].iter().collect();
    let suffix: String = chars[total - keep_side..].iter().collect();

    format!("{}...{}", prefix, suffix)
}

/// Formats an execution or age duration in a human-readable, non-jittering form.
pub fn format_duration_human(duration_secs: u64) -> String {
    if duration_secs < 60 {
        format!("{}s", duration_secs)
    } else if duration_secs < 3600 {
        let mins = duration_secs / 60;
        let secs = duration_secs % 60;
        format!("{}m {:02}s", mins, secs)
    } else {
        let hours = duration_secs / 3600;
        let mins = (duration_secs % 3600) / 60;
        format!("{}h {:02}m", hours, mins)
    }
}

/// Formats a process ID with tabular layout for layout grid stability.
pub fn format_pid(pid: u32) -> String {
    format!("{:>7}", pid)
}

/// Pluralizes a noun phrase cleanly based on count.
pub fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{} {}", count, singular)
    } else {
        format!("{} {}", count, plural)
    }
}

/// Visual and accessible badge presentation for a protection tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionBadge {
    pub label: &'static str,
    pub css_class: &'static str,
    pub accessible_description: &'static str,
}

/// Returns badge metadata for a `ProtectionTier`.
pub fn badge_for_protection_tier(tier: ProtectionTier) -> ProtectionBadge {
    match tier {
        ProtectionTier::StrictlyProtected => ProtectionBadge {
            label: "PROTECTED",
            css_class: "badge-protected",
            accessible_description: "Protected: strictly reserved and permanently non-recoverable",
        },
        ProtectionTier::UserConfirmRequired => ProtectionBadge {
            label: "CONFIRM REQUIRED",
            css_class: "badge-confirm",
            accessible_description: "User confirmation required prior to any review",
        },
        ProtectionTier::ObsoleteTransient => ProtectionBadge {
            label: "TRANSIENT",
            css_class: "badge-transient",
            accessible_description: "Transient: ephemeral build or compiler cache",
        },
        ProtectionTier::SafeRecoverable => ProtectionBadge {
            label: "RECOVERABLE",
            css_class: "badge-recoverable",
            accessible_description: "Potentially recoverable build cache or abandoned artifact",
        },
        ProtectionTier::NonActionable => ProtectionBadge {
            label: "NON-ACTIONABLE",
            css_class: "badge-non-actionable",
            accessible_description: "Informational or active resource: non-actionable",
        },
    }
}

/// Visual and accessible badge presentation for a lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleBadge {
    pub label: &'static str,
    pub css_class: &'static str,
    pub accessible_description: &'static str,
}

/// Returns badge metadata for a `LifecycleState`.
pub fn badge_for_lifecycle(lifecycle: LifecycleState) -> LifecycleBadge {
    match lifecycle {
        LifecycleState::Active => LifecycleBadge {
            label: "ACTIVE",
            css_class: "badge-active",
            accessible_description: "Active: resource is currently in use by a running process",
        },
        LifecycleState::Persistent => LifecycleBadge {
            label: "PERSISTENT",
            css_class: "badge-persistent",
            accessible_description: "Persistent: resource holds configuration or persistent state",
        },
        LifecycleState::DormantTransient => LifecycleBadge {
            label: "DORMANT",
            css_class: "badge-dormant",
            accessible_description: "Dormant: transient artifact with no active holding processes",
        },
        LifecycleState::Unknown => LifecycleBadge {
            label: "UNKNOWN",
            css_class: "badge-unknown",
            accessible_description: "Unknown: lifecycle status uncertain, default to preservation",
        },
    }
}
