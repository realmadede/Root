pub mod capabilities;
pub mod classification;
pub mod finding;
pub mod identity;
pub mod measurement;
pub mod monitor;
pub mod platform_paths;
pub mod process;
pub mod provenance;
pub mod resource;
pub mod schedule;

pub use capabilities::{CapabilityStatus, PlatformCapabilities};
pub use classification::{ProposedAction, ProtectionTier, RejectionReason, SafetyDecision};
pub use finding::{FindingTarget, ScanFinding, ScanReport, ScanSummary};
pub use identity::{FileIdentity, IdentityKind};
pub use measurement::{
    FilesystemUsage, MemoryMeasurement, PressureMetrics, StorageMeasurement, SystemMemorySummary,
};
pub use monitor::{
    DegradedReason, LiveFsEvent, LiveFsEventKind, MemoryObservation, MonitorBudget, MonitorEvent,
    MonitorScope, MonitorSessionState, MonitorSessionSummary, ProcessEventKind, ProcessObservation,
};
pub use platform_paths::{
    classify_windows_path, compare_windows_paths, is_filesystem_root, needs_extended_length,
    protected_system_prefix, pseudo_filesystem_prefix, to_extended_length_path, PathMatch,
    PlatformKind, WindowsPathKind,
};
pub use process::{ProcessCandidate, ProcessIdentity, ProcessState};
pub use provenance::{ConfidenceLevel, EvidenceProvenance, FindingEvidence};
pub use resource::{
    FileType, ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
    ResourceOwnership,
};
pub use schedule::{
    validate_executable, InspectionBudget, InspectionProfile, ScheduleConfig, ScheduleHistoryEntry,
    ScheduleInterval, ScheduleRunStatus, ScheduleStatus,
};
