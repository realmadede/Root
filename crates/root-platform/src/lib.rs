//! Root Platform: Operating system abstraction traits and minimal read-only implementations.

pub mod linux;
pub mod mock;
pub mod traits;

pub use linux::{
    DesktopNotifier, DiscoveredEntry, LinuxAccountant, LinuxEnvironment, LinuxFilesystem,
    LinuxProcess, LinuxScheduler, SkipReason, SystemdUnitGenerator, TraversalEvent,
    TraversalMetrics, TraversalOptions, TraversalOutcome,
};
pub use mock::MockPlatform;
pub use traits::{
    EnvironmentProvider, FilesystemProvider, FilesystemWatcher, ProcessProvider, ResourceAccountant,
};
