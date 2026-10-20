//! Root Platform: Operating system abstraction traits and minimal read-only implementations.

pub mod linux;
pub mod mock;
pub mod traits;

pub use linux::{
    DesktopNotifier, DiscoveredEntry, InotifyWatcher, LinuxAccountant, LinuxEnvironment,
    LinuxFilesystem, LinuxMonitorSession, LinuxProcess, LinuxScheduler, MemoryObserver,
    ProcessObserver, SkipReason, SystemdUnitGenerator, TraversalEvent, TraversalMetrics,
    TraversalOptions, TraversalOutcome, ROOT_UNIT_MARKER,
};
pub use mock::MockPlatform;
pub use traits::{
    EnvironmentProvider, FilesystemProvider, FilesystemWatcher, ProcessProvider, ResourceAccountant,
};
