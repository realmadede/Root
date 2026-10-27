//! Root Platform: Operating system abstraction traits and read-only platform adapters.
//!
//! Adapters for Linux, macOS, and Windows live in sibling modules of this crate. Pure logic in the
//! macOS and Windows modules compiles on every host; code that calls operating-system interfaces is
//! gated by `cfg(target_os)` or `cfg(windows)`. The `native` module selects the adapters for the
//! operating system being compiled for.

pub mod lock;
pub mod macos;
pub mod mock;
pub mod monitor;
pub mod native;
pub mod notify;
pub mod traits;
pub mod traversal;
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub use linux::{
    is_openat2_supported, DirectoryIdentity, InotifyWatcher, LinuxAccountant, LinuxEnvironment,
    LinuxFilesystem, LinuxMonitorSession, LinuxProcess, LinuxScheduler, MemoryObserver, OpenHow,
    PinnedDirectory, PinnedFile, ProcessObserver, ResolutionError, ResolutionMode,
    ResolutionOptions, SystemdUnitGenerator, RESOLVE_BENEATH, RESOLVE_CACHED, RESOLVE_IN_ROOT,
    RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV, ROOT_UNIT_MARKER,
};
pub use lock::{AdvisoryLock, LockGuard, LockStatus};
pub use mock::MockPlatform;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use native::{
    NativeAccountant, NativeEnvironment, NativeFilesystem, NativeMonitorSession, NativeProcess,
    NativeScheduler,
};
pub use notify::DesktopNotifier;
pub use traits::{
    EnvironmentProvider, FilesystemProvider, FilesystemWatcher, FsEventSource, ProcessProvider,
    ResourceAccountant, Scheduler,
};
pub use traversal::{
    DiscoveredEntry, SkipReason, TraversalEvent, TraversalMetrics, TraversalOptions,
    TraversalOutcome,
};
