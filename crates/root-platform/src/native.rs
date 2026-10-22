//! Compile-time selection of the platform adapters for the running operating system.
//!
//! Callers use these aliases so the same source compiles on Linux, macOS, and Windows.

#[cfg(target_os = "linux")]
mod selected {
    pub use crate::linux::{
        LinuxAccountant as NativeAccountant, LinuxEnvironment as NativeEnvironment,
        LinuxFilesystem as NativeFilesystem, LinuxMonitorSession as NativeMonitorSession,
        LinuxProcess as NativeProcess, LinuxScheduler as NativeScheduler,
    };
}

#[cfg(target_os = "macos")]
mod selected {
    use crate::{
        macos::{MacAccountant, MacEnvironment, MacFilesystem, MacProcess, MacScheduler},
        monitor::{PollingWatcher, PortableMonitorSession},
    };
    use root_core::{error::Result, model::MonitorScope};
    use std::time::Duration;

    pub type NativeAccountant = MacAccountant;
    pub type NativeEnvironment = MacEnvironment;
    pub type NativeFilesystem = MacFilesystem;
    pub type NativeProcess = MacProcess;
    pub type NativeScheduler = MacScheduler;

    /// Metadata-polling monitor (FSEvents is not wired in Phase 10).
    pub struct NativeMonitorSession(
        PortableMonitorSession<PollingWatcher, MacProcess, MacAccountant>,
    );

    impl NativeMonitorSession {
        pub fn new(scope: MonitorScope, current_uid: u32) -> Result<Self> {
            PortableMonitorSession::with_sources(
                scope,
                current_uid,
                crate::native::polling_watcher_for,
                MacProcess::new,
                MacAccountant::new,
            )
            .map(Self)
        }
    }
    impl std::ops::Deref for NativeMonitorSession {
        type Target = PortableMonitorSession<PollingWatcher, MacProcess, MacAccountant>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for NativeMonitorSession {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    #[allow(dead_code)]
    const _: Option<Duration> = None;
}

#[cfg(windows)]
mod selected {
    use crate::{
        monitor::{PollingWatcher, PortableMonitorSession},
        windows::{
            WindowsAccountant, WindowsEnvironment, WindowsFilesystem, WindowsProcess,
            WindowsScheduler,
        },
    };
    use root_core::{error::Result, model::MonitorScope};

    pub type NativeAccountant = WindowsAccountant;
    pub type NativeEnvironment = WindowsEnvironment;
    pub type NativeFilesystem = WindowsFilesystem;
    pub type NativeProcess = WindowsProcess;
    pub type NativeScheduler = WindowsScheduler;

    /// Metadata-polling monitor (`ReadDirectoryChangesW` is not wired in Phase 10).
    pub struct NativeMonitorSession(
        PortableMonitorSession<PollingWatcher, WindowsProcess, WindowsAccountant>,
    );

    impl NativeMonitorSession {
        pub fn new(scope: MonitorScope, current_uid: u32) -> Result<Self> {
            PortableMonitorSession::with_sources(
                scope,
                current_uid,
                crate::native::polling_watcher_for,
                WindowsProcess::new,
                WindowsAccountant::new,
            )
            .map(Self)
        }
    }
    impl std::ops::Deref for NativeMonitorSession {
        type Target = PortableMonitorSession<PollingWatcher, WindowsProcess, WindowsAccountant>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for NativeMonitorSession {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use selected::*;

/// Builds the polling watcher from a session's budget.
#[cfg(any(target_os = "macos", windows))]
pub(crate) fn polling_watcher_for(
    scope: &root_core::model::MonitorScope,
) -> crate::monitor::PollingWatcher {
    crate::monitor::PollingWatcher::new(
        scope.budget.max_watches,
        scope.budget.max_queued_events,
        std::time::Duration::from_millis(scope.budget.sampling_interval_millis.max(250)),
    )
}
