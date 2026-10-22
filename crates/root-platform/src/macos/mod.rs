//! macOS adapters (read-only).
//!
//! Pure logic (path layout, launchd plist generation, parsing helpers) compiles on every host so
//! it can be unit-tested on Linux CI. Code that calls Darwin interfaces is gated to
//! `target_os = "macos"`.

pub mod launchd;
pub mod parse;

#[cfg(unix)]
pub mod environment;
#[cfg(unix)]
pub mod filesystem;

#[cfg(target_os = "macos")]
pub mod accountant;
#[cfg(target_os = "macos")]
pub mod process;

#[cfg(target_os = "macos")]
pub use accountant::MacAccountant;
#[cfg(unix)]
pub use environment::MacEnvironment;
#[cfg(unix)]
pub use filesystem::MacFilesystem;
pub use launchd::{LaunchdPlistGenerator, MacScheduler, LAUNCHD_LABEL, ROOT_PLIST_MARKER};
#[cfg(target_os = "macos")]
pub use process::MacProcess;
