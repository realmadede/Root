//! Windows adapters (read-only).
//!
//! Pure logic (path layout, Task Scheduler XML, FILETIME and identity conversion) compiles on
//! every host so it can be unit-tested on Linux CI. Code that calls Win32 interfaces is gated to
//! `cfg(windows)`.

pub mod environment;
pub mod parse;
pub mod task_scheduler;

#[cfg(windows)]
pub mod accountant;
#[cfg(windows)]
pub mod filesystem;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub(crate) mod wide;

#[cfg(windows)]
pub use accountant::WindowsAccountant;
pub use environment::WindowsEnvironment;
#[cfg(windows)]
pub use filesystem::WindowsFilesystem;
#[cfg(windows)]
pub use process::WindowsProcess;
pub use task_scheduler::{TaskXmlGenerator, WindowsScheduler, ROOT_TASK_MARKER, ROOT_TASK_NAME};
