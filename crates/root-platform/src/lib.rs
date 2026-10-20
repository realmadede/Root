//! Root Platform: Operating system abstraction traits and minimal read-only implementations.

pub mod linux;
pub mod mock;
pub mod traits;

pub use linux::{LinuxAccountant, LinuxEnvironment, LinuxFilesystem, LinuxProcess};
pub use mock::MockPlatform;
pub use traits::{
    EnvironmentProvider, FilesystemProvider, FilesystemWatcher, ProcessProvider, ResourceAccountant,
};
