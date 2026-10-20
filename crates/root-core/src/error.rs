use std::path::PathBuf;
use thiserror::Error;

/// Root domain errors.
#[derive(Debug, Error)]
pub enum RootError {
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Path validation error: {0}")]
    InvalidPath(String),

    #[error("Symlink jail escape detected: {path:?} targets {target:?} outside root {root:?}")]
    SymlinkJailEscape {
        path: PathBuf,
        target: PathBuf,
        root: PathBuf,
    },

    #[error("Mount point boundary crossed: {path:?} on device {device_id} differs from root device {root_device_id}")]
    MountBoundaryCrossed {
        path: PathBuf,
        device_id: u64,
        root_device_id: u64,
    },

    #[error("Security policy violation: {reason}")]
    PolicyViolation { reason: String },

    #[error("Ownership mismatch: resource owned by UID {resource_uid}, but current user is UID {current_uid}")]
    OwnershipMismatch { resource_uid: u32, current_uid: u32 },

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Platform error: {0}")]
    Platform(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Transaction {tx_id} failed: {reason}")]
    TransactionFailed { tx_id: String, reason: String },

    #[error("Invalid transaction state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Destination collision at {path:?}: file or directory already exists")]
    DestinationCollision { path: PathBuf },

    #[error("Cross-device operations unsupported: source device {source_dev} differs from destination device {dest_dev}")]
    CrossDeviceUnsupported { source_dev: u64, dest_dev: u64 },

    #[error("Integrity verification failed for {path:?}: {reason}")]
    IntegrityVerificationFailed { path: PathBuf, reason: String },

    #[error("Journal error at {path:?}: {reason}")]
    JournalError { path: PathBuf, reason: String },

    #[error("Restoration conflict at {path:?}: {reason}")]
    RestorationConflict { path: PathBuf, reason: String },

    #[error("Sandbox boundary violation: {path:?} is outside trusted sandbox {sandbox_root:?}")]
    SandboxViolation {
        path: PathBuf,
        sandbox_root: PathBuf,
    },
}

pub type Result<T> = std::result::Result<T, RootError>;
