use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{
    identity::{FileIdentity, IdentityKind},
    measurement::StorageMeasurement,
};

/// Strongly typed identifier for a discovered resource candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId(pub String);

impl ResourceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn from_path_and_inode(path: &Path, device_id: u64, inode: u64) -> Self {
        Self(format!("{}:{}:{}", path.display(), device_id, inode))
    }

    /// Builds an id from a path and a platform-neutral identity. For POSIX identities the result
    /// is identical to `from_path_and_inode`.
    pub fn from_path_and_identity(path: &Path, identity: &FileIdentity) -> Self {
        Self(format!("{}:{}", path.display(), identity))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The architectural category of a filesystem resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCategory {
    /// Upstream package archive cache (npm, pip, cargo .crate). Bit-for-bit re-fetchable.
    PackageCache,
    /// Build output directory (e.g. `target/`, `node_modules/`, `dist/`).
    BuildArtifact,
    /// Agent execution scratchpad or temporary workspace (`brain/<id>/scratch/`).
    AgentScratchpad,
    /// Diagnostic log or execution trace (`log/cli-*.log`, `shell-snapshots/`).
    DiagnosticLog,
    /// Agent conversation history or session state (`transcript.jsonl`, `sessions/*.json`).
    SessionState,
    /// General user documents and source code (`Documents/`, tracked git files).
    UserDocument,
    /// Operating system core file or system configuration (`/etc`, `/usr`).
    SystemFile,
    /// Unknown or unclassified resource.
    Unknown,
}

/// Filesystem entity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
    Unknown,
}

/// Location and filesystem identity of a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLocation {
    /// Nominal path as discovered during scan traversal.
    pub path: PathBuf,
    /// Canonicalized path (resolving intermediate symlinks).
    pub canonical_path: Option<PathBuf>,
    /// Volume identifier: `st_dev` on POSIX, volume serial number on Windows.
    pub device_id: u64,
    /// Object identifier: `st_ino` on POSIX, low 64 bits of the file id on Windows.
    pub inode: u64,
    /// Which identity scheme the two fields above follow. Defaults to POSIX so previously
    /// serialized locations remain readable.
    #[serde(default)]
    pub identity_kind: IdentityKind,
}

impl ResourceLocation {
    pub fn new(path: PathBuf, canonical_path: Option<PathBuf>, device_id: u64, inode: u64) -> Self {
        Self {
            path,
            canonical_path,
            device_id,
            inode,
            identity_kind: IdentityKind::PosixDeviceInode,
        }
    }

    pub fn with_identity_kind(mut self, kind: IdentityKind) -> Self {
        self.identity_kind = kind;
        self
    }
}

/// Physical filesystem metadata for a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    pub file_type: FileType,
    pub storage: StorageMeasurement,
    pub permissions_mode: u32,
    pub mtime_epoch_secs: i64,
    pub atime_epoch_secs: i64,
    pub ctime_epoch_secs: i64,
}

/// Ownership identity of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceOwnership {
    pub uid: u32,
    pub gid: u32,
    /// Whether the resource is owned by the currently executing user.
    pub is_current_user: bool,
}

/// A fully qualified filesystem resource candidate evaluated by Root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCandidate {
    pub id: ResourceId,
    pub location: ResourceLocation,
    pub category: ResourceCategory,
    pub metadata: ResourceMetadata,
    pub ownership: ResourceOwnership,
    /// Attributed toolchain or AI agent name (e.g. "Google Antigravity", "Claude Code", "Cargo").
    pub associated_agent: Option<String>,
}
