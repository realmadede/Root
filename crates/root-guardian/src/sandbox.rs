use root_core::error::{Result, RootError};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// A trusted, isolated synthetic fixture sandbox enforcing strict mutation boundaries.
///
/// In Phase 04, all quarantine and restoration operations are strictly quarantined within
/// an instance of `FixtureSandbox`. No operation can mutate or access files outside this boundary.
#[derive(Debug, Clone)]
pub struct FixtureSandbox {
    root_path: PathBuf,
    canonical_root: PathBuf,
    quarantine_dir: PathBuf,
    journal_dir: PathBuf,
    journal_path: PathBuf,
    device_id: u64,
    operator_uid: u32,
}

impl FixtureSandbox {
    /// Initializes a verified fixture sandbox at the given root directory.
    pub fn new(root: &Path, operator_uid: u32) -> Result<Self> {
        let canonical_root = root.canonicalize().map_err(|e| RootError::Io {
            path: root.to_path_buf(),
            source: e,
        })?;

        let meta = fs::metadata(&canonical_root).map_err(|e| RootError::Io {
            path: canonical_root.clone(),
            source: e,
        })?;

        let device_id = meta.dev();
        let quarantine_dir = canonical_root.join(".root_quarantine");
        let journal_dir = canonical_root.join(".root_journal");
        let journal_path = journal_dir.join("journal.jsonl");

        // Establish quarantine area with 0o700 permissions
        fs::create_dir_all(&quarantine_dir).map_err(|e| RootError::Io {
            path: quarantine_dir.clone(),
            source: e,
        })?;
        fs::set_permissions(&quarantine_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            RootError::Io {
                path: quarantine_dir.clone(),
                source: e,
            }
        })?;

        // Establish journal area with 0o700 permissions
        fs::create_dir_all(&journal_dir).map_err(|e| RootError::Io {
            path: journal_dir.clone(),
            source: e,
        })?;
        fs::set_permissions(&journal_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            RootError::Io {
                path: journal_dir.clone(),
                source: e,
            }
        })?;

        Ok(Self {
            root_path: root.to_path_buf(),
            canonical_root,
            quarantine_dir,
            journal_dir,
            journal_path,
            device_id,
            operator_uid,
        })
    }

    pub fn root(&self) -> &Path {
        &self.canonical_root
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    pub fn operator_uid(&self) -> u32 {
        self.operator_uid
    }

    /// Validates that a candidate path strictly resides within this sandbox boundary.
    ///
    /// Verifies canonical prefix, device identity, non-symlink status, and isolation from
    /// the sandbox's private internal management directories.
    pub fn assert_within_bounds(&self, candidate: &Path) -> Result<PathBuf> {
        // Resolve parent canonical directory first
        let parent = candidate.parent().ok_or_else(|| {
            RootError::InvalidPath(format!("Path '{:?}' has no parent directory", candidate))
        })?;

        let canonical_parent = parent.canonicalize().map_err(|e| RootError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;

        if !canonical_parent.starts_with(&self.canonical_root) {
            return Err(RootError::SandboxViolation {
                path: candidate.to_path_buf(),
                sandbox_root: self.canonical_root.clone(),
            });
        }

        // If candidate itself exists, check its symlink status and device ID
        if let Ok(meta) = fs::symlink_metadata(candidate) {
            if meta.is_symlink() {
                return Err(RootError::PolicyViolation {
                    reason: format!(
                        "Candidate '{:?}' is a symbolic link; symlinks cannot be modified directly",
                        candidate
                    ),
                });
            }

            if meta.dev() != self.device_id {
                return Err(RootError::CrossDeviceUnsupported {
                    source_dev: meta.dev(),
                    dest_dev: self.device_id,
                });
            }
        }

        // Ensure candidate is not the sandbox root itself
        if candidate == self.canonical_root || candidate == self.root_path {
            return Err(RootError::PolicyViolation {
                reason: "Cannot mutate the sandbox root directory itself".into(),
            });
        }

        // Ensure candidate does not target internal management trees
        if candidate.starts_with(&self.quarantine_dir) || candidate.starts_with(&self.journal_dir) {
            return Err(RootError::PolicyViolation {
                reason: "Cannot target internal quarantine or journal management directories"
                    .into(),
            });
        }

        Ok(candidate.to_path_buf())
    }
}
