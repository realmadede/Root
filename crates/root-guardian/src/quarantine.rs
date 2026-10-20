use root_core::error::{Result, RootError};
use root_platform::LinuxFilesystem;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{crypto::sha256_file, sandbox::FixtureSandbox};

/// Quarantine staging store managing isolated artifact relocation.
pub struct QuarantineStore;

impl QuarantineStore {
    /// Generates a collision-resistant destination path within the sandbox quarantine area.
    pub fn allocate_quarantine_path(
        sandbox: &FixtureSandbox,
        transaction_id: &str,
        source_path: &Path,
        inode: u64,
    ) -> Result<PathBuf> {
        let file_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact");

        // Sanitize file name to avoid path traversal characters
        let sanitized: String = file_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let dest_name = format!("{}_{}_{}", transaction_id, inode, sanitized);
        let dest_path = sandbox.quarantine_dir().join(dest_name);

        if dest_path.exists() {
            return Err(RootError::DestinationCollision { path: dest_path });
        }

        Ok(dest_path)
    }

    /// Moves a synthetic candidate file atomically into the quarantine staging directory.
    ///
    /// Preserves file permissions and verifies that destination does not already exist.
    pub fn relocate_into_quarantine(
        source_path: &Path,
        dest_path: &Path,
        expected_dev: u64,
    ) -> Result<()> {
        let source_meta = fs::symlink_metadata(source_path).map_err(|e| RootError::Io {
            path: source_path.to_path_buf(),
            source: e,
        })?;

        // 1. Verify filesystem boundary
        if source_meta.dev() != expected_dev {
            return Err(RootError::CrossDeviceUnsupported {
                source_dev: source_meta.dev(),
                dest_dev: expected_dev,
            });
        }

        // 2. Perform same-filesystem atomic rename
        LinuxFilesystem::atomic_rename_no_replace(source_path, dest_path)?;

        // 3. Preserve original permissions on the quarantined file
        let _ = fs::set_permissions(
            dest_path,
            fs::Permissions::from_mode(source_meta.mode() & 0o777),
        );

        Ok(())
    }

    /// Verifies the integrity of a quarantined resource against pre-mutation snapshots.
    pub fn verify_quarantined_resource(
        dest_path: &Path,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<()> {
        if !dest_path.exists() {
            return Err(RootError::IntegrityVerificationFailed {
                path: dest_path.to_path_buf(),
                reason: "Quarantined destination file does not exist after move".into(),
            });
        }

        let meta = fs::metadata(dest_path).map_err(|e| RootError::Io {
            path: dest_path.to_path_buf(),
            source: e,
        })?;

        if meta.len() != expected_size {
            return Err(RootError::IntegrityVerificationFailed {
                path: dest_path.to_path_buf(),
                reason: format!(
                    "Quarantined file length ({} bytes) does not match expected length ({} bytes)",
                    meta.len(),
                    expected_size
                ),
            });
        }

        let computed_sha256 = sha256_file(dest_path)?;
        if computed_sha256 != expected_sha256 {
            return Err(RootError::IntegrityVerificationFailed {
                path: dest_path.to_path_buf(),
                reason: format!(
                    "Quarantined SHA-256 hash '{}' does not match snapshot '{}'",
                    computed_sha256, expected_sha256
                ),
            });
        }

        Ok(())
    }
}
