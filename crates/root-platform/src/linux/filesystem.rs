use root_core::{
    error::{Result, RootError},
    model::{FileIdentity, PlatformKind, ResourceMetadata},
};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub use crate::traversal::{
    DiscoveredEntry, SkipReason, TraversalEvent, TraversalMetrics, TraversalOptions,
    TraversalOutcome,
};
use crate::{
    posix::{posix_filesystem_usage, posix_symlink_metadata, PosixProbe},
    traits::FilesystemProvider,
    traversal::traverse_tree,
};

const LINUX_PROBE: PosixProbe = PosixProbe {
    platform: PlatformKind::Linux,
};

#[derive(Debug, Default, Clone)]
pub struct LinuxFilesystem;

impl LinuxFilesystem {
    pub fn new() -> Self {
        Self
    }

    /// Determines if a path belongs to an operating system pseudo-filesystem.
    pub fn is_pseudo_filesystem(path: &Path) -> bool {
        root_core::model::pseudo_filesystem_prefix(PlatformKind::Linux, &path.to_string_lossy())
            .is_some()
    }

    /// Executes defensive, bounded, read-only traversal over an explicitly selected root.
    pub fn traverse(
        &self,
        root_path: &Path,
        options: &TraversalOptions,
    ) -> Result<TraversalOutcome> {
        traverse_tree(&LINUX_PROBE, root_path, options)
    }
}

impl FilesystemProvider for LinuxFilesystem {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        posix_symlink_metadata(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        fs::canonicalize(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let entries = fs::read_dir(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| RootError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
            paths.push(entry.path());
        }
        paths.sort();
        Ok(paths)
    }

    fn get_device_id(&self, path: &Path) -> Result<u64> {
        let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(meta.dev())
    }

    fn get_inode(&self, path: &Path) -> Result<u64> {
        let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(meta.ino())
    }

    fn get_file_identity(&self, path: &Path) -> Result<FileIdentity> {
        let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(FileIdentity::posix(meta.dev(), meta.ino()))
    }

    fn get_filesystem_usage(&self, path: &Path) -> Result<root_core::model::FilesystemUsage> {
        posix_filesystem_usage(path)
    }
}

impl LinuxFilesystem {
    /// Performs an atomic rename that fails if destination already exists (`RENAME_NOREPLACE`).
    pub fn atomic_rename_no_replace(from: &Path, to: &Path) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let from_cstr = CString::new(from.as_os_str().as_bytes())
            .map_err(|e| RootError::InvalidPath(e.to_string()))?;
        let to_cstr = CString::new(to.as_os_str().as_bytes())
            .map_err(|e| RootError::InvalidPath(e.to_string()))?;

        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from_cstr.as_ptr(),
                libc::AT_FDCWD,
                to_cstr.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if res == 0 {
            // Synchronize parent directories if possible
            if let Some(parent) = to.parent() {
                if let Ok(dir_file) = fs::File::open(parent) {
                    let _ = dir_file.sync_all();
                }
            }
            if let Some(parent) = from.parent() {
                if let Ok(dir_file) = fs::File::open(parent) {
                    let _ = dir_file.sync_all();
                }
            }
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EEXIST) => Err(RootError::DestinationCollision {
                    path: to.to_path_buf(),
                }),
                Some(libc::EXDEV) => {
                    let source_dev = from.metadata().map(|m| m.dev()).unwrap_or(0);
                    let dest_dev = to
                        .parent()
                        .and_then(|p| p.metadata().ok())
                        .map(|m| m.dev())
                        .unwrap_or(0);
                    Err(RootError::CrossDeviceUnsupported {
                        source_dev,
                        dest_dev,
                    })
                }
                _ => Err(RootError::Io {
                    path: from.to_path_buf(),
                    source: err,
                }),
            }
        }
    }
}
