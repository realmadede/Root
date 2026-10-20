use root_core::{
    error::{Result, RootError},
    model::{FileType, ResourceMetadata, StorageMeasurement},
};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};

use crate::traits::FilesystemProvider;

/// Configuration parameters for defensive filesystem traversal.
#[derive(Debug, Clone)]
pub struct TraversalOptions {
    /// Maximum directory depth from the scan root (prevents stack exhaustion and deep traps).
    pub max_depth: usize,
    /// Maximum total filesystem entries to inspect in a single pass.
    pub max_entries: usize,
    /// Whether to descend into mount points on foreign device IDs. Default is false.
    pub allow_cross_device: bool,
    /// Maximum allowable wall-clock duration for the traversal before graceful cutoff.
    pub timeout: Option<std::time::Duration>,
}

impl Default for TraversalOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 250_000,
            allow_cross_device: false,
            timeout: Some(std::time::Duration::from_secs(30)),
        }
    }
}

/// Operational justification for skipping a path during traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    CrossDeviceBoundary { root_dev: u64, entry_dev: u64 },
    SymlinkNotFollowed,
    CycleDetected { dev: u64, ino: u64 },
    MaxDepthExceeded { depth: usize, limit: usize },
    PseudoFilesystem,
}

/// A single discovered filesystem node with verified metadata.
#[derive(Debug, Clone)]
pub struct DiscoveredEntry {
    pub path: PathBuf,
    pub metadata: ResourceMetadata,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub depth: usize,
}

/// Diagnostic traversal event recorded during discovery.
#[derive(Debug, Clone)]
pub enum TraversalEvent {
    Entry(DiscoveredEntry),
    Skipped { path: PathBuf, reason: SkipReason },
    PermissionDenied { path: PathBuf, error: String },
    Disappeared { path: PathBuf },
    Unsupported { path: PathBuf, reason: String },
}

/// Consolidated metrics and completeness status for a traversal pass.
#[derive(Debug, Clone, Default)]
pub struct TraversalMetrics {
    pub total_inspected: u64,
    pub skipped_count: u64,
    pub permission_denied_count: u64,
    pub disappeared_count: u64,
    pub unsupported_count: u64,
    pub is_complete: bool,
    pub incomplete_reason: Option<String>,
}

/// The final outcome of a defensive filesystem traversal pass.
#[derive(Debug, Clone)]
pub struct TraversalOutcome {
    pub root_path: PathBuf,
    pub entries: Vec<DiscoveredEntry>,
    pub events: Vec<TraversalEvent>,
    pub metrics: TraversalMetrics,
}

#[derive(Debug, Default, Clone)]
pub struct LinuxFilesystem;

impl LinuxFilesystem {
    pub fn new() -> Self {
        Self
    }

    /// Determines if a path belongs to an operating system pseudo-filesystem.
    pub fn is_pseudo_filesystem(path: &Path) -> bool {
        let p = path.to_string_lossy();
        p == "/proc"
            || p.starts_with("/proc/")
            || p == "/sys"
            || p.starts_with("/sys/")
            || p == "/dev"
            || p.starts_with("/dev/")
            || p == "/run"
            || p.starts_with("/run/")
    }

    /// Executes defensive, bounded, read-only traversal over an explicitly selected root.
    pub fn traverse(
        &self,
        root_path: &Path,
        options: &TraversalOptions,
    ) -> Result<TraversalOutcome> {
        // Enforce safety constraint: do not scan root or pseudo-filesystems
        if root_path == Path::new("/") {
            return Err(RootError::InvalidPath(
                "Refusing to scan host root directory ('/') directly; specify a bounded development directory"
                    .to_string(),
            ));
        }

        if Self::is_pseudo_filesystem(root_path) {
            return Err(RootError::InvalidPath(format!(
                "Refusing to scan pseudo-filesystem path '{}'",
                root_path.display()
            )));
        }

        let root_meta = fs::symlink_metadata(root_path).map_err(|e| RootError::Io {
            path: root_path.to_path_buf(),
            source: e,
        })?;

        let root_dev = root_meta.dev();
        let root_ino = root_meta.ino();

        let mut visited_dirs: HashSet<(u64, u64)> = HashSet::new();
        let mut entries = Vec::new();
        let mut events = Vec::new();
        let mut metrics = TraversalMetrics {
            is_complete: true,
            ..Default::default()
        };

        let start_time = Instant::now();

        // Worklist stack for iterative, non-recursive traversal
        let mut stack: Vec<(PathBuf, usize)> = Vec::new();

        if root_meta.is_dir() {
            visited_dirs.insert((root_dev, root_ino));
            // Read root's immediate children
            match fs::read_dir(root_path) {
                Ok(read_dir) => {
                    let mut children = Vec::new();
                    for child_res in read_dir {
                        match child_res {
                            Ok(entry) => children.push(entry.path()),
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::PermissionDenied {
                                    metrics.permission_denied_count += 1;
                                    events.push(TraversalEvent::PermissionDenied {
                                        path: root_path.to_path_buf(),
                                        error: e.to_string(),
                                    });
                                } else {
                                    metrics.unsupported_count += 1;
                                    events.push(TraversalEvent::Unsupported {
                                        path: root_path.to_path_buf(),
                                        reason: e.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    // Sort children for deterministic iteration order
                    children.sort();
                    for child in children.into_iter().rev() {
                        stack.push((child, 1));
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        metrics.permission_denied_count += 1;
                        events.push(TraversalEvent::PermissionDenied {
                            path: root_path.to_path_buf(),
                            error: e.to_string(),
                        });
                    } else {
                        return Err(RootError::Io {
                            path: root_path.to_path_buf(),
                            source: e,
                        });
                    }
                }
            }
        } else {
            // Root is a single file
            stack.push((root_path.to_path_buf(), 0));
        }

        while let Some((current_path, depth)) = stack.pop() {
            // 1. Timeout check
            if let Some(timeout) = options.timeout {
                if start_time.elapsed() >= timeout {
                    metrics.is_complete = false;
                    metrics.incomplete_reason =
                        Some(format!("Traversal timed out after {}s", timeout.as_secs()));
                    break;
                }
            }

            // 2. Entry limit check
            if metrics.total_inspected as usize >= options.max_entries {
                metrics.is_complete = false;
                metrics.incomplete_reason = Some(format!(
                    "Traversal stopped: entry limit of {} reached",
                    options.max_entries
                ));
                break;
            }

            // 3. Depth limit check
            if depth > options.max_depth {
                metrics.skipped_count += 1;
                events.push(TraversalEvent::Skipped {
                    path: current_path,
                    reason: SkipReason::MaxDepthExceeded {
                        depth,
                        limit: options.max_depth,
                    },
                });
                continue;
            }

            // 4. Defensive metadata inspection (lstat; never follows symlinks)
            let meta = match fs::symlink_metadata(&current_path) {
                Ok(m) => m,
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            metrics.permission_denied_count += 1;
                            events.push(TraversalEvent::PermissionDenied {
                                path: current_path,
                                error: e.to_string(),
                            });
                        }
                        std::io::ErrorKind::NotFound => {
                            metrics.disappeared_count += 1;
                            events.push(TraversalEvent::Disappeared { path: current_path });
                        }
                        _ => {
                            metrics.unsupported_count += 1;
                            events.push(TraversalEvent::Unsupported {
                                path: current_path,
                                reason: e.to_string(),
                            });
                        }
                    }
                    continue;
                }
            };

            let dev = meta.dev();
            let ino = meta.ino();
            let uid = meta.uid();
            let gid = meta.gid();

            // 5. Cross-device boundary check
            if dev != root_dev && !options.allow_cross_device {
                metrics.skipped_count += 1;
                events.push(TraversalEvent::Skipped {
                    path: current_path,
                    reason: SkipReason::CrossDeviceBoundary {
                        root_dev,
                        entry_dev: dev,
                    },
                });
                continue;
            }

            // 6. Pseudo-filesystem skip check
            if Self::is_pseudo_filesystem(&current_path) {
                metrics.skipped_count += 1;
                events.push(TraversalEvent::Skipped {
                    path: current_path,
                    reason: SkipReason::PseudoFilesystem,
                });
                continue;
            }

            // Record inspected entry
            metrics.total_inspected += 1;

            let file_type = Self::convert_file_type(&meta);
            let storage = StorageMeasurement::from_raw(meta.size(), meta.blocks(), meta.nlink());
            let resource_meta = ResourceMetadata {
                file_type,
                storage,
                permissions_mode: meta.mode(),
                mtime_epoch_secs: meta.mtime(),
                atime_epoch_secs: meta.atime(),
                ctime_epoch_secs: meta.ctime(),
            };

            let discovered = DiscoveredEntry {
                path: current_path.clone(),
                metadata: resource_meta,
                dev,
                ino,
                uid,
                gid,
                depth,
            };

            entries.push(discovered.clone());
            events.push(TraversalEvent::Entry(discovered));

            // 7. Symlink handling: never descend into symlink targets
            if meta.file_type().is_symlink() {
                metrics.skipped_count += 1;
                events.push(TraversalEvent::Skipped {
                    path: current_path,
                    reason: SkipReason::SymlinkNotFollowed,
                });
                continue;
            }

            // 8. Directory recursion with cycle detection
            if meta.is_dir() {
                if !visited_dirs.insert((dev, ino)) {
                    metrics.skipped_count += 1;
                    events.push(TraversalEvent::Skipped {
                        path: current_path,
                        reason: SkipReason::CycleDetected { dev, ino },
                    });
                    continue;
                }

                match fs::read_dir(&current_path) {
                    Ok(read_dir) => {
                        let mut children = Vec::new();
                        for child_res in read_dir {
                            match child_res {
                                Ok(entry) => children.push(entry.path()),
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                                        metrics.permission_denied_count += 1;
                                        events.push(TraversalEvent::PermissionDenied {
                                            path: current_path.clone(),
                                            error: e.to_string(),
                                        });
                                    } else if e.kind() == std::io::ErrorKind::NotFound {
                                        metrics.disappeared_count += 1;
                                        events.push(TraversalEvent::Disappeared {
                                            path: current_path.clone(),
                                        });
                                    } else {
                                        metrics.unsupported_count += 1;
                                        events.push(TraversalEvent::Unsupported {
                                            path: current_path.clone(),
                                            reason: e.to_string(),
                                        });
                                    }
                                }
                            }
                        }

                        children.sort();
                        for child in children.into_iter().rev() {
                            stack.push((child, depth + 1));
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            metrics.permission_denied_count += 1;
                            events.push(TraversalEvent::PermissionDenied {
                                path: current_path,
                                error: e.to_string(),
                            });
                        } else if e.kind() == std::io::ErrorKind::NotFound {
                            metrics.disappeared_count += 1;
                            events.push(TraversalEvent::Disappeared { path: current_path });
                        } else {
                            metrics.unsupported_count += 1;
                            events.push(TraversalEvent::Unsupported {
                                path: current_path,
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(TraversalOutcome {
            root_path: root_path.to_path_buf(),
            entries,
            events,
            metrics,
        })
    }

    fn convert_file_type(meta: &fs::Metadata) -> FileType {
        let ft = meta.file_type();
        if ft.is_file() {
            FileType::RegularFile
        } else if ft.is_dir() {
            FileType::Directory
        } else if ft.is_symlink() {
            FileType::Symlink
        } else {
            let mode = meta.mode();
            if (mode & 0o010000) != 0 {
                FileType::Fifo
            } else if (mode & 0o140000) != 0 {
                FileType::Socket
            } else if (mode & 0o060000) != 0 {
                FileType::BlockDevice
            } else if (mode & 0o020000) != 0 {
                FileType::CharacterDevice
            } else {
                FileType::Unknown
            }
        }
    }
}

impl FilesystemProvider for LinuxFilesystem {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let file_type = Self::convert_file_type(&meta);
        let storage = StorageMeasurement::from_raw(meta.size(), meta.blocks(), meta.nlink());

        Ok(ResourceMetadata {
            file_type,
            storage,
            permissions_mode: meta.mode(),
            mtime_epoch_secs: meta.mtime(),
            atime_epoch_secs: meta.atime(),
            ctime_epoch_secs: meta.ctime(),
        })
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
