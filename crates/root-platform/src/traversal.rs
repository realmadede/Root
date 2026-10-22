//! Platform-neutral, bounded, read-only filesystem traversal.
//!
//! The loop here is shared by every platform. Platform adapters implement [`NodeProbe`] to answer
//! two questions without ever following links: "what is at this path" and "is this a path Root
//! refuses to scan".

use root_core::{
    error::{Result, RootError},
    model::{FileIdentity, ResourceMetadata},
};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

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
    pub timeout: Option<Duration>,
}

impl Default for TraversalOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 250_000,
            allow_cross_device: false,
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// Operational justification for skipping a path during traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    CrossDeviceBoundary {
        root_dev: u64,
        entry_dev: u64,
    },
    SymlinkNotFollowed,
    /// Windows reparse point (junction, mount point, cloud placeholder, or non-symlink tag) that
    /// was recorded but not descended into.
    ReparsePointNotFollowed,
    CycleDetected {
        dev: u64,
        ino: u64,
    },
    MaxDepthExceeded {
        depth: usize,
        limit: usize,
    },
    PseudoFilesystem,
}

/// A single discovered filesystem node with verified metadata.
#[derive(Debug, Clone)]
pub struct DiscoveredEntry {
    pub path: PathBuf,
    pub metadata: ResourceMetadata,
    /// Volume identifier (legacy field; equals `identity.volume`).
    pub dev: u64,
    /// Low 64 bits of the object identifier (legacy field; see `identity` for the full value).
    pub ino: u64,
    pub identity: FileIdentity,
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

/// What a probe learned about one node. Probes must not follow links.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub metadata: ResourceMetadata,
    pub identity: FileIdentity,
    pub is_dir: bool,
    /// Symlink on POSIX; any reparse point on Windows. Never descended into.
    pub is_link_like: bool,
    /// True when `is_link_like` is a Windows reparse point rather than a POSIX symlink.
    pub is_reparse_point: bool,
    pub uid: u32,
    pub gid: u32,
}

/// Per-platform filesystem questions the shared traversal engine cannot answer itself.
pub trait NodeProbe {
    /// Inspects `path` without following links (lstat semantics).
    fn probe(&self, path: &Path) -> io::Result<NodeInfo>;

    /// Whether `path` lies in a pseudo-filesystem or device namespace that is never scanned.
    fn is_pseudo_filesystem(&self, path: &Path) -> bool;

    /// Returns an error if `root` must never be used as a scan root (host root, drive root,
    /// pseudo-filesystem).
    fn validate_root(&self, root: &Path) -> Result<()>;
}

fn record_io_error(
    path: &Path,
    e: &io::Error,
    metrics: &mut TraversalMetrics,
    events: &mut Vec<TraversalEvent>,
) {
    match e.kind() {
        io::ErrorKind::PermissionDenied => {
            metrics.permission_denied_count += 1;
            events.push(TraversalEvent::PermissionDenied {
                path: path.to_path_buf(),
                error: e.to_string(),
            });
        }
        io::ErrorKind::NotFound => {
            metrics.disappeared_count += 1;
            events.push(TraversalEvent::Disappeared {
                path: path.to_path_buf(),
            });
        }
        _ => {
            metrics.unsupported_count += 1;
            events.push(TraversalEvent::Unsupported {
                path: path.to_path_buf(),
                reason: e.to_string(),
            });
        }
    }
}

/// Lists a directory's children in deterministic order, recording per-entry errors.
fn read_children(
    dir: &Path,
    metrics: &mut TraversalMetrics,
    events: &mut Vec<TraversalEvent>,
) -> io::Result<Vec<PathBuf>> {
    let read_dir = fs::read_dir(dir)?;
    let mut children = Vec::new();
    for child in read_dir {
        match child {
            Ok(entry) => children.push(entry.path()),
            Err(e) => record_io_error(dir, &e, metrics, events),
        }
    }
    children.sort();
    Ok(children)
}

/// Executes defensive, bounded, read-only traversal over an explicitly selected root.
pub fn traverse_tree<P: NodeProbe>(
    probe: &P,
    root_path: &Path,
    options: &TraversalOptions,
) -> Result<TraversalOutcome> {
    probe.validate_root(root_path)?;

    let root_info = probe.probe(root_path).map_err(|e| RootError::Io {
        path: root_path.to_path_buf(),
        source: e,
    })?;
    let root_volume = root_info.identity.volume;

    let mut visited_dirs: HashSet<(u64, u128)> = HashSet::new();
    let mut entries = Vec::new();
    let mut events = Vec::new();
    let mut metrics = TraversalMetrics {
        is_complete: true,
        ..Default::default()
    };
    let start_time = Instant::now();

    // Worklist stack for iterative, non-recursive traversal
    let mut stack: Vec<(PathBuf, usize)> = Vec::new();

    if root_info.is_dir && !root_info.is_link_like {
        if root_info.identity.is_usable() {
            visited_dirs.insert((root_info.identity.volume, root_info.identity.object));
        }
        match read_children(root_path, &mut metrics, &mut events) {
            Ok(children) => {
                for child in children.into_iter().rev() {
                    stack.push((child, 1));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                record_io_error(root_path, &e, &mut metrics, &mut events);
            }
            Err(e) => {
                return Err(RootError::Io {
                    path: root_path.to_path_buf(),
                    source: e,
                })
            }
        }
    } else {
        // Root is a single file (or a link, which is recorded but never followed)
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

        // 4. Defensive metadata inspection (never follows links)
        let info = match probe.probe(&current_path) {
            Ok(info) => info,
            Err(e) => {
                record_io_error(&current_path, &e, &mut metrics, &mut events);
                continue;
            }
        };

        let identity = info.identity;
        let dev = identity.volume;
        let ino = identity.object_low64();

        // 5. Volume boundary check. An unavailable identity cannot prove the same volume, so the
        // check is skipped for it rather than rejecting every entry.
        if identity.is_usable() && dev != root_volume && !options.allow_cross_device {
            metrics.skipped_count += 1;
            events.push(TraversalEvent::Skipped {
                path: current_path,
                reason: SkipReason::CrossDeviceBoundary {
                    root_dev: root_volume,
                    entry_dev: dev,
                },
            });
            continue;
        }

        // 6. Pseudo-filesystem skip check
        if probe.is_pseudo_filesystem(&current_path) {
            metrics.skipped_count += 1;
            events.push(TraversalEvent::Skipped {
                path: current_path,
                reason: SkipReason::PseudoFilesystem,
            });
            continue;
        }

        // Record inspected entry
        metrics.total_inspected += 1;

        let discovered = DiscoveredEntry {
            path: current_path.clone(),
            metadata: info.metadata,
            dev,
            ino,
            identity,
            uid: info.uid,
            gid: info.gid,
            depth,
        };
        entries.push(discovered.clone());
        events.push(TraversalEvent::Entry(discovered));

        // 7. Link handling: never descend into symlink targets or reparse points
        if info.is_link_like {
            metrics.skipped_count += 1;
            events.push(TraversalEvent::Skipped {
                path: current_path,
                reason: if info.is_reparse_point {
                    SkipReason::ReparsePointNotFollowed
                } else {
                    SkipReason::SymlinkNotFollowed
                },
            });
            continue;
        }

        // 8. Directory recursion with cycle detection
        if info.is_dir {
            if identity.is_usable() && !visited_dirs.insert((identity.volume, identity.object)) {
                metrics.skipped_count += 1;
                events.push(TraversalEvent::Skipped {
                    path: current_path,
                    reason: SkipReason::CycleDetected { dev, ino },
                });
                continue;
            }

            match read_children(&current_path, &mut metrics, &mut events) {
                Ok(children) => {
                    for child in children.into_iter().rev() {
                        stack.push((child, depth + 1));
                    }
                }
                Err(e) => record_io_error(&current_path, &e, &mut metrics, &mut events),
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
