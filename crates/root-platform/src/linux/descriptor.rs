//! Linux directory descriptor abstraction and resolution safety.
//!
//! This module implements descriptor-pinned directory access for Linux, establishing
//! defense-in-depth against time-of-check/time-of-use (TOCTOU) ancestor substitution
//! and symlink traversal attacks.
//!
//! # Architecture & Security Guarantees
//!
//! Operating on path strings (e.g. `/home/user/project/target`) forces the kernel to resolve
//! each path component sequentially starting from the current working directory or filesystem
//! root. Between component checks and subsequent operations, a concurrent process can rename
//! an ancestor directory or substitute a directory component with a symlink.
//!
//! The [`PinnedDirectory`] abstraction mitigates this class of races by:
//! 1. Opening ancestor directories with `O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`.
//! 2. Holding the resulting directory descriptor open via Rust RAII (`Drop` closes the descriptor).
//! 3. Performing subsequent operations relative to that pinned descriptor (`openat`, `openat2`, `fstatat`).
//! 4. Using `openat2` resolution flags (`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`)
//!    where available on Linux 5.6+, with a defensive fallback for single-component lookups.
//!
//! # Invariant Boundaries & Limitations
//!
//! - **Descriptor vs. Namespace**: Holding an open directory descriptor pins the underlying
//!   filesystem object (`inode`). It does *not* prevent other processes from unlinking or renaming
//!   the directory dentry in the parent directory namespace.
//! - **Child Entries**: Pinning a parent directory does not pin child files until they are
//!   opened and pinned individually.
//! - **Production Isolation**: This module provides the filesystem primitive only. It is not
//!   connected to production mutation pathways or Guardian quarantine transactions.

use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, io::RawFd},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU8, Ordering},
};

use root_core::error::RootError;

/// Linux `openat2` resolution flags from `linux/openat2.h`.
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;
pub const RESOLVE_CACHED: u64 = 0x20;

/// Linux `open_how` structure used by the `openat2` system call.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

impl Default for OpenHow {
    fn default() -> Self {
        Self {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0,
        }
    }
}

/// Structured errors encountered during descriptor-relative resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolutionError {
    #[error("Invalid path or component: {0}")]
    InvalidComponent(String),

    #[error("Symlink rejected at component '{0}'; symlink traversal is prohibited")]
    SymlinkRejected(String),

    #[error("Filesystem object '{0}' is not a directory")]
    NotADirectory(String),

    #[error("Kernel capability unsupported or restricted: {0}")]
    UnsupportedCapability(&'static str),

    #[error("Permission denied accessing '{0}'")]
    PermissionDenied(String),

    #[error("Mount boundary crossed: parent device {parent_dev} != child device {child_dev}")]
    MountBoundaryCrossed { parent_dev: u64, child_dev: u64 },

    #[error("Filesystem object '{0}' not found")]
    NotFound(String),

    #[error("Destination collision at component '{0}'; refusing to overwrite existing object")]
    DestinationCollision(String),

    #[error("I/O error during descriptor resolution: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

impl From<ResolutionError> for RootError {
    fn from(err: ResolutionError) -> Self {
        match err {
            ResolutionError::InvalidComponent(msg) => RootError::InvalidPath(msg),
            ResolutionError::SymlinkRejected(name) => RootError::PolicyViolation {
                reason: format!(
                    "Symlink encountered at '{}'; symlink traversal is prohibited",
                    name
                ),
            },
            ResolutionError::NotADirectory(name) => {
                RootError::InvalidPath(format!("'{}' is not a directory", name))
            }
            ResolutionError::UnsupportedCapability(cap) => {
                RootError::Platform(format!("Kernel capability unsupported: {}", cap))
            }
            ResolutionError::PermissionDenied(name) => RootError::Io {
                path: PathBuf::from(name),
                source: std::io::Error::from_raw_os_error(libc::EACCES),
            },
            ResolutionError::MountBoundaryCrossed {
                parent_dev,
                child_dev,
            } => RootError::MountBoundaryCrossed {
                path: PathBuf::new(),
                device_id: child_dev,
                root_device_id: parent_dev,
            },
            ResolutionError::NotFound(name) => RootError::Io {
                path: PathBuf::from(name),
                source: std::io::Error::from_raw_os_error(libc::ENOENT),
            },
            ResolutionError::DestinationCollision(name) => RootError::DestinationCollision {
                path: PathBuf::from(name),
            },
            ResolutionError::Io { source } => RootError::Io {
                path: PathBuf::new(),
                source,
            },
        }
    }
}

/// Execution mode controlling path-resolution syscall dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMode {
    /// Automatically probe `openat2` capability and fall back to `openat` if unsupported.
    Auto,
    /// Force execution via `openat2`. Returns `ResolutionError::UnsupportedCapability` if absent.
    ForceOpenat2,
    /// Force execution via defensive `openat(O_NOFOLLOW)` fallback for single components.
    ForceFallback,
}

/// Options governing descriptor-relative resolution behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionOptions {
    pub mode: ResolutionMode,
    pub allow_mount_crossing: bool,
}

impl Default for ResolutionOptions {
    fn default() -> Self {
        Self {
            mode: ResolutionMode::Auto,
            allow_mount_crossing: false,
        }
    }
}

/// Verified identity snapshot of an opened directory object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirectoryIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl DirectoryIdentity {
    /// Constructs identity metadata from a POSIX `stat` buffer.
    #[allow(clippy::unnecessary_cast)]
    pub fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device_id: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            mode: stat.st_mode as u32,
            uid: stat.st_uid as u32,
            gid: stat.st_gid as u32,
        }
    }

    /// Verifies whether two identity instances refer to the exact same filesystem object.
    pub fn is_same_object(&self, other: &DirectoryIdentity) -> bool {
        self.device_id == other.device_id && self.inode == other.inode
    }

    /// Returns true if the object is a symbolic link.
    #[allow(clippy::unnecessary_cast)]
    pub fn is_symlink(&self) -> bool {
        (self.mode & (libc::S_IFMT as u32)) == (libc::S_IFLNK as u32)
    }

    /// Returns true if the object is a directory.
    #[allow(clippy::unnecessary_cast)]
    pub fn is_dir(&self) -> bool {
        (self.mode & (libc::S_IFMT as u32)) == (libc::S_IFDIR as u32)
    }

    /// Returns true if the object is a regular file.
    #[allow(clippy::unnecessary_cast)]
    pub fn is_regular_file(&self) -> bool {
        (self.mode & (libc::S_IFMT as u32)) == (libc::S_IFREG as u32)
    }
}

/// Probe state cache for `openat2` availability (0: unprobed, 1: supported, 2: unsupported).
static OPENAT2_STATUS: AtomicU8 = AtomicU8::new(0);

/// Probes whether `openat2` is supported and accessible on the running kernel.
pub fn is_openat2_supported() -> bool {
    match OPENAT2_STATUS.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let res = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    -1i32,
                    std::ptr::null::<libc::c_void>(),
                    std::ptr::null::<libc::c_void>(),
                    0usize,
                )
            };
            let supported = if res >= 0 {
                unsafe { libc::close(res as i32) };
                true
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                err == libc::EFAULT || err == libc::EINVAL
            };
            OPENAT2_STATUS.store(if supported { 1 } else { 2 }, Ordering::Relaxed);
            supported
        }
    }
}

/// RAII wrapper for an open regular file descriptor.
#[derive(Debug)]
pub struct PinnedFile {
    fd: RawFd,
    identity: DirectoryIdentity,
    size_bytes: u64,
}

impl PinnedFile {
    /// Returns the borrowed raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the verified identity of the pinned file.
    pub fn identity(&self) -> &DirectoryIdentity {
        &self.identity
    }

    /// Returns the size of the file in bytes observed at open time.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Sets permission bits on the open file descriptor via `fchmod`.
    pub fn set_permissions_mode(&self, mode: u32) -> Result<(), ResolutionError> {
        let res = unsafe { libc::fchmod(self.fd, (mode & 0o777) as libc::mode_t) };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            Err(ResolutionError::Io { source: err })
        } else {
            Ok(())
        }
    }
}

impl Drop for PinnedFile {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

unsafe impl Send for PinnedFile {}
unsafe impl Sync for PinnedFile {}

/// RAII wrapper for a pinned Linux directory descriptor.
///
/// Owns the underlying file descriptor and guarantees safe closure via `Drop`.
#[derive(Debug)]
pub struct PinnedDirectory {
    fd: RawFd,
    identity: DirectoryIdentity,
}

impl Drop for PinnedDirectory {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

unsafe impl Send for PinnedDirectory {}
unsafe impl Sync for PinnedDirectory {}

impl PinnedDirectory {
    /// Opens a root directory without following a symlink at the final path component.
    ///
    /// Validates with `fstat` that the opened object is a directory and records its identity.
    pub fn open_root(path: &Path) -> Result<Self, ResolutionError> {
        let path_str = path.as_os_str();
        if path_str.is_empty() {
            return Err(ResolutionError::InvalidComponent(
                "Root directory path cannot be empty".into(),
            ));
        }

        let c_path = CString::new(path_str.as_bytes()).map_err(|_| {
            ResolutionError::InvalidComponent("Path contains embedded null byte".into())
        })?;

        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::open(c_path.as_ptr(), flags) };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTDIR) || err.raw_os_error() == Some(libc::ELOOP)
            {
                if let Ok(meta) = std::fs::symlink_metadata(path) {
                    if meta.file_type().is_symlink() {
                        return Err(ResolutionError::SymlinkRejected(path.display().to_string()));
                    }
                }
            }
            return Err(map_os_error(err, path.display().to_string()));
        }

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(fd, &mut stat_buf) };

        if stat_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(ResolutionError::Io { source: err });
        }

        if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            unsafe { libc::close(fd) };
            return Err(ResolutionError::NotADirectory(path.display().to_string()));
        }

        let identity = DirectoryIdentity::from_stat(&stat_buf);
        Ok(Self { fd, identity })
    }

    /// Returns the borrowed raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the verified identity of the pinned directory.
    pub fn identity(&self) -> &DirectoryIdentity {
        &self.identity
    }

    /// Opens a single child directory component relative to this pinned descriptor.
    ///
    /// # Safety Invariants Enforced
    /// - `component_name` must be a strictly single component (no slashes, no nulls).
    /// - `.` and `..` are explicitly rejected.
    /// - If `options.allow_mount_crossing` is false, child `st_dev` must match parent `st_dev`.
    /// - Symlinks are unconditionally rejected at the child component.
    pub fn open_child_dir(
        &self,
        component_name: &str,
        options: ResolutionOptions,
    ) -> Result<Self, ResolutionError> {
        validate_single_component(component_name)?;

        let c_name = CString::new(component_name).map_err(|_| {
            ResolutionError::InvalidComponent("Component contains embedded null byte".into())
        })?;

        let use_openat2 = match options.mode {
            ResolutionMode::ForceOpenat2 => {
                if !is_openat2_supported() {
                    return Err(ResolutionError::UnsupportedCapability("openat2"));
                }
                true
            }
            ResolutionMode::ForceFallback => false,
            ResolutionMode::Auto => is_openat2_supported(),
        };

        let open_res = if use_openat2 {
            self.openat2_child_dir(&c_name, options.allow_mount_crossing, component_name)
        } else {
            self.fallback_child_dir(&c_name, component_name)
        };

        let fd = match open_res {
            Ok(fd) => fd,
            Err(e) => {
                // If opening failed with NotADirectory or Io, check if the component is actually a symlink
                let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
                let stat_res = unsafe {
                    libc::fstatat(
                        self.fd,
                        c_name.as_ptr(),
                        &mut stat_buf,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if stat_res == 0 && (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    return Err(ResolutionError::SymlinkRejected(component_name.to_string()));
                }
                return Err(e);
            }
        };

        // Post-open verification: fstat descriptor
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(fd, &mut stat_buf) };

        if stat_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(ResolutionError::Io { source: err });
        }

        if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            unsafe { libc::close(fd) };
            return Err(ResolutionError::NotADirectory(component_name.to_string()));
        }

        let child_identity = DirectoryIdentity::from_stat(&stat_buf);

        if !options.allow_mount_crossing && child_identity.device_id != self.identity.device_id {
            unsafe { libc::close(fd) };
            return Err(ResolutionError::MountBoundaryCrossed {
                parent_dev: self.identity.device_id,
                child_dev: child_identity.device_id,
            });
        }

        Ok(Self {
            fd,
            identity: child_identity,
        })
    }

    /// Opens a single child regular file component relative to this pinned descriptor.
    ///
    /// Verifies that the child object is NOT a directory and is NOT a symlink.
    pub fn open_child_file(
        &self,
        component_name: &str,
        extra_flags: libc::c_int,
        options: ResolutionOptions,
    ) -> Result<PinnedFile, ResolutionError> {
        validate_single_component(component_name)?;

        let c_name = CString::new(component_name).map_err(|_| {
            ResolutionError::InvalidComponent("Component contains embedded null byte".into())
        })?;

        let use_openat2 = match options.mode {
            ResolutionMode::ForceOpenat2 => {
                if !is_openat2_supported() {
                    return Err(ResolutionError::UnsupportedCapability("openat2"));
                }
                true
            }
            ResolutionMode::ForceFallback => false,
            ResolutionMode::Auto => is_openat2_supported(),
        };

        let fd = if use_openat2 {
            let mut resolve = RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;
            if !options.allow_mount_crossing {
                resolve |= RESOLVE_NO_XDEV;
            }

            let how = OpenHow {
                flags: (libc::O_RDONLY | libc::O_CLOEXEC | extra_flags) as u64,
                mode: 0,
                resolve,
            };

            let res = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    self.fd,
                    c_name.as_ptr(),
                    &how as *const OpenHow as *const libc::c_void,
                    std::mem::size_of::<OpenHow>(),
                )
            };

            if res >= 0 {
                res as RawFd
            } else {
                let err = std::io::Error::last_os_error();
                return Err(map_os_error(err, component_name.to_string()));
            }
        } else {
            let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | extra_flags;
            let res = unsafe { libc::openat(self.fd, c_name.as_ptr(), flags) };

            if res >= 0 {
                res
            } else {
                let err = std::io::Error::last_os_error();
                return Err(map_os_error(err, component_name.to_string()));
            }
        };

        // Post-open verification: must not be a directory
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(fd, &mut stat_buf) };

        if stat_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(ResolutionError::Io { source: err });
        }

        if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            unsafe { libc::close(fd) };
            return Err(ResolutionError::InvalidComponent(format!(
                "Expected regular file, but '{}' is a directory",
                component_name
            )));
        }

        let file_identity = DirectoryIdentity::from_stat(&stat_buf);

        if !options.allow_mount_crossing && file_identity.device_id != self.identity.device_id {
            unsafe { libc::close(fd) };
            return Err(ResolutionError::MountBoundaryCrossed {
                parent_dev: self.identity.device_id,
                child_dev: file_identity.device_id,
            });
        }

        Ok(PinnedFile {
            fd,
            identity: file_identity,
            size_bytes: stat_buf.st_size as u64,
        })
    }

    /// Inspects child metadata without following symlinks via `fstatat`.
    pub fn stat_child(&self, component_name: &str) -> Result<DirectoryIdentity, ResolutionError> {
        validate_single_component(component_name)?;

        let c_name = CString::new(component_name).map_err(|_| {
            ResolutionError::InvalidComponent("Component contains embedded null byte".into())
        })?;

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let res = unsafe {
            libc::fstatat(
                self.fd,
                c_name.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            return Err(map_os_error(err, component_name.to_string()));
        }

        Ok(DirectoryIdentity::from_stat(&stat_buf))
    }

    /// Checks whether a single child component exists relative to this pinned directory.
    pub fn exists_child(&self, component_name: &str) -> bool {
        self.stat_child(component_name).is_ok()
    }

    /// Creates an independent handle to this pinned directory via descriptor duplication (`fcntl(F_DUPFD_CLOEXEC)`).
    pub fn try_clone(&self) -> Result<Self, ResolutionError> {
        let fd = self.duplicate_fd()?;
        Ok(Self {
            fd,
            identity: self.identity,
        })
    }

    /// Atomically renames a child file from this pinned directory to a destination pinned directory
    /// without replacing an existing destination file (`RENAME_NOREPLACE`).
    ///
    /// Both `src_component` and `dest_component` must be strictly single components.
    /// Operates directly on the directory descriptors `self.raw_fd()` and `dest_dir.raw_fd()`,
    /// preventing ancestor directory substitution TOCTOU races.
    pub fn rename_child_to(
        &self,
        src_component: &str,
        dest_dir: &PinnedDirectory,
        dest_component: &str,
    ) -> Result<(), ResolutionError> {
        validate_single_component(src_component)?;
        validate_single_component(dest_component)?;

        let src_c = CString::new(src_component).map_err(|_| {
            ResolutionError::InvalidComponent("Source component contains embedded null byte".into())
        })?;
        let dest_c = CString::new(dest_component).map_err(|_| {
            ResolutionError::InvalidComponent(
                "Destination component contains embedded null byte".into(),
            )
        })?;

        // Cross-device rename is not supported by renameat2
        if self.identity.device_id != dest_dir.identity.device_id {
            return Err(ResolutionError::MountBoundaryCrossed {
                parent_dev: self.identity.device_id,
                child_dev: dest_dir.identity.device_id,
            });
        }

        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.fd,
                src_c.as_ptr(),
                dest_dir.fd,
                dest_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if res == 0 {
            // Attempt to synchronize directory changes to physical disk
            unsafe {
                libc::fsync(self.fd);
                libc::fsync(dest_dir.fd);
            }
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EEXIST) => Err(ResolutionError::DestinationCollision(
                    dest_component.to_string(),
                )),
                Some(libc::EXDEV) => Err(ResolutionError::MountBoundaryCrossed {
                    parent_dev: self.identity.device_id,
                    child_dev: dest_dir.identity.device_id,
                }),
                Some(libc::ENOENT) => Err(ResolutionError::NotFound(src_component.to_string())),
                _ => Err(ResolutionError::Io { source: err }),
            }
        }
    }

    /// Sets permission bits on a child file descriptor directly without path-based lookup.
    pub fn set_child_permissions_mode(
        &self,
        component_name: &str,
        mode: u32,
    ) -> Result<(), ResolutionError> {
        let pinned_file = self.open_child_file(component_name, 0, ResolutionOptions::default())?;
        pinned_file.set_permissions_mode(mode)
    }

    /// Safely resolves a multi-component relative path beneath this pinned directory.
    ///
    /// Iteratively resolves and pins each component using [`PinnedDirectory::open_child_dir`],
    /// guaranteeing that no symlinks are traversed, no `..` escapes occur, and mount boundaries
    /// are consistently respected.
    pub fn resolve_path_beneath(
        &self,
        relative_path: &Path,
        options: ResolutionOptions,
    ) -> Result<Self, ResolutionError> {
        if relative_path.is_absolute() {
            return Err(ResolutionError::InvalidComponent(
                "Path cannot be absolute in relative resolution".into(),
            ));
        }

        let mut current_fd = self.duplicate_fd()?;
        let mut current_identity = self.identity;

        for component in relative_path.components() {
            match component {
                Component::Normal(c) => {
                    let c_str = c.to_str().ok_or_else(|| {
                        ResolutionError::InvalidComponent("Component contains invalid UTF-8".into())
                    })?;

                    let temp_dir = PinnedDirectory {
                        fd: current_fd,
                        identity: current_identity,
                    };

                    let child_dir = temp_dir.open_child_dir(c_str, options)?;

                    current_fd = child_dir.duplicate_fd()?;
                    current_identity = child_dir.identity;
                }
                Component::CurDir => continue,
                Component::ParentDir => {
                    return Err(ResolutionError::InvalidComponent(
                        "Parent directory traversal ('..') is prohibited beneath pinned root"
                            .into(),
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(ResolutionError::InvalidComponent(
                        "Root or prefix component is prohibited in relative resolution".into(),
                    ));
                }
            }
        }

        Ok(Self {
            fd: current_fd,
            identity: current_identity,
        })
    }

    /// Internal helper executing `openat2` for child directory opening.
    fn openat2_child_dir(
        &self,
        c_name: &CString,
        allow_mount_crossing: bool,
        name_str: &str,
    ) -> Result<RawFd, ResolutionError> {
        let mut resolve = RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;
        if !allow_mount_crossing {
            resolve |= RESOLVE_NO_XDEV;
        }

        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve,
        };

        let res = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.fd,
                c_name.as_ptr(),
                &how as *const OpenHow as *const libc::c_void,
                std::mem::size_of::<OpenHow>(),
            )
        };

        if res >= 0 {
            Ok(res as RawFd)
        } else {
            let err = std::io::Error::last_os_error();
            Err(map_os_error(err, name_str.to_string()))
        }
    }

    /// Internal helper executing defensive `openat` fallback for child directory opening.
    fn fallback_child_dir(
        &self,
        c_name: &CString,
        name_str: &str,
    ) -> Result<RawFd, ResolutionError> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let res = unsafe { libc::openat(self.fd, c_name.as_ptr(), flags) };

        if res >= 0 {
            Ok(res)
        } else {
            let err = std::io::Error::last_os_error();
            Err(map_os_error(err, name_str.to_string()))
        }
    }

    /// Duplicates the current file descriptor with `O_CLOEXEC`.
    fn duplicate_fd(&self) -> Result<RawFd, ResolutionError> {
        let new_fd = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 0) };
        if new_fd < 0 {
            let err = std::io::Error::last_os_error();
            Err(ResolutionError::Io { source: err })
        } else {
            Ok(new_fd)
        }
    }
}

/// Validates that a string is strictly a single filename component.
fn validate_single_component(name: &str) -> Result<(), ResolutionError> {
    if name.is_empty() {
        return Err(ResolutionError::InvalidComponent(
            "Component name cannot be empty".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(ResolutionError::InvalidComponent(format!(
            "Special component '{}' is prohibited",
            name
        )));
    }
    if name.contains('/') {
        return Err(ResolutionError::InvalidComponent(
            "Path separators ('/') are prohibited in single-component operations".into(),
        ));
    }
    Ok(())
}

/// Translates raw OS error numbers into structured `ResolutionError` variants.
fn map_os_error(err: std::io::Error, name: String) -> ResolutionError {
    match err.raw_os_error() {
        Some(libc::ELOOP) => ResolutionError::SymlinkRejected(name),
        Some(libc::ENOTDIR) => ResolutionError::NotADirectory(name),
        Some(libc::EACCES) | Some(libc::EPERM) => ResolutionError::PermissionDenied(name),
        Some(libc::ENOENT) => ResolutionError::NotFound(name),
        Some(libc::EXDEV) => ResolutionError::MountBoundaryCrossed {
            parent_dev: 0,
            child_dev: 0,
        },
        Some(libc::ENOSYS) => ResolutionError::UnsupportedCapability("openat2"),
        _ => ResolutionError::Io { source: err },
    }
}
