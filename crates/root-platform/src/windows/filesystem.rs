//! Windows read-only filesystem inspection.
//!
//! Every node is inspected through a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so the
//! link itself, never its target, is examined. Any reparse point (symlink, junction, mount point,
//! cloud placeholder) is recorded and not descended into. `ctime` has no standard-library
//! equivalent on Windows; the creation time is substituted. POSIX permission bits do not exist;
//! `permissions_mode` is 0.

use root_core::{
    error::{Result, RootError},
    model::{
        is_filesystem_root, pseudo_filesystem_prefix, FileIdentity, FileType, FilesystemUsage,
        PlatformKind, ResourceMetadata, StorageMeasurement,
    },
};
use std::{
    fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};
use windows_sys::Win32::{
    Foundation::GetLastError,
    Storage::FileSystem::{
        CreateFileW, FileIdInfo, GetCompressedFileSizeW, GetDiskFreeSpaceExW,
        GetFileInformationByHandle, GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

use super::{
    parse::{identity_from_basic_info, identity_from_id_info},
    wide::{path_to_wide, OwnedHandle},
};
use crate::{
    traits::FilesystemProvider,
    traversal::{traverse_tree, NodeInfo, NodeProbe, TraversalOptions, TraversalOutcome},
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const INVALID_FILE_SIZE: u32 = 0xFFFF_FFFF;
const NO_ERROR: u32 = 0;

fn epoch_secs(t: io::Result<SystemTime>) -> i64 {
    t.ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct HandleInfo {
    identity: FileIdentity,
    link_count: u64,
}

/// Opens `path` without following reparse points and reads identity and link count.
fn handle_info(path: &Path) -> io::Result<HandleInfo> {
    let wide = path_to_wide(path);
    let handle = OwnedHandle(unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    });
    if !handle.is_valid() {
        return Err(io::Error::last_os_error());
    }

    let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut basic) } == 0 {
        return Err(io::Error::last_os_error());
    }

    // Prefer the 128-bit id (ReFS); fall back to the 64-bit index where `FileIdInfo` is rejected.
    let mut id_info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileIdInfo,
            &mut id_info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0;
    let identity = if ok {
        identity_from_id_info(id_info.VolumeSerialNumber, id_info.FileId.Identifier)
    } else {
        identity_from_basic_info(
            basic.dwVolumeSerialNumber,
            basic.nFileIndexHigh,
            basic.nFileIndexLow,
        )
    };
    Ok(HandleInfo {
        identity,
        link_count: basic.nNumberOfLinks as u64,
    })
}

/// Allocated size for compressed or sparse files; `None` when the call fails.
fn compressed_size(path: &Path) -> Option<u64> {
    let wide = path_to_wide(path);
    let mut high: u32 = 0;
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    if low == INVALID_FILE_SIZE && unsafe { GetLastError() } != NO_ERROR {
        return None;
    }
    Some(((high as u64) << 32) | low as u64)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProbe;

impl NodeProbe for WindowsProbe {
    fn probe(&self, path: &Path) -> io::Result<NodeInfo> {
        let meta = fs::symlink_metadata(path)?;
        let attrs = meta.file_attributes();
        let is_reparse = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_sparse = attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0;

        let info = handle_info(path)?;
        let size = if is_dir { 0 } else { meta.len() };
        // GetCompressedFileSizeW follows reparse points, so it is skipped for them.
        let allocated = if is_dir || is_reparse {
            size
        } else {
            compressed_size(path).unwrap_or(size)
        };

        let file_type = if meta.file_type().is_symlink() {
            FileType::Symlink
        } else if is_dir {
            FileType::Directory
        } else if meta.file_type().is_file() {
            FileType::RegularFile
        } else {
            FileType::Unknown
        };

        let mut storage =
            StorageMeasurement::from_raw(size, allocated.div_ceil(512), info.link_count.max(1));
        // Attribute-reported sparseness is authoritative even when allocation equals length.
        storage.is_sparse = storage.is_sparse || is_sparse;

        Ok(NodeInfo {
            metadata: ResourceMetadata {
                file_type,
                storage,
                permissions_mode: 0,
                mtime_epoch_secs: epoch_secs(meta.modified()),
                atime_epoch_secs: epoch_secs(meta.accessed()),
                ctime_epoch_secs: epoch_secs(meta.created()),
            },
            identity: info.identity,
            is_dir,
            is_link_like: is_reparse,
            is_reparse_point: is_reparse,
            uid: 0,
            gid: 0,
        })
    }

    fn is_pseudo_filesystem(&self, path: &Path) -> bool {
        pseudo_filesystem_prefix(PlatformKind::Windows, &path.to_string_lossy()).is_some()
    }

    fn validate_root(&self, root: &Path) -> Result<()> {
        let text = root.to_string_lossy();
        if is_filesystem_root(PlatformKind::Windows, &text) {
            return Err(RootError::InvalidPath(
                "Refusing to scan a drive root directly; specify a bounded development directory"
                    .to_string(),
            ));
        }
        if self.is_pseudo_filesystem(root) {
            return Err(RootError::InvalidPath(format!(
                "Refusing to scan device namespace path '{}'",
                root.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct WindowsFilesystem;

impl WindowsFilesystem {
    pub fn new() -> Self {
        Self
    }

    pub fn traverse(
        &self,
        root_path: &Path,
        options: &TraversalOptions,
    ) -> Result<TraversalOutcome> {
        traverse_tree(&WindowsProbe, root_path, options)
    }
}

fn io_err(path: &Path, e: io::Error) -> RootError {
    RootError::Io {
        path: path.to_path_buf(),
        source: e,
    }
}

impl FilesystemProvider for WindowsFilesystem {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        WindowsProbe
            .probe(path)
            .map(|n| n.metadata)
            .map_err(|e| io_err(path, e))
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        fs::canonicalize(path).map_err(|e| io_err(path, e))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| io_err(path, e))? {
            paths.push(entry.map_err(|e| io_err(path, e))?.path());
        }
        paths.sort();
        Ok(paths)
    }

    fn get_device_id(&self, path: &Path) -> Result<u64> {
        Ok(self.get_file_identity(path)?.volume)
    }

    fn get_inode(&self, path: &Path) -> Result<u64> {
        Ok(self.get_file_identity(path)?.object_low64())
    }

    fn get_file_identity(&self, path: &Path) -> Result<FileIdentity> {
        handle_info(path)
            .map(|h| h.identity)
            .map_err(|e| io_err(path, e))
    }

    fn get_filesystem_usage(&self, path: &Path) -> Result<FilesystemUsage> {
        let wide = path_to_wide(path);
        let (mut available, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free) } == 0
        {
            return Err(io_err(path, io::Error::last_os_error()));
        }
        Ok(FilesystemUsage {
            total_bytes: total,
            free_bytes: free,
            available_bytes: available,
            total_inodes: 0,
            free_inodes: 0,
            inode_accounting_supported: false,
        })
    }
}
