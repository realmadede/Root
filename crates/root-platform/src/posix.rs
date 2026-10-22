//! POSIX filesystem helpers shared by Linux and macOS.

use root_core::{
    error::{Result, RootError},
    model::{
        FileIdentity, FileType, FilesystemUsage, PlatformKind, ResourceMetadata, StorageMeasurement,
    },
};
use std::{
    ffi::CString,
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
};

use crate::traversal::{NodeInfo, NodeProbe};

/// Maps a POSIX file type without bit-masking `st_mode` by hand.
pub fn posix_file_type(meta: &fs::Metadata) -> FileType {
    let ft = meta.file_type();
    if ft.is_file() {
        FileType::RegularFile
    } else if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else if ft.is_fifo() {
        FileType::Fifo
    } else if ft.is_socket() {
        FileType::Socket
    } else if ft.is_block_device() {
        FileType::BlockDevice
    } else if ft.is_char_device() {
        FileType::CharacterDevice
    } else {
        FileType::Unknown
    }
}

/// Builds `ResourceMetadata` from an `lstat` result.
///
/// `allocated_bytes` is derived from `st_blocks` (512-byte units on every supported POSIX
/// platform). On APFS this is allocation as reported by the filesystem; it does not describe
/// clone or snapshot sharing.
pub fn posix_resource_metadata(meta: &fs::Metadata) -> ResourceMetadata {
    ResourceMetadata {
        file_type: posix_file_type(meta),
        storage: StorageMeasurement::from_raw(meta.size(), meta.blocks(), meta.nlink()),
        permissions_mode: meta.mode(),
        mtime_epoch_secs: meta.mtime(),
        atime_epoch_secs: meta.atime(),
        ctime_epoch_secs: meta.ctime(),
    }
}

/// Probe implementing `lstat`-based inspection for Linux and macOS.
#[derive(Debug, Clone, Copy)]
pub struct PosixProbe {
    pub platform: PlatformKind,
}

impl NodeProbe for PosixProbe {
    fn probe(&self, path: &Path) -> io::Result<NodeInfo> {
        let meta = fs::symlink_metadata(path)?;
        Ok(NodeInfo {
            metadata: posix_resource_metadata(&meta),
            identity: FileIdentity::posix(meta.dev(), meta.ino()),
            is_dir: meta.is_dir(),
            is_link_like: meta.file_type().is_symlink(),
            is_reparse_point: false,
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    fn is_pseudo_filesystem(&self, path: &Path) -> bool {
        root_core::model::pseudo_filesystem_prefix(self.platform, &path.to_string_lossy()).is_some()
    }

    fn validate_root(&self, root: &Path) -> Result<()> {
        if root_core::model::is_filesystem_root(self.platform, &root.to_string_lossy()) {
            return Err(RootError::InvalidPath(
                "Refusing to scan host root directory ('/') directly; specify a bounded development directory"
                    .to_string(),
            ));
        }
        if self.is_pseudo_filesystem(root) {
            return Err(RootError::InvalidPath(format!(
                "Refusing to scan pseudo-filesystem path '{}'",
                root.display()
            )));
        }
        Ok(())
    }
}

/// `lstat`-style metadata for a path.
pub fn posix_symlink_metadata(path: &Path) -> Result<ResourceMetadata> {
    let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(posix_resource_metadata(&meta))
}

/// Filesystem capacity through `statvfs`.
pub fn posix_filesystem_usage(path: &Path) -> Result<FilesystemUsage> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| RootError::InvalidPath(e.to_string()))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return Err(RootError::Io {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }

    let bsize = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };

    Ok(FilesystemUsage {
        total_bytes: stat.f_blocks as u64 * bsize,
        free_bytes: stat.f_bfree as u64 * bsize,
        available_bytes: stat.f_bavail as u64 * bsize,
        total_inodes: stat.f_files as u64,
        free_inodes: stat.f_ffree as u64,
        inode_accounting_supported: true,
    })
}
