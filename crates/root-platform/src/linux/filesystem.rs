use root_core::{
    error::{Result, RootError},
    model::{FileType, ResourceMetadata, StorageMeasurement},
};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::traits::FilesystemProvider;

#[derive(Debug, Default, Clone)]
pub struct LinuxFilesystem;

impl LinuxFilesystem {
    pub fn new() -> Self {
        Self
    }
}

impl FilesystemProvider for LinuxFilesystem {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        let meta = fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let file_type = {
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
        };

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
