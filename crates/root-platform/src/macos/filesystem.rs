use root_core::{
    error::{Result, RootError},
    model::{FileIdentity, FilesystemUsage, PlatformKind, ResourceMetadata},
};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::{
    posix::{posix_filesystem_usage, posix_symlink_metadata, PosixProbe},
    traits::FilesystemProvider,
    traversal::{traverse_tree, TraversalOptions, TraversalOutcome},
};

const MAC_PROBE: PosixProbe = PosixProbe {
    platform: PlatformKind::MacOs,
};

/// macOS read-only filesystem inspection.
///
/// `allocated_bytes` reflects `st_blocks`. On APFS, clones (`clonefile`) and snapshots share
/// extents, so allocated bytes are not a measure of reclaimable space and must not be presented
/// as one. Identity is `st_dev` + `st_ino`, valid within one observation session only.
#[derive(Debug, Default, Clone)]
pub struct MacFilesystem;

impl MacFilesystem {
    pub fn new() -> Self {
        Self
    }

    pub fn traverse(
        &self,
        root_path: &Path,
        options: &TraversalOptions,
    ) -> Result<TraversalOutcome> {
        traverse_tree(&MAC_PROBE, root_path, options)
    }
}

fn io_err(path: &Path, e: std::io::Error) -> RootError {
    RootError::Io {
        path: path.to_path_buf(),
        source: e,
    }
}

impl FilesystemProvider for MacFilesystem {
    fn symlink_metadata(&self, path: &Path) -> Result<ResourceMetadata> {
        posix_symlink_metadata(path)
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
        Ok(fs::symlink_metadata(path)
            .map_err(|e| io_err(path, e))?
            .dev())
    }

    fn get_inode(&self, path: &Path) -> Result<u64> {
        Ok(fs::symlink_metadata(path)
            .map_err(|e| io_err(path, e))?
            .ino())
    }

    fn get_file_identity(&self, path: &Path) -> Result<FileIdentity> {
        let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
        Ok(FileIdentity::posix(meta.dev(), meta.ino()))
    }

    fn get_filesystem_usage(&self, path: &Path) -> Result<FilesystemUsage> {
        posix_filesystem_usage(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traversal::SkipReason;

    #[test]
    fn traversal_does_not_follow_symlinks_and_refuses_root_and_dev() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("o.txt"), b"x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();

        let fsys = MacFilesystem::new();
        let out = fsys
            .traverse(dir.path(), &TraversalOptions::default())
            .unwrap();
        assert!(out.metrics.is_complete);
        assert!(out
            .entries
            .iter()
            .all(|e| !e.path.starts_with(outside.path())));
        assert!(out.events.iter().any(|e| matches!(
            e,
            crate::traversal::TraversalEvent::Skipped {
                reason: SkipReason::SymlinkNotFollowed,
                ..
            }
        )));

        assert!(fsys
            .traverse(Path::new("/"), &TraversalOptions::default())
            .is_err());
        assert!(fsys
            .traverse(Path::new("/dev"), &TraversalOptions::default())
            .is_err());
    }

    #[test]
    fn identity_is_posix_pair() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, b"x").unwrap();
        let id = MacFilesystem::new().get_file_identity(&f).unwrap();
        assert_eq!(
            id.object_low64(),
            MacFilesystem::new().get_inode(&f).unwrap()
        );
    }
}
