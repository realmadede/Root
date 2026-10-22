//! Cross-platform non-blocking advisory lock.
//!
//! Maps to `flock(LOCK_EX | LOCK_NB)` on POSIX systems (Linux, macOS) and `LockFileEx` with
//! `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY` on Windows. The lock is tied to the open
//! file: it is released when the guard is dropped or the process exits. The lock file itself is
//! never deleted to release a lock, because deleting it would let a second process lock a different inode.

use root_core::error::{Result, RootError};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

/// Outcome of a non-blocking lock attempt.
#[derive(Debug)]
pub enum LockStatus {
    Acquired(LockGuard),
    /// Another holder owns the lock.
    Contended,
}

/// Holds the lock for as long as it lives.
#[derive(Debug)]
pub struct LockGuard {
    file: File,
    path: PathBuf,
}

impl LockGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

pub struct AdvisoryLock;

impl AdvisoryLock {
    /// Opens (creating if needed, owner-only on POSIX) and tries to lock `path` exclusively.
    pub fn try_acquire(path: &Path) -> Result<LockStatus> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let file = options.open(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        match try_lock_file(&file) {
            Ok(true) => Ok(LockStatus::Acquired(LockGuard {
                file,
                path: path.to_path_buf(),
            })),
            Ok(false) => Ok(LockStatus::Contended),
            Err(e) => Err(RootError::Io {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }
}

#[cfg(unix)]
fn try_lock_file(file: &File) -> io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::unix::io::AsRawFd;
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(windows)]
fn try_lock_file(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };

    let handle = file.as_raw_handle() as isize;
    let mut overlapped = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ret != 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;

    let handle = file.as_raw_handle() as isize;
    let mut overlapped = unsafe { std::mem::zeroed() };
    let _ = unsafe { UnlockFileEx(handle, 0, 1, 0, &mut overlapped) };
}

#[cfg(not(any(unix, windows)))]
fn try_lock_file(_file: &File) -> io::Result<bool> {
    Ok(true)
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &File) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquisition_is_contended_until_guard_drops() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.lock");

        let first = match AdvisoryLock::try_acquire(&path).unwrap() {
            LockStatus::Acquired(g) => g,
            LockStatus::Contended => panic!("first should succeed"),
        };

        match AdvisoryLock::try_acquire(&path).unwrap() {
            LockStatus::Contended => {}
            LockStatus::Acquired(_) => panic!("second must be contended while first lives"),
        }

        drop(first);

        match AdvisoryLock::try_acquire(&path).unwrap() {
            LockStatus::Acquired(_g) => {}
            LockStatus::Contended => panic!("acquisition must succeed after drop"),
        }
    }
}
