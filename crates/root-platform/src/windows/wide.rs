//! Small helpers for calling wide-character Win32 APIs.

use root_core::model::{needs_extended_length, to_extended_length_path};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// NUL-terminated UTF-16 for a path, switching to the extended-length form only when the path is
/// long enough to need it. Relative, device, and already-verbatim paths are passed through
/// unchanged; Root never guesses a prefix for them.
pub fn path_to_wide(path: &Path) -> Vec<u16> {
    let text = path.to_string_lossy();
    let effective = if needs_extended_length(&text) {
        to_extended_length_path(&text).unwrap_or_else(|| text.to_string())
    } else {
        text.to_string()
    };
    OsStr::new(&effective)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Closes the wrapped handle on drop.
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
