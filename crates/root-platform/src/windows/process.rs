//! Windows read-only process inspection.
//!
//! Processes are enumerated with a Toolhelp snapshot and inspected with
//! `PROCESS_QUERY_LIMITED_INFORMATION`, which works without elevation for the user's own
//! processes. A process that cannot be opened, or that has exited, yields `Ok(None)`. Command
//! lines and environments are never read. Identity is the creation time, so a reused PID is
//! detected by a changed `start_time_ticks`.

use root_core::{
    error::{Result, RootError},
    model::{MemoryMeasurement, ProcessCandidate, ProcessIdentity, ProcessState},
};
use std::path::PathBuf;
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        },
        Threading::{
            GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::{
    parse::{filetime_from_parts, is_reserved_pid, wide_to_string},
    wide::OwnedHandle,
};
use crate::traits::ProcessProvider;

const STILL_ACTIVE: u32 = 259;

#[derive(Debug, Default, Clone)]
pub struct WindowsProcess;

struct SnapshotEntry {
    pid: u32,
    ppid: u32,
    name: String,
}

impl WindowsProcess {
    pub fn new() -> Self {
        Self
    }

    fn snapshot() -> Result<Vec<SnapshotEntry>> {
        let snap = OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) });
        if !snap.is_valid() {
            return Err(RootError::Platform(format!(
                "CreateToolhelp32Snapshot failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) } != 0;
        while ok {
            out.push(SnapshotEntry {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                name: wide_to_string(&entry.szExeFile),
            });
            ok = unsafe { Process32NextW(snap.0, &mut entry) } != 0;
        }
        Ok(out)
    }

    fn open(pid: u32) -> Option<OwnedHandle> {
        let h = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        h.is_valid().then_some(h)
    }

    fn creation_ticks(handle: &OwnedHandle) -> Option<u64> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok =
            unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) }
                != 0;
        ok.then(|| filetime_from_parts(creation.dwHighDateTime, creation.dwLowDateTime))
    }

    fn still_running(handle: &OwnedHandle) -> bool {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(handle.0, &mut code) != 0 && code == STILL_ACTIVE }
    }

    fn image_path(handle: &OwnedHandle) -> Option<PathBuf> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok =
            unsafe { QueryFullProcessImageNameW(handle.0, 0, buf.as_mut_ptr(), &mut len) } != 0;
        ok.then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }

    fn working_set(handle: &OwnedHandle) -> Option<u64> {
        let mut counters: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let ok = unsafe {
            K32GetProcessMemoryInfo(
                handle.0,
                &mut counters as *mut _ as *mut PROCESS_MEMORY_COUNTERS,
                counters.cb,
            )
        } != 0;
        ok.then_some(counters.WorkingSetSize as u64)
    }
}

impl ProcessProvider for WindowsProcess {
    fn list_pids(&self) -> Result<Vec<u32>> {
        let mut pids: Vec<u32> = Self::snapshot()?
            .into_iter()
            .map(|e| e.pid)
            .filter(|p| !is_reserved_pid(*p))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    /// Working set only. A private-working-set figure is not a USS equivalent and per-process
    /// swap is not reported, so those fields are `None`.
    fn get_process_memory(&self, pid: u32) -> Result<Option<MemoryMeasurement>> {
        let Some(handle) = Self::open(pid) else {
            return Ok(None);
        };
        Ok(Self::working_set(&handle).map(|rss| MemoryMeasurement::new(rss, None, None, None)))
    }

    fn inspect_process(&self, pid: u32) -> Result<Option<ProcessCandidate>> {
        if is_reserved_pid(pid) {
            return Ok(None);
        }
        let Some(handle) = Self::open(pid) else {
            return Ok(None); // access denied or gone
        };
        if !Self::still_running(&handle) {
            return Ok(None);
        }
        let Some(start_time_ticks) = Self::creation_ticks(&handle) else {
            return Ok(None);
        };
        let (ppid, name) = Self::snapshot()?
            .into_iter()
            .find(|e| e.pid == pid)
            .map(|e| (e.ppid, e.name))
            .unwrap_or((0, String::new()));
        let rss = Self::working_set(&handle).unwrap_or(0);

        Ok(Some(ProcessCandidate {
            identity: ProcessIdentity {
                pid,
                ppid,
                // No POSIX uid; see `WindowsEnvironment`.
                real_uid: 0,
                name,
                executable: Self::image_path(&handle),
                cmdline: Vec::new(),
                start_time_ticks,
                tty_nr: 0,
            },
            // Windows exposes no run/sleep state comparable to POSIX.
            state: ProcessState::Unknown,
            memory: MemoryMeasurement::new(rss, None, None, None),
            is_reparented_to_init: false,
            is_abandoned: false,
            associated_agent: None,
        }))
    }
}
