//! Read-only Darwin process inspection through `libproc`.
//!
//! Only unprivileged, public interfaces are used. Command-line arguments and environments are not
//! read (they require `KERN_PROCARGS2` and expose secrets); `cmdline` is therefore empty.
//! Processes that exit or deny access between enumeration and inspection yield `Ok(None)`.

use root_core::{
    error::{Result, RootError},
    model::{MemoryMeasurement, ProcessCandidate, ProcessIdentity, ProcessState},
};
use std::{ffi::c_void, mem, path::PathBuf};

use super::parse::{
    fixed_buffer_to_string, process_state_from_bsd_status, start_ticks_from_timeval,
};
use crate::traits::ProcessProvider;

/// `PROC_ALL_PIDS` from `<libproc.h>`; the constant is not exported by the `libc` crate.
const PROC_ALL_PIDS: u32 = 1;

#[derive(Debug, Default, Clone)]
pub struct MacProcess;

impl MacProcess {
    pub fn new() -> Self {
        Self
    }

    fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut c_void,
                size,
            )
        };
        // A short or failed read means the process exited or access was denied.
        if written == size {
            Some(info)
        } else {
            None
        }
    }

    fn task_info(pid: u32) -> Option<libc::proc_taskinfo> {
        let mut info: libc::proc_taskinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut c_void,
                size,
            )
        };
        if written == size {
            Some(info)
        } else {
            None
        }
    }

    fn executable_path(pid: u32) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
            )
        };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(PathBuf::from(String::from_utf8_lossy(&buf).to_string()))
    }
}

impl ProcessProvider for MacProcess {
    fn list_pids(&self) -> Result<Vec<u32>> {
        let needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
        if needed <= 0 {
            return Err(RootError::Platform(
                "proc_listpids could not size the process table".to_string(),
            ));
        }
        // Headroom for processes spawned between the sizing call and the listing call.
        let capacity = needed as usize / mem::size_of::<libc::c_int>() + 64;
        let mut pids = vec![0 as libc::c_int; capacity];
        let written = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr() as *mut c_void,
                (pids.len() * mem::size_of::<libc::c_int>()) as libc::c_int,
            )
        };
        if written <= 0 {
            return Err(RootError::Platform(
                "proc_listpids failed to list processes".to_string(),
            ));
        }
        pids.truncate(written as usize / mem::size_of::<libc::c_int>());
        let mut out: Vec<u32> = pids
            .into_iter()
            .filter(|p| *p > 0)
            .map(|p| p as u32)
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// RSS only. PSS and USS have no unprivileged Darwin equivalent and per-process swap is not
    /// reported, so those fields are `None` rather than zero.
    fn get_process_memory(&self, pid: u32) -> Result<Option<MemoryMeasurement>> {
        Ok(Self::task_info(pid)
            .map(|t| MemoryMeasurement::new(t.pti_resident_size, None, None, None)))
    }

    fn inspect_process(&self, pid: u32) -> Result<Option<ProcessCandidate>> {
        let Some(bsd) = Self::bsd_info(pid) else {
            return Ok(None);
        };
        let comm_bytes: Vec<u8> = bsd.pbi_comm.iter().map(|c| *c as u8).collect();
        let name = fixed_buffer_to_string(&comm_bytes);
        let state = process_state_from_bsd_status(bsd.pbi_status);
        let memory = self
            .get_process_memory(pid)?
            .unwrap_or_else(|| MemoryMeasurement::new(0, None, None, None));

        let identity = ProcessIdentity {
            pid: bsd.pbi_pid,
            ppid: bsd.pbi_ppid,
            real_uid: bsd.pbi_ruid,
            name,
            executable: Self::executable_path(pid),
            cmdline: Vec::new(),
            start_time_ticks: start_ticks_from_timeval(bsd.pbi_start_tvsec, bsd.pbi_start_tvusec),
            // `e_tdev` is the controlling terminal device; (dev_t)-1 / 0 mean none.
            tty_nr: if bsd.e_tdev == 0 || bsd.e_tdev == u32::MAX {
                0
            } else {
                bsd.e_tdev as i32
            },
        };

        // Abandonment requires corroborating evidence beyond PPID 1 (launchd adopts orphans).
        let is_reparented_to_init = identity.ppid == 1;
        let is_abandoned = false;

        Ok(Some(ProcessCandidate {
            identity,
            state: if state == ProcessState::Unknown {
                ProcessState::Unknown
            } else {
                state
            },
            memory,
            is_reparented_to_init,
            is_abandoned,
            associated_agent: None,
        }))
    }
}
