//! Cross-platform desktop notification dispatcher and privacy-safe fingerprinting.

use root_core::{error::Result, model::ScheduleRunStatus};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// Desktop notification dispatcher.
pub struct DesktopNotifier;

impl DesktopNotifier {
    /// Computes a privacy-safe cryptographic fingerprint of aggregate inspection findings.
    ///
    /// Uses only summary counters and status; never incorporates file paths or names.
    pub fn compute_fingerprint(
        status: ScheduleRunStatus,
        total_inspected: u64,
        total_findings: usize,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let payload = format!(
            "{}:{}:{}",
            status.display_badge(),
            total_inspected,
            total_findings
        );
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Dispatches a notification to the local desktop notification service.
    #[cfg(target_os = "linux")]
    pub fn dispatch(title: &str, body: &str, urgency: &str) -> Result<bool> {
        let clean_title = title.replace('\n', " ").replace('\r', "");
        let clean_body = body.replace('\r', "");

        let res = Command::new("notify-send")
            .arg("-a")
            .arg("Root")
            .arg("-u")
            .arg(urgency)
            .arg(&clean_title)
            .arg(&clean_body)
            .status();

        match res {
            Ok(status) if status.success() => Ok(true),
            _ => Self::dispatch_dbus(&clean_title, &clean_body),
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_dbus(title: &str, body: &str) -> Result<bool> {
        let res = Command::new("dbus-send")
            .arg("--session")
            .arg("--dest=org.freedesktop.Notifications")
            .arg("--type=method_call")
            .arg("/org/freedesktop/Notifications")
            .arg("org.freedesktop.Notifications.Notify")
            .arg("string:Root")
            .arg("uint32:0")
            .arg("string:")
            .arg(format!("string:{}", title))
            .arg(format!("string:{}", body))
            .arg("array:string:")
            .arg("dict:string:variant:")
            .arg("int32:5000")
            .status();

        match res {
            Ok(status) if status.success() => Ok(true),
            _ => Ok(false),
        }
    }

    #[cfg(target_os = "macos")]
    pub fn dispatch(title: &str, body: &str, _urgency: &str) -> Result<bool> {
        let clean_title = title.replace('"', "\\\"").replace('\n', " ");
        let clean_body = body.replace('"', "\\\"").replace('\n', " ");
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            clean_body, clean_title
        );
        let res = Command::new("osascript").arg("-e").arg(&script).status();
        match res {
            Ok(status) if status.success() => Ok(true),
            _ => Ok(false),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn dispatch(_title: &str, _body: &str, _urgency: &str) -> Result<bool> {
        Ok(false)
    }
}
