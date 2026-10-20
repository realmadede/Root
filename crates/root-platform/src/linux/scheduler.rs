use root_core::{
    error::{Result, RootError},
    model::ScheduleInterval,
};
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

/// Utility for generating security-hardened systemd user service and timer units.
pub struct SystemdUnitGenerator;

impl SystemdUnitGenerator {
    /// Generates the contents of `root-inspect.service`.
    ///
    /// Hardened with `NoNewPrivileges=true`, `Nice=19`, `IOSchedulingClass=idle`,
    /// and strict non-shell command execution.
    pub fn generate_service_unit(exec_path: &Path, additional_args: &[&str]) -> String {
        let exec_str = exec_path.to_string_lossy();
        let args_str = if additional_args.is_empty() {
            String::new()
        } else {
            format!(" {}", additional_args.join(" "))
        };

        format!(
            "[Unit]\n\
             Description=Root System Resource Inspection (Mode B Scheduled)\n\
             Documentation=https://github.com/realmadede/Root\n\
             ConditionPathExists={}\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart={}{}\n\
             Nice=19\n\
             IOSchedulingClass=idle\n\
             IOSchedulingPriority=7\n\
             TimeoutSec=120\n\
             NoNewPrivileges=true\n",
            exec_str, exec_str, args_str
        )
    }

    /// Generates the contents of `root-inspect.timer`.
    pub fn generate_timer_unit(interval: &ScheduleInterval) -> Result<String> {
        let on_calendar = interval.to_calendar_spec()?;

        Ok(format!(
            "[Unit]\n\
             Description=Root Scheduled Resource Inspection Timer\n\
             Documentation=https://github.com/realmadede/Root\n\
             \n\
             [Timer]\n\
             OnCalendar={}\n\
             Persistent=true\n\
             RandomizedDelaySec=15m\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            on_calendar
        ))
    }
}

/// Linux systemd user-level scheduler controller.
#[derive(Debug, Clone)]
pub struct LinuxScheduler {
    custom_unit_dir: Option<PathBuf>,
}

impl Default for LinuxScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxScheduler {
    pub fn new() -> Self {
        Self {
            custom_unit_dir: None,
        }
    }

    /// Creates a scheduler instance pointing to a custom unit directory (used for testing).
    pub fn with_unit_dir(unit_dir: impl Into<PathBuf>) -> Self {
        Self {
            custom_unit_dir: Some(unit_dir.into()),
        }
    }

    /// Resolves the systemd user unit directory (`$XDG_CONFIG_HOME/systemd/user`).
    pub fn unit_dir(&self) -> PathBuf {
        if let Some(ref custom) = self.custom_unit_dir {
            return custom.clone();
        }

        if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(config_home).join("systemd").join("user")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
                .join(".config")
                .join("systemd")
                .join("user")
        } else {
            PathBuf::from("/tmp/root_systemd_user")
        }
    }

    pub fn service_unit_path(&self) -> PathBuf {
        self.unit_dir().join("root-inspect.service")
    }

    pub fn timer_unit_path(&self) -> PathBuf {
        self.unit_dir().join("root-inspect.timer")
    }

    /// Installs systemd user service and timer unit files with restrictive permissions.
    pub fn install_units(&self, exec_path: &Path, interval: &ScheduleInterval) -> Result<()> {
        let dir = self.unit_dir();
        fs::create_dir_all(&dir).map_err(|e| RootError::Io {
            path: dir.clone(),
            source: e,
        })?;

        let service_content =
            SystemdUnitGenerator::generate_service_unit(exec_path, &["schedule", "run"]);
        let timer_content = SystemdUnitGenerator::generate_timer_unit(interval)?;

        let service_path = self.service_unit_path();
        let timer_path = self.timer_unit_path();

        fs::write(&service_path, service_content).map_err(|e| RootError::Io {
            path: service_path.clone(),
            source: e,
        })?;
        fs::set_permissions(&service_path, Permissions::from_mode(0o644)).map_err(|e| {
            RootError::Io {
                path: service_path,
                source: e,
            }
        })?;

        fs::write(&timer_path, timer_content).map_err(|e| RootError::Io {
            path: timer_path.clone(),
            source: e,
        })?;
        fs::set_permissions(&timer_path, Permissions::from_mode(0o644)).map_err(|e| {
            RootError::Io {
                path: timer_path,
                source: e,
            }
        })?;

        Ok(())
    }

    /// Uninstalls systemd user unit files if present.
    pub fn uninstall_units(&self) -> Result<()> {
        let service_path = self.service_unit_path();
        if service_path.exists() {
            let _ = fs::remove_file(&service_path);
        }

        let timer_path = self.timer_unit_path();
        if timer_path.exists() {
            let _ = fs::remove_file(&timer_path);
        }

        Ok(())
    }

    /// Checks whether the systemd user manager is active and reachable.
    pub fn is_systemd_user_available(&self) -> bool {
        // If pointing to a mock/custom unit dir, simulate based on presence
        if self.custom_unit_dir.is_some() {
            return true;
        }

        Command::new("systemctl")
            .arg("--user")
            .arg("is-system-running")
            .output()
            .map(|out| out.status.success() || !out.stdout.is_empty())
            .unwrap_or(false)
    }

    /// Reloads systemd user daemon and enables the timer unit.
    pub fn enable_timer(&self) -> Result<()> {
        if self.custom_unit_dir.is_some() {
            return Ok(());
        }

        let reload = Command::new("systemctl")
            .arg("--user")
            .arg("daemon-reload")
            .status()
            .map_err(|e| {
                RootError::ScheduleError(format!("systemctl daemon-reload failed: {}", e))
            })?;

        if !reload.success() {
            return Err(RootError::ScheduleError(
                "Failed to reload systemd user daemon".to_string(),
            ));
        }

        let enable = Command::new("systemctl")
            .arg("--user")
            .arg("enable")
            .arg("--now")
            .arg("root-inspect.timer")
            .status()
            .map_err(|e| {
                RootError::ScheduleError(format!("systemctl enable timer failed: {}", e))
            })?;

        if !enable.success() {
            return Err(RootError::ScheduleError(
                "Failed to enable root-inspect.timer via systemctl --user".to_string(),
            ));
        }

        Ok(())
    }

    /// Stops and disables the timer unit.
    pub fn disable_timer(&self) -> Result<()> {
        if self.custom_unit_dir.is_some() {
            return Ok(());
        }

        let _ = Command::new("systemctl")
            .arg("--user")
            .arg("stop")
            .arg("root-inspect.timer")
            .status();

        let _ = Command::new("systemctl")
            .arg("--user")
            .arg("disable")
            .arg("root-inspect.timer")
            .status();

        let _ = Command::new("systemctl")
            .arg("--user")
            .arg("daemon-reload")
            .status();

        Ok(())
    }

    /// Checks if `root-inspect.timer` is actively running.
    pub fn is_timer_active(&self) -> bool {
        if self.custom_unit_dir.is_some() {
            return self.timer_unit_path().exists();
        }

        Command::new("systemctl")
            .arg("--user")
            .arg("is-active")
            .arg("--quiet")
            .arg("root-inspect.timer")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Queries the next scheduled trigger timestamp for `root-inspect.timer`.
    pub fn query_next_trigger(&self) -> Option<String> {
        if self.custom_unit_dir.is_some() {
            return None;
        }

        let output = Command::new("systemctl")
            .arg("--user")
            .arg("list-timers")
            .arg("root-inspect.timer")
            .arg("--no-legend")
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Output format: NEXT LEFT LAST PASSED UNIT ACTIVATES
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4 {
            Some(format!("{} {}", parts[0], parts[1]))
        } else {
            Some(trimmed.to_string())
        }
    }
}

/// Linux desktop notification dispatcher utilizing FreeDesktop mechanisms (`notify-send` or D-Bus).
pub struct DesktopNotifier;

impl DesktopNotifier {
    /// Dispatches a notification to the local desktop notification service.
    ///
    /// Handled gracefully: if the desktop notification daemon is not available,
    /// returns `Ok(false)` rather than failing the scan.
    pub fn dispatch(title: &str, body: &str, urgency: &str) -> Result<bool> {
        // 1. Sanitize text inputs
        let clean_title = title.replace('\n', " ").replace('\r', "");
        let clean_body = body.replace('\r', "");

        // 2. Try notify-send command
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
            _ => {
                // Try dbus-send fallback if notify-send failed or missing
                Self::dispatch_dbus(&clean_title, &clean_body)
            }
        }
    }

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
            _ => Ok(false), // Desktop notification daemon unavailable; non-fatal
        }
    }
}
