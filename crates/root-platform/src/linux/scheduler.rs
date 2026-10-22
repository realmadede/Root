use root_core::{
    error::{Result, RootError},
    model::{validate_executable, ScheduleInterval},
};
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

/// Root identifier marker embedded in all Root-managed systemd units.
pub const ROOT_UNIT_MARKER: &str = "Root System Resource Inspection";

/// Utility for generating security-hardened systemd user service and timer units.
pub struct SystemdUnitGenerator;

impl SystemdUnitGenerator {
    /// Generates the contents of `root-inspect.service`.
    ///
    /// Hardened with `NoNewPrivileges=true`, `Nice=19`, `IOSchedulingClass=idle`,
    /// unprivileged user execution, and direct executable invocation.
    pub fn generate_service_unit(
        exec_path: &Path,
        additional_args: &[&str],
        ac_power_only: bool,
    ) -> String {
        let exec_str = exec_path.to_string_lossy();
        let args_str = if additional_args.is_empty() {
            String::new()
        } else {
            format!(" {}", additional_args.join(" "))
        };

        let ac_directive = if ac_power_only {
            "ConditionACPower=true\n"
        } else {
            ""
        };

        format!(
            "# Root System Resource Inspection Service\n\
             [Unit]\n\
             Description=Root System Resource Inspection (Mode B Scheduled)\n\
             Documentation=https://github.com/realmadede/Root\n\
             ConditionPathExists={}\n\
             {}\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart={}{}\n\
             Nice=19\n\
             IOSchedulingClass=idle\n\
             IOSchedulingPriority=7\n\
             TimeoutSec=120\n\
             NoNewPrivileges=true\n",
            exec_str, ac_directive, exec_str, args_str
        )
    }

    /// Generates the contents of `root-inspect.timer`.
    pub fn generate_timer_unit(interval: &ScheduleInterval, catch_up: bool) -> Result<String> {
        let on_calendar = interval.to_calendar_spec()?;
        let persistent_str = if catch_up { "true" } else { "false" };

        Ok(format!(
            "# Root Scheduled Resource Inspection Timer\n\
             [Unit]\n\
             Description=Root Scheduled Resource Inspection Timer\n\
             Documentation=https://github.com/realmadede/Root\n\
             \n\
             [Timer]\n\
             OnCalendar={}\n\
             Persistent={}\n\
             RandomizedDelaySec=15m\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            on_calendar, persistent_str
        ))
    }

    /// Validates unit file syntax and directives before installation.
    pub fn validate_unit_content(content: &str, expected_section: &str) -> Result<()> {
        if content.trim().is_empty() {
            return Err(RootError::ScheduleError(
                "Generated unit file content is empty".to_string(),
            ));
        }

        if !content.contains("[Unit]") || !content.contains(expected_section) {
            return Err(RootError::ScheduleError(format!(
                "Generated unit file missing required [Unit] or {} section",
                expected_section
            )));
        }

        // Prohibit invalid user directives in user services
        if content.contains("User=") || content.contains("User=%h") {
            return Err(RootError::ScheduleError(
                "User directive is illegal in systemd user service units".to_string(),
            ));
        }

        Ok(())
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

    /// Checks if a file exists and was not created by Root (collision protection).
    fn check_collision(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if !content.contains(ROOT_UNIT_MARKER) && !content.contains("realmadede/Root") {
            return Err(RootError::ScheduleError(format!(
                "Collision: existing unit file '{}' was not created by Root; refusing to overwrite unknown file",
                path.display()
            )));
        }

        Ok(())
    }

    /// Installs systemd user service and timer unit files with transactional rollback.
    pub fn install_units_transactional(
        &self,
        exec_path: &Path,
        interval: &ScheduleInterval,
        catch_up: bool,
        ac_power_only: bool,
    ) -> Result<()> {
        // 1. Validate executable path
        let validated_exec = validate_executable(exec_path)?;

        let dir = self.unit_dir();
        fs::create_dir_all(&dir).map_err(|e| RootError::Io {
            path: dir.clone(),
            source: e,
        })?;

        let service_path = self.service_unit_path();
        let timer_path = self.timer_unit_path();

        // 2. Reject collisions with unrelated files
        self.check_collision(&service_path)?;
        self.check_collision(&timer_path)?;

        // 3. Generate unit contents
        let service_content = SystemdUnitGenerator::generate_service_unit(
            &validated_exec,
            &["schedule", "run"],
            ac_power_only,
        );
        let timer_content = SystemdUnitGenerator::generate_timer_unit(interval, catch_up)?;

        // 4. Validate unit contents
        SystemdUnitGenerator::validate_unit_content(&service_content, "[Service]")?;
        SystemdUnitGenerator::validate_unit_content(&timer_content, "[Timer]")?;

        // 5. Staged writes to temporary sibling files
        let service_tmp = service_path.with_extension("tmp");
        let timer_tmp = timer_path.with_extension("tmp");

        fs::write(&service_tmp, service_content).map_err(|e| RootError::Io {
            path: service_tmp.clone(),
            source: e,
        })?;
        let _ = fs::set_permissions(&service_tmp, Permissions::from_mode(0o644));

        fs::write(&timer_tmp, timer_content).map_err(|e| RootError::Io {
            path: timer_tmp.clone(),
            source: e,
        })?;
        let _ = fs::set_permissions(&timer_tmp, Permissions::from_mode(0o644));

        // 6. Transactional swap with rollback on failure
        if let Err(e) = fs::rename(&service_tmp, &service_path) {
            let _ = fs::remove_file(&service_tmp);
            let _ = fs::remove_file(&timer_tmp);
            return Err(RootError::Io {
                path: service_path,
                source: e,
            });
        }

        if let Err(e) = fs::rename(&timer_tmp, &timer_path) {
            // Rollback service file
            let _ = fs::remove_file(&service_path);
            let _ = fs::remove_file(&timer_tmp);
            return Err(RootError::Io {
                path: timer_path,
                source: e,
            });
        }

        // 7. Reload systemd daemon if not in simulated test mode
        if self.custom_unit_dir.is_none() {
            let reload = Command::new("systemctl")
                .arg("--user")
                .arg("daemon-reload")
                .status();

            if let Err(e) = reload {
                // Rollback units
                let _ = fs::remove_file(&service_path);
                let _ = fs::remove_file(&timer_path);
                return Err(RootError::ScheduleError(format!(
                    "systemctl daemon-reload failed: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Backwards-compatible install helper.
    pub fn install_units(&self, exec_path: &Path, interval: &ScheduleInterval) -> Result<()> {
        self.install_units_transactional(exec_path, interval, false, false)
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

        if self.custom_unit_dir.is_none() {
            let _ = Command::new("systemctl")
                .arg("--user")
                .arg("daemon-reload")
                .status();
        }

        Ok(())
    }

    /// Checks whether the systemd user manager is active and reachable.
    pub fn is_systemd_user_available(&self) -> bool {
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

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4 {
            Some(format!("{} {}", parts[0], parts[1]))
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Checks whether the system is currently connected to AC power.
    ///
    /// Evaluates `/sys/class/power_supply/`. If power supply telemetry is absent
    /// or inconclusive (e.g. containers, VMs), defaults to true (assumes AC power).
    pub fn is_ac_power_connected() -> bool {
        let ps_dir = Path::new("/sys/class/power_supply");
        if !ps_dir.exists() {
            return true;
        }

        let entries = match fs::read_dir(ps_dir) {
            Ok(e) => e,
            Err(_) => return true,
        };

        let mut has_ac = false;
        let mut on_ac = false;
        let mut battery_discharging = false;

        for entry in entries.flatten() {
            let path = entry.path();
            let type_path = path.join("type");
            if let Ok(supply_type) = fs::read_to_string(&type_path) {
                let trimmed_type = supply_type.trim();
                if trimmed_type == "Mains" || trimmed_type == "AC" {
                    has_ac = true;
                    if let Ok(online) = fs::read_to_string(path.join("online")) {
                        if online.trim() == "1" {
                            on_ac = true;
                        }
                    }
                } else if trimmed_type == "Battery" {
                    if let Ok(status) = fs::read_to_string(path.join("status")) {
                        if status.trim().eq_ignore_ascii_case("discharging") {
                            battery_discharging = true;
                        }
                    }
                }
            }
        }

        if has_ac {
            on_ac
        } else {
            !battery_discharging
        }
    }

    /// Checks whether host memory pressure is above a specified percentage threshold.
    ///
    /// Inspects `/proc/pressure/memory` (PSI) 10-second stall percentage.
    /// Also verifies `/proc/meminfo` available memory is above 200 MiB.
    pub fn is_memory_pressure_high(stall_threshold_pct: f64) -> bool {
        // 1. Check PSI memory pressure
        if let Ok(psi) = fs::read_to_string("/proc/pressure/memory") {
            for line in psi.lines() {
                if line.starts_with("some") {
                    for part in line.split_whitespace() {
                        if let Some(val) = part.strip_prefix("avg10=") {
                            if let Ok(v) = val.parse::<f64>() {
                                if v > stall_threshold_pct {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Check MemAvailable
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemAvailable:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            // If available memory is less than 200 MiB (204,800 kB), pressure is critical
                            if kb < 204_800 {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

impl crate::traits::Scheduler for LinuxScheduler {
    fn backend_name(&self) -> &'static str {
        "systemd user timer"
    }

    fn backend_available(&self) -> bool {
        self.is_systemd_user_available()
    }

    fn install(
        &self,
        exec_path: &Path,
        interval: &ScheduleInterval,
        catch_up: bool,
        ac_power_only: bool,
    ) -> Result<()> {
        self.install_units_transactional(exec_path, interval, catch_up, ac_power_only)
    }

    fn uninstall(&self) -> Result<()> {
        self.uninstall_units()
    }

    fn enable(&self) -> Result<()> {
        self.enable_timer()
    }

    fn disable(&self) -> Result<()> {
        self.disable_timer()
    }

    fn is_active(&self) -> bool {
        self.is_timer_active()
    }

    fn next_trigger(&self) -> Option<String> {
        self.query_next_trigger()
    }

    fn artifact_paths(&self) -> Vec<PathBuf> {
        vec![self.service_unit_path(), self.timer_unit_path()]
    }

    fn ac_power_connected(&self) -> Option<bool> {
        Some(Self::is_ac_power_connected())
    }

    fn memory_pressure_high(&self, stall_threshold_pct: f64) -> Option<bool> {
        Some(Self::is_memory_pressure_high(stall_threshold_pct))
    }
}

pub use crate::notify::DesktopNotifier;
