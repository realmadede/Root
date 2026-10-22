//! launchd LaunchAgent scheduling (user domain only).
//!
//! Generation and validation are pure and portable. Activation invokes `launchctl` directly (no
//! shell). launchd offers no public C API for managing user agents other than `launchctl`/XPC;
//! this is a documented exception to the native-API preference (see the Phase 10 design).

use root_core::{
    error::{Result, RootError},
    model::{validate_executable, ScheduleInterval},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::traits::Scheduler;

#[cfg(unix)]
fn current_uid_for_launchd() -> u32 {
    unsafe { libc::getuid() }
}

/// launchd domains are a macOS concept; on other hosts this value is never used to run launchctl.
#[cfg(not(unix))]
fn current_uid_for_launchd() -> u32 {
    0
}

/// Fixed, Root-owned launchd label.
pub const LAUNCHD_LABEL: &str = "io.github.realmadede.root.inspect";

/// Marker embedded in every Root-generated plist; absence means "not ours, do not touch".
pub const ROOT_PLIST_MARKER: &str = "Root System Resource Inspection";

pub struct LaunchdPlistGenerator;

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

impl LaunchdPlistGenerator {
    /// Calendar keys equivalent to systemd's `hourly`, `daily`, and `weekly`. Custom systemd
    /// `OnCalendar` expressions have no portable meaning and are rejected.
    fn calendar_dict(interval: &ScheduleInterval) -> Result<&'static str> {
        match interval {
            ScheduleInterval::Hourly => Ok("        <key>Minute</key>\n        <integer>0</integer>\n"),
            ScheduleInterval::Daily => Ok(
                "        <key>Hour</key>\n        <integer>0</integer>\n        <key>Minute</key>\n        <integer>0</integer>\n",
            ),
            ScheduleInterval::Weekly => Ok(
                "        <key>Weekday</key>\n        <integer>1</integer>\n        <key>Hour</key>\n        <integer>0</integer>\n        <key>Minute</key>\n        <integer>0</integer>\n",
            ),
            ScheduleInterval::Custom(_) => Err(RootError::ScheduleError(
                "Custom systemd OnCalendar expressions are supported only by the systemd backend; use hourly, daily, or weekly on macOS"
                    .to_string(),
            )),
        }
    }

    pub fn generate_plist(
        exec_path: &Path,
        additional_args: &[&str],
        interval: &ScheduleInterval,
    ) -> Result<String> {
        let exec = exec_path.to_string_lossy();
        if exec.contains('\n') || exec.contains('\r') || exec.contains('\0') {
            return Err(RootError::ScheduleError(
                "Executable path contains control characters".to_string(),
            ));
        }
        let calendar = Self::calendar_dict(interval)?;
        let mut args = format!("        <string>{}</string>\n", xml_escape(&exec));
        for a in additional_args {
            args.push_str(&format!("        <string>{}</string>\n", xml_escape(a)));
        }

        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<!-- {marker} -->\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>{label}</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
{args}    </array>\n\
    <key>StartCalendarInterval</key>\n\
    <dict>\n\
{calendar}    </dict>\n\
    <key>RunAtLoad</key>\n\
    <false/>\n\
    <key>ProcessType</key>\n\
    <string>Background</string>\n\
    <key>LowPriorityIO</key>\n\
    <true/>\n\
    <key>Nice</key>\n\
    <integer>19</integer>\n\
    <key>ExitTimeOut</key>\n\
    <integer>120</integer>\n\
</dict>\n\
</plist>\n",
            marker = ROOT_PLIST_MARKER,
            label = LAUNCHD_LABEL,
            args = args,
            calendar = calendar,
        ))
    }

    /// Rejects plists that are not a user-level Root agent.
    pub fn validate_plist(content: &str) -> Result<()> {
        let required = [
            ROOT_PLIST_MARKER,
            "<key>Label</key>",
            LAUNCHD_LABEL,
            "<key>ProgramArguments</key>",
        ];
        for needle in required {
            if !content.contains(needle) {
                return Err(RootError::ScheduleError(format!(
                    "Generated launchd plist is missing required element '{}'",
                    needle
                )));
            }
        }
        // User agents must not request a different account or privileged behavior.
        for forbidden in [
            "<key>UserName</key>",
            "<key>GroupName</key>",
            "<key>SessionCreate</key>",
            "LaunchDaemons",
        ] {
            if content.contains(forbidden) {
                return Err(RootError::ScheduleError(format!(
                    "launchd plist contains forbidden directive '{}'",
                    forbidden
                )));
            }
        }
        Ok(())
    }
}

/// launchd user-agent scheduler. Never touches `/Library/LaunchDaemons`.
#[derive(Debug, Clone, Default)]
pub struct MacScheduler {
    custom_agents_dir: Option<PathBuf>,
}

impl MacScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Points the scheduler at a directory and disables every `launchctl` call (tests).
    pub fn with_agents_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            custom_agents_dir: Some(dir.into()),
        }
    }

    pub fn agents_dir(&self) -> PathBuf {
        if let Some(dir) = &self.custom_agents_dir {
            return dir.clone();
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/empty"))
            .join("Library")
            .join("LaunchAgents")
    }

    pub fn plist_path(&self) -> PathBuf {
        self.agents_dir().join(format!("{}.plist", LAUNCHD_LABEL))
    }

    fn simulated(&self) -> bool {
        self.custom_agents_dir.is_some()
    }

    fn domain_target() -> String {
        format!("gui/{}", current_uid_for_launchd())
    }

    fn service_target() -> String {
        format!("{}/{}", Self::domain_target(), LAUNCHD_LABEL)
    }

    fn check_collision(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let content = fs::read_to_string(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if !content.contains(ROOT_PLIST_MARKER) {
            return Err(RootError::ScheduleError(format!(
                "Collision: existing launchd plist '{}' was not created by Root; refusing to overwrite",
                path.display()
            )));
        }
        Ok(())
    }

    fn launchctl(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
        Command::new("launchctl").args(args).status()
    }
}

impl Scheduler for MacScheduler {
    fn backend_name(&self) -> &'static str {
        "launchd user agent"
    }

    fn backend_available(&self) -> bool {
        if self.simulated() {
            return true;
        }
        cfg!(target_os = "macos")
            && Command::new("launchctl")
                .arg("version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    fn install(
        &self,
        exec_path: &Path,
        interval: &ScheduleInterval,
        _catch_up: bool,
        _ac_power_only: bool,
    ) -> Result<()> {
        // `catch_up`: launchd coalesces missed calendar runs after sleep but not after power-off;
        // there is no setting to change that. `ac_power_only` is enforced by `schedule run`.
        let exec = validate_executable(exec_path)?;
        let content = LaunchdPlistGenerator::generate_plist(&exec, &["schedule", "run"], interval)?;
        LaunchdPlistGenerator::validate_plist(&content)?;

        let dir = self.agents_dir();
        fs::create_dir_all(&dir).map_err(|e| RootError::Io {
            path: dir.clone(),
            source: e,
        })?;
        let path = self.plist_path();
        Self::check_collision(&path)?;

        let tmp = path.with_extension("plist.tmp");
        fs::write(&tmp, content).map_err(|e| RootError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(RootError::Io { path, source: e });
        }
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let path = self.plist_path();
        if !path.exists() {
            return Ok(());
        }
        // Only remove what Root created.
        Self::check_collision(&path)?;
        if !self.simulated() {
            let _ = Self::launchctl(&["bootout", &Self::service_target()]);
        }
        fs::remove_file(&path).map_err(|e| RootError::Io { path, source: e })
    }

    fn enable(&self) -> Result<()> {
        if self.simulated() {
            return Ok(());
        }
        let path = self.plist_path();
        if !path.exists() {
            return Err(RootError::ScheduleError(
                "launchd plist is not installed; run install first".to_string(),
            ));
        }
        let status =
            Self::launchctl(&["bootstrap", &Self::domain_target(), &path.to_string_lossy()])
                .map_err(|e| {
                    RootError::ScheduleError(format!("launchctl bootstrap failed: {}", e))
                })?;
        if !status.success() {
            return Err(RootError::ScheduleError(
                "launchctl bootstrap returned a failure status (the agent may already be loaded)"
                    .to_string(),
            ));
        }
        let _ = Self::launchctl(&["enable", &Self::service_target()]);
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        if self.simulated() {
            return Ok(());
        }
        let _ = Self::launchctl(&["bootout", &Self::service_target()]);
        Ok(())
    }

    fn is_active(&self) -> bool {
        if self.simulated() {
            return self.plist_path().exists();
        }
        Self::launchctl(&["print", &Self::service_target()])
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// launchd does not expose the next calendar fire time.
    fn next_trigger(&self) -> Option<String> {
        None
    }

    fn artifact_paths(&self) -> Vec<PathBuf> {
        vec![self.plist_path()]
    }

    fn ac_power_connected(&self) -> Option<bool> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let out = Command::new("pmset").args(["-g", "batt"]).output().ok()?;
        crate::macos::parse::parse_pmset_power_source(&String::from_utf8_lossy(&out.stdout))
    }

    fn memory_pressure_high(&self, _stall_threshold_pct: f64) -> Option<bool> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("root");
        fs::write(&p, b"#!/bin/true\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        (dir, p)
    }

    #[test]
    fn plist_is_user_level_and_escaped() {
        let plist = LaunchdPlistGenerator::generate_plist(
            Path::new("/Users/a&b/root"),
            &["schedule", "run"],
            &ScheduleInterval::Daily,
        )
        .unwrap();
        assert!(plist.contains("/Users/a&amp;b/root"));
        assert!(plist.contains(LAUNCHD_LABEL));
        assert!(plist.contains("<key>RunAtLoad</key>\n<false/>"));
        assert!(!plist.contains("LaunchDaemons"));
        LaunchdPlistGenerator::validate_plist(&plist).unwrap();
    }

    #[test]
    fn custom_interval_is_rejected_explicitly() {
        let err = LaunchdPlistGenerator::generate_plist(
            Path::new("/x/root"),
            &[],
            &ScheduleInterval::Custom("*-*-* 03:00".into()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("systemd"));
    }

    #[test]
    fn validation_rejects_privileged_directives() {
        let mut plist = LaunchdPlistGenerator::generate_plist(
            Path::new("/x/root"),
            &[],
            &ScheduleInterval::Hourly,
        )
        .unwrap();
        plist = plist.replace(
            "<key>RunAtLoad</key>",
            "<key>UserName</key>\n<string>root</string>\n<key>RunAtLoad</key>",
        );
        assert!(LaunchdPlistGenerator::validate_plist(&plist).is_err());
    }

    #[test]
    fn install_collision_and_removal() {
        let (_g, exe_path) = exe();
        let agents = tempfile::tempdir().unwrap();
        let sched = MacScheduler::with_agents_dir(agents.path());

        // A foreign plist at the same path must be refused and left intact.
        fs::write(sched.plist_path(), "<plist>someone else</plist>").unwrap();
        assert!(sched
            .install(&exe_path, &ScheduleInterval::Daily, false, false)
            .is_err());
        assert!(sched.uninstall().is_err());
        assert_eq!(
            fs::read_to_string(sched.plist_path()).unwrap(),
            "<plist>someone else</plist>"
        );
        fs::remove_file(sched.plist_path()).unwrap();

        sched
            .install(&exe_path, &ScheduleInterval::Weekly, false, false)
            .unwrap();
        assert!(sched.is_active());
        // Reinstall over our own plist is allowed.
        sched
            .install(&exe_path, &ScheduleInterval::Hourly, false, false)
            .unwrap();
        sched.uninstall().unwrap();
        assert!(!sched.plist_path().exists());
    }

    #[test]
    fn nothing_is_installed_by_default() {
        let agents = tempfile::tempdir().unwrap();
        let sched = MacScheduler::with_agents_dir(agents.path());
        assert!(!sched.is_active());
        assert!(sched.artifact_paths().iter().all(|p| !p.exists()));
    }
}
