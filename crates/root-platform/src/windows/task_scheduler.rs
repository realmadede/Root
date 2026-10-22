//! Windows Task Scheduler integration (current user, least privilege).
//!
//! The task definition is generated as XML and registered with `schtasks.exe /Create /XML`. The
//! Task Scheduler programmatic API is COM, which would add a large binding dependency; the
//! `schtasks` tool is invoked directly with fixed arguments and no shell. This is a documented
//! exception to the native-API preference (see the Phase 10 design).

use root_core::{
    error::{Result, RootError},
    model::{validate_executable, ScheduleInterval},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use super::parse::encode_utf16le_with_bom;
use crate::traits::Scheduler;

/// Fixed task path. A dedicated `\Root\` folder avoids collisions with unrelated tasks.
pub const ROOT_TASK_NAME: &str = "\\Root\\Inspect";

/// Embedded in the task description; absence means the task is not Root's.
pub const ROOT_TASK_MARKER: &str = "Root System Resource Inspection";

pub struct TaskXmlGenerator;

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

/// Removes the `\\?\` prefix `canonicalize` adds, because Task Scheduler does not need it and it
/// makes the registered command harder to audit.
fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{}", rest)
    } else if let Some(rest) = path.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        path.to_string()
    }
}

impl TaskXmlGenerator {
    fn trigger(interval: &ScheduleInterval) -> Result<&'static str> {
        match interval {
            ScheduleInterval::Hourly => Ok(
                "    <TimeTrigger>\n      <Repetition>\n        <Interval>PT1H</Interval>\n      </Repetition>\n      <StartBoundary>2000-01-01T00:00:00</StartBoundary>\n      <Enabled>true</Enabled>\n    </TimeTrigger>\n",
            ),
            ScheduleInterval::Daily => Ok(
                "    <CalendarTrigger>\n      <StartBoundary>2000-01-01T00:00:00</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n    </CalendarTrigger>\n",
            ),
            ScheduleInterval::Weekly => Ok(
                "    <CalendarTrigger>\n      <StartBoundary>2000-01-03T00:00:00</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByWeek>\n        <WeeksInterval>1</WeeksInterval>\n        <DaysOfWeek>\n          <Monday />\n        </DaysOfWeek>\n      </ScheduleByWeek>\n    </CalendarTrigger>\n",
            ),
            ScheduleInterval::Custom(_) => Err(RootError::ScheduleError(
                "Custom systemd OnCalendar expressions are supported only by the systemd backend; use hourly, daily, or weekly on Windows"
                    .to_string(),
            )),
        }
    }

    pub fn generate_task_xml(
        exec_path: &str,
        arguments: &str,
        interval: &ScheduleInterval,
        catch_up: bool,
        ac_power_only: bool,
    ) -> Result<String> {
        for (what, value) in [("Executable path", exec_path), ("Arguments", arguments)] {
            if value.contains('\n') || value.contains('\r') || value.contains('\0') {
                return Err(RootError::ScheduleError(format!(
                    "{} contains control characters",
                    what
                )));
            }
        }
        let trigger = Self::trigger(interval)?;
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
  <RegistrationInfo>\n\
    <Description>{marker} (scheduled, read-only)</Description>\n\
    <URI>{uri}</URI>\n\
  </RegistrationInfo>\n\
  <Triggers>\n\
{trigger}  </Triggers>\n\
  <Principals>\n\
    <Principal id=\"Author\">\n\
      <LogonType>InteractiveToken</LogonType>\n\
      <RunLevel>LeastPrivilege</RunLevel>\n\
    </Principal>\n\
  </Principals>\n\
  <Settings>\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
    <DisallowStartIfOnBatteries>{battery}</DisallowStartIfOnBatteries>\n\
    <StopIfGoingOnBatteries>{battery}</StopIfGoingOnBatteries>\n\
    <StartWhenAvailable>{catch_up}</StartWhenAvailable>\n\
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>\n\
    <Priority>7</Priority>\n\
    <Enabled>true</Enabled>\n\
  </Settings>\n\
  <Actions Context=\"Author\">\n\
    <Exec>\n\
      <Command>{command}</Command>\n\
      <Arguments>{arguments}</Arguments>\n\
    </Exec>\n\
  </Actions>\n\
</Task>\n",
            marker = ROOT_TASK_MARKER,
            uri = xml_escape(ROOT_TASK_NAME),
            trigger = trigger,
            battery = ac_power_only,
            catch_up = catch_up,
            command = xml_escape(exec_path),
            arguments = xml_escape(arguments),
        ))
    }

    /// Rejects definitions that would run with elevated rights or as another account.
    pub fn validate_task_xml(content: &str) -> Result<()> {
        for needle in [
            ROOT_TASK_MARKER,
            "<LogonType>InteractiveToken</LogonType>",
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<Command>",
        ] {
            if !content.contains(needle) {
                return Err(RootError::ScheduleError(format!(
                    "Generated task XML is missing required element '{}'",
                    needle
                )));
            }
        }
        for forbidden in [
            "HighestAvailable",
            "<UserId>",
            "S4U",
            "<LogonType>Password</LogonType>",
            "ServiceAccount",
        ] {
            if content.contains(forbidden) {
                return Err(RootError::ScheduleError(format!(
                    "Task XML contains forbidden directive '{}'",
                    forbidden
                )));
            }
        }
        Ok(())
    }
}

/// Current-user Task Scheduler controller.
#[derive(Debug, Clone, Default)]
pub struct WindowsScheduler {
    custom_dir: Option<PathBuf>,
}

impl WindowsScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages definitions in `dir` and disables every `schtasks` call (tests).
    pub fn with_definition_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            custom_dir: Some(dir.into()),
        }
    }

    fn simulated(&self) -> bool {
        self.custom_dir.is_some()
    }

    pub fn definition_dir(&self) -> PathBuf {
        if let Some(dir) = &self.custom_dir {
            return dir.clone();
        }
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Root")
            .join("schedule")
    }

    pub fn definition_path(&self) -> PathBuf {
        self.definition_dir().join("root-inspect-task.xml")
    }

    fn schtasks(args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new("schtasks.exe").args(args).output()
    }

    /// Whether a task already exists at Root's path and, if so, whether it is Root's.
    fn registered_task_is_foreign(&self) -> Result<bool> {
        let out = Self::schtasks(&["/Query", "/TN", ROOT_TASK_NAME, "/XML"])
            .map_err(|e| RootError::ScheduleError(format!("schtasks query failed: {}", e)))?;
        if !out.status.success() {
            return Ok(false); // no such task
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(!text.contains(ROOT_TASK_MARKER))
    }

    fn staged_definition_is_foreign(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        let bytes = fs::read(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(!String::from_utf16_lossy(&units).contains(ROOT_TASK_MARKER))
    }
}

impl Scheduler for WindowsScheduler {
    fn backend_name(&self) -> &'static str {
        "Windows Task Scheduler"
    }

    fn backend_available(&self) -> bool {
        if self.simulated() {
            return true;
        }
        cfg!(windows)
            && Self::schtasks(&["/?"])
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    /// Validates the executable, generates and checks the XML, and stages it atomically. The task
    /// is registered only by `enable`.
    fn install(
        &self,
        exec_path: &Path,
        interval: &ScheduleInterval,
        catch_up: bool,
        ac_power_only: bool,
    ) -> Result<()> {
        let exec = validate_executable(exec_path)?;
        let exec_str = strip_verbatim_prefix(&exec.to_string_lossy());
        let xml = TaskXmlGenerator::generate_task_xml(
            &exec_str,
            "schedule run",
            interval,
            catch_up,
            ac_power_only,
        )?;
        TaskXmlGenerator::validate_task_xml(&xml)?;

        let dir = self.definition_dir();
        fs::create_dir_all(&dir).map_err(|e| RootError::Io {
            path: dir.clone(),
            source: e,
        })?;
        let path = self.definition_path();
        if Self::staged_definition_is_foreign(&path)? {
            return Err(RootError::ScheduleError(format!(
                "Collision: existing file '{}' was not created by Root; refusing to overwrite",
                path.display()
            )));
        }

        let tmp = path.with_extension("xml.tmp");
        fs::write(&tmp, encode_utf16le_with_bom(&xml)).map_err(|e| RootError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(RootError::Io { path, source: e });
        }
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        if !self.simulated() && !self.registered_task_is_foreign()? {
            // Delete only when a Root task exists; a foreign task at our path is left alone.
            let _ = Self::schtasks(&["/Delete", "/TN", ROOT_TASK_NAME, "/F"]);
        }
        let path = self.definition_path();
        if path.exists() {
            if Self::staged_definition_is_foreign(&path)? {
                return Err(RootError::ScheduleError(format!(
                    "Refusing to remove '{}': not created by Root",
                    path.display()
                )));
            }
            fs::remove_file(&path).map_err(|e| RootError::Io { path, source: e })?;
        }
        Ok(())
    }

    fn enable(&self) -> Result<()> {
        if self.simulated() {
            return Ok(());
        }
        let path = self.definition_path();
        if !path.exists() {
            return Err(RootError::ScheduleError(
                "Task definition is not staged; run install first".to_string(),
            ));
        }
        if self.registered_task_is_foreign()? {
            return Err(RootError::ScheduleError(format!(
                "Collision: a task named '{}' already exists and was not created by Root",
                ROOT_TASK_NAME
            )));
        }
        let out = Self::schtasks(&[
            "/Create",
            "/TN",
            ROOT_TASK_NAME,
            "/XML",
            &path.to_string_lossy(),
            "/F",
        ])
        .map_err(|e| RootError::ScheduleError(format!("schtasks create failed: {}", e)))?;
        if !out.status.success() {
            return Err(RootError::ScheduleError(format!(
                "schtasks /Create failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        if self.simulated() {
            return Ok(());
        }
        let _ = Self::schtasks(&["/Change", "/TN", ROOT_TASK_NAME, "/DISABLE"]);
        Ok(())
    }

    fn is_active(&self) -> bool {
        if self.simulated() {
            return self.definition_path().exists();
        }
        Self::schtasks(&["/Query", "/TN", ROOT_TASK_NAME])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// `schtasks` output is localized, so Root does not parse the next run time.
    fn next_trigger(&self) -> Option<String> {
        None
    }

    fn artifact_paths(&self) -> Vec<PathBuf> {
        vec![self.definition_path()]
    }

    fn ac_power_connected(&self) -> Option<bool> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
            let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
            if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
                return None;
            }
            super::parse::ac_line_status_to_bool(status.ACLineStatus)
        }
        #[cfg(not(windows))]
        {
            None
        }
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
        fs::write(&p, b"binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        (dir, p)
    }

    fn decode(path: &Path) -> String {
        let bytes = fs::read(path).unwrap();
        assert_eq!(&bytes[..2], &[0xFF, 0xFE], "UTF-16LE BOM expected");
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn xml_runs_with_least_privilege_and_escapes_paths() {
        let xml = TaskXmlGenerator::generate_task_xml(
            "C:\\Program Files\\Root & Co\\root.exe",
            "schedule run",
            &ScheduleInterval::Daily,
            true,
            true,
        )
        .unwrap();
        assert!(xml.contains("Root &amp; Co"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>true"));
        assert!(!xml.contains("HighestAvailable"));
        TaskXmlGenerator::validate_task_xml(&xml).unwrap();
    }

    #[test]
    fn custom_interval_and_control_characters_are_rejected() {
        assert!(TaskXmlGenerator::generate_task_xml(
            "C:\\r.exe",
            "",
            &ScheduleInterval::Custom("x".into()),
            false,
            false
        )
        .is_err());
        assert!(TaskXmlGenerator::generate_task_xml(
            "C:\\r.exe\n",
            "",
            &ScheduleInterval::Daily,
            false,
            false
        )
        .is_err());
    }

    #[test]
    fn validation_rejects_elevation() {
        let xml = TaskXmlGenerator::generate_task_xml(
            "C:\\r.exe",
            "",
            &ScheduleInterval::Hourly,
            false,
            false,
        )
        .unwrap()
        .replace("LeastPrivilege", "HighestAvailable");
        assert!(TaskXmlGenerator::validate_task_xml(&xml).is_err());
    }

    #[test]
    fn verbatim_prefix_is_stripped() {
        assert_eq!(
            strip_verbatim_prefix("\\\\?\\C:\\a\\root.exe"),
            "C:\\a\\root.exe"
        );
        assert_eq!(
            strip_verbatim_prefix("\\\\?\\UNC\\srv\\s\\r.exe"),
            "\\\\srv\\s\\r.exe"
        );
        assert_eq!(strip_verbatim_prefix("C:\\a"), "C:\\a");
    }

    #[test]
    fn staging_collision_and_removal() {
        let (_g, exe_path) = exe();
        let dir = tempfile::tempdir().unwrap();
        let sched = WindowsScheduler::with_definition_dir(dir.path());
        assert!(!sched.is_active(), "nothing is installed by default");

        fs::write(sched.definition_path(), b"foreign").unwrap();
        assert!(sched
            .install(&exe_path, &ScheduleInterval::Daily, false, false)
            .is_err());
        assert!(sched.uninstall().is_err());
        assert_eq!(fs::read(sched.definition_path()).unwrap(), b"foreign");
        fs::remove_file(sched.definition_path()).unwrap();

        sched
            .install(&exe_path, &ScheduleInterval::Weekly, true, false)
            .unwrap();
        let staged = decode(&sched.definition_path());
        assert!(staged.contains(ROOT_TASK_MARKER));
        assert!(sched.is_active());
        sched.uninstall().unwrap();
        assert!(!sched.definition_path().exists());
    }
}
