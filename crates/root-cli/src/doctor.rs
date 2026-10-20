use root_core::{error::Result, model::CapabilityStatus};
use root_platform::{
    traits::{EnvironmentProvider, ResourceAccountant},
    LinuxAccountant, LinuxEnvironment,
};

pub fn run_doctor() -> Result<()> {
    let env = LinuxEnvironment::new();
    let accountant = LinuxAccountant::new();

    let caps = accountant.get_capabilities()?;
    let mem = accountant.get_system_memory()?;
    let pressure = accountant.get_pressure_metrics()?;

    println!("============================================================");
    println!(" ROOT PLATFORM DOCTOR & CAPABILITIES AUDIT");
    println!("============================================================");
    println!("Platform Identity:");
    println!("  Operating System : {}", caps.os_name);
    println!("  Kernel Release   : {}", caps.kernel_version);
    println!(
        "  Invoking User    : UID {} | GID {}",
        caps.user_uid, caps.user_gid
    );
    println!("  Privilege Level  : Unprivileged User Space (No root/sudo)");

    println!("\nStandard XDG Directories:");
    println!("  XDG Config Home  : {}", env.config_dir().display());
    println!("  XDG Data Home    : {}", env.data_dir().display());
    println!("  XDG Cache Home   : {}", env.cache_dir().display());
    println!("  XDG State Home   : {}", env.state_dir().display());
    println!(
        "  XDG Runtime Dir  : {}",
        env.runtime_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Not set".to_string())
    );

    println!("\nLinux Kernel Interfaces & Capability Status:");
    print_cap_status("/proc virtual filesystem", caps.proc_fs);
    print_cap_status("/proc/meminfo (memory accounting)", caps.proc_meminfo);
    print_cap_status(
        "/proc/pressure/memory (kernel PSI stalls)",
        caps.proc_pressure_memory,
    );
    print_cap_status(
        "/proc/[pid]/smaps_rollup (granular PSS/USS)",
        caps.proc_smaps_rollup,
    );
    print_cap_status("cgroups v2 hierarchy (/sys/fs/cgroup)", caps.cgroups_v2);
    print_cap_status("pidfd (pidfd_open & safe process pinning)", caps.pidfd);
    print_cap_status("openat2 (RESOLVE_BENEATH traversal)", caps.openat2);
    print_cap_status("statx (extended filesystem metadata)", caps.statx);

    println!("\nHost Memory Summary (Kernel Accounting):");
    println!(
        "  Total RAM        : {:>10.2} GiB",
        mem.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Available RAM    : {:>10.2} GiB",
        mem.available_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Cached / Buffers : {:>10.2} GiB",
        mem.cached_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Swap Total       : {:>10.2} GiB",
        mem.swap_total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Swap Free        : {:>10.2} GiB",
        mem.swap_free_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );

    if let Some(press) = pressure {
        println!("\nMemory Pressure Stalls (PSI):");
        println!("  Some (last 10s)  : {:>6.2}%", press.some_10s_pct);
        println!("  Some (last 60s)  : {:>6.2}%", press.some_60s_pct);
        println!("  Some (last 300s) : {:>6.2}%", press.some_300s_pct);
        println!("  Full Thrashing   : {:>6.2}%", press.full_10s_pct);
    }

    println!("\nActive Governance Phase:");
    println!("  Phase Status     : Phase 06 (Scheduled Inspections, systemd User Timers & Desktop Notifications)");
    println!("  Safety Policy    : Production Read-Only (Quarantine & Rollback Isolated to Synthetic Fixtures)");
    println!("============================================================");

    Ok(())
}

fn print_cap_status(name: &str, status: CapabilityStatus) {
    let mark = match status {
        CapabilityStatus::SupportedAndAccessible => "SUPPORTED",
        CapabilityStatus::PermissionRestricted => "RESTRICTED",
        CapabilityStatus::Unavailable => "UNAVAILABLE",
        CapabilityStatus::NotTested => "NOT TESTED",
    };
    println!("  [{:>11}] {}", mark, name);
}
