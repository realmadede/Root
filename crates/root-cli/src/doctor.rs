use root_core::{
    error::Result,
    model::{CapabilityStatus, PlatformKind},
};
use root_platform::{
    traits::{EnvironmentProvider, ResourceAccountant},
    NativeAccountant, NativeEnvironment,
};

pub fn run_doctor() -> Result<()> {
    let env = NativeEnvironment::new();
    let accountant = NativeAccountant::new();

    let caps = accountant.get_capabilities()?;
    let mem = accountant.get_system_memory()?;
    let pressure = accountant.get_pressure_metrics()?;

    println!("============================================================");
    println!(" ROOT PLATFORM DOCTOR & CAPABILITIES AUDIT");
    println!("============================================================");
    println!("Platform Identity:");
    println!("  Operating System : {}", caps.os_name);
    println!("  Kernel Release   : {}", caps.kernel_version);
    if caps.platform == PlatformKind::Windows {
        println!("  Invoking User    : Windows User Token");
    } else {
        println!(
            "  Invoking User    : UID {} | GID {}",
            caps.user_uid, caps.user_gid
        );
    }
    println!("  Privilege Level  : Unprivileged User Space (No root/sudo/admin)");

    let dir_header = match caps.platform {
        PlatformKind::Linux => "Standard User Directories (XDG):",
        PlatformKind::MacOs => "Standard User Directories (macOS Library):",
        PlatformKind::Windows => "Standard User Directories (Windows AppData):",
        PlatformKind::Other => "Standard User Directories:",
    };
    println!("\n{}", dir_header);
    println!("  Config Directory : {}", env.config_dir().display());
    println!("  Data Directory   : {}", env.data_dir().display());
    println!("  Cache Directory  : {}", env.cache_dir().display());
    println!("  State Directory  : {}", env.state_dir().display());
    if let Some(runtime) = env.runtime_dir() {
        println!("  Runtime Directory: {}", runtime.display());
    }

    if caps.platform == PlatformKind::Linux {
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
    }

    println!("\nPlatform Inspection Capabilities:");
    print_cap_status("Process enumeration", caps.process_enumeration);
    print_cap_status("Process start time", caps.process_start_time);
    print_cap_status("Process RSS accounting", caps.process_rss);
    print_cap_status("Process private memory", caps.process_private_memory);
    print_cap_status("System memory accounting", caps.system_memory);
    print_cap_status("Memory pressure metrics", caps.memory_pressure);
    print_cap_status("Filesystem resource identity", caps.file_identity);
    print_cap_status("Filesystem live monitoring", caps.filesystem_events);
    print_cap_status("User-level scheduler", caps.scheduler);
    print_cap_status("File advisory locking", caps.file_locking);

    println!("\nHost Memory Summary:");
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
    if mem.swap_total_bytes > 0 {
        println!(
            "  Swap Total       : {:>10.2} GiB",
            mem.swap_total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
        );
        println!(
            "  Swap Free        : {:>10.2} GiB",
            mem.swap_free_bytes as f64 / 1024.0 / 1024.0 / 1024.0
        );
    }

    if let Some(press) = pressure {
        println!("\nMemory Pressure Stalls (PSI):");
        println!("  Some (last 10s)  : {:>6.2}%", press.some_10s_pct);
        println!("  Some (last 60s)  : {:>6.2}%", press.some_60s_pct);
        println!("  Some (last 300s) : {:>6.2}%", press.some_300s_pct);
        println!("  Full Thrashing   : {:>6.2}%", press.full_10s_pct);
    }

    println!("\nActive Governance Phase:");
    println!("  Phase Status     : Phase 13 (Read-Only Hardening and Classification Safety)");
    println!(
        "  Safety Policy    : Production Read-Only (Deterministic Inspection; Mutation Disabled)"
    );
    println!("============================================================");

    Ok(())
}

fn print_cap_status(name: &str, status: CapabilityStatus) {
    let mark = match status {
        CapabilityStatus::SupportedAndAccessible => "SUPPORTED",
        CapabilityStatus::PermissionRestricted => "RESTRICTED",
        CapabilityStatus::Unavailable => "UNAVAILABLE",
        CapabilityStatus::Unsupported => "UNSUPPORTED",
        CapabilityStatus::NotTested => "NOT TESTED",
    };
    println!("  [{:>11}] {}", mark, name);
}
