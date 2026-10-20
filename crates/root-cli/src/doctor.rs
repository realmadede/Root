use root_core::error::Result;
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

    println!("\nLinux Kernel Interfaces & Safety Subsystems:");
    print_cap_status(
        "pidfd (Linux 5.3+ pidfd_open & 5.4+ pidfd_send_signal)",
        caps.has_pidfd,
    );
    print_cap_status(
        "cgroups v2 PSI (/proc/pressure/memory)",
        caps.has_cgroups_v2_psi,
    );
    print_cap_status(
        "smaps_rollup (/proc/[pid]/smaps_rollup PSS/USS)",
        caps.has_smaps_rollup,
    );
    print_cap_status(
        "openat2 (Linux 5.6+ RESOLVE_BENEATH traversal)",
        caps.has_openat2,
    );

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
    println!("  Phase Status     : Phase 01 (Core Models, Platform Traits, & Fixtures)");
    println!("  Safety Policy    : Strict Read-Only (Zero filesystem or process mutation)");
    println!("============================================================");

    Ok(())
}

fn print_cap_status(name: &str, supported: bool) {
    let mark = if supported {
        "SUPPORTED"
    } else {
        "UNAVAILABLE"
    };
    println!("  [{:>11}] {}", mark, name);
}
