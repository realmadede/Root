use root_core::model::ProtectionTier;
use std::io::IsTerminal;

/// Determines whether ANSI color codes should be emitted.
///
/// Respects the NO_COLOR specification (<https://no-color.org/>),
/// non-interactive pipes (`!is_terminal()`), and `TERM=dumb`.
pub fn is_color_enabled() -> bool {
    // 1. NO_COLOR environment variable overrides all other color settings
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // 2. Disabled when stdout is redirected or piped
    if !std::io::stdout().is_terminal() {
        return false;
    }

    // 3. Disabled when terminal indicates dumb capabilities
    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }

    true
}

/// Detects the current terminal width in columns, falling back to 100 columns.
pub fn get_terminal_width() -> usize {
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(width) = cols.parse::<usize>() {
            if width >= 40 {
                return width;
            }
        }
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let mut winsize: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) == 0
            && winsize.ws_col >= 40
        {
            return winsize.ws_col as usize;
        }
    }

    100
}

/// ANSI styling codes with automatic NO_COLOR suppression.
pub struct Style;

impl Style {
    pub fn bold(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn dim(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[2m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn green(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[32m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn yellow(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[33m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn red(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[31m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn cyan(text: &str) -> String {
        if is_color_enabled() {
            format!("\x1b[36m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }
}

/// Formats a byte quantity into human-readable binary units (B, KiB, MiB, GiB, TiB).
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes < KIB {
        format!("{} B", bytes)
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes < TIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    }
}

/// Formats a percentage value to one decimal place.
pub fn format_percent(pct: f32) -> String {
    format!("{:.1}%", pct)
}

/// Truncates a string in the middle with an ellipsis (`...`) to preserve the beginning and end.
pub fn truncate_middle(text: &str, max_chars: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return chars[..max_chars].iter().collect();
    }
    let keep = (max_chars - 3) / 2;
    let end_start = chars.len() - (max_chars - 3 - keep);
    let start_part: String = chars[..keep].iter().collect();
    let end_part: String = chars[end_start..].iter().collect();
    format!("{}...{}", start_part, end_part)
}

/// Formats a ProtectionTier with clear badge text and restrained color styling.
pub fn format_tier_badge(tier: ProtectionTier) -> String {
    match tier {
        ProtectionTier::StrictlyProtected => Style::red("[TIER 1: PROTECTED]"),
        ProtectionTier::UserConfirmRequired => Style::yellow("[TIER 2: CONFIRM]"),
        ProtectionTier::ObsoleteTransient => Style::cyan("[TIER 3: TRANSIENT]"),
        ProtectionTier::SafeRecoverable => Style::green("[TIER 4: RECOVERABLE]"),
        ProtectionTier::NonActionable => Style::dim("[NON-ACTIONABLE]"),
    }
}
