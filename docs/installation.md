# Root — Installation Guide

Root is a local-first, deterministic system resource inspection and monitoring utility. It operates entirely unprivileged and never requires administrative (`root` or `sudo`) privileges during normal execution.

---

## Supported Distribution Channels

Root is distributed for Linux systems via two primary channels:
1. **Debian Package (`.deb`)**: Recommended for Debian, Kali Linux, Ubuntu, and Debian-derived systems. Integrates automatically with the desktop environment, application launcher, icons, AppStream metadata, and manual pages.
2. **Portable Linux Archive (`.tar.gz`)**: Self-contained archive suitable for unprivileged installation into `~/.local` or any user-chosen directory across any modern x86_64 Linux distribution.

---

## Method 1: Debian Package Installation (Debian / Kali / Ubuntu)

### Download and Verification
Download the official `.deb` package and the corresponding `SHA256SUMS` manifest from the release repository:

```bash
# Verify cryptographic checksum prior to installation
sha256sum -c SHA256SUMS --ignore-missing
```

### Installation via apt
Using `apt` automatically resolves runtime dependencies (`libgtk-4-1`, `libadwaita-1-0`, `libc6`):

```bash
sudo apt install ./root_0.1.0-rc.1-1_amd64.deb
```

*Note: While package manager installation requires administrative authorization to place files in `/usr/bin` and `/usr/share`, Root itself executes strictly as an unprivileged user process.*

### Verification
Confirm that the binaries and desktop integration are installed and functional:

```bash
# Check CLI version and doctor telemetry
root --version
root doctor

# Launch the desktop graphical interface
root-gui
```

---

## Method 2: Portable Archive Installation (Unprivileged User Mode)

The portable archive allows complete installation without administrative privileges.

### Extraction and Installation
```bash
# Extract the archive
tar -xzf root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz
cd root-v0.1.0-rc.1-x86_64-unknown-linux-gnu

# Run the user-level installer (defaults to ~/.local)
./install.sh
```

### Path Configuration
Ensure `~/.local/bin` is present in your shell's `PATH` variable:

```bash
export PATH="${HOME}/.local/bin:${PATH}"
```

### Custom Prefix Installation
To install into a custom location (e.g., `/opt/root` or an enterprise workstation directory):

```bash
PREFIX=/opt/root ./install.sh
```

---

## Method 3: Building from Source

### Prerequisites
- Rust 1.85 or later (via rustup)
- C build tools: `pkg-config`, `gcc` or `clang`
- GTK4 and Libadwaita development headers (optional, for graphical desktop interface):
  - Debian/Kali/Ubuntu: `sudo apt install pkg-config libgtk-4-dev libadwaita-1-dev`
  - Fedora: `sudo dnf install pkgconf-pkg-config gtk4-devel libadwaita-devel`
  - Arch Linux: `sudo pacman -S pkgconf gtk4 libadwaita`

### Build Instructions
```bash
# Clone the repository
git clone https://github.com/realmadede/Root.git
cd Root

# Build optimized release binaries (Headless CLI only)
cargo build --release -p root-cli

# Build optimized release binaries with native desktop GUI
cargo build --release -p root-cli
cargo build --release -p root-gui --features gtk
```

The compiled executables will be located in:
- `target/release/root` (CLI)
- `target/release/root-gui` (GUI)

---

## Post-Installation Verification Checklist

1. Run `root doctor` to verify that Linux `/proc` and kernel interfaces are detected.
2. Run `root status` to verify host memory and resource accounting.
3. Run `root-gui` or open "Root" from the GNOME application overview.
4. Verify that `root schedule status` reports `[DISABLED by default]`.
