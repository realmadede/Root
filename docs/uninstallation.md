# Root — Uninstallation Guide

Root is engineered to respect user data boundaries. Uninstalling Root removes binaries, manual pages, application launchers, and desktop icons. It preserves your personal configuration, preferences, and scan history by default.

---

## Method 1: Debian Package Removal

### Standard Removal (Preserves User Configuration)
To remove the application executables and desktop files while preserving configuration files:

```bash
sudo apt remove root
```

This removes:
- `/usr/bin/root`
- `/usr/bin/root-gui`
- `/usr/share/applications/io.github.realmadede.Root.desktop`
- `/usr/share/metainfo/io.github.realmadede.Root.metainfo.xml`
- `/usr/share/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg`
- `/usr/share/man/man1/root*.1.gz`
- `/usr/share/doc/root/`

It automatically updates the desktop application database and icon caches.

### Complete Purge
```bash
sudo apt purge root
```

*Note: In accordance with standard Debian packaging rules, package scripts never recursively delete directories in user home folders ($HOME).*

---

## Method 2: Portable Archive Uninstallation

If Root was installed using the portable archive installer (`install.sh`), use the corresponding `uninstall.sh` script:

```bash
# From the extracted distribution archive directory:
./uninstall.sh

# Or with a custom installation prefix:
PREFIX=/opt/root ./uninstall.sh
```

---

## Cleaning User State and Preferences (Optional)

If you wish to completely delete Root's local inspection history and preferences from your user home directory, remove the following standard XDG directories:

```bash
# Remove cached scan reports and history
rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/root"

# Remove user inspection configuration and preferences
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/root"

# Remove user-level scheduled inspection timers (if previously enabled)
systemctl --user stop root-inspect.timer 2>/dev/null || true
systemctl --user disable root-inspect.timer 2>/dev/null || true
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/root-inspect.service"
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/root-inspect.timer"
systemctl --user daemon-reload 2>/dev/null || true
```
