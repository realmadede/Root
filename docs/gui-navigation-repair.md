# GUI Navigation Repair: Vertical Sidebar and Functional Page Rendering

## 1. Executive Summary

This document details the diagnostic findings, architectural corrections, and verification results for Root's native GTK4/libadwaita desktop application (`root-gui`).

Prior to this correction, the desktop interface exhibited two release-blocking defects:
1. **Incorrect Navigation Layout**: Seven primary destinations were placed horizontally across the top header bar (`AdwViewSwitcher`), violating GNOME Human Interface Guidelines and crowding the window header.
2. **Nonfunctional Navigation**: Selecting navigation items (such as Settings or System Memory/Overview) failed to display page content or appeared entirely unresponsive due to layout collapse, nested scrolling conflicts, and decoupled view model synchronization.

Both defects have been resolved by implementing a native vertical navigation sidebar on the left side of the window, eliminating nested scrolling wrappers in favor of direct view stack child expansion, and establishing bidirectional selection synchronization with a re-entrancy guard.

All thirty GUI test suites pass, zero GTK runtime warnings are emitted, all eleven repository continuous assurance invariants pass, and the application remains strictly non-destructive and read-only.

---

## 2. Root Cause Analysis

### Cause 1: Horizontal Layout and Header Bar Starvation

In the previous design, `root-gui` embedded an `adw::ViewSwitcher` directly inside the window's `AdwHeaderBar` via `header_bar.set_title_widget(Some(&switcher))`. Libadwaita view switchers are intended for simple views with three or four compact items. With seven destinations (Overview, Resources, Agents, Processes, Activity, Schedule, Settings), the switcher exceeded available horizontal space across standard display widths. This resulted in severe label clipping, tab overflow, and failure of mouse pointer events on rightmost buttons, particularly Settings.

### Cause 2: Unexpanded ViewStack and Nested Scroll Collapse

The main page stack container (`AdwViewStack`) was initialized without explicit expansion properties (`hexpand = false`, `vexpand = false`). Additionally, each individual page view constructor in `crates/root-gui/src/gtk/views/` (such as `build_overview_view` and `build_settings_view`) returns an `adw::PreferencesPage`, which internally integrates its own `GtkScrolledWindow` and `AdwClamp`. The window assembly previously wrapped each page in a second, outer scrolled window (`wrap_in_scrolled_clamp`). This double-scrolled configuration created an unbounded virtual height computation within GTK4 layout passes, causing child widgets to collapse to zero allocated height or fail to paint when switched.

### Cause 3: View Model State Disconnection

The GTK view stack selection was only connected in one direction. When a tab was clicked, the view switcher changed the visible stack child, but the application controller's `state.navigation` model was never notified. Consequently, view model state updates, active title updates, and accelerator handlers operated out of sync with the visible interface.

### Cause 4: The "System" Navigation Ambiguity

The diagnostic investigation clarified the reference to "System": users selecting either the Overview page (whose top group is "System Memory") or the "System" appearance toggle in Settings encountered a blank or non-responsive area due to the layout collapse described in Cause 2. With the elimination of redundant scroll wrappers and the restoration of proper widget expansion, both sections render reliably.

---

## 5. Architectural Implementation

### Native Vertical Navigation Sidebar

The window layout is structured using a horizontal two-pane split:
- **Left Sidebar** (`GtkBox` with CSS class `sidebar`): A fixed-width (240px) vertical pane containing:
  - Header branding label: "Root Resource Auditor".
  - Top navigation list (`GtkListBox` with CSS class `navigation-sidebar`): Six primary destinations (Overview, Resources, Agents, Processes, Activity, Schedule).
  - Flexible vertical spacer (`vexpand = true`) and separator (`GtkSeparator`).
  - Bottom navigation list (`GtkListBox` with CSS class `navigation-sidebar`): Dedicated row for Settings at the bottom of the sidebar.
  - Operational status footer: Displays a subtle read-only indicator badge ("READ-ONLY AUDIT") confirming non-destructive operation.
- **Right Content Area** (`GtkBox` with CSS class `content-pane`):
  - Dedicated Header Bar (`AdwHeaderBar`): Contains an `adw::WindowTitle` dynamically displaying the active section title and descriptive subtitle, a manual Refresh button on the left, and a Directory Chooser button on the right.
  - Content Stack (`AdwViewStack`): Receives all seven page containers with `hexpand = true` and `vexpand = true`.

### Re-Entrancy Guard and Bidirectional Synchronization

To coordinate selection between the top navigation list, the bottom Settings list, keyboard accelerators, and view stack events without recursive signal loops, a shared re-entrancy guard (`Rc<Cell<bool>>`) governs page transitions.

When a navigation item is selected:
1. The guard prevents re-entrant handler execution.
2. The visible child of `AdwViewStack` is updated to the selected item's page identifier.
3. The `AdwWindowTitle` updates its title and subtitle.
4. The corresponding row in either the top list or bottom list is selected, and selection on the alternate list is cleared.
5. The application controller's navigation state is synchronized via `controller.navigate_to(item)`.

---

## 4. Code Modifications Inventory

| File | Type | Description |
|---|---|---|
| `crates/root-gui/src/model/navigation.rs` | Modification | Added `subtitle(&self) -> &'static str` providing clear descriptions for all seven destinations. Added `from_page_id` and verified `ALL` enumeration. |
| `crates/root-gui/src/gtk/window.rs` | Rewrite | Replaced horizontal `AdwViewSwitcher` with native vertical left sidebar (`GtkListBox` with `navigation-sidebar`). Placed Settings at sidebar bottom. Removed nested scrolled clamping. Added `AdwWindowTitle` header synchronization. Wired keyboard shortcuts (`Ctrl+1` through `Ctrl+7`). |
| `crates/root-gui/tests/gui_view_model_tests.rs` | Modification | Consolidated native GTK tests to run on a single thread (`test_26`), expanded comprehensive navigation model verification (`test_28`), added metadata contract validation (`test_29`), and verified Settings positioning and non-destructive guarantees (`test_30`). |

---

## 5. Human-Computer Interaction & Accessibility

- **Keyboard Navigation**:
  - `Ctrl+1`: Overview
  - `Ctrl+2`: Resources
  - `Ctrl+3`: Agents
  - `Ctrl+4`: Processes
  - `Ctrl+5`: Activity
  - `Ctrl+6`: Schedule
  - `Ctrl+7`: Settings
  - Full arrow-key, Tab, and Enter traversal across sidebar rows.
- **Typographic & Layout Resilience**:
  - Tabular figures (`tnum`) applied to memory, count, and size readouts.
  - Middle truncation (`...`) for path representations preserving both parent root and leaf names.
  - Dynamic window title displaying contextual subtitle for each destination.
- **Theme Support**:
  - Full compatibility with GNOME light and dark appearance preferences, as well as forced light or dark override in Settings.

---

## 6. Non-Destructive Safety Guarantees

As required by `AGENTS.md` and repository architectural invariants:
- **Zero Mutation Capability**: The GUI exposes zero quarantine, prune, or delete actions. All file-system operations are strictly read-only inspection (`statx`, directory enumeration, and procfs inspection).
- **Guardian Enforcement**: All transaction requests through the Guardian subsystem are rejected unconditionally in the GUI context.
- **Scheduler Boundary**: The Schedule view remains informational and disabled by default, requiring explicit user authorization.

---

## 7. Verification Results

### Quality Gate Summary

```text
cargo fmt --check: PASSED
cargo check --workspace --all-targets --all-features: PASSED
cargo clippy --workspace --all-targets --all-features -- -D warnings: PASSED
cargo test --workspace --all-targets: PASSED (251 passing tests)
cargo test --features gtk -p root-gui: PASSED (30 passing tests)
cargo doc --workspace --no-deps: PASSED
python3 .github/scripts/check_invariants.py: PASSED (11 invariants passing)
```

### Verification Checklist

- [x] Horizontal view switcher removed from top header bar.
- [x] Left-side vertical navigation sidebar implemented using native GTK4/libadwaita styling.
- [x] All seven destinations present: Overview, Resources, Agents, Processes, Activity, Schedule, Settings.
- [x] Settings placed at the bottom of the sidebar.
- [x] Page switching functions cleanly across all seven destinations.
- [x] Empty states render meaningful guidance instead of appearing broken.
- [x] Keyboard shortcuts (`Ctrl+1` .. `Ctrl+7`) switch pages instantly.
- [x] Window title and subtitle synchronize with active destination.
- [x] No GTK runtime errors, assertion failures, or warnings during launch or navigation.
- [x] Strictly zero emojis across code, tests, UI labels, and documentation.
