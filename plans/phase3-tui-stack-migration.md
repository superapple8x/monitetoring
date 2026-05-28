# Phase 3: TUI Stack Migration Plan

## Goal
Upgrade `crossterm` 0.27 → 0.29 and `ratatui` 0.26 → 0.30 simultaneously (they are coupled).

## Summary of Breaking Changes

### ratatui 0.28 (the big one)

#### 1. Layout API — Complete Rewrite
The builder-pattern `Layout` was replaced with `Layout::vertical()` / `Layout::horizontal()` constructors.  
`Direction` enum is removed.

**Old pattern:**
```rust
Layout::default()
    .direction(Direction::Vertical)
    .margin(1)
    .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
    .split(area)
```

**New pattern:**
```rust
Layout::vertical([Constraint::Length(3), Constraint::Min(0)])
    .margin(1)
    .split(area)
```

For horizontal:
```rust
// Old
Layout::default().direction(Direction::Horizontal).constraints([...].as_ref()).split(area)
// New
Layout::horizontal([...]).split(area)
```

**Key points:**
- `.constraints()` now takes owned values — no more `.as_ref()` needed
- `Constraint::Percentage(100)` still works
- `.margin()` still works
- `vec![...]` still works for dynamic constraints

#### 2. Table::new Constructor
`Table::new(rows, widths)` now accepts `impl IntoIterator<Item = Constraint>` where `Constraint: Clone`.  
Most existing code passing `&[Constraint]` should still compile because `&[T]` implements `IntoIterator` and `&Constraint` can be cloned into `Constraint`.

**Potential issues:** Some edge cases where `&Vec<Constraint>` needs explicit `as_slice()` or clone.

#### 3. Clear Widget
`ratatui::widgets::Clear` should still exist at the same path. May need `Clear::default()` instead of bare `Clear` struct.

### crossterm 0.27 → 0.29
Mostly backward-compatible for this project's usage. No code changes expected beyond the version bump.

---

## File-by-File Migration Map

### 0. Cargo.toml
```
- crossterm = "0.27"
+ crossterm = "0.29"

- ratatui = "0.26"
+ ratatui = "0.30"
```

### 1. src/ui/mod.rs — 1 change area

| Line(s) | Current Code | Change |
|---------|-------------|--------|
| 40 | `use ratatui::widgets::Clear;` | Verify still compiles; may need no change |
| 41 | `f.render_widget(Clear, f.size());` | May need `Clear::default()` |

### 2. src/ui/renderers/normal.rs — 7 Layout + 2 Table

| Lines | Type | Migration |
|-------|------|-----------|
| 32–45 | Layout V + margin + 4 dynamic constraints | `Layout::vertical([...]).margin(1).split(f.size())` |
| 47–59 | Layout V + margin + 3 dynamic constraints | Same as above |
| 72–76 | Layout H + `.as_ref()` | `Layout::horizontal([...]).split(main_chunks[1])` — remove `.as_ref()` |
| 78–81 | Layout H + `.as_ref()` | Same |
| 97–107 | Layout V + `vec![]` dynamic | `Layout::vertical(vec![...]).split(content_chunks[0])` |
| 495–498 | Layout V + `.as_ref()` | `Layout::vertical([...]).split(area)` — remove `.as_ref()` |
| 546–549 | Layout V + `.as_ref()` | Same |
| 298 | `Table::new(rows, widths)` where widths: `&[Constraint; N]` | Should work; verify |
| 396 | `Table::new(rows, &widths)` where widths: `Vec<Constraint>` | May need `widths.as_slice()` or just `widths` |

**Also:** Remove `Direction` from imports (line 3).

### 3. src/ui/renderers/bandwidth.rs — 2 Layout + 2 Table

| Lines | Type | Migration |
|-------|------|-----------|
| 28–40 | Layout V + margin + `.as_ref()` | `Layout::vertical([...]).margin(1).split(f.size())` |
| 51–63 | Layout V + margin + `.as_ref()` | Same |
| 181 | `Table::new(rows, widths)` where widths: `&[Constraint; N]` | Verify |
| 277 | `Table::new(rows, widths)` where widths: `&[Constraint; N]` | Verify |

**Also:** Remove `Direction` from imports (line 3).

### 4. src/ui/renderers/overview.rs — 4 Layout + 1 Table

| Lines | Type | Migration |
|-------|------|-----------|
| 14–22 | Layout V + margin | `Layout::vertical([...]).margin(1).split(f.size())` |
| 47–53 | Layout V | `Layout::vertical([...]).split(area)` |
| 102–108 | Layout H | `Layout::horizontal([...]).split(proto_inner)` |
| 113–119 | Layout V | `Layout::vertical([...]).split(protocol_chunks[1])` |
| 221–229 | `Table::new(rows, [...])` inline array | Verify |

**Also:** Remove `Direction` from imports (line 3).

### 5. src/ui/renderers/alert.rs — 1 Layout

| Lines | Type | Migration |
|-------|------|-----------|
| 12–24 | Layout V + margin(2) + `.as_ref()` | `Layout::vertical([...]).margin(2).split(f.size())` |

**Also:** Remove `Direction` from imports (line 3).

### 6. src/ui/renderers/settings.rs — 3 Layout

| Lines | Type | Migration |
|-------|------|-----------|
| 14–23 | Layout V + margin | `Layout::vertical([...]).margin(1).split(f.size())` |
| 25–33 | Layout V + margin | Same |
| 58–64 | Layout H | `Layout::horizontal([...]).split(area)` |

**Also:** Remove `Direction` from imports (line 3).

### 7. src/ui/renderers/packet_details/render.rs — 2 Layout + 1 Table

| Lines | Type | Migration |
|-------|------|-----------|
| 29–38 | Layout V (conditional) | `Layout::vertical([...]).split(area)` |
| 40–48 | Layout V (else branch) | Same |
| 200 | `Table::new(rows, &constraints)` where constraints: `Vec<Constraint>` | May need just `constraints` instead of `&constraints` |

**Also:** Remove `Direction` from imports (line 1, if present).

### 8. src/ui/charts.rs
No Layout or Table calls. `Chart`, `Dataset`, `Axis`, `BarChart`, `BarGroup` APIs unchanged.  
Verify `ratatui::symbols::Marker::Braille` and `GraphType::Line` still exist.

---

## Files NOT Affected (no changes expected)
- `src/ui/terminal.rs` — crossterm backend usage is stable
- `src/ui/input.rs` — only uses `crossterm::event::KeyCode` (stable)
- `src/ui/utils.rs` — no ratatui/crossterm imports
- `src/ui/widgets/mod.rs` — placeholder only
- `src/ui/renderers/packet_details/layout.rs` — only uses `Constraint`, `Row`, `Cell`, `Span`, `Style` (stable)
- `src/ui/renderers/packet_details/cache.rs` — only uses `Style`, `Color` (stable)
- `src/ui/renderers/packet_details/export.rs` — no UI imports
- `src/ui/renderers/packet_details/utils.rs` — only uses `Color` (stable)
- `src/main.rs` — only uses `crossterm::event` (stable)
- `src/interactive.rs` — only uses `crossterm::event` (stable)

---

## Execution Order (within Phase 3)

1. **Bump `Cargo.toml`** versions first — this lets `cargo check` drive the migration
2. **`cargo check`** — see what breaks; the compiler will pinpoint exact errors
3. **Fix errors file-by-file** in order: normal → bandwidth → overview → alert → settings → packet_details/render → mod.rs
4. **Remove `Direction` imports** from all files that no longer need it
5. **`cargo check`** — verify clean
6. **`cargo clippy --all-targets`** — check for warnings
7. **`cargo build --release`** — final verification
8. **Smoke test** — run the binary to verify TUI renders correctly
