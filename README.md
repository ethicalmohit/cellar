# Cellar

A terminal UI for monitoring your Homebrew packages and macOS applications — with vulnerability scanning, disk usage, outdated alerts, dependency inspection, and one-key upgrades/uninstalls.

```
 cellar  [1] Formulae  [2] Casks  [3] Apps  [4] Vulnerabilities

 Name          Version    Latest     Size      Status
 ────────────────────────────────────────────────────────────
 gnupg         2.4.7      2.4.7      45.2 MB   ● CVE
 terraform     1.9.0      1.10.0     58.1 MB   ↑ outdated
 sops          3.9.1      3.9.1      7.2 MB    ✓ ok
 tmux          3.5a       3.5a       1.3 MB    ✓ ok

 scan: 14:32:01  ·  18 formulae  ·  5 casks  ·  77 apps  ·  2 CVEs
 [/] filter  [s/S] sort  [u] upgrade  [x] uninstall  [d] deps  [r] refresh  [q] quit
```

## Features

- **Four tabs** — Formulae, Casks, macOS Apps, Vulnerabilities
- **CVE scanning** — queries the [OSV database](https://osv.dev) for known vulnerabilities across all installed packages
- **Outdated detection** — shows available upgrades via `brew outdated`
- **Disk usage** — real sizes for every formula, cask, and app
- **Live filter** — press `/` and type to filter any tab instantly
- **Sort by column** — `s` cycles columns, `S` flips direction
- **One-key upgrade** — press `u` on any outdated package, confirm with `y`
- **One-key uninstall** — press `x` on any formula or cask, confirm with `y`
- **Dependency tree** — press `d` to view the full dep tree and reverse deps
- **Detail panel** — press `enter` for full package info + CVE details

## Requirements

- macOS (Intel or Apple Silicon)
- [Homebrew](https://brew.sh) installed

## Installation

### Build from source

```bash
git clone https://github.com/mohit/cellar
cd cellar
make install
```

This builds the binary and copies it to `/usr/local/bin/cellar`.

### Go install

```bash
go install github.com/mohit/cellar@latest
```

### Manual build

```bash
git clone https://github.com/mohit/cellar
cd cellar
go build -o cellar .
./cellar
```

## Usage

```bash
cellar
```

Cellar opens full-screen. All data loads asynchronously — vulnerability scanning runs after packages load and may take a few seconds depending on how many packages you have.

### Key bindings

| Key | Action |
|-----|--------|
| `1` / `2` / `3` / `4` | Switch to Formulae / Casks / Apps / Vulns tab |
| `Tab` | Cycle to next tab |
| `↑` / `↓` or `j` / `k` | Navigate rows |
| `Enter` | Show detail panel |
| `Esc` | Close panel / clear filter |
| `/` | Enter filter mode (type to search) |
| `s` | Cycle sort column |
| `S` | Flip sort direction (▲ / ▼) |
| `u` | Upgrade selected package (formulae/casks only, outdated only) |
| `x` | Uninstall selected package (formulae/casks only) |
| `d` | Show dependency tree + reverse dependencies |
| `r` | Refresh all data |
| `q` / `Ctrl+C` | Quit |

### Tabs

**Formulae** — all installed Homebrew formulae with version, latest available, disk size, and status.

**Casks** — all installed Homebrew casks with the same columns.

**Apps** — all apps found in `/Applications` and `/System/Applications`, showing name, version, build number, and size.

**Vulnerabilities** — flattened list of all CVEs found across formulae and casks, with severity, CVE ID, and summary. Severity is colour-coded: red = critical/high, yellow = medium, grey = low.

## How vulnerability scanning works

Cellar queries the [OSV API](https://osv.dev) (`https://api.osv.dev/v1/query`) for each installed package using the `Homebrew` ecosystem. No API key is required. Results are cached for the session and refreshed when you press `r`.

## Project structure

```
cellar/
├── main.go           # entry point
├── data/
│   ├── brew.go       # brew info/outdated/list via shell
│   ├── apps.go       # /Applications scanner + plist parser
│   ├── osv.go        # OSV vulnerability API client
│   ├── deps.go       # brew deps / brew uses
│   ├── upgrade.go    # brew upgrade wrapper
│   └── uninstall.go  # brew uninstall wrapper
└── ui/
    ├── model.go      # Bubble Tea model, all state + key handling
    └── styles.go     # Lip Gloss color/style definitions
```

## Built with

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) — TUI framework
- [Bubbles](https://github.com/charmbracelet/bubbles) — table, spinner, textinput, viewport
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) — styling
- [howett.net/plist](https://github.com/DHowett/go-plist) — macOS plist parsing
- [OSV](https://osv.dev) — open-source vulnerability database

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
