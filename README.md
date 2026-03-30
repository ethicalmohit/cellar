# Cellar

A terminal UI for monitoring your Homebrew packages and macOS applications — with vulnerability scanning, disk usage, outdated alerts, dependency inspection, service management, and one-key upgrades/uninstalls.

```
 cellar  [1] Formulae  [2] Casks  [3] Apps  [4] Vulnerabilities  [5] Services  [6] Taps

 Name          Version    Latest     Size      Status    Description
 ─────────────────────────────────────────────────────────────────────────────
 gnupg         2.4.7      2.4.7      45.2 MB   ● CVE     GNU Privacy Guard
 terraform     1.9.0      1.10.0     58.1 MB   ↑ outdated  Infrastructure as Code tool
 sops          3.9.1      3.9.1      7.2 MB    ✓ ok      Encryption for secrets
 tmux          3.5a       3.5a       1.3 MB    ✓ ok      Terminal multiplexer

 scan: 14:32:01  ·  18 formulae  ·  5 casks  ·  77 apps  ·  2 CVEs  ·  3/8 services
 [/] filter  [s/S] sort  [u] upgrade  [x] uninstall  [d] deps  [r] refresh  [q] quit
```

## Features

- **Six tabs** — Formulae, Casks, macOS Apps, Vulnerabilities, Services, Taps
- **Package descriptions** — what each package does, shown inline and in full in the detail panel
- **Service management** — start, stop, and restart Homebrew services directly from the TUI
- **CVE scanning** — queries the [OSV database](https://osv.dev) for known vulnerabilities across all installed packages
- **Outdated detection** — shows available upgrades via `brew outdated`
- **Disk usage** — real sizes for every formula, cask, and app
- **Live filter** — press `/` and type to filter any tab instantly
- **Sort by column** — `s` cycles columns, `S` flips direction
- **One-key upgrade** — press `u` on any outdated package, confirm with `y`
- **One-key uninstall** — press `x` on any formula or cask, confirm with `y`
- **Dependency tree** — press `d` to view the full dep tree and reverse deps
- **Detail panel** — press `enter` for full package info, homepage, license, caveats, and CVE details

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
| `1` / `2` / `3` / `4` / `5` / `6` | Switch to Formulae / Casks / Apps / Vulns / Services / Taps tab |
| `Tab` | Cycle to next tab |
| `↑` / `↓` or `j` / `k` | Navigate rows |
| `Enter` | Show detail panel (packages) or service action menu |
| `Esc` | Close panel / clear filter / cancel |
| `/` | Enter filter mode (type to search) |
| `s` | Cycle sort column |
| `S` | Flip sort direction (▲ / ▼) |
| `u` | Upgrade selected package (formulae/casks only, outdated only) |
| `x` | Uninstall selected package (formulae/casks only) |
| `d` | Show dependency tree + reverse dependencies |
| `r` | Refresh all data |
| `q` / `Ctrl+C` | Quit |

**Service action menu** (press `Enter` on a service):

| Key | Action |
|-----|--------|
| `s` | Start the service |
| `o` | Stop the service |
| `R` | Restart the service |
| `Esc` | Cancel |

### Tabs

**Formulae** — all installed Homebrew formulae with version, latest available, disk size, status, and description.

**Casks** — all installed Homebrew casks with the same columns.

**Apps** — all apps found in `/Applications` and `/System/Applications`, showing name, version, build number, and size.

**Vulnerabilities** — flattened list of all CVEs found across formulae and casks, with severity, CVE ID, and summary. Severity is colour-coded: red = critical/high, yellow = medium, grey = low.

**Services** — all Homebrew-managed services with name, status (● started / ○ stopped / ✗ error), user, and plist file. Press `Enter` to start, stop, or restart any service.

**Taps** — all installed Homebrew taps with tap name, formula count, cask count, and remote URL. Press `Enter` for full tap details including branch and last commit time.

## How vulnerability scanning works

Cellar queries the [OSV API](https://osv.dev) (`https://api.osv.dev/v1/query`) for each installed package using the `Homebrew` ecosystem. No API key is required. Results are cached for the session and refreshed when you press `r`.

## Project structure

```
cellar/
├── main.go           # entry point
├── data/
│   ├── brew.go       # brew info/outdated/list via shell (incl. package metadata)
│   ├── apps.go       # /Applications scanner + plist parser
│   ├── osv.go        # OSV vulnerability API client
│   ├── deps.go       # brew deps / brew uses
│   ├── services.go   # brew services list/start/stop/restart
│   ├── taps.go       # brew tap-info --installed --json
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
