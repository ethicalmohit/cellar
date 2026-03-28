# Contributing to Cellar

Thanks for your interest in contributing.

## Getting started

```bash
git clone https://github.com/mohit/cellar
cd cellar
go build ./...
```

Run the app directly:

```bash
go run .
```

## Project structure

```
cellar/
├── main.go           # entry point — wires Bubble Tea program
├── data/             # all data-fetching and shell-out logic
│   ├── brew.go       # formulae + casks: info, outdated, sizes
│   ├── apps.go       # /Applications plist scanner
│   ├── osv.go        # OSV vulnerability API client
│   ├── deps.go       # dependency tree (brew deps / brew uses)
│   ├── upgrade.go    # brew upgrade
│   └── uninstall.go  # brew uninstall
└── ui/
    ├── model.go      # Bubble Tea model: state, messages, key handling, views
    └── styles.go     # Lip Gloss styles and colour palette
```

The `data` package is pure logic — no TUI code. The `ui` package is pure presentation — it calls into `data` via `tea.Cmd` goroutines and never blocks the render loop.

## Making changes

**Adding a new data source** — add a function in `data/` that returns a value or error, then wire it up as a `tea.Cmd` in `ui/model.go` following the existing pattern (`loadFormulae`, `loadApps`, etc.).

**Adding a new tab** — add a constant to the `tab` iota, extend `tabNames`, add a `tabState` entry, add a table field to `Model`, wire up the key handler in `handleKey`, and add a case to `renderBody`.

**Changing styles** — edit `ui/styles.go`. Colours use the Catppuccin Mocha palette.

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Update `README.md` if you add or change key bindings or features
- Run `go build ./...` and `go vet ./...` before submitting
- There are no automated tests yet — manual testing against a real Homebrew installation is expected

## Reporting issues

Please include:
- macOS version
- Homebrew version (`brew --version`)
- Terminal emulator and size
- Steps to reproduce
