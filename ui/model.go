package ui

import (
	"github.com/mohit/cellar/data"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type tab int

const (
	tabFormulae tab = iota
	tabCasks
	tabApps
	tabVulns
)

var tabNames = []string{"Formulae", "Casks", "Apps", "Vulnerabilities"}

type uiMode int

const (
	modeNormal uiMode = iota
	modeFilter
	modeConfirm
	modeDetail
	modeDeps
	modeUpgrading
	modeUninstalling
)

type confirmAction int

const (
	actionUpgrade confirmAction = iota
	actionUninstall
)

type tabState struct {
	filter  string
	sortCol int // -1 = no sort
	sortAsc bool
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

type formulaeLoadedMsg []data.Package
type casksLoadedMsg []data.Package
type appsLoadedMsg []data.App
type vulnsLoadedMsg struct {
	formulae []data.Package
	casks    []data.Package
}
type depsLoadedMsg data.DepInfo
type upgradeDoneMsg struct {
	name string
	err  error
}
type uninstallDoneMsg struct {
	name string
	err  error
}
type errMsg struct{ err error }

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type Model struct {
	activeTab tab
	width     int
	height    int
	loading      bool
	vulnsLoading bool
	lastScan     time.Time
	spinner      spinner.Model

	formulae []data.Package
	casks    []data.Package
	apps     []data.App

	fTable table.Model
	cTable table.Model
	aTable table.Model
	vTable table.Model

	tabStates [4]tabState

	mode uiMode

	filterInput textinput.Model

	// confirm upgrade / uninstall
	confirmPkg    string
	confirmFrom   string
	confirmTo     string
	confirmAction confirmAction
	actionMsg     string

	// deps panel
	depsViewport viewport.Model
	depsContent  string

	// detail panel
	detailContent string

	err error
}

func New() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorActive)

	fi := textinput.New()
	fi.Placeholder = "type to filter…"
	fi.CharLimit = 64

	states := [4]tabState{}
	for i := range states {
		states[i].sortCol = -1
		states[i].sortAsc = true
	}

	return Model{
		spinner:   s,
		loading:   true,
		filterInput: fi,
		tabStates: states,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, loadFormulae, loadCasks, loadApps)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func loadFormulae() tea.Msg {
	pkgs, err := data.LoadBrewFormulae()
	if err != nil {
		return errMsg{err}
	}
	return formulaeLoadedMsg(pkgs)
}

func loadCasks() tea.Msg {
	pkgs, err := data.LoadBrewCasks()
	if err != nil {
		return casksLoadedMsg(nil)
	}
	return casksLoadedMsg(pkgs)
}

func loadApps() tea.Msg {
	apps, err := data.LoadApps()
	if err != nil {
		return appsLoadedMsg(nil)
	}
	return appsLoadedMsg(apps)
}

func loadVulns(formulae, casks []data.Package) tea.Cmd {
	return func() tea.Msg {
		enrich := func(pkgs []data.Package) []data.Package {
			for i, p := range pkgs {
				if cves, err := data.QueryVulns(p.Name, p.Version); err == nil && len(cves) > 0 {
					pkgs[i].CVEs = cves
					pkgs[i].Vulnerable = true
				}
			}
			return pkgs
		}
		return vulnsLoadedMsg{formulae: enrich(formulae), casks: enrich(casks)}
	}
}

func loadDeps(name string) tea.Cmd {
	return func() tea.Msg {
		return depsLoadedMsg(data.LoadDepInfo(name))
	}
}

func upgradePackage(name string) tea.Cmd {
	return func() tea.Msg {
		err := data.UpgradePackage(name)
		return upgradeDoneMsg{name: name, err: err}
	}
}

func uninstallPackage(name string, isCask bool) tea.Cmd {
	return func() tea.Msg {
		err := data.UninstallPackage(name, isCask)
		return uninstallDoneMsg{name: name, err: err}
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.depsViewport = viewport.New(m.width-4, m.tableHeight())
		m.depsViewport.SetContent(m.depsContent)
		m.rebuildTables()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case formulaeLoadedMsg:
		m.formulae = []data.Package(msg)
		m.rebuildTables()
		m.checkDoneLoading(&cmds)

	case casksLoadedMsg:
		m.casks = []data.Package(msg)
		m.rebuildTables()
		m.checkDoneLoading(&cmds)

	case appsLoadedMsg:
		m.apps = []data.App(msg)
		m.rebuildTables()
		m.checkDoneLoading(&cmds)

	case vulnsLoadedMsg:
		m.formulae = msg.formulae
		m.casks = msg.casks
		m.vulnsLoading = false
		m.rebuildTables()
		m.vTable.Focus()

	case depsLoadedMsg:
		info := data.DepInfo(msg)
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Dependencies of %s:\n\n", info.Name))
		sb.WriteString(info.Tree)
		sb.WriteString("\n\n")
		if len(info.Dependents) == 0 {
			sb.WriteString("Required by: (none)")
		} else {
			sb.WriteString("Required by:\n  ")
			sb.WriteString(strings.Join(info.Dependents, "  "))
		}
		m.depsContent = sb.String()
		m.depsViewport.SetContent(m.depsContent)
		m.depsViewport.GotoTop()
		m.mode = modeDeps

	case upgradeDoneMsg:
		if msg.err != nil {
			m.actionMsg = StyleDanger.Render("✗ upgrade failed: " + msg.err.Error())
		} else {
			m.actionMsg = StyleOk.Render("✓ upgraded " + msg.name)
		}
		m.mode = modeNormal
		m.loading = true
		cmds = append(cmds, tea.Batch(m.spinner.Tick, loadFormulae, loadCasks))

	case uninstallDoneMsg:
		if msg.err != nil {
			m.actionMsg = StyleDanger.Render("✗ uninstall failed: " + msg.err.Error())
		} else {
			m.actionMsg = StyleOk.Render("✓ uninstalled " + msg.name)
		}
		m.mode = modeNormal
		m.loading = true
		cmds = append(cmds, tea.Batch(m.spinner.Tick, loadFormulae, loadCasks))

	case errMsg:
		m.err = msg.err
		m.loading = false

	case tea.KeyMsg:
		cmds = append(cmds, m.handleKey(msg)...)
	}

	// Forward navigation to active table when in normal mode
	if m.mode == modeNormal {
		switch m.activeTab {
		case tabFormulae:
			m.fTable, _ = m.fTable.Update(msg)
		case tabCasks:
			m.cTable, _ = m.cTable.Update(msg)
		case tabApps:
			m.aTable, _ = m.aTable.Update(msg)
		case tabVulns:
			m.vTable, _ = m.vTable.Update(msg)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleKey(msg tea.KeyMsg) []tea.Cmd {
	var cmds []tea.Cmd

	switch m.mode {

	case modeFilter:
		switch msg.String() {
		case "esc":
			m.mode = modeNormal
			m.filterInput.Blur()
		case "enter":
			m.mode = modeNormal
			m.filterInput.Blur()
		default:
			var cmd tea.Cmd
			m.filterInput, cmd = m.filterInput.Update(msg)
			m.tabStates[m.activeTab].filter = m.filterInput.Value()
			m.rebuildTables()
			cmds = append(cmds, cmd)
		}

	case modeConfirm:
		switch msg.String() {
		case "y", "Y":
			if m.confirmAction == actionUninstall {
				m.mode = modeUninstalling
				isCask := m.activeTab == tabCasks
				cmds = append(cmds, tea.Batch(m.spinner.Tick, uninstallPackage(m.confirmPkg, isCask)))
			} else {
				m.mode = modeUpgrading
				cmds = append(cmds, tea.Batch(m.spinner.Tick, upgradePackage(m.confirmPkg)))
			}
		case "n", "N", "esc", "q":
			m.mode = modeNormal
		}

	case modeDetail:
		m.mode = modeNormal

	case modeDeps:
		switch msg.String() {
		case "esc", "q", "d":
			m.mode = modeNormal
		default:
			var cmd tea.Cmd
			m.depsViewport, cmd = m.depsViewport.Update(msg)
			cmds = append(cmds, cmd)
		}

	case modeUpgrading:
		// block all input while upgrading

	case modeNormal:
		switch msg.String() {
		case "q", "ctrl+c":
			cmds = append(cmds, tea.Quit)
		case "1":
			m.switchTab(tabFormulae)
		case "2":
			m.switchTab(tabCasks)
		case "3":
			m.switchTab(tabApps)
		case "4":
			m.switchTab(tabVulns)
		case "tab":
			m.switchTab((m.activeTab + 1) % 4)
		case "r":
			m.loading = true
			m.vulnsLoading = false
			m.actionMsg = ""
			m.err = nil
			cmds = append(cmds, tea.Batch(m.spinner.Tick, loadFormulae, loadCasks, loadApps))
		case "/":
			m.mode = modeFilter
			m.filterInput.SetValue(m.tabStates[m.activeTab].filter)
			m.filterInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "esc":
			// clear filter for current tab
			m.tabStates[m.activeTab].filter = ""
			m.filterInput.SetValue("")
			m.rebuildTables()
		case "s":
			st := &m.tabStates[m.activeTab]
			maxCol := m.maxSortCol()
			if st.sortCol == maxCol {
				st.sortCol = -1
			} else {
				if st.sortCol == -1 {
					st.sortCol = 0
					st.sortAsc = true
				} else {
					st.sortCol++
					st.sortAsc = true
				}
			}
			m.rebuildTables()
		case "S":
			st := &m.tabStates[m.activeTab]
			if st.sortCol >= 0 {
				st.sortAsc = !st.sortAsc
				m.rebuildTables()
			}
		case "enter":
			m.detailContent = m.buildDetail()
			if m.detailContent != "" {
				m.mode = modeDetail
			}
		case "u":
			if m.activeTab == tabFormulae || m.activeTab == tabCasks {
				m.tryConfirmUpgrade()
			}
		case "x":
			if m.activeTab == tabFormulae || m.activeTab == tabCasks {
				m.tryConfirmUninstall()
			}
		case "d":
			if m.activeTab == tabFormulae || m.activeTab == tabCasks {
				if name := m.selectedName(); name != "" {
					cmds = append(cmds, loadDeps(name))
				}
			}
		}
	}

	return cmds
}

func (m *Model) switchTab(t tab) {
	m.activeTab = t
	m.filterInput.SetValue(m.tabStates[t].filter)
}

func (m *Model) maxSortCol() int {
	switch m.activeTab {
	case tabFormulae, tabCasks:
		return 4 // Name, Version, Latest, Size, Status
	case tabApps:
		return 3 // Name, Version, Build, Size
	case tabVulns:
		return 4 // Package, Version, CVE ID, Severity, Summary
	}
	return 0
}

func (m *Model) tryConfirmUpgrade() {
	pkg := m.selectedPkg()
	if pkg == nil || !pkg.Outdated {
		return
	}
	m.confirmPkg = pkg.Name
	m.confirmFrom = pkg.Version
	m.confirmTo = pkg.Latest
	m.confirmAction = actionUpgrade
	m.mode = modeConfirm
}

func (m *Model) tryConfirmUninstall() {
	pkg := m.selectedPkg()
	if pkg == nil {
		return
	}
	m.confirmPkg = pkg.Name
	m.confirmFrom = pkg.Version
	m.confirmTo = ""
	m.confirmAction = actionUninstall
	m.mode = modeConfirm
}

func (m *Model) selectedPkg() *data.Package {
	name := m.selectedName()
	if name == "" {
		return nil
	}
	switch m.activeTab {
	case tabFormulae:
		for i := range m.formulae {
			if m.formulae[i].Name == name {
				return &m.formulae[i]
			}
		}
	case tabCasks:
		for i := range m.casks {
			if m.casks[i].Name == name {
				return &m.casks[i]
			}
		}
	}
	return nil
}

func (m *Model) selectedName() string {
	var row table.Row
	switch m.activeTab {
	case tabFormulae:
		row = m.fTable.SelectedRow()
	case tabCasks:
		row = m.cTable.SelectedRow()
	case tabApps:
		row = m.aTable.SelectedRow()
	case tabVulns:
		row = m.vTable.SelectedRow()
	}
	if row == nil {
		return ""
	}
	return row[0]
}

func (m *Model) checkDoneLoading(cmds *[]tea.Cmd) {
	if m.formulae != nil && m.casks != nil && m.apps != nil {
		m.loading = false
		m.lastScan = time.Now()
		m.vulnsLoading = true
		*cmds = append(*cmds, loadVulns(m.formulae, m.casks))
	}
}

// ---------------------------------------------------------------------------
// Table building
// ---------------------------------------------------------------------------

func (m *Model) tableHeight() int {
	h := m.height - 8 // header(1) + divider(1) + filter(1) + divider(1) + stats(1) + keys(1) + padding(2)
	if h < 5 {
		h = 5
	}
	return h
}

func (m *Model) rebuildTables() {
	th := m.tableHeight()
	cw := m.width - 4
	if cw < 60 {
		cw = 60
	}
	fState := m.tabStates[tabFormulae]
	cState := m.tabStates[tabCasks]
	aState := m.tabStates[tabApps]
	vState := m.tabStates[tabVulns]

	m.fTable = buildPackageTable(filteredPkgs(m.formulae, fState.filter), cw, th, fState.sortCol, fState.sortAsc)
	m.cTable = buildPackageTable(filteredPkgs(m.casks, cState.filter), cw, th, cState.sortCol, cState.sortAsc)
	m.aTable = buildAppTable(filteredApps(m.apps, aState.filter), cw, th, aState.sortCol, aState.sortAsc)
	m.vTable = buildVulnTable(filteredPkgs(m.formulae, vState.filter), filteredPkgs(m.casks, vState.filter), cw, th, vState.sortCol, vState.sortAsc)

	if m.depsContent != "" {
		m.depsViewport.Width = cw
		m.depsViewport.Height = th
		m.depsViewport.SetContent(m.depsContent)
	}
}

// ---------------------------------------------------------------------------
// Filter helpers
// ---------------------------------------------------------------------------

func filteredPkgs(pkgs []data.Package, query string) []data.Package {
	if query == "" {
		return pkgs
	}
	q := strings.ToLower(query)
	var out []data.Package
	for _, p := range pkgs {
		if strings.Contains(strings.ToLower(p.Name), q) ||
			strings.Contains(strings.ToLower(p.Version), q) ||
			strings.Contains(strings.ToLower(p.Latest), q) {
			out = append(out, p)
		}
	}
	return out
}

func filteredApps(apps []data.App, query string) []data.App {
	if query == "" {
		return apps
	}
	q := strings.ToLower(query)
	var out []data.App
	for _, a := range apps {
		if strings.Contains(strings.ToLower(a.Name), q) ||
			strings.Contains(strings.ToLower(a.Version), q) {
			out = append(out, a)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Sort helpers
// ---------------------------------------------------------------------------

func sortedPkgs(pkgs []data.Package, col int, asc bool) []data.Package {
	if col < 0 {
		return pkgs
	}
	cp := make([]data.Package, len(pkgs))
	copy(cp, pkgs)
	sort.SliceStable(cp, func(i, j int) bool {
		var less bool
		switch col {
		case 0:
			less = cp[i].Name < cp[j].Name
		case 1:
			less = cp[i].Version < cp[j].Version
		case 2:
			less = cp[i].Latest < cp[j].Latest
		case 3:
			less = cp[i].SizeBytes < cp[j].SizeBytes
		case 4:
			// status priority: vulnerable > outdated > ok
			less = pkgStatusPriority(cp[i]) < pkgStatusPriority(cp[j])
		}
		if !asc {
			return !less
		}
		return less
	})
	return cp
}

func pkgStatusPriority(p data.Package) int {
	if p.Vulnerable {
		return 0
	}
	if p.Outdated {
		return 1
	}
	return 2
}

func sortedApps(apps []data.App, col int, asc bool) []data.App {
	if col < 0 {
		return apps
	}
	cp := make([]data.App, len(apps))
	copy(cp, apps)
	sort.SliceStable(cp, func(i, j int) bool {
		var less bool
		switch col {
		case 0:
			less = cp[i].Name < cp[j].Name
		case 1:
			less = cp[i].Version < cp[j].Version
		case 2:
			less = cp[i].Build < cp[j].Build
		case 3:
			less = cp[i].Size < cp[j].Size
		}
		if !asc {
			return !less
		}
		return less
	})
	return cp
}

// ---------------------------------------------------------------------------
// Table builders
// ---------------------------------------------------------------------------

func sortIndicator(col, activeCol int, asc bool) string {
	if col != activeCol || activeCol < 0 {
		return ""
	}
	if asc {
		return " ▲"
	}
	return " ▼"
}

func buildPackageTable(pkgs []data.Package, width, height, sortCol int, sortAsc bool) table.Model {
	pkgs = sortedPkgs(pkgs, sortCol, sortAsc)

	nameW := width / 4
	verW := 12
	latestW := 12
	sizeW := 10
	statusW := width - nameW - verW - latestW - sizeW - 6
	if statusW < 10 {
		statusW = 10
	}

	cols := []table.Column{
		{Title: "Name" + sortIndicator(0, sortCol, sortAsc), Width: nameW},
		{Title: "Version" + sortIndicator(1, sortCol, sortAsc), Width: verW},
		{Title: "Latest" + sortIndicator(2, sortCol, sortAsc), Width: latestW},
		{Title: "Size" + sortIndicator(3, sortCol, sortAsc), Width: sizeW},
		{Title: "Status" + sortIndicator(4, sortCol, sortAsc), Width: statusW},
	}

	rows := make([]table.Row, 0, len(pkgs))
	for _, p := range pkgs {
		sev := ""
		if len(p.CVEs) > 0 {
			sev = p.CVEs[0].Severity
		}
		rows = append(rows, table.Row{
			p.Name,
			p.Version,
			p.Latest,
			data.FormatSize(p.SizeBytes),
			StatusIcon(p.Outdated, p.Vulnerable, sev),
		})
	}
	return styledTable(cols, rows, height)
}

func buildAppTable(apps []data.App, width, height, sortCol int, sortAsc bool) table.Model {
	apps = sortedApps(apps, sortCol, sortAsc)

	nameW := width / 3
	verW := 15
	buildW := 15
	sizeW := width - nameW - verW - buildW - 4
	if sizeW < 8 {
		sizeW = 8
	}

	cols := []table.Column{
		{Title: "Name" + sortIndicator(0, sortCol, sortAsc), Width: nameW},
		{Title: "Version" + sortIndicator(1, sortCol, sortAsc), Width: verW},
		{Title: "Build" + sortIndicator(2, sortCol, sortAsc), Width: buildW},
		{Title: "Size" + sortIndicator(3, sortCol, sortAsc), Width: sizeW},
	}

	rows := make([]table.Row, 0, len(apps))
	for _, a := range apps {
		rows = append(rows, table.Row{a.Name, a.Version, a.Build, data.FormatSize(a.Size)})
	}
	return styledTable(cols, rows, height)
}

type vulnRow struct {
	pkg      string
	version  string
	cveID    string
	severity string
	summary  string
}

func buildVulnTable(formulae, casks []data.Package, width, height, sortCol int, sortAsc bool) table.Model {
	pkgW := width / 5
	verW := 12
	cveW := 16
	sevW := 10
	sumW := width - pkgW - verW - cveW - sevW - 6
	if sumW < 10 {
		sumW = 10
	}

	cols := []table.Column{
		{Title: "Package" + sortIndicator(0, sortCol, sortAsc), Width: pkgW},
		{Title: "Version" + sortIndicator(1, sortCol, sortAsc), Width: verW},
		{Title: "CVE ID" + sortIndicator(2, sortCol, sortAsc), Width: cveW},
		{Title: "Severity" + sortIndicator(3, sortCol, sortAsc), Width: sevW},
		{Title: "Summary" + sortIndicator(4, sortCol, sortAsc), Width: sumW},
	}

	var vrows []vulnRow
	for _, p := range append(formulae, casks...) {
		for _, cve := range p.CVEs {
			vrows = append(vrows, vulnRow{p.Name, p.Version, cve.ID, cve.Severity, cve.Summary})
		}
	}

	if sortCol >= 0 {
		sort.SliceStable(vrows, func(i, j int) bool {
			var less bool
			switch sortCol {
			case 0:
				less = vrows[i].pkg < vrows[j].pkg
			case 1:
				less = vrows[i].version < vrows[j].version
			case 2:
				less = vrows[i].cveID < vrows[j].cveID
			case 3:
				less = sevPriority(vrows[i].severity) < sevPriority(vrows[j].severity)
			case 4:
				less = vrows[i].summary < vrows[j].summary
			}
			if !sortAsc {
				return !less
			}
			return less
		})
	}

	rows := make([]table.Row, 0, len(vrows))
	for _, v := range vrows {
		sevStyle := StyleWarn
		if v.severity == "critical" || v.severity == "high" {
			sevStyle = StyleDanger
		} else if v.severity == "low" {
			sevStyle = StyleMuted
		}
		rows = append(rows, table.Row{v.pkg, v.version, v.cveID, sevStyle.Render(v.severity), v.summary})
	}
	return styledTable(cols, rows, height)
}

func sevPriority(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func styledTable(cols []table.Column, rows []table.Row, height int) table.Model {
	t := table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(height),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(colorBorder).BorderBottom(true).Bold(true)
	s.Selected = StyleSelected
	t.SetStyles(s)
	return t
}

// ---------------------------------------------------------------------------
// Detail builders
// ---------------------------------------------------------------------------

func (m Model) buildDetail() string {
	switch m.activeTab {
	case tabFormulae:
		if row := m.fTable.SelectedRow(); row != nil {
			for _, p := range m.formulae {
				if p.Name == row[0] {
					return packageDetail(p)
				}
			}
		}
	case tabCasks:
		if row := m.cTable.SelectedRow(); row != nil {
			for _, p := range m.casks {
				if p.Name == row[0] {
					return packageDetail(p)
				}
			}
		}
	case tabApps:
		if row := m.aTable.SelectedRow(); row != nil {
			for _, a := range m.apps {
				if a.Name == row[0] {
					return fmt.Sprintf("Name:    %s\nVersion: %s\nBuild:   %s\nSize:    %s\nPath:    %s",
						a.Name, a.Version, a.Build, data.FormatSize(a.Size), a.Path)
				}
			}
		}
	case tabVulns:
		if row := m.vTable.SelectedRow(); row != nil {
			return fmt.Sprintf("Package:  %s\nVersion:  %s\nCVE ID:   %s\nSeverity: %s\nSummary:  %s",
				row[0], row[1], row[2], row[3], row[4])
		}
	}
	return ""
}

func packageDetail(p data.Package) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name:    %s\n", p.Name))
	sb.WriteString(fmt.Sprintf("Version: %s\n", p.Version))
	sb.WriteString(fmt.Sprintf("Latest:  %s\n", p.Latest))
	sb.WriteString(fmt.Sprintf("Size:    %s\n", data.FormatSize(p.SizeBytes)))
	if p.Outdated {
		sb.WriteString(StyleWarn.Render("\n⚠  Update available\n"))
	}
	if len(p.CVEs) > 0 {
		sb.WriteString("\nVulnerabilities:\n")
		for _, c := range p.CVEs {
			sb.WriteString(fmt.Sprintf("  %s [%s]  %s\n", c.ID, c.Severity, c.Summary))
			sb.WriteString(StyleMuted.Render(fmt.Sprintf("  %s\n\n", c.URL)))
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m Model) View() string {
	if m.width == 0 {
		return "Initializing…"
	}

	// ── Header ──────────────────────────────────────────────────────────────
	title := StyleTitle.Render("brew-monitor")
	tabs := ""
	for i, name := range tabNames {
		if tab(i) == m.activeTab {
			tabs += StyleTabActive.Render(fmt.Sprintf("[%d] %s", i+1, name))
		} else {
			tabs += StyleTabInactive.Render(fmt.Sprintf("[%d] %s", i+1, name))
		}
	}
	header := lipgloss.JoinHorizontal(lipgloss.Left, title, "  ", tabs)
	divider := StyleMuted.Render(strings.Repeat("─", m.width))

	// ── Filter bar ──────────────────────────────────────────────────────────
	filterBar := m.renderFilterBar()

	// ── Body ────────────────────────────────────────────────────────────────
	body := m.renderBody()

	// ── Status bar ──────────────────────────────────────────────────────────
	statusBar := m.renderStatusBar()

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		filterBar,
		body,
		divider,
		statusBar,
	)
}

func (m Model) renderFilterBar() string {
	st := m.tabStates[m.activeTab]
	if m.mode == modeFilter {
		prompt := StyleWarn.Render("/") + " " + m.filterInput.View()
		return "  " + prompt
	}
	if st.filter != "" {
		return "  " + StyleMuted.Render("filter: ") + StyleWarn.Render(st.filter) + StyleMuted.Render("  [esc to clear]")
	}
	return StyleMuted.Render("  press / to filter")
}

func (m Model) renderBody() string {
	switch m.mode {
	case modeDetail:
		return StyleDetail.Width(m.width - 4).Render(m.detailContent) +
			StyleMuted.Render("\n  any key to close")

	case modeConfirm:
		var msg string
		if m.confirmAction == actionUninstall {
			msg = fmt.Sprintf(
				"Uninstall %s  (%s)\n\n  [y] confirm   [n/esc] cancel",
				StyleDanger.Render(m.confirmPkg),
				StyleMuted.Render(m.confirmFrom),
			)
		} else {
			msg = fmt.Sprintf(
				"Upgrade %s\n  %s  →  %s\n\n  [y] confirm   [n/esc] cancel",
				StyleTabActive.Render(m.confirmPkg),
				StyleMuted.Render(m.confirmFrom),
				StyleOk.Render(m.confirmTo),
			)
		}
		return StyleDetail.Width(m.width - 4).Render(msg)

	case modeDeps:
		header := StyleTabActive.Render("Dependency tree") + StyleMuted.Render("  [esc/d] close  [↑↓] scroll")
		return lipgloss.JoinVertical(lipgloss.Left, "  "+header, m.depsViewport.View())

	case modeUpgrading:
		return fmt.Sprintf("\n  %s Upgrading %s…\n", m.spinner.View(), StyleTabActive.Render(m.confirmPkg))

	case modeUninstalling:
		return fmt.Sprintf("\n  %s Uninstalling %s…\n", m.spinner.View(), StyleDanger.Render(m.confirmPkg))
	}

	// Normal / loading
	if m.loading {
		return fmt.Sprintf("\n  %s Loading data…\n", m.spinner.View())
	}
	if m.err != nil {
		return StyleDanger.Render(fmt.Sprintf("\n  Error: %v\n", m.err))
	}

	switch m.activeTab {
	case tabFormulae:
		return m.fTable.View()
	case tabCasks:
		return m.cTable.View()
	case tabApps:
		return m.aTable.View()
	case tabVulns:
		if m.vulnsLoading {
			return fmt.Sprintf("\n  %s Scanning for vulnerabilities…\n", m.spinner.View())
		}
		if len(m.vTable.Rows()) == 0 {
			return StyleMuted.Render("\n  No vulnerabilities found.")
		}
		return m.vTable.View()
	}
	return ""
}

func (m Model) renderStatusBar() string {
	scanTime := "—"
	if !m.lastScan.IsZero() {
		scanTime = m.lastScan.Format("15:04:05")
	}

	vulnCount, outdatedCount := 0, 0
	for _, p := range append(m.formulae, m.casks...) {
		vulnCount += len(p.CVEs)
		if p.Outdated {
			outdatedCount++
		}
	}

	parts := []string{
		fmt.Sprintf("scan: %s", scanTime),
		fmt.Sprintf("%d formulae", len(m.formulae)),
		fmt.Sprintf("%d casks", len(m.casks)),
		fmt.Sprintf("%d apps", len(m.apps)),
	}
	if outdatedCount > 0 {
		parts = append(parts, StyleWarn.Render(fmt.Sprintf("%d outdated", outdatedCount)))
	}
	if vulnCount > 0 {
		parts = append(parts, StyleDanger.Render(fmt.Sprintf("%d CVEs", vulnCount)))
	}
	if m.actionMsg != "" {
		parts = append(parts, m.actionMsg)
	}

	var keys string
	switch m.mode {
	case modeFilter:
		keys = StyleMuted.Render("[enter/esc] done")
	case modeConfirm:
		keys = StyleMuted.Render("[y] yes  [n/esc] no")
	case modeDeps:
		keys = StyleMuted.Render("[↑↓] scroll  [esc/d] close")
	default:
		sortInfo := ""
		if st := m.tabStates[m.activeTab]; st.sortCol >= 0 {
			dir := "▲"
			if !st.sortAsc {
				dir = "▼"
			}
			sortInfo = fmt.Sprintf(" sort:col%d%s", st.sortCol, dir)
		}
		keys = StyleMuted.Render("[/] filter  [s/S] sort"+sortInfo+"  [u] upgrade  [x] uninstall  [d] deps  [r] refresh  [q] quit")
	}

	stats := StyleStatusBar.Render(strings.Join(parts, "  ·  "))
	return lipgloss.JoinVertical(lipgloss.Left, stats, "  "+keys)
}
