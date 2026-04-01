package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethicalmohit/cellar/data"

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
	tabServices
	tabTaps
)

var tabNames = []string{"Formulae", "Casks", "Apps", "Vulnerabilities", "Services", "Taps"}

type uiMode int

const (
	modeNormal uiMode = iota
	modeFilter
	modeConfirm
	modeDetail
	modeDeps
	modeUpgrading
	modeUninstalling
	modeServiceAction
	modeServiceRunning
)

type confirmAction int

const (
	actionUpgrade confirmAction = iota
	actionUninstall
)

type tabState struct {
	filter  string
	sortCol int
	sortAsc bool
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

type formulaeLoadedMsg []data.Package
type casksLoadedMsg []data.Package
type appsLoadedMsg []data.App
type servicesLoadedMsg []data.Service
type tapsLoadedMsg []data.Tap
type vulnsLoadedMsg struct {
	formulae []data.Package
	casks    []data.Package
}
type depsLoadedMsg data.DepInfo
type upgradeDoneMsg struct{ name string; err error }
type uninstallDoneMsg struct{ name string; err error }
type serviceActionDoneMsg struct {
	name   string
	action string
	err    error
}
type errMsg struct{ err error }

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type Model struct {
	activeTab    tab
	width        int
	height       int
	loading      bool
	vulnsLoading bool
	lastScan     time.Time
	spinner      spinner.Model

	formulae []data.Package
	casks    []data.Package
	apps     []data.App
	services []data.Service
	taps     []data.Tap

	fTable   table.Model
	cTable   table.Model
	aTable   table.Model
	vTable   table.Model
	svcTable table.Model
	tTable   table.Model

	tabStates [6]tabState

	mode uiMode

	filterInput textinput.Model

	// confirm upgrade / uninstall
	confirmPkg    string
	confirmFrom   string
	confirmTo     string
	confirmAction confirmAction

	// service action
	selectedSvc string
	actionMsg   string

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

	states := [6]tabState{}
	for i := range states {
		states[i].sortCol = -1
		states[i].sortAsc = true
	}

	return Model{
		spinner:     s,
		loading:     true,
		filterInput: fi,
		tabStates:   states,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, loadFormulae, loadCasks, loadApps, loadServices, loadTaps)
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

func loadServices() tea.Msg {
	svcs, err := data.LoadServices()
	if err != nil {
		return servicesLoadedMsg(nil)
	}
	return servicesLoadedMsg(svcs)
}

func loadTaps() tea.Msg {
	taps, err := data.LoadTaps()
	if err != nil {
		return tapsLoadedMsg(nil)
	}
	return tapsLoadedMsg(taps)
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
	return func() tea.Msg { return depsLoadedMsg(data.LoadDepInfo(name)) }
}

func upgradePackage(name string) tea.Cmd {
	return func() tea.Msg {
		return upgradeDoneMsg{name: name, err: data.UpgradePackage(name)}
	}
}

func uninstallPackage(name string, isCask bool) tea.Cmd {
	return func() tea.Msg {
		return uninstallDoneMsg{name: name, err: data.UninstallPackage(name, isCask)}
	}
}

func runServiceAction(action, name string) tea.Cmd {
	return func() tea.Msg {
		var err error
		switch action {
		case "start":
			err = data.StartService(name)
		case "stop":
			err = data.StopService(name)
		case "restart":
			err = data.RestartService(name)
		}
		return serviceActionDoneMsg{name: name, action: action, err: err}
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

	case servicesLoadedMsg:
		m.services = []data.Service(msg)
		m.rebuildTables()

	case tapsLoadedMsg:
		m.taps = []data.Tap(msg)
		m.rebuildTables()

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

	case serviceActionDoneMsg:
		if msg.err != nil {
			m.actionMsg = StyleDanger.Render(fmt.Sprintf("✗ %s %s failed: %v", msg.action, msg.name, msg.err))
		} else {
			m.actionMsg = StyleOk.Render(fmt.Sprintf("✓ %s %s", msg.action, msg.name))
		}
		m.mode = modeNormal
		cmds = append(cmds, loadServices)

	case errMsg:
		m.err = msg.err
		m.loading = false

	case tea.KeyMsg:
		cmds = append(cmds, m.handleKey(msg)...)
	}

	// Forward navigation keys to the active table in normal mode.
	// Keys consumed by handleKey must NOT be forwarded — some conflict with
	// Bubbles table's built-in bindings ("d"=HalfPageDown, "u"=HalfPageUp)
	// which would scroll the cursor to an unintended row.
	if m.mode == modeNormal {
		if km, ok := msg.(tea.KeyMsg); ok {
			switch km.String() {
			case "q", "ctrl+c",
				"1", "2", "3", "4", "5", "6",
				"tab",
				"r", "/", "esc", "s", "S",
				"enter", "u", "x", "d":
				// consumed by handleKey — do not forward to table
			default:
				switch m.activeTab {
				case tabFormulae:
					m.fTable, _ = m.fTable.Update(msg)
				case tabCasks:
					m.cTable, _ = m.cTable.Update(msg)
				case tabApps:
					m.aTable, _ = m.aTable.Update(msg)
				case tabVulns:
					m.vTable, _ = m.vTable.Update(msg)
				case tabServices:
					m.svcTable, _ = m.svcTable.Update(msg)
				case tabTaps:
					m.tTable, _ = m.tTable.Update(msg)
				}
			}
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleKey(msg tea.KeyMsg) []tea.Cmd {
	var cmds []tea.Cmd

	switch m.mode {

	case modeFilter:
		switch msg.String() {
		case "esc", "enter":
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
				cmds = append(cmds, tea.Batch(m.spinner.Tick, uninstallPackage(m.confirmPkg, m.activeTab == tabCasks)))
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

	case modeUpgrading, modeUninstalling, modeServiceRunning:
		// block input while running

	case modeServiceAction:
		switch msg.String() {
		case "s":
			m.mode = modeServiceRunning
			cmds = append(cmds, tea.Batch(m.spinner.Tick, runServiceAction("start", m.selectedSvc)))
		case "o":
			m.mode = modeServiceRunning
			cmds = append(cmds, tea.Batch(m.spinner.Tick, runServiceAction("stop", m.selectedSvc)))
		case "R":
			m.mode = modeServiceRunning
			cmds = append(cmds, tea.Batch(m.spinner.Tick, runServiceAction("restart", m.selectedSvc)))
		case "esc", "q", "enter":
			m.mode = modeNormal
		}

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
		case "5":
			m.switchTab(tabServices)
		case "6":
			m.switchTab(tabTaps)
		case "tab":
			m.switchTab((m.activeTab + 1) % 6)
		case "r":
			m.loading = true
			m.vulnsLoading = false
			m.actionMsg = ""
			m.err = nil
			cmds = append(cmds, tea.Batch(m.spinner.Tick, loadFormulae, loadCasks, loadApps, loadServices, loadTaps))
		case "/":
			m.mode = modeFilter
			m.filterInput.SetValue(m.tabStates[m.activeTab].filter)
			m.filterInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "esc":
			m.tabStates[m.activeTab].filter = ""
			m.filterInput.SetValue("")
			m.rebuildTables()
		case "s":
			st := &m.tabStates[m.activeTab]
			max := m.maxSortCol()
			if st.sortCol >= max {
				st.sortCol = -1
			} else {
				st.sortCol++
				st.sortAsc = true
			}
			m.rebuildTables()
		case "S":
			if st := &m.tabStates[m.activeTab]; st.sortCol >= 0 {
				st.sortAsc = !st.sortAsc
				m.rebuildTables()
			}
		case "enter":
			if m.activeTab == tabServices {
				if name := m.selectedName(); name != "" {
					m.selectedSvc = name
					m.mode = modeServiceAction
				}
			} else if m.activeTab == tabTaps {
				if name := m.selectedName(); name != "" {
					m.detailContent = m.buildTapDetail(name)
					if m.detailContent != "" {
						m.mode = modeDetail
					}
				}
			} else {
				m.detailContent = m.buildDetail()
				if m.detailContent != "" {
					m.mode = modeDetail
				}
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
		return 5 // Name, Version, Latest, Size, Status, Description
	case tabApps:
		return 3 // Name, Version, Build, Size
	case tabVulns:
		return 4 // Package, Version, CVE ID, Severity, Summary
	case tabServices:
		return 2 // Name, Status, User
	case tabTaps:
		return 3 // Name, Formulae, Casks, Remote
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
	case tabServices:
		row = m.svcTable.SelectedRow()
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
	h := m.height - 8
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

	m.fTable = buildPackageTable(filteredPkgs(m.formulae, m.tabStates[tabFormulae].filter), cw, th, m.tabStates[tabFormulae].sortCol, m.tabStates[tabFormulae].sortAsc)
	m.cTable = buildPackageTable(filteredPkgs(m.casks, m.tabStates[tabCasks].filter), cw, th, m.tabStates[tabCasks].sortCol, m.tabStates[tabCasks].sortAsc)
	m.aTable = buildAppTable(filteredApps(m.apps, m.tabStates[tabApps].filter), cw, th, m.tabStates[tabApps].sortCol, m.tabStates[tabApps].sortAsc)
	m.vTable = buildVulnTable(filteredPkgs(m.formulae, m.tabStates[tabVulns].filter), filteredPkgs(m.casks, m.tabStates[tabVulns].filter), cw, th, m.tabStates[tabVulns].sortCol, m.tabStates[tabVulns].sortAsc)
	m.svcTable = buildServiceTable(filteredServices(m.services, m.tabStates[tabServices].filter), cw, th, m.tabStates[tabServices].sortCol, m.tabStates[tabServices].sortAsc)
	m.tTable = buildTapTable(filteredTaps(m.taps, m.tabStates[tabTaps].filter), cw, th, m.tabStates[tabTaps].sortCol, m.tabStates[tabTaps].sortAsc)

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
			strings.Contains(strings.ToLower(p.Description), q) {
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

func filteredServices(svcs []data.Service, query string) []data.Service {
	if query == "" {
		return svcs
	}
	q := strings.ToLower(query)
	var out []data.Service
	for _, s := range svcs {
		if strings.Contains(strings.ToLower(s.Name), q) ||
			strings.Contains(strings.ToLower(s.Status), q) {
			out = append(out, s)
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
			less = pkgStatusPriority(cp[i]) < pkgStatusPriority(cp[j])
		case 5:
			less = cp[i].Description < cp[j].Description
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

func sortedServices(svcs []data.Service, col int, asc bool) []data.Service {
	if col < 0 {
		return svcs
	}
	cp := make([]data.Service, len(svcs))
	copy(cp, svcs)
	sort.SliceStable(cp, func(i, j int) bool {
		var less bool
		switch col {
		case 0:
			less = cp[i].Name < cp[j].Name
		case 1:
			less = svcStatusPriority(cp[i].Status) < svcStatusPriority(cp[j].Status)
		case 2:
			less = cp[i].User < cp[j].User
		}
		if !asc {
			return !less
		}
		return less
	})
	return cp
}

func svcStatusPriority(s string) int {
	switch s {
	case "error":
		return 0
	case "started":
		return 1
	case "stopped":
		return 2
	default:
		return 3
	}
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

	nameW := width / 5
	verW := 10
	latestW := 10
	sizeW := 8
	statusW := 12
	descW := width - nameW - verW - latestW - sizeW - statusW - 8
	if descW < 10 {
		descW = 10
	}

	cols := []table.Column{
		{Title: "Name" + sortIndicator(0, sortCol, sortAsc), Width: nameW},
		{Title: "Version" + sortIndicator(1, sortCol, sortAsc), Width: verW},
		{Title: "Latest" + sortIndicator(2, sortCol, sortAsc), Width: latestW},
		{Title: "Size" + sortIndicator(3, sortCol, sortAsc), Width: sizeW},
		{Title: "Status" + sortIndicator(4, sortCol, sortAsc), Width: statusW},
		{Title: "Description" + sortIndicator(5, sortCol, sortAsc), Width: descW},
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
			StatusText(p.Outdated, p.Vulnerable, sev),
			truncateStr(p.Description, descW),
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

func buildServiceTable(svcs []data.Service, width, height, sortCol int, sortAsc bool) table.Model {
	svcs = sortedServices(svcs, sortCol, sortAsc)

	nameW := width / 3
	statusW := 12
	userW := 20
	fileW := width - nameW - statusW - userW - 6
	if fileW < 10 {
		fileW = 10
	}

	cols := []table.Column{
		{Title: "Name" + sortIndicator(0, sortCol, sortAsc), Width: nameW},
		{Title: "Status" + sortIndicator(1, sortCol, sortAsc), Width: statusW},
		{Title: "User" + sortIndicator(2, sortCol, sortAsc), Width: userW},
		{Title: "Plist File", Width: fileW},
	}

	rows := make([]table.Row, 0, len(svcs))
	for _, s := range svcs {
		rows = append(rows, table.Row{
			s.Name,
			svcStatusIcon(s.Status),
			s.User,
			truncateStr(s.File, fileW),
		})
	}
	return styledTable(cols, rows, height)
}

func filteredTaps(taps []data.Tap, query string) []data.Tap {
	if query == "" {
		return taps
	}
	q := strings.ToLower(query)
	var out []data.Tap
	for _, t := range taps {
		if strings.Contains(strings.ToLower(t.Name), q) ||
			strings.Contains(strings.ToLower(t.Remote), q) {
			out = append(out, t)
		}
	}
	return out
}

func buildTapTable(taps []data.Tap, width, height, sortCol int, sortAsc bool) table.Model {
	cp := make([]data.Tap, len(taps))
	copy(cp, taps)
	sort.SliceStable(cp, func(i, j int) bool {
		var less bool
		switch sortCol {
		case 1:
			less = cp[i].Formulae < cp[j].Formulae
		case 2:
			less = cp[i].Casks < cp[j].Casks
		case 3:
			less = cp[i].Remote < cp[j].Remote
		default:
			less = cp[i].Name < cp[j].Name
		}
		if !sortAsc {
			return !less
		}
		return less
	})

	nameW := width / 3
	formulaeW := 10
	casksW := 8
	remoteW := width - nameW - formulaeW - casksW - 8
	if remoteW < 15 {
		remoteW = 15
	}

	cols := []table.Column{
		{Title: "Tap" + sortIndicator(0, sortCol, sortAsc), Width: nameW},
		{Title: "Formulae" + sortIndicator(1, sortCol, sortAsc), Width: formulaeW},
		{Title: "Casks" + sortIndicator(2, sortCol, sortAsc), Width: casksW},
		{Title: "Remote" + sortIndicator(3, sortCol, sortAsc), Width: remoteW},
	}

	rows := make([]table.Row, 0, len(cp))
	for _, t := range cp {
		rows = append(rows, table.Row{
			t.Name,
			fmt.Sprintf("%d", t.Formulae),
			fmt.Sprintf("%d", t.Casks),
			truncateStr(t.Remote, remoteW),
		})
	}
	return styledTable(cols, rows, height)
}

func svcStatusIcon(status string) string {
	switch status {
	case "started":
		return StyleOk.Render("● started")
	case "stopped":
		return StyleWarn.Render("○ stopped")
	case "error":
		return StyleDanger.Render("✗ error")
	default:
		return StyleMuted.Render("— none")
	}
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

func truncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
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
	sb.WriteString(fmt.Sprintf("%-10s %s\n", "Name:", p.Name))
	if p.Description != "" {
		sb.WriteString(fmt.Sprintf("%-10s %s\n", "About:", p.Description))
	}
	if p.Homepage != "" {
		sb.WriteString(fmt.Sprintf("%-10s %s\n", "Homepage:", p.Homepage))
	}
	if p.License != "" {
		sb.WriteString(fmt.Sprintf("%-10s %s\n", "License:", p.License))
	}
	sb.WriteString(fmt.Sprintf("%-10s %s\n", "Version:", p.Version))
	sb.WriteString(fmt.Sprintf("%-10s %s\n", "Latest:", p.Latest))
	sb.WriteString(fmt.Sprintf("%-10s %s\n", "Size:", data.FormatSize(p.SizeBytes)))
	if p.Outdated {
		sb.WriteString(StyleWarn.Render("\n⚠  Update available: " + p.Latest + "\n"))
	}
	if p.Caveats != "" {
		sb.WriteString(StyleWarn.Render("\nCaveats:\n"))
		sb.WriteString(StyleMuted.Render(p.Caveats + "\n"))
	}
	if len(p.CVEs) > 0 {
		sb.WriteString(StyleDanger.Render("\nVulnerabilities:\n"))
		for _, c := range p.CVEs {
			sb.WriteString(fmt.Sprintf("  %s [%s]  %s\n", c.ID, c.Severity, c.Summary))
			sb.WriteString(StyleMuted.Render(fmt.Sprintf("  %s\n\n", c.URL)))
		}
	}
	return sb.String()
}

func (m Model) buildTapDetail(name string) string {
	for _, t := range m.taps {
		if t.Name == name {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%-12s %s\n", "Tap:", t.Name))
			sb.WriteString(fmt.Sprintf("%-12s %d\n", "Formulae:", t.Formulae))
			sb.WriteString(fmt.Sprintf("%-12s %d\n", "Casks:", t.Casks))
			if t.Remote != "" {
				sb.WriteString(fmt.Sprintf("%-12s %s\n", "Remote:", t.Remote))
			}
			if t.Branch != "" {
				sb.WriteString(fmt.Sprintf("%-12s %s\n", "Branch:", t.Branch))
			}
			if t.LastCommit != "" {
				sb.WriteString(fmt.Sprintf("%-12s %s\n", "Last commit:", t.LastCommit))
			}
			if t.Official {
				sb.WriteString(StyleOk.Render("\n● Official Homebrew tap\n"))
			}
			return sb.String()
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m Model) View() string {
	if m.width == 0 {
		return "Initializing…"
	}

	title := StyleTitle.Render("cellar")
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

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		m.renderFilterBar(),
		m.renderBody(),
		divider,
		m.renderStatusBar(),
	)
}

func (m Model) renderFilterBar() string {
	st := m.tabStates[m.activeTab]
	if m.mode == modeFilter {
		return "  " + StyleWarn.Render("/") + " " + m.filterInput.View()
	}
	if st.filter != "" {
		return "  " + StyleMuted.Render("filter: ") + StyleWarn.Render(st.filter) + StyleMuted.Render("  [esc to clear]")
	}
	return StyleMuted.Render("  press / to filter")
}

func (m Model) renderBody() string {
	switch m.mode {
	case modeDetail:
		return StyleDetail.Width(m.width-4).Render(m.detailContent) +
			StyleMuted.Render("\n  any key to close")

	case modeConfirm:
		var msg string
		if m.confirmAction == actionUninstall {
			msg = fmt.Sprintf("Uninstall %s  (%s)\n\n  [y] confirm   [n/esc] cancel",
				StyleDanger.Render(m.confirmPkg), StyleMuted.Render(m.confirmFrom))
		} else {
			msg = fmt.Sprintf("Upgrade %s\n  %s  →  %s\n\n  [y] confirm   [n/esc] cancel",
				StyleTabActive.Render(m.confirmPkg), StyleMuted.Render(m.confirmFrom), StyleOk.Render(m.confirmTo))
		}
		return StyleDetail.Width(m.width - 4).Render(msg)

	case modeDeps:
		hdr := StyleTabActive.Render("Dependency tree") + StyleMuted.Render("  [esc/d] close  [↑↓] scroll")
		return lipgloss.JoinVertical(lipgloss.Left, "  "+hdr, m.depsViewport.View())

	case modeUpgrading:
		return fmt.Sprintf("\n  %s Upgrading %s…\n", m.spinner.View(), StyleTabActive.Render(m.confirmPkg))

	case modeUninstalling:
		return fmt.Sprintf("\n  %s Uninstalling %s…\n", m.spinner.View(), StyleDanger.Render(m.confirmPkg))

	case modeServiceAction:
		svc := m.findService(m.selectedSvc)
		statusLine := ""
		if svc != nil {
			statusLine = fmt.Sprintf("Status:  %s\n\n", svcStatusIcon(svc.Status))
		}
		msg := fmt.Sprintf("Service: %s\n%s  [s] start   [o] stop   [R] restart   [esc] cancel",
			StyleTabActive.Render(m.selectedSvc), statusLine)
		return StyleDetail.Width(m.width - 4).Render(msg)

	case modeServiceRunning:
		return fmt.Sprintf("\n  %s Running service command…\n", m.spinner.View())
	}

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
	case tabServices:
		if len(m.services) == 0 {
			return StyleMuted.Render("\n  No services found.")
		}
		return m.svcTable.View()
	case tabTaps:
		if len(m.taps) == 0 {
			return StyleMuted.Render("\n  No taps found.")
		}
		return m.tTable.View()
	}
	return ""
}

func (m Model) findService(name string) *data.Service {
	for i := range m.services {
		if m.services[i].Name == name {
			return &m.services[i]
		}
	}
	return nil
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
	startedCount := 0
	for _, s := range m.services {
		if s.Status == "started" {
			startedCount++
		}
	}

	parts := []string{
		fmt.Sprintf("scan: %s", scanTime),
		fmt.Sprintf("%d formulae", len(m.formulae)),
		fmt.Sprintf("%d casks", len(m.casks)),
		fmt.Sprintf("%d apps", len(m.apps)),
	}
	if len(m.services) > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d services", startedCount, len(m.services)))
	}
	if len(m.taps) > 0 {
		parts = append(parts, fmt.Sprintf("%d taps", len(m.taps)))
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
	case modeServiceAction:
		keys = StyleMuted.Render("[s] start  [o] stop  [R] restart  [esc] cancel")
	default:
		sortInfo := ""
		if st := m.tabStates[m.activeTab]; st.sortCol >= 0 {
			dir := "▲"
			if !st.sortAsc {
				dir = "▼"
			}
			sortInfo = fmt.Sprintf(" sort:col%d%s", st.sortCol, dir)
		}
		switch m.activeTab {
		case tabServices:
			keys = StyleMuted.Render("[enter] manage  [/] filter  [s/S] sort" + sortInfo + "  [r] refresh  [q] quit")
		case tabTaps:
			keys = StyleMuted.Render("[enter] detail  [/] filter  [s/S] sort" + sortInfo + "  [r] refresh  [q] quit")
		default:
			keys = StyleMuted.Render("[enter] detail  [/] filter  [s/S] sort" + sortInfo + "  [u] upgrade  [x] uninstall  [d] deps  [r] refresh  [q] quit")
		}
	}

	stats := StyleStatusBar.Render(strings.Join(parts, "  ·  "))
	return lipgloss.JoinVertical(lipgloss.Left, stats, "  "+keys)
}
