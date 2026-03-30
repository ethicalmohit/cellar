package ui

import "github.com/charmbracelet/lipgloss"

var (
	colorGreen  = lipgloss.Color("#22c55e")
	colorYellow = lipgloss.Color("#f59e0b")
	colorRed    = lipgloss.Color("#ef4444")
	colorBlue   = lipgloss.Color("#3b82f6")
	colorGray   = lipgloss.Color("#6b7280")
	colorWhite  = lipgloss.Color("#f9fafb")
	colorBg     = lipgloss.Color("#1e1e2e")
	colorBorder = lipgloss.Color("#313244")
	colorActive = lipgloss.Color("#cba6f7")

	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorActive).
			Padding(0, 1)

	StyleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorActive).
			Underline(true).
			Padding(0, 1)

	StyleTabInactive = lipgloss.NewStyle().
				Foreground(colorGray).
				Padding(0, 1)

	StyleStatusBar = lipgloss.NewStyle().
			Foreground(colorGray).
			Padding(0, 1)

	StyleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	StyleOk       = lipgloss.NewStyle().Foreground(colorGreen)
	StyleWarn     = lipgloss.NewStyle().Foreground(colorYellow)
	StyleDanger   = lipgloss.NewStyle().Foreground(colorRed)
	StyleMuted    = lipgloss.NewStyle().Foreground(colorGray)
	StyleSelected = lipgloss.NewStyle().Bold(true).Foreground(colorWhite).Background(lipgloss.Color("#45475a"))

	StyleDetail = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBlue).
			Padding(0, 1)
)

// StatusIcon returns a colored status string for use in detail panels.
func StatusIcon(outdated, vulnerable bool, severity string) string {
	if vulnerable {
		switch severity {
		case "critical", "high":
			return StyleDanger.Render("● CVE")
		default:
			return StyleWarn.Render("● CVE")
		}
	}
	if outdated {
		return StyleWarn.Render("↑ outdated")
	}
	return StyleOk.Render("✓ ok")
}

// StatusText returns a plain-text status string safe for table cells.
// Bubbles table uses runewidth.Truncate internally, which does not strip ANSI
// escape codes — passing colored strings corrupts the cell layout.
func StatusText(outdated, vulnerable bool, severity string) string {
	if vulnerable {
		return "● CVE"
	}
	if outdated {
		return "↑ outdated"
	}
	return "✓ ok"
}
