package data

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Package struct {
	Name        string
	Version     string
	Latest      string
	SizeBytes   int64
	Outdated    bool
	Vulnerable  bool
	CVEs        []CVE
	Description string
	Homepage    string
	License     string
	Caveats     string
}

type brewInfoJSON struct {
	Formulae []struct {
		Name     string `json:"name"`
		Desc     string `json:"desc"`
		Homepage string `json:"homepage"`
		License  string `json:"license"`
		Caveats  string `json:"caveats"`
		Installed []struct {
			Version string `json:"version"`
		} `json:"installed"`
	} `json:"formulae"`
	Casks []struct {
		Token     string `json:"token"`
		Desc      string `json:"desc"`
		Homepage  string `json:"homepage"`
		Version   string `json:"version"`
		Installed string `json:"installed"`
	} `json:"casks"`
}

type brewOutdatedJSON struct {
	Formulae []struct {
		Name           string `json:"name"`
		CurrentVersion string `json:"current_version"`
	} `json:"formulae"`
	Casks []struct {
		Name           string `json:"name"`
		CurrentVersion string `json:"current_version"`
	} `json:"casks"`
}

// LoadBrewPackages returns all installed formulae and casks in a single
// brew info call, with sizes fetched via one du invocation per base dir.
func LoadBrewPackages() (formulae []Package, casks []Package, err error) {
	infoOut, err := exec.Command("brew", "info", "--json=v2", "--installed").Output()
	if err != nil {
		return nil, nil, fmt.Errorf("brew info: %w", err)
	}

	// A single brew outdated --json=v2 returns both formulae and casks.
	outdatedOut, _ := exec.Command("brew", "outdated", "--json=v2").Output()
	if outdatedOut == nil {
		outdatedOut = []byte(`{"formulae":[],"casks":[]}`)
	}

	var info brewInfoJSON
	if err := json.Unmarshal(infoOut, &info); err != nil {
		return nil, nil, fmt.Errorf("parse brew info: %w", err)
	}

	var outdated brewOutdatedJSON
	json.Unmarshal(outdatedOut, &outdated)

	fOutdated := make(map[string]string, len(outdated.Formulae))
	for _, f := range outdated.Formulae {
		fOutdated[f.Name] = f.CurrentVersion
	}
	cOutdated := make(map[string]string, len(outdated.Casks))
	for _, c := range outdated.Casks {
		cOutdated[c.Name] = c.CurrentVersion
	}

	cellarSizes := batchDirSizes("/opt/homebrew/Cellar")
	caskroomSizes := batchDirSizes("/opt/homebrew/Caskroom")

	for _, f := range info.Formulae {
		if len(f.Installed) == 0 {
			continue
		}
		ver := f.Installed[0].Version
		latest, isOutdated := fOutdated[f.Name]
		if !isOutdated {
			latest = ver
		}
		formulae = append(formulae, Package{
			Name:        f.Name,
			Version:     ver,
			Latest:      latest,
			SizeBytes:   cellarSizes[f.Name],
			Outdated:    isOutdated,
			Description: f.Desc,
			Homepage:    f.Homepage,
			License:     f.License,
			Caveats:     strings.TrimSpace(f.Caveats),
		})
	}

	for _, c := range info.Casks {
		if c.Installed == "" {
			continue
		}
		ver := c.Installed
		latest, isOutdated := cOutdated[c.Token]
		if !isOutdated {
			latest = ver
		}
		casks = append(casks, Package{
			Name:        c.Token,
			Version:     ver,
			Latest:      latest,
			SizeBytes:   caskroomSizes[c.Token],
			Outdated:    isOutdated,
			Description: c.Desc,
			Homepage:    c.Homepage,
		})
	}
	return formulae, casks, nil
}

// batchDirSizes runs a single `du -sk` across all immediate children of
// baseDir and returns a map of child name → byte size. One subprocess instead
// of N.
func batchDirSizes(baseDir string) map[string]int64 {
	entries, err := os.ReadDir(baseDir)
	if err != nil || len(entries) == 0 {
		return map[string]int64{}
	}
	args := make([]string, 0, len(entries)+1)
	args = append(args, "-sk")
	for _, e := range entries {
		args = append(args, filepath.Join(baseDir, e.Name()))
	}
	var buf bytes.Buffer
	cmd := exec.Command("du", args...)
	cmd.Stdout = &buf
	cmd.Run() // partial output is fine if some paths are missing
	sizes := make(map[string]int64, len(entries))
	for _, line := range strings.Split(buf.String(), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		var kb int64
		fmt.Sscanf(parts[0], "%d", &kb)
		sizes[filepath.Base(strings.TrimSpace(parts[1]))] = kb * 1024
	}
	return sizes
}

func FormatSize(bytes int64) string {
	if bytes == 0 {
		return "—"
	}
	mb := float64(bytes) / 1024 / 1024
	if mb >= 1024 {
		return fmt.Sprintf("%.1f GB", mb/1024)
	}
	if mb >= 1 {
		return fmt.Sprintf("%.1f MB", mb)
	}
	return fmt.Sprintf("%d KB", bytes/1024)
}
