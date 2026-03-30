package data

import (
	"encoding/json"
	"fmt"
	"os/exec"
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
		Name              string   `json:"name"`
		InstalledVersions []string `json:"installed_versions"`
		CurrentVersion    string   `json:"current_version"`
	} `json:"formulae"`
	Casks []struct {
		Name              string   `json:"name"`
		InstalledVersions []string `json:"installed_versions"`
		CurrentVersion    string   `json:"current_version"`
	} `json:"casks"`
}

func LoadBrewFormulae() ([]Package, error) {
	infoOut, err := exec.Command("brew", "info", "--json=v2", "--installed").Output()
	if err != nil {
		return nil, fmt.Errorf("brew info: %w", err)
	}

	outdatedOut, err := exec.Command("brew", "outdated", "--json=v2").Output()
	if err != nil {
		outdatedOut = []byte(`{"formulae":[],"casks":[]}`)
	}

	var info brewInfoJSON
	if err := json.Unmarshal(infoOut, &info); err != nil {
		return nil, fmt.Errorf("parse brew info: %w", err)
	}

	var outdated brewOutdatedJSON
	json.Unmarshal(outdatedOut, &outdated)

	outdatedMap := map[string]string{}
	for _, f := range outdated.Formulae {
		outdatedMap[f.Name] = f.CurrentVersion
	}

	var pkgs []Package
	for _, f := range info.Formulae {
		if len(f.Installed) == 0 {
			continue
		}
		ver := f.Installed[0].Version
		latest, isOutdated := outdatedMap[f.Name]
		if !isOutdated {
			latest = ver
		}
		pkgs = append(pkgs, Package{
			Name:        f.Name,
			Version:     ver,
			Latest:      latest,
			SizeBytes:   cellarDiskSize(f.Name),
			Outdated:    isOutdated,
			Description: f.Desc,
			Homepage:    f.Homepage,
			License:     f.License,
			Caveats:     strings.TrimSpace(f.Caveats),
		})
	}
	return pkgs, nil
}

func LoadBrewCasks() ([]Package, error) {
	infoOut, err := exec.Command("brew", "info", "--json=v2", "--installed").Output()
	if err != nil {
		return nil, fmt.Errorf("brew info: %w", err)
	}

	outdatedOut, err := exec.Command("brew", "outdated", "--cask", "--json=v2").Output()
	if err != nil {
		outdatedOut = []byte(`{"formulae":[],"casks":[]}`)
	}

	var info brewInfoJSON
	if err := json.Unmarshal(infoOut, &info); err != nil {
		return nil, fmt.Errorf("parse brew info: %w", err)
	}

	var outdated brewOutdatedJSON
	json.Unmarshal(outdatedOut, &outdated)

	outdatedMap := map[string]string{}
	for _, c := range outdated.Casks {
		outdatedMap[c.Name] = c.CurrentVersion
	}

	var pkgs []Package
	for _, c := range info.Casks {
		if c.Installed == "" {
			continue
		}
		ver := c.Installed
		latest, isOutdated := outdatedMap[c.Token]
		if !isOutdated {
			latest = ver
		}
		pkgs = append(pkgs, Package{
			Name:        c.Token,
			Version:     ver,
			Latest:      latest,
			SizeBytes:   caskDiskSize(c.Token),
			Outdated:    isOutdated,
			Description: c.Desc,
			Homepage:    c.Homepage,
		})
	}
	return pkgs, nil
}

func cellarDiskSize(name string) int64 {
	out, err := exec.Command("du", "-sk", "/opt/homebrew/Cellar/"+name).Output()
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(out))
	if len(parts) == 0 {
		return 0
	}
	var kb int64
	fmt.Sscanf(parts[0], "%d", &kb)
	return kb * 1024
}

func caskDiskSize(token string) int64 {
	out, err := exec.Command("du", "-sk", "/opt/homebrew/Caskroom/"+token).Output()
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(out))
	if len(parts) == 0 {
		return 0
	}
	var kb int64
	fmt.Sscanf(parts[0], "%d", &kb)
	return kb * 1024
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
