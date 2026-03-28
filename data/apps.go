package data

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

type App struct {
	Name    string
	Version string
	Build   string
	Path    string
	Size    int64
}

type infoPlist struct {
	BundleName        string `plist:"CFBundleName"`
	BundleDisplayName string `plist:"CFBundleDisplayName"`
	ShortVersion      string `plist:"CFBundleShortVersionString"`
	BundleVersion     string `plist:"CFBundleVersion"`
}

func LoadApps() ([]App, error) {
	dirs := []string{"/Applications", "/System/Applications"}
	var apps []App
	seen := map[string]bool{}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || filepath.Ext(e.Name()) != ".app" {
				continue
			}
			appPath := filepath.Join(dir, e.Name())
			plistPath := filepath.Join(appPath, "Contents", "Info.plist")

			f, err := os.Open(plistPath)
			if err != nil {
				continue
			}

			var info infoPlist
			plist.NewDecoder(f).Decode(&info)
			f.Close()

			name := info.BundleDisplayName
			if name == "" {
				name = info.BundleName
			}
			if name == "" {
				name = strings.TrimSuffix(e.Name(), ".app")
			}

			if seen[name] {
				continue
			}
			seen[name] = true

			apps = append(apps, App{
				Name:    name,
				Version: info.ShortVersion,
				Build:   info.BundleVersion,
				Path:    appPath,
				Size:    appDirSize(appPath),
			})
		}
	}
	return apps, nil
}

func appDirSize(path string) int64 {
	out, err := exec.Command("du", "-sk", path).Output()
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
