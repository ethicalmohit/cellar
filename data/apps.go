package data

import (
	"bytes"
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
			})
		}
	}

	// Batch all .app sizes in a single du call instead of one subprocess per app.
	if len(apps) > 0 {
		args := make([]string, 0, len(apps)+1)
		args = append(args, "-sk")
		for _, a := range apps {
			args = append(args, a.Path)
		}
		var buf bytes.Buffer
		cmd := exec.Command("du", args...)
		cmd.Stdout = &buf
		cmd.Run() // partial output is fine
		sizeByPath := make(map[string]int64, len(apps))
		for _, line := range strings.Split(buf.String(), "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			var kb int64
			fmt.Sscanf(parts[0], "%d", &kb)
			sizeByPath[strings.TrimSpace(parts[1])] = kb * 1024
		}
		for i := range apps {
			apps[i].Size = sizeByPath[apps[i].Path]
		}
	}

	return apps, nil
}
