package data

import (
	"os/exec"
	"strings"
)

type DepInfo struct {
	Name       string
	Tree       string
	Dependents []string
}

func LoadDepInfo(name string) DepInfo {
	info := DepInfo{Name: name}

	if out, err := exec.Command("brew", "deps", "--tree", name).Output(); err == nil {
		info.Tree = strings.TrimSpace(string(out))
	} else {
		info.Tree = "(no dependencies)"
	}

	if out, err := exec.Command("brew", "uses", "--installed", name).Output(); err == nil {
		info.Dependents = strings.Fields(string(out))
	}

	return info
}
