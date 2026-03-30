package data

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type Tap struct {
	Name       string
	Formulae   int
	Casks      int
	Remote     string
	LastCommit string
	Branch     string
	Official   bool
}

func LoadTaps() ([]Tap, error) {
	out, err := exec.Command("brew", "tap-info", "--installed", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("brew tap-info: %w", err)
	}
	var raw []struct {
		Name         string   `json:"name"`
		FormulaNames []string `json:"formula_names"`
		CaskTokens   []string `json:"cask_tokens"`
		Remote       string   `json:"remote"`
		LastCommit   string   `json:"last_commit"`
		Branch       string   `json:"branch"`
		Official     bool     `json:"official"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("parse taps: %w", err)
	}
	taps := make([]Tap, len(raw))
	for i, r := range raw {
		taps[i] = Tap{
			Name:       r.Name,
			Formulae:   len(r.FormulaNames),
			Casks:      len(r.CaskTokens),
			Remote:     r.Remote,
			LastCommit: r.LastCommit,
			Branch:     r.Branch,
			Official:   r.Official,
		}
	}
	return taps, nil
}
