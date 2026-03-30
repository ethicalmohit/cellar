package data

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type Service struct {
	Name   string
	Status string // started | stopped | error | none
	User   string
	File   string
}

func LoadServices() ([]Service, error) {
	out, err := exec.Command("brew", "services", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("brew services: %w", err)
	}
	var raw []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		User   string `json:"user"`
		File   string `json:"file"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("parse services: %w", err)
	}
	svcs := make([]Service, len(raw))
	for i, r := range raw {
		user := r.User
		if user == "" {
			user = "—"
		}
		svcs[i] = Service{Name: r.Name, Status: r.Status, User: user, File: r.File}
	}
	return svcs, nil
}

func StartService(name string) error   { return runServiceCmd("start", name) }
func StopService(name string) error    { return runServiceCmd("stop", name) }
func RestartService(name string) error { return runServiceCmd("restart", name) }

func runServiceCmd(action, name string) error {
	cmd := exec.Command("brew", "services", action, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
