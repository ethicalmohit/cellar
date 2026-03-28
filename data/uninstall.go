package data

import (
	"fmt"
	"os/exec"
)

func UninstallPackage(name string, isCask bool) error {
	args := []string{"uninstall"}
	if isCask {
		args = append(args, "--cask")
	}
	args = append(args, name)
	cmd := exec.Command("brew", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(out))
	}
	return nil
}
