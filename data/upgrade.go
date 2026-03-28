package data

import (
	"fmt"
	"os/exec"
)

func UpgradePackage(name string) error {
	cmd := exec.Command("brew", "upgrade", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(out))
	}
	return nil
}
