package git

import (
	"fmt"
	"os/exec"
)

// CloneRepo clones a Git repository to the specified directory
func CloneRepo(repoURL, targetDir string) error {
	cmd := exec.Command("git", "clone", "--depth=1", repoURL, targetDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}
