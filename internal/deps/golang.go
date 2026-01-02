package deps

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type GoModule struct {
	Path    string
	Version string
	Replace string
	Dir     string
}

func DiscoverGoModules(dir string) []GoModule {
	p := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(p); err != nil {
		return nil
	}

	cmd := exec.Command("go", "list", "-m", "-f", "{{.Path}} {{.Version}} {{.Replace}} {{.Dir}}", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var modules []GoModule
	re := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S*)\s*(.*)$`)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m != nil {
			var replStr string
			if m[3] != "<nil>" {
				replStr = m[3]
			}
			modules = append(modules, GoModule{
				Path:    m[1],
				Version: m[2],
				Replace: replStr,
				Dir:     strings.TrimSpace(m[4]),
			})
		}
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Path < modules[j].Path
	})
	return modules
}
