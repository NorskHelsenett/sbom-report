package deps

import (
	"os"
	"path/filepath"
	"strings"
)

func DiscoverPythonReqs(dir string) []PackageRef {
	var refs []PackageRef
	paths := []string{"requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile"}
	for _, f := range paths {
		p := filepath.Join(dir, f)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// super basic extraction: lines like "requests==2.31.0"
		if strings.HasSuffix(f, ".txt") {
			for _, ln := range strings.Split(string(b), "\n") {
				ln = strings.TrimSpace(ln)
				if ln == "" || strings.HasPrefix(ln, "#") {
					continue
				}
				name, ver := splitAny(ln, []string{"==", ">=", "<=", "~=", ">", "<"})
				if name != "" {
					refs = append(refs, PackageRef{Ecosystem: "python", Name: name, Version: ver, Source: f})
				}
			}
		} else {
			refs = append(refs, PackageRef{Ecosystem: "python", Name: "(see file)", Version: "", Source: f})
		}
	}
	return refs
}

func splitAny(s string, seps []string) (string, string) {
	for _, sep := range seps {
		if idx := strings.Index(s, sep); idx >= 0 {
			return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+len(sep):])
		}
	}
	// bare name
	return strings.TrimSpace(s), ""
}
