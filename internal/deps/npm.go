package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

func DiscoverNpm(dir string) []PackageRef {
	var refs []PackageRef
	// quick parse for lockfiles (best-effort summaries)
	lockFiles := []string{"package-lock.json", "npm-shrinkwrap.json"}
	for _, lf := range lockFiles {
		p := filepath.Join(dir, lf)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// package-lock v2+ has "packages" object with many entries; we'll just extract top-level deps.
		var obj map[string]any
		if json.Unmarshal(b, &obj) != nil {
			continue
		}
		if deps, ok := obj["dependencies"].(map[string]any); ok {
			for name, v := range deps {
				mv, _ := v.(map[string]any)
				ver, _ := mv["version"].(string)
				refs = append(refs, PackageRef{Ecosystem: "npm", Name: name, Version: ver, Source: lf})
			}
		}
	}
	// yarn.lock / pnpm-lock.yaml could be added here.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs
}
