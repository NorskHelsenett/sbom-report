package deps

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

func DiscoverMaven(dir string) []PackageRef {
	// detect pom.xml only (real parsing can be added later)
	p := filepath.Join(dir, "pom.xml")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	// naive extraction of <groupId>, <artifactId>, <version> blocks (not accurate for complex poms)
	type dep struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	type pom struct {
		Deps []dep `xml:"dependencies>dependency"`
	}
	var x pom
	if xml.Unmarshal(b, &x) != nil {
		return []PackageRef{{Ecosystem: "maven", Name: "(see pom.xml)", Source: "pom.xml"}}
	}
	var refs []PackageRef
	for _, d := range x.Deps {
		n := strings.TrimSpace(d.GroupID + ":" + d.ArtifactID)
		refs = append(refs, PackageRef{Ecosystem: "maven", Name: n, Version: strings.TrimSpace(d.Version), Source: "pom.xml"})
	}
	return refs
}
