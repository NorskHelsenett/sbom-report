package report

import (
	"time"

	"sbom-report/internal/deps"
	"sbom-report/internal/git"
	"sbom-report/internal/repo"
	"sbom-report/internal/sbom"
)

type Report struct {
	GeneratedAt time.Time
	BaseDir     string

	Trivy sbom.TrivyResult
	SBOM  sbom.Summary

	Project struct {
		GitDetected bool
		Remotes     []git.Remote
		LastCommit  *git.Commit
	}

	Dependencies struct {
		GoModules   []deps.GoModule
		NpmPackages []deps.PackageRef
		PythonReqs  []deps.PackageRef
		MavenDeps   []deps.PackageRef
		OtherNotes  []string
	}

	Repos []repo.Assessment
}
