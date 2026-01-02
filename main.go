package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sbom-report/internal/config"
	"sbom-report/internal/deps"
	"sbom-report/internal/git"
	"sbom-report/internal/repo"
	"sbom-report/internal/report"
	"sbom-report/internal/sbom"
)

func main() {
	var cfg config.Config
	flag.StringVar(&cfg.BaseDir, "dir", ".", "Project base directory")
	flag.StringVar(&cfg.OutDir, "out", "out", "Output directory")
	flag.StringVar(&cfg.TrivyPath, "trivy", "trivy", "Path to trivy executable")
	flag.StringVar(&cfg.GitHubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token (or set GITHUB_TOKEN)")
	flag.BoolVar(&cfg.EnableGeoGuess, "geo-guess", false, "Try to guess country from owner location string (very naive)")
	flag.DurationVar(&cfg.RequestTimeout, "http-timeout", 12*time.Second, "HTTP timeout")
	flag.StringVar(&cfg.TrivyFormat, "sbom-format", "cyclonedx", "Trivy SBOM format (cyclonedx recommended)")
	flag.Parse()

	cfg.Now = time.Now()
	cfg.UserAgent = "sbom-report/1.0"
	cfg.MaxHTTPBytes = 2 << 20 // 2MB
	cfg.TrivySBOMName = "sbom.cdx.json"
	cfg.HTMLReportName = "report.html"

	// Inform user about GitHub authentication status
	if cfg.GitHubToken != "" {
		fmt.Println("GitHub authentication: enabled (using token)")
	} else {
		fmt.Println("GitHub authentication: none (rate limits apply - use --github-token or GITHUB_TOKEN env var)")
	}

	if err := run(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	baseDir, err := filepath.Abs(cfg.BaseDir)
	if err != nil {
		return err
	}
	cfg.BaseDir = baseDir

	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return err
	}

	rep := &report.Report{
		GeneratedAt: cfg.Now,
		BaseDir:     cfg.BaseDir,
	}

	// 1) Run trivy SBOM
	sbomPath := filepath.Join(cfg.OutDir, cfg.TrivySBOMName)
	rep.Trivy = sbom.RunTrivy(cfg.TrivyPath, cfg.TrivyFormat, cfg.BaseDir, sbomPath)

	// 2) Parse SBOM (best-effort)
	if rep.Trivy.OK {
		summary, err := sbom.ParseCycloneDX(sbomPath)
		if err != nil {
			rep.SBOM.Errors = append(rep.SBOM.Errors, err.Error())
		} else {
			rep.SBOM = *summary
		}

		// Extract packages from SBOM components
		npmPkgs, pythonPkgs := sbom.ExtractPackagesFromSBOM(sbomPath)
		rep.Dependencies.NpmPackages = append(rep.Dependencies.NpmPackages, npmPkgs...)
		rep.Dependencies.PythonReqs = append(rep.Dependencies.PythonReqs, pythonPkgs...)
	}

	// 2b) Run vulnerability scan
	fmt.Println("Running vulnerability scan...")
	vulnPath := filepath.Join(cfg.OutDir, "vulns.json")
	vulnMap, err := sbom.RunVulnerabilityScan(cfg.TrivyPath, cfg.BaseDir, vulnPath)
	if err != nil {
		fmt.Printf("Warning: vulnerability scan failed: %v\n", err)
		vulnMap = make(map[string][]sbom.VulnInfo)
	} else {
		totalVulns := 0
		for _, vulns := range vulnMap {
			totalVulns += len(vulns)
		}
		fmt.Printf("✓ Found %d vulnerabilities across %d packages\n", totalVulns, len(vulnMap))
	}
	
	// Convert sbom.VulnInfo to config.VulnInfo for cfg
	cfgVulnMap := make(map[string][]config.VulnInfo)
	for pkg, vulns := range vulnMap {
		var cfgVulns []config.VulnInfo
		for _, v := range vulns {
			cfgVulns = append(cfgVulns, config.VulnInfo{
				ID:          v.ID,
				Severity:    v.Severity,
				Score:       v.Score,
				Title:       v.Title,
				Description: v.Description,
				Package:     v.Package,
				Version:     v.Version,
			})
		}
		cfgVulnMap[pkg] = cfgVulns
	}
	cfg.VulnMap = cfgVulnMap

	// 3) Discover project git info + remotes
	rep.Project.GitDetected = git.IsGitRepo(cfg.BaseDir)
	if rep.Project.GitDetected {
		rep.Project.Remotes = git.GetRemotes(cfg.BaseDir)
		rep.Project.LastCommit = git.GetLastCommit(cfg.BaseDir)
	}

	// 4) Discover package repository usage (best-effort)
	rep.Dependencies.GoModules = deps.DiscoverGoModules(cfg.BaseDir)
	rep.Dependencies.NpmPackages = append(rep.Dependencies.NpmPackages, deps.DiscoverNpm(cfg.BaseDir)...)
	rep.Dependencies.PythonReqs = append(rep.Dependencies.PythonReqs, deps.DiscoverPythonReqs(cfg.BaseDir)...)
	rep.Dependencies.MavenDeps = deps.DiscoverMaven(cfg.BaseDir)

	// 5) Assess remote repos (focus on GitHub out-of-box)
	// Start with git remotes
	rep.Repos = repo.AssessRemotes(cfg, rep.Project.Remotes, rep.Project.LastCommit)

	// Extract repository info from Go modules
	goModuleRepos := repo.ExtractReposFromGoModules(rep.Dependencies.GoModules)
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, goModuleRepos)...)

	// Extract repository info from Python packages
	pythonRepos := repo.ExtractReposFromPythonPackages(cfg, rep.Dependencies.PythonReqs)
	fmt.Printf("✓ Resolved %d/%d Python packages to GitHub repos\n", len(pythonRepos), len(rep.Dependencies.PythonReqs))
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, pythonRepos)...)

	// Extract repository info from NPM packages
	npmRepos := repo.ExtractReposFromNpmPackages(cfg, rep.Dependencies.NpmPackages)
	fmt.Printf("✓ Resolved %d/%d NPM packages to GitHub repos\n", len(npmRepos), len(rep.Dependencies.NpmPackages))
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, npmRepos)...)

	// 6) Render HTML report
	htmlPath := filepath.Join(cfg.OutDir, cfg.HTMLReportName)
	if err := report.RenderHTML(htmlPath, rep); err != nil {
		return err
	}

	fmt.Println("\nWrote:")
	fmt.Println(" -", sbomPath)
	fmt.Println(" -", htmlPath)
	return nil
}
