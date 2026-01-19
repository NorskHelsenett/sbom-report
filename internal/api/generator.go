package api

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sbom-report/internal/config"
	"sbom-report/internal/database"
	"sbom-report/internal/deps"
	"sbom-report/internal/git"
	"sbom-report/internal/graph"
	"sbom-report/internal/repo"
	"sbom-report/internal/report"
	"sbom-report/internal/sbom"
)

// GenerateReportForRepo generates an SBOM report for a given repository URL
// It clones the repo, runs the analysis, and stores the results in the database
func GenerateReportForRepo(repoURL, projectName, projectDesc string, cfg *config.Config) (*database.Report, error) {
	// Create or get project with token
	project, err := database.CreateProjectWithToken(repoURL, projectName, projectDesc, cfg.GitHubToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create project: %w", err)
	}

	// Use stored token if not provided in config
	if cfg.GitHubToken == "" && project.GitHubToken != "" {
		cfg.GitHubToken = project.GitHubToken
	}

	// Create a temporary directory for cloning
	tmpDir, err := os.MkdirTemp("", "sbom-report-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Clone the repository
	fmt.Printf("Cloning repository: %s\n", repoURL)
	if err := git.CloneRepo(repoURL, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Set base directory to the cloned repo
	cfg.BaseDir = tmpDir

	// Create output directory in temp
	outDir := filepath.Join(tmpDir, "sbom-output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	cfg.OutDir = outDir

	// Generate the report using the existing logic
	rep, err := generateReport(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	// Read generated files
	sbomPath := filepath.Join(cfg.OutDir, cfg.TrivySBOMName)
	sbomData, _ := os.ReadFile(sbomPath)

	htmlPath := filepath.Join(cfg.OutDir, cfg.HTMLReportName)
	htmlData, _ := os.ReadFile(htmlPath)

	graphPath := filepath.Join(cfg.OutDir, cfg.GraphSVGName)
	graphData, _ := os.ReadFile(graphPath)

	// Calculate total dependencies and vulnerabilities
	totalDeps := len(rep.Dependencies.GoModules) + len(rep.Dependencies.NpmPackages) +
		len(rep.Dependencies.PythonReqs) + len(rep.Dependencies.MavenDeps)

	totalVulns := 0
	for _, vulns := range cfg.VulnMap {
		totalVulns += len(vulns)
	}

	// Create database report
	dbReport := &database.Report{
		ProjectID:         project.ID,
		GeneratedAt:       time.Now(),
		BaseDir:           repoURL,
		SBOMFormat:        cfg.TrivyFormat,
		SBOMData:          string(sbomData),
		HTMLReport:        string(htmlData),
		GraphSVG:          string(graphData),
		TotalDependencies: totalDeps,
		TotalVulns:        totalVulns,
	}

	// Store dependencies (deduplicated)
	dependencies := make([]*database.Dependency, 0)

	// Process Go modules
	for _, goMod := range rep.Dependencies.GoModules {
		dep, err := database.GetOrCreateDependency("go", goMod.Path, goMod.Version)
		if err == nil {
			dependencies = append(dependencies, dep)
		}
	}

	// Process NPM packages
	for _, pkg := range rep.Dependencies.NpmPackages {
		dep, err := database.GetOrCreateDependency("npm", pkg.Name, pkg.Version)
		if err == nil {
			dependencies = append(dependencies, dep)
		}
	}

	// Process Python packages
	for _, pkg := range rep.Dependencies.PythonReqs {
		dep, err := database.GetOrCreateDependency("python", pkg.Name, pkg.Version)
		if err == nil {
			dependencies = append(dependencies, dep)
		}
	}

	// Process Maven dependencies
	for _, pkg := range rep.Dependencies.MavenDeps {
		dep, err := database.GetOrCreateDependency("maven", pkg.Name, pkg.Version)
		if err == nil {
			dependencies = append(dependencies, dep)
		}
	}

	dbReport.Dependencies = make([]database.Dependency, len(dependencies))
	for i, dep := range dependencies {
		dbReport.Dependencies[i] = *dep
	}

	// Save report to database
	if err := database.CreateReport(dbReport); err != nil {
		return nil, fmt.Errorf("failed to save report: %w", err)
	}

	return dbReport, nil
}

// generateReport is the core report generation logic extracted from main.go
func generateReport(cfg *config.Config) (*report.Report, error) {
	rep := &report.Report{
		GeneratedAt: cfg.Now,
		BaseDir:     cfg.BaseDir,
	}

	// Run trivy SBOM
	sbomPath := filepath.Join(cfg.OutDir, cfg.TrivySBOMName)
	rep.Trivy = sbom.RunTrivy(cfg.TrivyPath, cfg.TrivyFormat, cfg.BaseDir, sbomPath)

	// Parse SBOM (best-effort)
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

	// Run vulnerability scan
	fmt.Println("Running vulnerability scan...")
	vulnPath := filepath.Join(cfg.OutDir, "vulns.json")
	vulnMap, err := sbom.RunVulnerabilityScan(cfg.TrivyPath, cfg.BaseDir, vulnPath)
	if err != nil {
		fmt.Printf("Warning: vulnerability scan failed: %v\n", err)
		vulnMap = make(map[string][]sbom.VulnInfo)
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

	// Discover project git info + remotes
	rep.Project.GitDetected = git.IsGitRepo(cfg.BaseDir)
	if rep.Project.GitDetected {
		rep.Project.Remotes = git.GetRemotes(cfg.BaseDir)
		rep.Project.LastCommit = git.GetLastCommit(cfg.BaseDir)
	}

	// Discover package repository usage (best-effort)
	rep.Dependencies.GoModules = deps.DiscoverGoModules(cfg.BaseDir)
	rep.Dependencies.NpmPackages = append(rep.Dependencies.NpmPackages, deps.DiscoverNpm(cfg.BaseDir)...)
	rep.Dependencies.PythonReqs = append(rep.Dependencies.PythonReqs, deps.DiscoverPythonReqs(cfg.BaseDir)...)
	rep.Dependencies.MavenDeps = deps.DiscoverMaven(cfg.BaseDir)

	// Assess remote repos
	rep.Repos = repo.AssessRemotes(cfg, rep.Project.Remotes, rep.Project.LastCommit)

	// Extract repository info from Go modules
	goModuleRepos := repo.ExtractReposFromGoModules(rep.Dependencies.GoModules)
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, goModuleRepos)...)

	// Extract repository info from Python packages
	pythonRepos := repo.ExtractReposFromPythonPackages(cfg, rep.Dependencies.PythonReqs)
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, pythonRepos)...)

	// Extract repository info from NPM packages
	npmRepos := repo.ExtractReposFromNpmPackages(cfg, rep.Dependencies.NpmPackages)
	rep.Repos = append(rep.Repos, repo.AssessModuleRepos(cfg, npmRepos)...)

	// Generate dependency graph SVG
	graphPath := filepath.Join(cfg.OutDir, cfg.GraphSVGName)
	projectName := filepath.Base(cfg.BaseDir)
	if err := graph.GenerateDependencyGraph(
		graphPath,
		projectName,
		rep.Dependencies.GoModules,
		rep.Dependencies.NpmPackages,
		rep.Dependencies.PythonReqs,
		rep.Dependencies.MavenDeps,
		rep.Repos,
	); err != nil {
		fmt.Printf("Warning: failed to generate dependency graph: %v\n", err)
	}

	// Render HTML report
	htmlPath := filepath.Join(cfg.OutDir, cfg.HTMLReportName)
	if err := report.RenderHTML(htmlPath, rep); err != nil {
		return nil, err
	}

	return rep, nil
}
