package database

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is the global database instance
var DB *gorm.DB

// InitDB initializes the database connection and runs migrations
func InitDB(dbPath string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto migrate the schema
	if err := DB.AutoMigrate(&Project{}, &Report{}, &Dependency{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// CreateProject creates a new project or returns existing one
func CreateProject(repoURL, name, description string) (*Project, error) {
	return CreateProjectWithToken(repoURL, name, description, "")
}

// CreateProjectWithToken creates a new project with a GitHub token or returns existing one
func CreateProjectWithToken(repoURL, name, description, githubToken string) (*Project, error) {
	project := &Project{
		RepoURL:     repoURL,
		Name:        name,
		Description: description,
		GitHubToken: githubToken,
	}

	// Try to find existing project first
	var existing Project
	result := DB.Where("repo_url = ?", repoURL).First(&existing)
	if result.Error == nil {
		// Project exists, update it
		existing.Name = name
		existing.Description = description
		if githubToken != "" {
			existing.GitHubToken = githubToken
		}
		if err := DB.Save(&existing).Error; err != nil {
			return nil, err
		}
		return &existing, nil
	}

	// Create new project
	if err := DB.Create(project).Error; err != nil {
		return nil, err
	}

	return project, nil
}

// GetProject retrieves a project by ID
func GetProject(id uint) (*Project, error) {
	var project Project
	if err := DB.Preload("Reports").First(&project, id).Error; err != nil {
		return nil, err
	}
	return &project, nil
}

// GetProjectByURL retrieves a project by repository URL
func GetProjectByURL(repoURL string) (*Project, error) {
	var project Project
	if err := DB.Where("repo_url = ?", repoURL).Preload("Reports").First(&project).Error; err != nil {
		return nil, err
	}
	return &project, nil
}

// ListProjects returns all projects with reports
func ListProjects() ([]Project, error) {
	var projects []Project
	if err := DB.Preload("Reports").Find(&projects).Error; err != nil {
		return nil, err
	}
	return projects, nil
}

// ListProjectsSummary returns all projects without reports (minimal data)
func ListProjectsSummary() ([]Project, error) {
	var projects []Project
	if err := DB.Find(&projects).Error; err != nil {
		return nil, err
	}
	return projects, nil
}

// UpdateProject updates an existing project
func UpdateProject(project *Project) error {
	return DB.Save(project).Error
}

// CreateReport creates a new report for a project
func CreateReport(report *Report) error {
	return DB.Create(report).Error
}

// GetReport retrieves a report by ID
func GetReport(id uint) (*Report, error) {
	var report Report
	if err := DB.Preload("Project").Preload("Dependencies").First(&report, id).Error; err != nil {
		return nil, err
	}
	return &report, nil
}

// ListReportsByProject returns all reports for a specific project
func ListReportsByProject(projectID uint) ([]Report, error) {
	var reports []Report
	if err := DB.Where("project_id = ?", projectID).Preload("Dependencies").Order("created_at DESC").Find(&reports).Error; err != nil {
		return nil, err
	}
	return reports, nil
}

// GetOrCreateDependency gets an existing dependency or creates a new one
// This ensures dependencies are deduplicated across projects
func GetOrCreateDependency(pkgType, name, version string) (*Dependency, error) {
	var dep Dependency

	// Try to find existing dependency
	result := DB.Where("package_type = ? AND name = ? AND version = ?", pkgType, name, version).First(&dep)
	if result.Error == nil {
		return &dep, nil
	}

	// Create new dependency
	dep = Dependency{
		PackageType: pkgType,
		Name:        name,
		Version:     version,
	}

	if err := DB.Create(&dep).Error; err != nil {
		return nil, err
	}

	return &dep, nil
}

// GetOrCreateDependencyWithVulns gets an existing dependency or creates a new one,
// updating the vulnerability count
func GetOrCreateDependencyWithVulns(pkgType, name, version string, vulnCount int) (*Dependency, error) {
	var dep Dependency

	// Try to find existing dependency
	result := DB.Where("package_type = ? AND name = ? AND version = ?", pkgType, name, version).First(&dep)
	if result.Error == nil {
		// Update vulnerability count if it changed
		if dep.VulnCount != vulnCount {
			dep.VulnCount = vulnCount
			if err := DB.Save(&dep).Error; err != nil {
				return nil, err
			}
		}
		return &dep, nil
	}

	// Create new dependency with vulnerability count
	dep = Dependency{
		PackageType: pkgType,
		Name:        name,
		Version:     version,
		VulnCount:   vulnCount,
	}

	if err := DB.Create(&dep).Error; err != nil {
		return nil, err
	}

	return &dep, nil
}

// GetDependencyUsage returns the latest report for each project that uses a specific dependency
func GetDependencyUsage(dependencyID uint) ([]Report, error) {
	var reports []Report

	query := `
		SELECT r.*
		FROM reports r
		INNER JOIN report_dependencies rd ON r.id = rd.report_id
		WHERE rd.dependency_id = ?
		AND r.id IN (
			SELECT MAX(r2.id)
			FROM reports r2
			INNER JOIN report_dependencies rd2 ON r2.id = rd2.report_id
			WHERE rd2.dependency_id = ?
			GROUP BY r2.project_id
		)
		ORDER BY r.generated_at DESC
	`

	if err := DB.Raw(query, dependencyID, dependencyID).Scan(&reports).Error; err != nil {
		return nil, err
	}

	return reports, nil
}

// DependencyWithUsage extends Dependency with usage count
type DependencyWithUsage struct {
	Dependency
	ProjectCount int `json:"project_count"`
}

// GetAllDependencies returns all unique dependencies
func GetAllDependencies() ([]Dependency, error) {
	var deps []Dependency
	if err := DB.Find(&deps).Error; err != nil {
		return nil, err
	}
	return deps, nil
}

// GetDependenciesByPackageType returns dependencies filtered by package type
func GetDependenciesByPackageType(pkgType string) ([]Dependency, error) {
	var deps []Dependency
	if err := DB.Where("package_type = ?", pkgType).Find(&deps).Error; err != nil {
		return nil, err
	}
	return deps, nil
}

// GetAllDependenciesWithUsage returns all dependencies with project usage count
func GetAllDependenciesWithUsage() ([]DependencyWithUsage, error) {
	var results []DependencyWithUsage

	query := `
		SELECT 
			d.*,
			COUNT(DISTINCT r.project_id) as project_count
		FROM dependencies d
		LEFT JOIN report_dependencies rd ON d.id = rd.dependency_id
		LEFT JOIN reports r ON rd.report_id = r.id
		GROUP BY d.id
		ORDER BY project_count DESC, d.name ASC
	`

	if err := DB.Raw(query).Scan(&results).Error; err != nil {
		return nil, err
	}

	return results, nil
}

// GetDependenciesByPackageTypeWithUsage returns dependencies filtered by package type with usage count
func GetDependenciesByPackageTypeWithUsage(pkgType string) ([]DependencyWithUsage, error) {
	var results []DependencyWithUsage

	query := `
		SELECT 
			d.*,
			COUNT(DISTINCT r.project_id) as project_count
		FROM dependencies d
		LEFT JOIN report_dependencies rd ON d.id = rd.dependency_id
		LEFT JOIN reports r ON rd.report_id = r.id
		WHERE d.package_type = ?
		GROUP BY d.id
		ORDER BY project_count DESC, d.name ASC
	`

	if err := DB.Raw(query, pkgType).Scan(&results).Error; err != nil {
		return nil, err
	}

	return results, nil
}
