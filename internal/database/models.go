package database

import (
	"time"

	"gorm.io/gorm"
)

// Project represents a submitted repository project
type Project struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	RepoURL     string   `gorm:"uniqueIndex;not null" json:"repo_url"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Reports     []Report `gorm:"foreignKey:ProjectID" json:"reports,omitempty"`
}

// Report represents a generated SBOM report for a project
type Report struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	ProjectID uint    `gorm:"not null;index" json:"project_id"`
	Project   Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	GeneratedAt time.Time `json:"generated_at"`
	BaseDir     string    `json:"base_dir"`

	// SBOM data
	SBOMFormat string `json:"sbom_format"`
	SBOMData   string `gorm:"type:text" json:"sbom_data,omitempty"` // JSON or XML data

	// HTML report
	HTMLReport string `gorm:"type:text" json:"html_report,omitempty"`

	// SVG graph
	GraphSVG string `gorm:"type:text" json:"graph_svg,omitempty"`

	// Stats
	TotalDependencies int `json:"total_dependencies"`
	TotalVulns        int `json:"total_vulns"`

	Dependencies []Dependency `gorm:"many2many:report_dependencies;" json:"dependencies,omitempty"`
}

// Dependency represents a unique dependency across all projects
// This allows deduplication of dependencies across projects
type Dependency struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Unique combination of package type, name, and version
	PackageType string `gorm:"not null;index:idx_dependency_unique" json:"package_type"` // npm, python, go, maven
	Name        string `gorm:"not null;index:idx_dependency_unique" json:"name"`
	Version     string `gorm:"not null;index:idx_dependency_unique" json:"version"`

	// Repository information
	RepoURL     string `json:"repo_url,omitempty"`
	Description string `json:"description,omitempty"`

	// Vulnerabilities
	VulnCount int `json:"vuln_count"`

	Reports []Report `gorm:"many2many:report_dependencies;" json:"-"`
}

// TableName overrides
func (Project) TableName() string {
	return "projects"
}

func (Report) TableName() string {
	return "reports"
}

func (Dependency) TableName() string {
	return "dependencies"
}
