package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sbom-report/internal/config"
	"sbom-report/internal/database"

	"github.com/gin-gonic/gin"
)

// SubmitRequest represents a request to analyze a repository
type SubmitRequest struct {
	RepoURL     string `json:"repo_url" binding:"required" example:"https://github.com/username/repo"`
	Name        string `json:"name" example:"My Project"`
	Description string `json:"description" example:"A sample project"`
	GitHubToken string `json:"github_token,omitempty" example:"ghp_xxxxxxxxxxxx"`
}

// SubmitResponse represents the response after submitting a repository
type SubmitResponse struct {
	Message   string           `json:"message" example:"Report generation started"`
	ProjectID uint             `json:"project_id" example:"1"`
	ReportID  uint             `json:"report_id" example:"1"`
	Report    *database.Report `json:"report,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid request"`
}

// ProjectSummary represents minimal project information
type ProjectSummary struct {
	ID      uint   `json:"id" example:"1"`
	Name    string `json:"name" example:"My Project"`
	RepoURL string `json:"repo_url" example:"https://github.com/owner/repo"`
}

// ListProjectsResponse represents a list of projects
type ListProjectsResponse struct {
	Projects []ProjectSummary `json:"projects"`
	Count    int              `json:"count" example:"5"`
}

// ListReportsResponse represents a list of reports
type ListReportsResponse struct {
	Reports []database.Report `json:"reports"`
	Count   int               `json:"count" example:"3"`
}

// DependencyStatsResponse represents dependency statistics
type DependencyStatsResponse struct {
	TotalDependencies int                   `json:"total_dependencies" example:"150"`
	ByType            map[string]int        `json:"by_type"`
	TopDependencies   []database.Dependency `json:"top_dependencies"`
}

// Handler contains the API handlers
type Handler struct {
	config *config.Config
}

// NewHandler creates a new API handler
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{config: cfg}
}

// SubmitRepository godoc
// @Summary Submit a repository for SBOM analysis
// @Description Analyzes a Git repository and generates an SBOM report
// @Tags repositories
// @Accept json
// @Produce json
// @Param request body SubmitRequest true "Repository information"
// @Success 200 {object} SubmitResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/submit [post]
func (h *Handler) SubmitRepository(c *gin.Context) {
	var req SubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Use project name from request or derive from URL
	projectName := req.Name
	if projectName == "" {
		projectName = req.RepoURL
	}

	// Clone config and override GitHub token if provided
	cfg := *h.config
	if req.GitHubToken != "" {
		cfg.GitHubToken = req.GitHubToken
	}

	// Generate report in the background
	// For simplicity, we'll do it synchronously here, but in production
	// you'd want to use a job queue
	report, err := GenerateReportForRepo(req.RepoURL, projectName, req.Description, &cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: fmt.Sprintf("Failed to generate report: %v", err)})
		return
	}

	c.JSON(http.StatusOK, SubmitResponse{
		Message:   "Report generated successfully",
		ProjectID: report.ProjectID,
		ReportID:  report.ID,
		Report:    report,
	})
}

// ListProjects godoc
// @Summary List all projects
// @Description Returns a minimal list of all submitted projects (ID, name, URL only)
// @Tags projects
// @Produce json
// @Success 200 {object} ListProjectsResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/projects [get]
func (h *Handler) ListProjects(c *gin.Context) {
	projects, err := database.ListProjectsSummary()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Convert to ProjectSummary
	summaries := make([]ProjectSummary, len(projects))
	for i, p := range projects {
		summaries[i] = ProjectSummary{
			ID:      p.ID,
			Name:    p.Name,
			RepoURL: p.RepoURL,
		}
	}

	c.JSON(http.StatusOK, ListProjectsResponse{
		Projects: summaries,
		Count:    len(summaries),
	})
}

// GetProject godoc
// @Summary Get a project by ID
// @Description Returns details of a specific project
// @Tags projects
// @Produce json
// @Param id path int true "Project ID"
// @Success 200 {object} database.Project
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/projects/{id} [get]
func (h *Handler) GetProject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid project ID"})
		return
	}

	project, err := database.GetProject(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Project not found"})
		return
	}

	c.JSON(http.StatusOK, project)
}

// UpdateProjectRequest represents a request to update and re-analyze a project
type UpdateProjectRequest struct {
	Name        string `json:"name,omitempty" example:"Updated Project Name"`
	Description string `json:"description,omitempty" example:"Updated description"`
	GitHubToken string `json:"github_token,omitempty" example:"ghp_xxxxxxxxxxxx"`
	Regenerate  bool   `json:"regenerate,omitempty" example:"true"`
}

// UpdateProject godoc
// @Summary Update a project and optionally regenerate report
// @Description Update project details and optionally regenerate SBOM report with new GitHub token
// @Tags projects
// @Accept json
// @Produce json
// @Param id path int true "Project ID"
// @Param request body UpdateProjectRequest true "Update request"
// @Success 200 {object} SubmitResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/projects/{id} [put]
func (h *Handler) UpdateProject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid project ID"})
		return
	}

	var req UpdateProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Get existing project
	project, err := database.GetProject(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Project not found"})
		return
	}

	// Update project fields if provided
	if req.Name != "" {
		project.Name = req.Name
	}
	if req.Description != "" {
		project.Description = req.Description
	}
	if req.GitHubToken != "" {
		project.GitHubToken = req.GitHubToken
	}

	// Update the project in database
	if err := database.UpdateProject(project); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// If regenerate flag is set, generate a new report
	if req.Regenerate {
		// Clone config and use stored token from project
		cfg := *h.config
		// Use the stored token from the project (which was just updated if provided)
		if project.GitHubToken != "" {
			cfg.GitHubToken = project.GitHubToken
		}

		// Capture values for the goroutine
		repoURL := project.RepoURL
		name := project.Name
		desc := project.Description

		go func(cfg config.Config) {
			_, _ = GenerateReportForRepo(repoURL, name, desc, &cfg)
		}(cfg)

		c.JSON(http.StatusOK, SubmitResponse{
			Message:   "Project updated and report regeneration started",
			ProjectID: project.ID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Project updated successfully",
		"project": project,
	})
}

// RegenerateReport godoc
// @Summary Regenerate SBOM report for a project
// @Description Triggers regeneration of SBOM report using stored GitHub token
// @Tags projects
// @Produce json
// @Param id path int true "Project ID"
// @Success 200 {object} SubmitResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/projects/{id}/regenerate [post]
func (h *Handler) RegenerateReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid project ID"})
		return
	}

	// Get existing project
	project, err := database.GetProject(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Project not found"})
		return
	}

	// Clone config and use stored token from project
	cfg := *h.config
	if project.GitHubToken != "" {
		cfg.GitHubToken = project.GitHubToken
	}

	// Capture values for the goroutine
	repoURL := project.RepoURL
	name := project.Name
	desc := project.Description

	go func(cfg config.Config) {
		_, _ = GenerateReportForRepo(repoURL, name, desc, &cfg)
	}(cfg)

	c.JSON(http.StatusOK, SubmitResponse{
		Message:   "Report regeneration started",
		ProjectID: project.ID,
	})
}

// ListReportsByProject godoc
// @Summary List reports for a project
// @Description Returns all reports generated for a specific project
// @Tags reports
// @Produce json
// @Param id path int true "Project ID"
// @Success 200 {object} ListReportsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/projects/{id}/reports [get]
func (h *Handler) ListReportsByProject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid project ID"})
		return
	}

	reports, err := database.ListReportsByProject(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ListReportsResponse{
		Reports: reports,
		Count:   len(reports),
	})
}

// GetReport godoc
// @Summary Get a report by ID
// @Description Returns details of a specific report including dependencies
// @Tags reports
// @Produce json
// @Param id path int true "Report ID"
// @Success 200 {object} database.Report
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/reports/{id} [get]
func (h *Handler) GetReport(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid report ID"})
		return
	}

	report, err := database.GetReport(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Report not found"})
		return
	}

	c.JSON(http.StatusOK, report)
}

// GetReportHTML godoc
// @Summary Get report HTML
// @Description Returns the HTML report for a specific report
// @Tags reports
// @Produce html
// @Param id path int true "Report ID"
// @Success 200 {string} string "HTML content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/reports/{id}/html [get]
func (h *Handler) GetReportHTML(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid report ID"})
		return
	}

	report, err := database.GetReport(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Report not found"})
		return
	}

	// Replace the hardcoded dependency-graph.svg link with the correct API endpoint
	htmlContent := report.HTMLReport
	htmlContent = strings.Replace(htmlContent, `href="dependency-graph.svg"`, `href="graph"`, 1)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlContent))
}

// GetReportGraph godoc
// @Summary Get report dependency graph
// @Description Returns the SVG dependency graph for a specific report
// @Tags reports
// @Produce image/svg+xml
// @Param id path int true "Report ID"
// @Success 200 {string} string "SVG content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/reports/{id}/graph [get]
func (h *Handler) GetReportGraph(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid report ID"})
		return
	}

	report, err := database.GetReport(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Report not found"})
		return
	}

	c.Data(http.StatusOK, "image/svg+xml", []byte(report.GraphSVG))
}

// GetDependencyStats godoc
// @Summary Get dependency statistics
// @Description Returns statistics about dependencies across all projects (deduplicated)
// @Tags dependencies
// @Produce json
// @Success 200 {object} DependencyStatsResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/dependencies/stats [get]
func (h *Handler) GetDependencyStats(c *gin.Context) {
	deps, err := database.GetAllDependencies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Calculate stats
	byType := make(map[string]int)
	for _, dep := range deps {
		byType[dep.PackageType]++
	}

	// Get top 20 dependencies (by usage count)
	topDeps := deps
	if len(topDeps) > 20 {
		topDeps = topDeps[:20]
	}

	c.JSON(http.StatusOK, DependencyStatsResponse{
		TotalDependencies: len(deps),
		ByType:            byType,
		TopDependencies:   topDeps,
	})
}

// ListDependencies godoc
// @Summary List all dependencies
// @Description Returns all unique dependencies across all projects (deduplicated)
// @Tags dependencies
// @Produce json
// @Param type query string false "Filter by package type (npm, python, go, maven)"
// @Success 200 {array} database.Dependency
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/dependencies [get]
func (h *Handler) ListDependencies(c *gin.Context) {
	pkgType := c.Query("type")

	var deps []database.Dependency
	var err error

	if pkgType != "" {
		deps, err = database.GetDependenciesByPackageType(pkgType)
	} else {
		deps, err = database.GetAllDependencies()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, deps)
}

// HealthCheck godoc
// @Summary Health check endpoint
// @Description Returns the health status of the API
// @Tags system
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
