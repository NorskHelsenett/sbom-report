package api

import (
	"fmt"
	"os"
	"time"

	_ "sbom-report/docs" // Import swagger docs
	"sbom-report/internal/config"
	"sbom-report/internal/database"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title SBOM Report API
// @version 1.0
// @description API for generating and managing Software Bill of Materials (SBOM) reports
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http

// Server contains the HTTP server configuration
type Server struct {
	router  *gin.Engine
	handler *Handler
	config  *config.Config
	dbPath  string
}

// NewServer creates a new API server
func NewServer(dbPath string) (*Server, error) {
	// Initialize database
	if err := database.InitDB(dbPath); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Create default config
	cfg := &config.Config{
		TrivyPath:      "trivy",
		TrivyFormat:    "cyclonedx",
		TrivySBOMName:  "sbom.cdx.json",
		HTMLReportName: "report.html",
		GraphSVGName:   "dependency-graph.svg",
		GitHubToken:    os.Getenv("GITHUB_TOKEN"),
		UserAgent:      "sbom-report-api/1.0",
		RequestTimeout: 30 * time.Second,
		MaxHTTPBytes:   2 << 20, // 2MB
		Now:            time.Now(),
	}

	// Create handler
	handler := NewHandler(cfg)

	// Set up Gin router
	router := gin.Default()

	// Health check
	router.GET("/health", handler.HealthCheck)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Submit repository for analysis
		v1.POST("/submit", handler.SubmitRepository)

		// Project endpoints
		projects := v1.Group("/projects")
		{
			projects.GET("", handler.ListProjects)
			projects.GET("/:id", handler.GetProject)
			projects.GET("/:id/reports", handler.ListReportsByProject)
		}

		// Report endpoints
		reports := v1.Group("/reports")
		{
			reports.GET("/:id", handler.GetReport)
			reports.GET("/:id/html", handler.GetReportHTML)
			reports.GET("/:id/graph", handler.GetReportGraph)
		}

		// Dependency endpoints (deduplicated across projects)
		dependencies := v1.Group("/dependencies")
		{
			dependencies.GET("", handler.ListDependencies)
			dependencies.GET("/stats", handler.GetDependencyStats)
		}
	}

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return &Server{
		router:  router,
		handler: handler,
		config:  cfg,
		dbPath:  dbPath,
	}, nil
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	fmt.Printf("Starting SBOM Report API server on %s\n", addr)
	fmt.Printf("Swagger documentation available at http://%s/swagger/index.html\n", addr)
	return s.router.Run(addr)
}
