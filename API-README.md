# SBOM Report API Server

This is a REST API server that provides SBOM (Software Bill of Materials) analysis as a service.

## Features

- 📦 **Repository Analysis**: Submit any Git repository URL for SBOM analysis
- 💾 **Persistent Storage**: All reports are saved in a SQLite database
- 📊 **Project Management**: Track multiple projects and their reports
- 🔍 **Dependency Deduplication**: Dependencies are deduplicated across all projects
- 📈 **Statistics**: Get insights on dependencies across all analyzed projects
- 📖 **Swagger Documentation**: Interactive API documentation at `/swagger/index.html`

## API Endpoints

### Health Check
- `GET /health` - Check API health status

### Repository Submission
- `POST /api/v1/submit` - Submit a repository for SBOM analysis

### Projects
- `GET /api/v1/projects` - List all submitted projects
- `GET /api/v1/projects/:id` - Get project details
- `GET /api/v1/projects/:project_id/reports` - List reports for a project

### Reports
- `GET /api/v1/reports/:id` - Get report details
- `GET /api/v1/reports/:id/html` - Get HTML report
- `GET /api/v1/reports/:id/graph` - Get dependency graph (SVG)

### Dependencies (Deduplicated)
- `GET /api/v1/dependencies` - List all unique dependencies
- `GET /api/v1/dependencies?type=npm` - Filter dependencies by type (npm, python, go, maven)
- `GET /api/v1/dependencies/stats` - Get dependency statistics

## Installation

### Prerequisites

- Go 1.23 or later
- Trivy CLI tool (`trivy` must be in PATH)
- Git

### Build

```bash
# Install dependencies
go mod download

# Build the server
go build -o sbom-server ./cmd/server
```

## Usage

### Start the Server

```bash
# Start with default settings (port 8080, database: sbom-reports.db)
./sbom-server

# Custom port and database
./sbom-server -port 3000 -db /path/to/database.db
```

### Environment Variables

- `GITHUB_TOKEN` - GitHub API token for enhanced rate limits (optional but recommended)

### Example API Calls

#### Submit a Repository

```bash
curl -X POST http://localhost:8080/api/v1/submit \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/microsoft/vscode",
    "name": "VS Code",
    "description": "Visual Studio Code editor"
  }'
```

#### List Projects

```bash
curl http://localhost:8080/api/v1/projects
```

#### Get Project Reports

```bash
curl http://localhost:8080/api/v1/projects/1/reports
```

#### View Dependency Statistics

```bash
curl http://localhost:8080/api/v1/dependencies/stats
```

#### List NPM Dependencies (Deduplicated)

```bash
curl http://localhost:8080/api/v1/dependencies?type=npm
```

## Swagger Documentation

Once the server is running, visit:

```
http://localhost:8080/swagger/index.html
```

This provides an interactive API documentation where you can:
- View all available endpoints
- See request/response schemas
- Try out API calls directly from the browser

## Database Schema

The server uses SQLite with the following main tables:

- **projects** - Stores repository projects
- **reports** - Stores SBOM analysis reports
- **dependencies** - Stores unique dependencies (deduplicated)
- **report_dependencies** - Many-to-many relationship between reports and dependencies

### Deduplication

Dependencies are automatically deduplicated based on:
- Package type (npm, python, go, maven)
- Package name
- Package version

This means if multiple projects use the same dependency version, it's stored only once in the database.

## Architecture

- **Gin** - HTTP web framework
- **GORM** - ORM for database operations
- **Swagger** - API documentation
- **SQLite** - Embedded database
- **Trivy** - SBOM generation and vulnerability scanning

## Development

### Regenerate Swagger Documentation

After modifying API handlers:

```bash
/go/bin/swag init -g internal/api/server.go -o docs
```

### Database Migrations

GORM auto-migration runs on server startup. The database schema is automatically updated.

## Command-line Tool

The original command-line tool is still available:

```bash
# Build the CLI
go build -o sbom-report .

# Run on a local directory
./sbom-report -dir /path/to/project -out ./output
```

## License

See LICENSE file for details.
