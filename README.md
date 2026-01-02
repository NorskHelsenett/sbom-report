# SBOM Report Tool

Generates a comprehensive SBOM (Software Bill of Materials) and repository hygiene report for your project.

## Features

- Generates CycloneDX SBOM using Trivy
- Analyzes repository liveness metrics (stars, forks, issues, PRs)
- Tracks dependency maintenance status
- Assesses project health and staleness
- Supports Go modules, NPM, Python, and Maven dependencies

## Usage

### Basic Usage

```bash
./sbom-report
```

### GitHub Authentication (Recommended)

To avoid GitHub API rate limiting, provide a Personal Access Token (PAT):

**Option 1: Environment Variable**
```bash
export GITHUB_TOKEN="ghp_your_token_here"
./sbom-report
```

**Option 2: Command-line Flag**
```bash
./sbom-report --github-token ghp_your_token_here
```

### Creating a GitHub Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token" → "Generate new token (classic)"
3. Give it a descriptive name (e.g., "SBOM Report Tool")
4. Select scopes: **public_repo** (for public repositories access)
5. Click "Generate token"
6. Copy the token immediately (you won't be able to see it again)

### Additional Options

```bash
./sbom-report [options]

Options:
  --dir <path>              Project base directory (default: ".")
  --out <path>              Output directory (default: "out")
  --trivy <path>            Path to trivy executable (default: "trivy")
  --github-token <token>    GitHub token for API access (or set GITHUB_TOKEN env var)
  --geo-guess               Try to guess country from owner location string
  --http-timeout <duration> HTTP timeout (default: 12s)
  --sbom-format <format>    Trivy SBOM format (default: "cyclonedx")
```

## Output

The tool generates two files in the output directory:

- `sbom.cdx.json` - CycloneDX SBOM in JSON format
- `report.html` - HTML report with repository assessments and liveness metrics

## Requirements

- [Trivy](https://github.com/aquasecurity/trivy) must be installed and in PATH
- Go 1.22 or later (for building from source)

## Building

```bash
go build
```

## Rate Limits

**Without authentication:**
- GitHub API: 60 requests per hour per IP address

**With authentication (recommended):**
- GitHub API: 5,000 requests per hour per token

For projects with many dependencies, authentication is highly recommended.
