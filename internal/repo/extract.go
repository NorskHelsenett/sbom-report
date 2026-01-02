package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"sbom-report/internal/config"
	"sbom-report/internal/deps"
	"sbom-report/internal/git"
)

// ExtractReposFromGoModules extracts GitHub repository URLs from Go modules
func ExtractReposFromGoModules(modules []deps.GoModule) []git.Remote {
	var repos []git.Remote
	seen := make(map[string]bool)

	for _, mod := range modules {
		if strings.HasPrefix(mod.Path, "github.com/") {
			parts := strings.Split(strings.TrimPrefix(mod.Path, "github.com/"), "/")
			if len(parts) >= 2 {
				owner := parts[0]
				repo := parts[1]
				key := owner + "/" + repo

				if !seen[key] {
					seen[key] = true
					repos = append(repos, git.Remote{
						Name: mod.Path,
						URL:  "https://github.com/" + owner + "/" + repo,
						Kind: "https",
						Host: "github.com",
						Path: owner + "/" + repo,
					})
				}
			}
		}
	}

	return repos
}

type pypiInfo struct {
	Info struct {
		ProjectURLs map[string]string `json:"project_urls"`
		HomePageURL string             `json:"home_page"`
	} `json:"info"`
}

// ExtractReposFromPythonPackages queries PyPI and extracts GitHub repository URLs
func ExtractReposFromPythonPackages(cfg *config.Config, packages []deps.PackageRef) []git.Remote {
	var repos []git.Remote
	seen := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout*5)
	defer cancel()

	progress := NewProgressBar(len(packages), "Resolving Python packages to GitHub")

	for _, pkg := range packages {
		progress.Increment()
		
		if pkg.Name == "" || pkg.Name == "(see file)" {
			continue
		}

		pypiURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)
		var info pypiInfo
		if err := httpGetJSON(ctx, cfg, pypiURL, &info); err != nil {
			continue
		}

		var repoURL string
		for _, u := range info.Info.ProjectURLs {
			if strings.Contains(u, "github.com") {
				repoURL = u
				break
			}
		}
		if repoURL == "" && strings.Contains(info.Info.HomePageURL, "github.com") {
			repoURL = info.Info.HomePageURL
		}

		if repoURL != "" {
			if remote := parseGitHubURL(repoURL); remote != nil {
				key := remote.Path
				if !seen[key] {
					seen[key] = true
					remote.Name = pkg.Name
					repos = append(repos, *remote)
				}
			}
		}
	}

	return repos
}

type npmPackageInfo struct {
	Repository struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repository"`
	Homepage string `json:"homepage"`
}

// ExtractReposFromNpmPackages queries npm registry and extracts GitHub repository URLs
func ExtractReposFromNpmPackages(cfg *config.Config, packages []deps.PackageRef) []git.Remote {
	var repos []git.Remote
	seen := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout*5)
	defer cancel()

	progress := NewProgressBar(len(packages), "Resolving NPM packages to GitHub")

	for _, pkg := range packages {
		progress.Increment()
		
		if pkg.Name == "" {
			continue
		}

		npmURL := fmt.Sprintf("https://registry.npmjs.org/%s", pkg.Name)
		var info npmPackageInfo
		if err := httpGetJSON(ctx, cfg, npmURL, &info); err != nil {
			continue
		}

		var repoURL string
		if strings.Contains(info.Repository.URL, "github.com") {
			repoURL = info.Repository.URL
		} else if strings.Contains(info.Homepage, "github.com") {
			repoURL = info.Homepage
		}

		if repoURL != "" {
			if remote := parseGitHubURL(repoURL); remote != nil {
				key := remote.Path
				if !seen[key] {
					seen[key] = true
					remote.Name = pkg.Name
					repos = append(repos, *remote)
				}
			}
		}
	}

	return repos
}

func parseGitHubURL(rawURL string) *git.Remote {
	rawURL = strings.TrimPrefix(rawURL, "git+")
	rawURL = strings.TrimSuffix(rawURL, ".git")

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	if !strings.Contains(parsed.Host, "github.com") {
		return nil
	}

	path := strings.Trim(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil
	}

	owner := parts[0]
	repo := parts[1]
	repoPath := owner + "/" + repo

	return &git.Remote{
		URL:  "https://github.com/" + repoPath,
		Kind: "https",
		Host: "github.com",
		Path: repoPath,
	}
}

func httpGetJSON(ctx context.Context, cfg *config.Config, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", cfg.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxHTTPBytes))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return err
	}
	return nil
}
