package repo

import (
	"fmt"
	"strings"
	"time"

	"sbom-report/internal/config"
	"sbom-report/internal/git"
)

func AssessRemotes(cfg *config.Config, remotes []git.Remote, lastCommit *git.Commit) []Assessment {
	var out []Assessment
	for _, r := range remotes {
		ra := Assessment{Remote: r}
		ra.LastCommitAuthor = ""
		if lastCommit != nil {
			ra.LastCommitAuthor = fmt.Sprintf("%s <%s>", lastCommit.Author, lastCommit.AuthorEmail)
		}

		provider, owner, repo := classifyRepo(r)
		ra.Provider = provider
		ra.Owner = owner
		ra.Repo = repo
		ra.RepoURL = repoURL(r, provider, owner, repo)

		switch provider {
		case "github":
			fillGitHub(cfg, &ra)
		case "gitlab":
			ra.Err = "GitLab lookup not implemented (yet)"
		case "bitbucket":
			ra.Err = "Bitbucket lookup not implemented (yet)"
		default:
			ra.Err = "Unknown git provider or non-HTTP remote"
		}

		ra.MaintenanceStatus, ra.StalenessDays = maintenance(cfg.Now, ra.LastActivityAt)

		out = append(out, ra)
	}
	return out
}

func AssessModuleRepos(cfg *config.Config, remotes []git.Remote) []Assessment {
	var out []Assessment
	
	if len(remotes) == 0 {
		return out
	}
	
	progress := NewProgressBar(len(remotes), "Assessing GitHub repositories")
	
	for _, r := range remotes {
		progress.Increment()
		
		ra := Assessment{Remote: r}

		provider, owner, repo := classifyRepo(r)
		ra.Provider = provider
		ra.Owner = owner
		ra.Repo = repo
		ra.RepoURL = repoURL(r, provider, owner, repo)

		switch provider {
		case "github":
			fillGitHub(cfg, &ra)
		case "gitlab":
			ra.Err = "GitLab lookup not implemented (yet)"
		case "bitbucket":
			ra.Err = "Bitbucket lookup not implemented (yet)"
		default:
			ra.Err = "Unknown git provider or non-HTTP remote"
		}

		ra.MaintenanceStatus, ra.StalenessDays = maintenance(cfg.Now, ra.LastActivityAt)

		// Add vulnerability information if available
		if cfg.VulnMap != nil {
			// Try to match repo name or owner/repo to package names
			for pkgName, vulns := range cfg.VulnMap {
				// Match if package name contains repo name, or exact match
				if strings.Contains(pkgName, ra.Repo) || pkgName == ra.Repo || 
				   strings.Contains(strings.ToLower(pkgName), strings.ToLower(ra.Repo)) {
					for _, v := range vulns {
						ra.Vulnerabilities = append(ra.Vulnerabilities, Vulnerability{
							ID:          v.ID,
							Severity:    v.Severity,
							Score:       v.Score,
							Title:       v.Title,
							Description: v.Description,
							Package:     v.Package,
							Version:     v.Version,
						})
					}
				}
			}
		}

		out = append(out, ra)
	}
	return out
}

func classifyRepo(r git.Remote) (provider, owner, repo string) {
	host := r.Host
	path := strings.Trim(r.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "unknown", "", ""
	}
	owner = parts[0]
	repo = parts[1]

	switch {
	case strings.Contains(host, "github.com"):
		return "github", owner, repo
	case strings.Contains(host, "gitlab.com"):
		return "gitlab", owner, repo
	case strings.Contains(host, "bitbucket.org"):
		return "bitbucket", owner, repo
	default:
		return "unknown", owner, repo
	}
}

func repoURL(r git.Remote, provider, owner, repo string) string {
	if provider == "github" {
		return "https://github.com/" + owner + "/" + repo
	}
	if r.Kind == "https" || r.Kind == "http" {
		return fmt.Sprintf("%s://%s/%s", r.Kind, r.Host, strings.TrimPrefix(r.Path, "/"))
	}
	return r.URL
}

func maintenance(now time.Time, last time.Time) (status string, days int) {
	if last.IsZero() {
		return "Unknown", 0
	}
	d := int(now.Sub(last).Hours() / 24)
	switch {
	case d <= 183:
		return "Maintained", d
	case d <= 365:
		return "Stale (> 6 months)", d
	default:
		return "Possibly EOL (> 12 months)", d
	}
}
