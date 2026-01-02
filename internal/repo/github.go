package repo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sbom-report/internal/config"
)

type ghRepo struct {
	FullName      string    `json:"full_name"`
	HTMLURL       string    `json:"html_url"`
	UpdatedAt     time.Time `json:"updated_at"`
	PushedAt      time.Time `json:"pushed_at"`
	DefaultBranch string    `json:"default_branch"`
	Archived      bool      `json:"archived"`
	OpenIssues    int       `json:"open_issues_count"`
	Forks         int       `json:"forks_count"`
	Stars         int       `json:"stargazers_count"`
	Watchers      int       `json:"watchers_count"`
	License       *struct {
		SPDXID string `json:"spdx_id"`
		Name   string `json:"name"`
	} `json:"license"`
	Owner struct {
		Login string `json:"login"`
		Type  string `json:"type"`
		URL   string `json:"url"`
	} `json:"owner"`
}

type ghUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Location string `json:"location"`
	HTMLURL  string `json:"html_url"`
}

func fillGitHub(cfg *config.Config, ra *Assessment) {
	if ra.Owner == "" || ra.Repo == "" {
		ra.Err = "Could not parse owner/repo from remote"
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	defer cancel()

	// Fetch repository info
	repoAPI := fmt.Sprintf("https://api.github.com/repos/%s/%s", ra.Owner, ra.Repo)
	var gr ghRepo
	if err := ghGet(ctx, cfg, repoAPI, &gr); err != nil {
		ra.Err = "GitHub repo API error: " + err.Error()
		return
	}

	ra.DefaultBranch = gr.DefaultBranch
	ra.Archived = gr.Archived
	ra.UpdatedAt = gr.UpdatedAt
	ra.PushedAt = gr.PushedAt
	ra.OpenIssues = gr.OpenIssues
	ra.Forks = gr.Forks
	ra.Stars = gr.Stars
	ra.Watchers = gr.Watchers

	// Choose last activity as max(updated_at, pushed_at)
	ra.LastActivityAt = gr.UpdatedAt
	if gr.PushedAt.After(ra.LastActivityAt) {
		ra.LastActivityAt = gr.PushedAt
	}

	if gr.License != nil {
		if gr.License.SPDXID != "" && gr.License.SPDXID != "NOASSERTION" {
			ra.License = gr.License.SPDXID
		} else {
			ra.License = gr.License.Name
		}
	}

	// Fetch detailed issue and PR counts
	if err := fetchIssueCounts(ctx, cfg, ra); err != nil {
		ra.Notes = append(ra.Notes, "Issue/PR count lookup failed: "+err.Error())
	}

	// Fetch owner profile
	var gu ghUser
	if err := ghGet(ctx, cfg, gr.Owner.URL, &gu); err != nil {
		ra.Notes = append(ra.Notes, "Owner profile lookup failed: "+err.Error())
	} else {
		ra.OwnerDisplay = gu.Login
		if gu.Name != "" {
			ra.OwnerDisplay = fmt.Sprintf("%s (%s)", gu.Login, gu.Name)
		}
		ra.OwnerLocation = gu.Location
		if cfg.EnableGeoGuess {
			ra.CountryGuess = naiveCountryGuess(gu.Location)
		}
	}

	ra.RepoURL = gr.HTMLURL
}

func fetchIssueCounts(ctx context.Context, cfg *config.Config, ra *Assessment) error {
	// Use list endpoints instead of search API (better rate limits)
	// Get open PRs count
	openPRsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls?state=open&per_page=1", ra.Owner, ra.Repo)
	openPRCount, err := getCountFromListEndpoint(ctx, cfg, openPRsURL)
	if err != nil {
		return fmt.Errorf("open PRs: %w", err)
	}
	ra.OpenPRs = openPRCount

	// Get closed PRs count
	closedPRsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls?state=closed&per_page=1", ra.Owner, ra.Repo)
	closedPRCount, err := getCountFromListEndpoint(ctx, cfg, closedPRsURL)
	if err != nil {
		return fmt.Errorf("closed PRs: %w", err)
	}
	ra.ClosedPRs = closedPRCount

	// Get closed issues count (open issues from repo API)
	closedIssuesURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues?state=closed&per_page=1", ra.Owner, ra.Repo)
	closedIssuesCount, err := getCountFromListEndpoint(ctx, cfg, closedIssuesURL)
	if err != nil {
		return fmt.Errorf("closed issues: %w", err)
	}
	ra.ClosedIssues = closedIssuesCount

	// GitHub's open_issues_count includes open PRs, so subtract
	ra.OpenIssues = ra.OpenIssues - ra.OpenPRs
	if ra.OpenIssues < 0 {
		ra.OpenIssues = 0
	}

	return nil
}

func getCountFromListEndpoint(ctx context.Context, cfg *config.Config, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", cfg.UserAgent)
	if cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// Parse Link header to get total count
	// Format: <url>; rel="next", <url>; rel="last"
	linkHeader := resp.Header.Get("Link")
	if linkHeader == "" {
		// No pagination, count the items in response
		var items []map[string]interface{}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxHTTPBytes))
		if err := unmarshalJSON(body, &items); err != nil {
			return 0, err
		}
		return len(items), nil
	}

	// Extract page number from last link
	// Example: <https://api.github.com/repos/owner/repo/pulls?state=open&per_page=1&page=42>; rel="last"
	for _, link := range strings.Split(linkHeader, ",") {
		if strings.Contains(link, `rel="last"`) {
			// Extract URL
			start := strings.Index(link, "<")
			end := strings.Index(link, ">")
			if start >= 0 && end > start {
				lastURL := link[start+1 : end]
				// Parse page parameter
				if strings.Contains(lastURL, "page=") {
					parts := strings.Split(lastURL, "page=")
					if len(parts) > 1 {
						pageStr := strings.Split(parts[1], "&")[0]
						var count int
						fmt.Sscanf(pageStr, "%d", &count)
						return count, nil
					}
				}
			}
		}
	}

	// Fallback: just return 0 if we can't parse
	return 0, nil
}

func ghGet(ctx context.Context, cfg *config.Config, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", cfg.UserAgent)
	if cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxHTTPBytes))
	if err != nil {
		return err
	}

	return unmarshalJSON(body, into)
}

func naiveCountryGuess(location string) string {
	loc := strings.ToLower(strings.TrimSpace(location))
	if loc == "" {
		return ""
	}
	switch {
	case strings.Contains(loc, "norway") || strings.Contains(loc, "norge") || strings.Contains(loc, "oslo"):
		return "Norway (guessed)"
	case strings.Contains(loc, "sweden") || strings.Contains(loc, "sverige") || strings.Contains(loc, "stockholm"):
		return "Sweden (guessed)"
	case strings.Contains(loc, "denmark") || strings.Contains(loc, "danmark") || strings.Contains(loc, "copenhagen"):
		return "Denmark (guessed)"
	case strings.Contains(loc, "finland") || strings.Contains(loc, "helsinki"):
		return "Finland (guessed)"
	case strings.Contains(loc, "usa") || strings.Contains(loc, "united states") || strings.Contains(loc, "america"):
		return "USA (guessed)"
	case strings.Contains(loc, "uk") || strings.Contains(loc, "united kingdom") || strings.Contains(loc, "london") || strings.Contains(loc, "england"):
		return "UK (guessed)"
	case strings.Contains(loc, "germany") || strings.Contains(loc, "deutschland") || strings.Contains(loc, "berlin"):
		return "Germany (guessed)"
	case strings.Contains(loc, "france") || strings.Contains(loc, "paris"):
		return "France (guessed)"
	case strings.Contains(loc, "canada"):
		return "Canada (guessed)"
	case strings.Contains(loc, "australia"):
		return "Australia (guessed)"
	case strings.Contains(loc, "china") || strings.Contains(loc, "beijing") || strings.Contains(loc, "shanghai"):
		return "China (guessed)"
	case strings.Contains(loc, "japan") || strings.Contains(loc, "tokyo"):
		return "Japan (guessed)"
	case strings.Contains(loc, "india"):
		return "India (guessed)"
	case strings.Contains(loc, "netherlands") || strings.Contains(loc, "amsterdam"):
		return "Netherlands (guessed)"
	case strings.Contains(loc, "spain") || strings.Contains(loc, "madrid") || strings.Contains(loc, "barcelona"):
		return "Spain (guessed)"
	default:
		return ""
	}
}
