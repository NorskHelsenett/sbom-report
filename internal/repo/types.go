package repo

import (
	"time"

	"sbom-report/internal/git"
)

type Assessment struct {
	Remote   git.Remote
	Provider string
	RepoURL  string
	Owner    string
	Repo     string

	OwnerDisplay     string
	LastCommitAuthor string

	OwnerLocation string
	CountryGuess  string

	DefaultBranch string
	Archived      bool
	License       string

	UpdatedAt      time.Time
	PushedAt       time.Time
	LastActivityAt time.Time

	MaintenanceStatus string
	StalenessDays     int

	OpenIssues   int
	ClosedIssues int
	OpenPRs      int
	ClosedPRs    int
	Forks        int
	Stars        int
	Watchers     int

	Vulnerabilities []Vulnerability

	Notes []string
	Err   string
}

type Vulnerability struct {
	ID          string
	Severity    string
	Score       float64
	Title       string
	Description string
	Package     string
	Version     string
}
