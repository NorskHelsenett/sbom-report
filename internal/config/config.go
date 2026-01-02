package config

import (
	"time"
)

type VulnInfo struct {
	ID          string
	Severity    string
	Score       float64
	Title       string
	Description string
	Package     string
	Version     string
}

type Config struct {
	BaseDir        string
	OutDir         string
	TrivyPath      string
	GitHubToken    string
	EnableGeoGuess bool
	Now            time.Time
	RequestTimeout time.Duration
	UserAgent      string
	MaxHTTPBytes   int64
	TrivyFormat    string
	TrivySBOMName  string
	HTMLReportName string
	VulnMap        map[string][]VulnInfo
}
