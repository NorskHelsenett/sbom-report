package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Remote struct {
	Name string
	URL  string
	Kind string // https/ssh/file/unknown
	Host string
	Path string // e.g. owner/repo
}

type Commit struct {
	Hash        string
	Author      string
	AuthorEmail string
	Date        time.Time
	Subject     string
}

func IsGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func GetRemotes(dir string) []Remote {
	cmd := exec.Command("git", "remote", "-v")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var remotes []Remote
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		url := fields[1]
		key := name + "|" + url
		if seen[key] {
			continue
		}
		seen[key] = true

		r := Remote{Name: name, URL: url}
		r.Kind, r.Host, r.Path = parseRemoteURL(url)
		remotes = append(remotes, r)
	}
	return remotes
}

func GetLastCommit(dir string) *Commit {
	cmd := exec.Command("git", "log", "-1", "--format=%H|%an|%ae|%aI|%s")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	fields := strings.SplitN(strings.TrimSpace(string(out)), "|", 5)
	if len(fields) < 5 {
		return nil
	}

	date, _ := time.Parse(time.RFC3339, fields[3])
	return &Commit{
		Hash:        fields[0],
		Author:      fields[1],
		AuthorEmail: fields[2],
		Date:        date,
		Subject:     fields[4],
	}
}

func parseRemoteURL(rawURL string) (kind, host, path string) {
	rawURL = strings.TrimSpace(rawURL)

	// ssh: git@github.com:owner/repo.git
	sshRe := regexp.MustCompile(`^[a-zA-Z0-9_.-]+@([^:]+):(.+)$`)
	if m := sshRe.FindStringSubmatch(rawURL); m != nil {
		return "ssh", m[1], strings.TrimSuffix(m[2], ".git")
	}

	// https/http
	if strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://") {
		var scheme string
		if strings.HasPrefix(rawURL, "https://") {
			scheme = "https"
			rawURL = strings.TrimPrefix(rawURL, "https://")
		} else {
			scheme = "http"
			rawURL = strings.TrimPrefix(rawURL, "http://")
		}

		parts := strings.SplitN(rawURL, "/", 2)
		if len(parts) == 2 {
			return scheme, parts[0], strings.TrimSuffix(parts[1], ".git")
		}
		return scheme, parts[0], ""
	}

	// file:// or other
	if strings.HasPrefix(rawURL, "file://") {
		return "file", "", strings.TrimPrefix(rawURL, "file://")
	}

	return "unknown", "", rawURL
}
