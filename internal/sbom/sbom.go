package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"sbom-report/internal/deps"
)

type Summary struct {
	Format         string
	SpecVersion    string
	SerialNumber   string
	MetadataTool   string
	MetadataTime   string
	ComponentCount int
	TopComponents  []ComponentSummary
	ComponentTypes map[string]int
	Namespaces     map[string]int
	Errors         []string
}

type ComponentSummary struct {
	Name    string
	Version string
	Type    string
	PURL    string
}

type TrivyResult struct {
	SBOMPath string
	Stdout   string
	Stderr   string
	OK       bool
}

func RunTrivy(trivyPath, sbomFormat, baseDir, outputPath string) TrivyResult {
	args := []string{
		"fs",
		"--format", sbomFormat,
		"--output", outputPath,
		baseDir,
	}

	cmd := exec.Command(trivyPath, args...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	stdout := outb.String()
	stderr := errb.String()
	if err != nil {
		stderr = stderr + "\n(trivy error: " + err.Error() + ")"
		return TrivyResult{SBOMPath: outputPath, Stdout: stdout, Stderr: stderr, OK: false}
	}
	return TrivyResult{SBOMPath: outputPath, Stdout: stdout, Stderr: stderr, OK: true}
}

type VulnResult struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string  `json:"VulnerabilityID"`
			PkgName         string  `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			Severity        string  `json:"Severity"`
			Title           string  `json:"Title"`
			Description     string  `json:"Description"`
			CVSS            map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func RunVulnerabilityScan(trivyPath, baseDir, outputPath string) (map[string][]VulnInfo, error) {
	args := []string{
		"fs",
		"--format", "json",
		"--output", outputPath,
		baseDir,
	}

	cmd := exec.Command(trivyPath, args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	// Parse the vulnerability report
	f, err := os.Open(outputPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vulnResult VulnResult
	if err := json.NewDecoder(f).Decode(&vulnResult); err != nil {
		return nil, err
	}

	// Map package names to vulnerabilities
	vulnMap := make(map[string][]VulnInfo)
	for _, result := range vulnResult.Results {
		for _, vuln := range result.Vulnerabilities {
			score := 0.0
			for _, cvss := range vuln.CVSS {
				if cvss.V3Score > score {
					score = cvss.V3Score
				}
			}

			vulnMap[vuln.PkgName] = append(vulnMap[vuln.PkgName], VulnInfo{
				ID:          vuln.VulnerabilityID,
				Severity:    vuln.Severity,
				Score:       score,
				Title:       vuln.Title,
				Description: vuln.Description,
				Package:     vuln.PkgName,
				Version:     vuln.InstalledVersion,
			})
		}
	}

	return vulnMap, nil
}

type VulnInfo struct {
	ID          string
	Severity    string
	Score       float64
	Title       string
	Description string
	Package     string
	Version     string
}

func ParseCycloneDX(path string) (*Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var bom cdx.BOM
	dec := json.NewDecoder(f)
	if err := dec.Decode(&bom); err != nil {
		return nil, err
	}

	summary := &Summary{
		Format:         "CycloneDX JSON",
		SpecVersion:    string(bom.SpecVersion),
		SerialNumber:   bom.SerialNumber,
		ComponentTypes: map[string]int{},
		Namespaces:     map[string]int{},
	}

	if bom.Metadata != nil {
		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Tools != nil && len(*bom.Metadata.Tools.Tools) > 0 {
			t := (*bom.Metadata.Tools.Tools)[0]
			summary.MetadataTool = strings.TrimSpace(t.Name + " " + t.Version)
		}
		if bom.Metadata.Timestamp != "" {
			summary.MetadataTime = bom.Metadata.Timestamp
		}
	}

	components := bom.Components
	if components == nil {
		return summary, nil
	}

	summary.ComponentCount = len(*components)

	// Summaries
	typeCount := map[string]int{}
	nsCount := map[string]int{}
	summaries := make([]ComponentSummary, 0, min(15, len(*components)))

	all := make([]cdx.Component, 0, len(*components))
	for _, c := range *components {
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool {
		return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name)
	})

	for i, c := range all {
		ct := string(c.Type)
		typeCount[ct]++

		purl := ""
		if c.PackageURL != "" {
			purl = c.PackageURL
			if ns := purlNamespace(purl); ns != "" {
				nsCount[ns]++
			}
		}

		if i < cap(summaries) {
			summaries = append(summaries, ComponentSummary{
				Name:    c.Name,
				Version: c.Version,
				Type:    ct,
				PURL:    purl,
			})
		}
	}

	summary.ComponentTypes = typeCount
	summary.Namespaces = nsCount
	summary.TopComponents = summaries
	return summary, nil
}

func ExtractPackagesFromSBOM(sbomPath string) (npm []deps.PackageRef, python []deps.PackageRef) {
	f, err := os.Open(sbomPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var bom cdx.BOM
	dec := json.NewDecoder(f)
	if err := dec.Decode(&bom); err != nil {
		return nil, nil
	}

	if bom.Components == nil {
		return nil, nil
	}

	seen := make(map[string]bool)

	for _, c := range *bom.Components {
		purl := c.PackageURL
		if purl == "" {
			continue
		}

		if strings.HasPrefix(purl, "pkg:npm/") {
			name := c.Name
			key := "npm:" + name
			if !seen[key] {
				seen[key] = true
				npm = append(npm, deps.PackageRef{
					Ecosystem: "npm",
					Name:      name,
					Version:   c.Version,
					Source:    "SBOM",
				})
			}
		} else if strings.HasPrefix(purl, "pkg:pypi/") {
			name := c.Name
			key := "pypi:" + name
			if !seen[key] {
				seen[key] = true
				python = append(python, deps.PackageRef{
					Ecosystem: "python",
					Name:      name,
					Version:   c.Version,
					Source:    "SBOM",
				})
			}
		}
	}

	return npm, python
}

func purlNamespace(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	p := strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 2 {
		return parts[0]
	}
	return parts[0]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
