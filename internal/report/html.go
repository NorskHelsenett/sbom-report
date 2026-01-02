package report

import (
	"html/template"
	"os"
	"time"
)

func RenderHTML(outPath string, rep *Report) error {
	tpl, err := template.New("report").Funcs(template.FuncMap{
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format(time.RFC3339)
		},
		"cvssColor": func(score float64) string {
			if score >= 9.0 {
				return "#d32f2f" // Critical - red
			} else if score >= 7.0 {
				return "#f57c00" // High - orange
			} else if score >= 4.0 {
				return "#ffa726" // Medium - yellow
			}
			return "#388e3c" // Low - green
		},
		"cvssLabel": func(severity string) string {
			switch severity {
			case "CRITICAL":
				return "CRITICAL"
			case "HIGH":
				return "HIGH"
			case "MEDIUM":
				return "MEDIUM"
			case "LOW":
				return "LOW"
			default:
				return severity
			}
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tpl.Execute(f, rep)
}

const htmlTemplate = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SBOM + Repo Hygiene Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --color-primary-dark: #015945;
      --color-primary-light: #7BEFB2;
      --color-green-1: #002920;
      --color-green-2: #247360;
      --color-green-3: #02A67F;
      --color-green-4: #C4F2DA;
      --color-gray-1: #000000;
      --color-gray-2: #808285;
      --color-gray-3: #BCBEC0;
      
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #1c2128;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --border-color: #30363d;
    }
    body { 
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; 
      margin: 24px; 
      line-height: 1.35;
      color: var(--text-primary);
      background-color: var(--bg-primary);
    }
    h1, h2, h3 { color: var(--color-primary-light); }
    a { color: var(--color-green-3); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .muted { color: var(--text-secondary); }
    .ok { font-weight: 600; color: var(--color-green-3); }
    .bad { font-weight: 700; color: #f85149; }
    .box { 
      border: 1px solid var(--border-color); 
      border-radius: 10px; 
      padding: 16px; 
      margin: 14px 0;
      background: var(--bg-secondary);
    }
    table { 
      border-collapse: collapse; 
      width: 100%;
      background: var(--bg-tertiary);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td { 
      border-bottom: 1px solid var(--border-color); 
      padding: 8px; 
      text-align: left; 
      vertical-align: top; 
    }
    th { 
      background: var(--color-primary-dark);
      color: white;
      font-weight: 600;
      cursor: pointer;
      user-select: none;
      position: relative;
      padding-right: 20px;
    }
    th:hover {
      background: var(--color-green-2);
    }
    th.sortable::after {
      content: '⇅';
      position: absolute;
      right: 8px;
      opacity: 0.5;
      font-size: 10px;
    }
    th.sort-asc::after {
      content: '▲';
      opacity: 1;
    }
    th.sort-desc::after {
      content: '▼';
      opacity: 1;
    }
    code { 
      background: var(--bg-primary); 
      padding: 2px 4px; 
      border-radius: 5px;
      color: var(--color-primary-light);
      font-size: 0.9em;
      border: 1px solid var(--border-color);
    }
    .pill { 
      display: inline-block; 
      padding: 2px 8px; 
      border-radius: 999px; 
      border: 1px solid var(--color-green-3); 
      font-size: 12px;
      background: var(--color-green-1);
      color: var(--color-primary-light);
      font-weight: 500;
    }
    .cve-badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 5px;
      font-size: 11px;
      color: white;
      font-weight: 600;
      margin: 2px;
      text-decoration: none;
    }
    .cve-badge:hover {
      text-decoration: underline;
      opacity: 0.9;
    }
    .vuln-section {
      margin-top: 8px;
      padding-top: 8px;
      border-top: 1px solid var(--border-color);
    }
    details summary { 
      cursor: pointer; 
      color: var(--color-green-3);
      font-weight: 500;
    }
    details summary:hover { color: var(--color-primary-light); }
    details[open] summary {
      margin-bottom: 12px;
    }
    summary {
      font-size: 1.17em;
      font-weight: bold;
      color: var(--color-primary-light);
      margin-bottom: 8px;
    }
    summary:hover {
      color: var(--color-green-3);
    }
    pre { 
      background: var(--bg-primary); 
      padding: 12px; 
      border-radius: 5px;
      overflow-x: auto;
      border-left: 3px solid var(--color-green-3);
      color: var(--text-primary);
    }
  </style>
</head>
<body>
  <h1>SBOM + Repo Hygiene Report</h1>
  <div class="muted">Generated at: <code>{{ .GeneratedAt.Format "2006-01-02 15:04:05Z07:00" }}</code></div>
  <div class="muted">Base dir: <code>{{ .BaseDir }}</code></div>

  <div class="box">
    <details open>
      <summary>Trivy SBOM</summary>
      <div>SBOM file: <code>{{ .Trivy.SBOMPath }}</code></div>
      <div>Status:
        {{ if .Trivy.OK }}<span class="pill ok">OK</span>{{ else }}<span class="pill bad">FAILED</span>{{ end }}
      </div>
      {{ if .Trivy.Stderr }}
        <details>
          <summary>Trivy stderr</summary>
          <pre>{{ .Trivy.Stderr }}</pre>
        </details>
      {{ end }}
    </details>
  </div>

  <div class="box">
    <details open>
      <summary>SBOM Summary</summary>
      <div>Format: <code>{{ .SBOM.Format }}</code></div>
      <div>Spec: <code>{{ .SBOM.SpecVersion }}</code></div>
      <div>Components: <code>{{ .SBOM.ComponentCount }}</code></div>
      {{ if .SBOM.MetadataTool }}<div>Tool: <code>{{ .SBOM.MetadataTool }}</code></div>{{ end }}
      {{ if .SBOM.Errors }}
        <div class="bad">Parse issues:</div>
        <ul>
          {{ range .SBOM.Errors }}<li>{{ . }}</li>{{ end }}
        </ul>
      {{ end }}

      <h3>Top components (sample)</h3>
      <table>
        <tr><th>Name</th><th>Version</th><th>Type</th><th>PURL</th></tr>
        {{ range .SBOM.TopComponents }}
          <tr>
            <td>{{ .Name }}</td>
            <td><code>{{ .Version }}</code></td>
            <td>{{ .Type }}</td>
            <td><code>{{ .PURL }}</code></td>
          </tr>
        {{ end }}
      </table>
    </details>
  </div>

  <div class="box">
    <details open>
      <summary>Project Git</summary>
      <div>Git detected: <code>{{ .Project.GitDetected }}</code></div>
      {{ if .Project.LastCommit }}
        <div>Last commit: <code>{{ .Project.LastCommit.Hash }}</code></div>
        <div>Author: <code>{{ .Project.LastCommit.Author }} &lt;{{ .Project.LastCommit.AuthorEmail }}&gt;</code></div>
        <div>Date: <code>{{ ts .Project.LastCommit.Date }}</code></div>
        <div>Subject: {{ .Project.LastCommit.Subject }}</div>
      {{ end }}

      <h3>Remotes</h3>
      <table>
        <tr><th>Name</th><th>URL</th><th>Host</th><th>Path</th></tr>
        {{ range .Project.Remotes }}
          <tr><td>{{ .Name }}</td><td><code>{{ .URL }}</code></td><td>{{ .Host }}</td><td><code>{{ .Path }}</code></td></tr>
        {{ end }}
      </table>
    </details>
  </div>

  <div class="box">
    <details open>
      <summary>Dependency / Package Repository Usage</summary>

      <h3>Go modules</h3>
      {{ if .Dependencies.GoModules }}
      <table>
        <tr><th>Module</th><th>Version</th><th>Replace</th></tr>
        {{ range .Dependencies.GoModules }}
          <tr><td><code>{{ .Path }}</code></td><td><code>{{ .Version }}</code></td><td><code>{{ .Replace }}</code></td></tr>
        {{ end }}
      </table>
      {{ else }}
        <div class="muted">No go.mod or unable to list modules.</div>
      {{ end }}

      <h3>NPM</h3>
      {{ if .Dependencies.NpmPackages }}
        <table>
          <tr><th>Name</th><th>Version</th><th>Source</th></tr>
          {{ range .Dependencies.NpmPackages }}
            <tr><td><code>{{ .Name }}</code></td><td><code>{{ .Version }}</code></td><td><code>{{ .Source }}</code></td></tr>
          {{ end }}
        </table>
      {{ else }}
        <div class="muted">No npm lockfile detected (or not parsed).</div>
      {{ end }}

      <h3>Python</h3>
      {{ if .Dependencies.PythonReqs }}
        <table>
          <tr><th>Name</th><th>Version</th><th>Source</th></tr>
          {{ range .Dependencies.PythonReqs }}
            <tr><td><code>{{ .Name }}</code></td><td><code>{{ .Version }}</code></td><td><code>{{ .Source }}</code></td></tr>
          {{ end }}
        </table>
      {{ else }}
        <div class="muted">No python dependency files detected (or not parsed).</div>
      {{ end }}

      <h3>Maven</h3>
      {{ if .Dependencies.MavenDeps }}
        <table>
          <tr><th>Name</th><th>Version</th><th>Source</th></tr>
          {{ range .Dependencies.MavenDeps }}
            <tr><td><code>{{ .Name }}</code></td><td><code>{{ .Version }}</code></td><td><code>{{ .Source }}</code></td></tr>
          {{ end }}
        </table>
      {{ else }}
        <div class="muted">No pom.xml detected (or not parsed).</div>
      {{ end }}
    </details>
  </div>

  <div class="box">
    <details open>
      <summary>Remote Repo Assessments</summary>
      {{ if .Repos }}
        <table id="repoTable">
          <thead>
          <tr>
            <th class="sortable" data-sort="0">Repo</th>
            <th class="sortable" data-sort="1">Provider</th>
            <th class="sortable" data-sort="2">Owner / "Author"</th>
            <th class="sortable" data-sort="3">Location / Country</th>
            <th class="sortable" data-sort="4">Last activity</th>
            <th class="sortable" data-sort="5">Status</th>
            <th class="sortable" data-sort="6">Liveness Metrics</th>
            <th class="sortable" data-sort="7">License</th>
            <th class="sortable" data-sort="8">Vulnerabilities</th>
            <th class="sortable" data-sort="9">Notes / Errors</th>
          </tr>
          </thead>
          <tbody>
          {{ range .Repos }}
            <tr>
              <td><a href="{{ .RepoURL }}">{{ .Owner }}/{{ .Repo }}</a></td>
              <td>{{ .Provider }}</td>
              <td>
                <div>Owner: <code>{{ .OwnerDisplay }}</code></div>
                {{ if .LastCommitAuthor }}<div>Last commit author: <code>{{ .LastCommitAuthor }}</code></div>{{ end }}
              </td>
              <td>
                <div>Location: <code>{{ .OwnerLocation }}</code></div>
                {{ if .CountryGuess }}<div>Country: <code>{{ .CountryGuess }}</code></div>{{ end }}
              </td>
              <td>
                <div><code>{{ ts .LastActivityAt }}</code></div>
                {{ if .StalenessDays }}<div class="muted">{{ .StalenessDays }} days since activity</div>{{ end }}
              </td>
              <td><span class="pill">{{ .MaintenanceStatus }}</span></td>
              <td>
                <div>Stars: <strong>{{ .Stars }}</strong></div>
                <div>Forks: <strong>{{ .Forks }}</strong></div>
                <div>Watchers: <strong>{{ .Watchers }}</strong></div>
                <div>Issues: {{ .OpenIssues }} open / {{ .ClosedIssues }} closed</div>
                <div>PRs: {{ .OpenPRs }} open / {{ .ClosedPRs }} closed</div>
              </td>
              <td>
                {{ if .License }}<code>{{ .License }}</code>{{ else }}<span class="muted">-</span>{{ end }}
              </td>
              <td>
                {{ if .Vulnerabilities }}
                  <div><strong>{{ len .Vulnerabilities }} CVEs</strong></div>
                  {{ range .Vulnerabilities }}
                    <a href="https://nvd.nist.gov/vuln/detail/{{ .ID }}" 
                       class="cve-badge" 
                       style="background-color: {{ cvssColor .Score }}"
                       title="{{ .Title }}">
                      {{ .ID }}
                      {{ if .Score }}({{ printf "%.1f" .Score }}){{ end }}
                    </a>
                  {{ end }}
                {{ else }}
                  <span class="muted">None</span>
                {{ end }}
              </td>
              <td>
                {{ if .Err }}<div class="bad">{{ .Err }}</div>{{ end }}
                {{ if .Archived }}<div class="bad">Archived</div>{{ end }}
                {{ if .Notes }}
                  <ul>{{ range .Notes }}<li>{{ . }}</li>{{ end }}</ul>
                {{ end }}
              </td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      {{ else }}
        <div class="muted">No remotes found.</div>
      {{ end }}
    </details>
  </div>

  <script>
    // Make table sortable
    document.addEventListener('DOMContentLoaded', function() {
      const table = document.getElementById('repoTable');
      if (!table) return;
      
      const headers = table.querySelectorAll('th.sortable');
      let sortDirection = {};
      
      headers.forEach(header => {
        const col = header.dataset.sort;
        sortDirection[col] = 1; // 1 = ascending, -1 = descending
        
        header.addEventListener('click', function() {
          const tbody = table.querySelector('tbody');
          const rows = Array.from(tbody.querySelectorAll('tr'));
          
          // Toggle sort direction
          sortDirection[col] *= -1;
          
          // Remove sort indicators from all headers
          headers.forEach(h => {
            h.classList.remove('sort-asc', 'sort-desc');
          });
          
          // Add sort indicator to clicked header
          header.classList.add(sortDirection[col] === 1 ? 'sort-asc' : 'sort-desc');
          
          // Sort rows
          rows.sort((a, b) => {
            const cellA = a.cells[col];
            const cellB = b.cells[col];
            
            if (!cellA || !cellB) return 0;
            
            let valA = cellA.textContent.trim();
            let valB = cellB.textContent.trim();
            
            // Try to parse as number
            const numA = parseFloat(valA);
            const numB = parseFloat(valB);
            
            if (!isNaN(numA) && !isNaN(numB)) {
              return (numA - numB) * sortDirection[col];
            }
            
            // String comparison
            return valA.localeCompare(valB) * sortDirection[col];
          });
          
          // Re-append sorted rows
          rows.forEach(row => tbody.appendChild(row));
        });
      });
    });
  </script>

</body>
</html>`
