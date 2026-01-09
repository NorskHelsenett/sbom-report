package graph

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sbom-report/internal/deps"
	"sbom-report/internal/repo"
)

// Node represents a dependency in the graph
type Node struct {
	ID           string
	Label        string
	FullName     string
	Type         string // "project", "go", "npm", "python", "maven", "repo"
	X, Y         float64
	Level        int // Depth in dependency tree
	Color        string
	IsVulnerable bool
}

// Edge represents a connection between dependencies
type Edge struct {
	From string
	To   string
}

// Graph represents the dependency graph
type Graph struct {
	Nodes        []Node
	Edges        []Edge
	nodeIndex    map[string]int      // Quick lookup for node by ID
	adjacencyMap map[string][]string // For layout calculations
}

// GenerateDependencyGraph creates an SVG visualization of dependencies
func GenerateDependencyGraph(outputPath string, projectName string, goMods []deps.GoModule, npmPkgs, pythonPkgs, mavenDeps []deps.PackageRef, repos []repo.Assessment) error {
	g := &Graph{
		Nodes:        []Node{},
		Edges:        []Edge{},
		nodeIndex:    make(map[string]int),
		adjacencyMap: make(map[string][]string),
	}

	// Add root project node
	rootID := sanitizeID("project-" + projectName)
	g.addNode(Node{
		ID:       rootID,
		Label:    truncate(projectName, 40),
		FullName: projectName,
		Type:     "project",
		Color:    "#7BEFB2",
		Level:    0,
	})

	// Get base directory for go mod graph
	baseDir := filepath.Dir(outputPath)
	if wd, err := os.Getwd(); err == nil {
		baseDir = wd
	}

	// Parse Go module dependencies with transitive relationships
	if len(goMods) > 0 {
		parseGoModGraph(g, rootID, baseDir, repos)
	}

	// For NPM, Python, Maven - add as direct dependencies for now
	// (can be enhanced later to parse their dependency trees)
	for _, pkg := range npmPkgs {
		nodeID := sanitizeID("npm-" + pkg.Name)
		if !g.hasNode(nodeID) {
			isVuln := hasVulnerability(pkg.Name, repos)
			g.addNode(Node{
				ID:           nodeID,
				Label:        truncate(pkg.Name, 40),
				FullName:     pkg.Name,
				Type:         "npm",
				Color:        getColorByType("npm", isVuln),
				IsVulnerable: isVuln,
				Level:        1,
			})
			g.addEdge(rootID, nodeID)
		}
	}

	for _, pkg := range pythonPkgs {
		nodeID := sanitizeID("python-" + pkg.Name)
		if !g.hasNode(nodeID) {
			isVuln := hasVulnerability(pkg.Name, repos)
			g.addNode(Node{
				ID:           nodeID,
				Label:        truncate(pkg.Name, 40),
				FullName:     pkg.Name,
				Type:         "python",
				Color:        getColorByType("python", isVuln),
				IsVulnerable: isVuln,
				Level:        1,
			})
			g.addEdge(rootID, nodeID)
		}
	}

	for _, pkg := range mavenDeps {
		nodeID := sanitizeID("maven-" + pkg.Name)
		if !g.hasNode(nodeID) {
			isVuln := hasVulnerability(pkg.Name, repos)
			g.addNode(Node{
				ID:           nodeID,
				Label:        truncate(pkg.Name, 40),
				FullName:     pkg.Name,
				Type:         "maven",
				Color:        getColorByType("maven", isVuln),
				IsVulnerable: isVuln,
				Level:        1,
			})
			g.addEdge(rootID, nodeID)
		}
	}

	// Calculate levels for all nodes based on dependency depth
	g.calculateLevels(rootID)

	// Layout the graph hierarchically
	layoutHierarchical(g)

	// Generate SVG
	return generateSVG(g, outputPath)
}

// parseGoModGraph parses the output of `go mod graph` to get transitive dependencies
func parseGoModGraph(g *Graph, rootID, baseDir string, repos []repo.Assessment) {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = baseDir
	output, err := cmd.Output()
	if err != nil {
		// Fallback: can't get graph, skip Go dependencies
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		fromPkg := parts[0]
		toPkg := parts[1]

		// Determine if this is a direct dependency from the project
		var fromID string
		if strings.HasPrefix(fromPkg, "sbom-report") || !strings.Contains(fromPkg, "@") {
			fromID = rootID
		} else {
			fromID = sanitizeID("go-" + fromPkg)
		}

		toID := sanitizeID("go-" + toPkg)

		// Extract package name from versioned string (e.g., "github.com/foo/bar@v1.2.3" -> "github.com/foo/bar")
		toName := extractPackageName(toPkg)
		isVuln := hasVulnerability(toName, repos)

		// Add the "to" node if it doesn't exist
		if !g.hasNode(toID) {
			g.addNode(Node{
				ID:           toID,
				Label:        truncate(toName, 50),
				FullName:     toPkg,
				Type:         "go",
				Color:        getColorByType("go", isVuln),
				IsVulnerable: isVuln,
			})
		}

		// Add the "from" node if it's not the root and doesn't exist
		if fromID != rootID && !g.hasNode(fromID) {
			fromName := extractPackageName(fromPkg)
			fromVuln := hasVulnerability(fromName, repos)
			g.addNode(Node{
				ID:           fromID,
				Label:        truncate(fromName, 50),
				FullName:     fromPkg,
				Type:         "go",
				Color:        getColorByType("go", fromVuln),
				IsVulnerable: fromVuln,
			})
		}

		// Add edge
		g.addEdge(fromID, toID)
	}
}

// extractPackageName extracts the package path from a versioned string
func extractPackageName(pkg string) string {
	if idx := strings.Index(pkg, "@"); idx != -1 {
		return pkg[:idx]
	}
	return pkg
}

// Graph helper methods
func (g *Graph) addNode(n Node) {
	g.nodeIndex[n.ID] = len(g.Nodes)
	g.Nodes = append(g.Nodes, n)
}

func (g *Graph) hasNode(id string) bool {
	_, exists := g.nodeIndex[id]
	return exists
}

func (g *Graph) addEdge(from, to string) {
	g.Edges = append(g.Edges, Edge{From: from, To: to})
	g.adjacencyMap[from] = append(g.adjacencyMap[from], to)
}

func (g *Graph) getNode(id string) *Node {
	if idx, ok := g.nodeIndex[id]; ok {
		return &g.Nodes[idx]
	}
	return nil
}

// calculateLevels performs BFS to assign levels to nodes
func (g *Graph) calculateLevels(rootID string) {
	visited := make(map[string]bool)
	queue := []string{rootID}
	visited[rootID] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentNode := g.getNode(current)
		if currentNode == nil {
			continue
		}

		for _, childID := range g.adjacencyMap[current] {
			if !visited[childID] {
				visited[childID] = true
				childNode := g.getNode(childID)
				if childNode != nil {
					childNode.Level = currentNode.Level + 1
					queue = append(queue, childID)
				}
			}
		}
	}
}

// layoutHierarchical arranges nodes in a hierarchical tree layout
func layoutHierarchical(g *Graph) {
	if len(g.Nodes) == 0 {
		return
	}

	// Group nodes by level
	levelGroups := make(map[int][]int)
	maxLevel := 0
	for i, node := range g.Nodes {
		levelGroups[node.Level] = append(levelGroups[node.Level], i)
		if node.Level > maxLevel {
			maxLevel = node.Level
		}
	}

	// Layout parameters - pacgraph-style tree layout with spacing for label boxes
	minHorizontalSpacing := 30.0 // Minimum gap between label boxes
	verticalSpacing := 180.0     // Increased to accommodate label boxes
	startY := 100.0

	// Calculate actual width needed for each node's label
	nodeWidth := make(map[string]float64)
	for i, node := range g.Nodes {
		// Estimate text width (roughly 7 pixels per character for 12px monospace font)
		textWidth := float64(len(node.Label)) * 7.0
		boxWidth := textWidth + 12.0 // Add padding
		nodeWidth[node.ID] = boxWidth
		_ = i
	}

	// Calculate positions using a tree layout approach
	// First pass: calculate subtree widths
	subtreeWidth := make(map[string]float64)

	// Process levels bottom-up to calculate widths
	for level := maxLevel; level >= 0; level-- {
		indices := levelGroups[level]
		for _, idx := range indices {
			nodeID := g.Nodes[idx].ID
			children := g.adjacencyMap[nodeID]

			if len(children) == 0 {
				// Leaf node - width is the node's label width plus minimum spacing
				subtreeWidth[nodeID] = nodeWidth[nodeID] + minHorizontalSpacing
			} else {
				// Internal node: width is max of (sum of children's widths, own label width)
				totalWidth := 0.0
				for _, childID := range children {
					totalWidth += subtreeWidth[childID]
				}
				// Ensure parent is at least as wide as its label
				ownWidth := nodeWidth[nodeID] + minHorizontalSpacing
				if totalWidth < ownWidth {
					totalWidth = ownWidth
				}
				subtreeWidth[nodeID] = totalWidth
			}
		}
	}

	// Second pass: position nodes top-down
	positioned := make(map[string]bool)

	// Position root node(s)
	rootIndices := levelGroups[0]
	currentX := 300.0 // Offset to avoid legend

	for _, idx := range rootIndices {
		nodeID := g.Nodes[idx].ID
		width := subtreeWidth[nodeID]
		g.Nodes[idx].X = currentX + width/2
		g.Nodes[idx].Y = startY
		positioned[nodeID] = true
		positionChildren(g, nodeID, currentX, startY+verticalSpacing, verticalSpacing, subtreeWidth, positioned)
		currentX += width + minHorizontalSpacing
	}
}

// positionChildren recursively positions child nodes centered under their parent
func positionChildren(g *Graph, parentID string, leftBound, y, vSpacing float64, subtreeWidth map[string]float64, positioned map[string]bool) {
	children := g.adjacencyMap[parentID]
	if len(children) == 0 {
		return
	}

	currentX := leftBound
	for _, childID := range children {
		if positioned[childID] {
			continue // Already positioned (handles DAGs)
		}

		childIdx, ok := g.nodeIndex[childID]
		if !ok {
			continue
		}

		width := subtreeWidth[childID]
		g.Nodes[childIdx].X = currentX + width/2
		g.Nodes[childIdx].Y = y
		positioned[childID] = true

		// Recursively position this child's children
		positionChildren(g, childID, currentX, y+vSpacing, vSpacing, subtreeWidth, positioned)

		currentX += width
	}
}

// generateSVG creates the SVG file with a large canvas
func generateSVG(g *Graph, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Calculate actual bounds from node positions
	minX, minY := 0.0, 0.0
	maxX, maxY := 1000.0, 800.0

	for _, node := range g.Nodes {
		if node.X > maxX {
			maxX = node.X
		}
		if node.Y > maxY {
			maxY = node.Y
		}
	}

	// Add padding
	padding := 150.0
	maxX += padding
	maxY += padding

	width := int(maxX - minX)
	height := int(maxY - minY)

	var svg strings.Builder
	svg.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	svg.WriteString("\n")
	svg.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">`, width, height))
	svg.WriteString("\n")

	// Add styles
	svg.WriteString(`<defs>
    <style>
      .node { stroke: #30363d; stroke-width: 2.5; cursor: pointer; transition: all 0.2s; }
      .node:hover { stroke: #58a6ff; stroke-width: 4; }
      .node-label { 
        fill: #e6edf3; 
        font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; 
        font-size: 12px; 
        text-anchor: middle;
        pointer-events: none;
        font-weight: 500;
      }
      .label-box {
        fill: #161b22;
        stroke: #30363d;
        stroke-width: 1;
        rx: 4;
        ry: 4;
      }
      .label-box:hover {
        fill: #1c2128;
        stroke: #58a6ff;
      }
      .edge { stroke: #30363d; stroke-width: 1.5; stroke-opacity: 0.4; fill: none; }
      .edge-vulnerable { stroke: #f85149; stroke-width: 2; stroke-opacity: 0.6; }
      .legend-text { fill: #8b949e; font-family: system-ui, sans-serif; font-size: 13px; }
      .title { fill: #7BEFB2; font-family: system-ui, sans-serif; font-size: 24px; font-weight: 600; }
      .subtitle { fill: #8b949e; font-family: system-ui, sans-serif; font-size: 14px; }
    </style>
  </defs>`)
	svg.WriteString("\n")

	// Add background
	svg.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#0d1117"/>`, width, height))
	svg.WriteString("\n")

	// Add title
	svg.WriteString(`<text x="20" y="35" class="title">Dependency Graph</text>`)
	svg.WriteString("\n")
	svg.WriteString(`<text x="20" y="55" class="subtitle">Transitive dependency visualization</text>`)
	svg.WriteString("\n")

	// Draw edges first (so they appear behind nodes)
	for _, edge := range g.Edges {
		fromNode := g.getNode(edge.From)
		toNode := g.getNode(edge.To)
		if fromNode == nil || toNode == nil {
			continue
		}

		edgeClass := "edge"
		if toNode.IsVulnerable {
			edgeClass = "edge-vulnerable"
		}

		svg.WriteString(fmt.Sprintf(`<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" class="%s"/>`,
			fromNode.X, fromNode.Y, toNode.X, toNode.Y, edgeClass))
		svg.WriteString("\n")
	}

	// Draw nodes
	for _, node := range g.Nodes {
		radius := 10.0
		if node.Type == "project" {
			radius = 16.0
		}

		title := node.FullName
		if title == "" {
			title = node.Label
		}
		title = fmt.Sprintf("%s (%s) - Level %d", title, node.Type, node.Level)
		if node.IsVulnerable {
			title += " ⚠️ HAS VULNERABILITIES"
		}

		svg.WriteString(fmt.Sprintf(`<circle cx="%.2f" cy="%.2f" r="%.1f" fill="%s" class="node">`,
			node.X, node.Y, radius, node.Color))
		svg.WriteString(fmt.Sprintf(`<title>%s</title>`, escapeXML(title)))
		svg.WriteString(`</circle>`)
		svg.WriteString("\n")

		// Add label with background box
		labelText := escapeXML(node.Label)
		// Estimate text width (roughly 7 pixels per character for 12px monospace font)
		textWidth := float64(len(node.Label)) * 7.0
		boxWidth := textWidth + 12.0 // Add padding
		boxHeight := 20.0
		boxX := node.X - boxWidth/2
		boxY := node.Y + radius + 8

		// Draw background box
		svg.WriteString(fmt.Sprintf(`<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" class="label-box"/>`,
			boxX, boxY, boxWidth, boxHeight))
		svg.WriteString("\n")

		// Draw text centered in box
		svg.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.2f" class="node-label">%s</text>`,
			node.X, boxY+boxHeight/2+4, labelText))
		svg.WriteString("\n")
	}

	// Add legend
	legendX := 20.0
	legendY := 85.0
	legendItems := []struct {
		label string
		color string
	}{
		{"Project Root", "#7BEFB2"},
		{"Go Module", "#00ADD8"},
		{"NPM Package", "#CB3837"},
		{"Python Package", "#3776AB"},
		{"Maven Dependency", "#B07219"},
		{"Has Vulnerabilities", "#f85149"},
	}

	svg.WriteString(`<g id="legend">`)
	svg.WriteString("\n")
	for i, item := range legendItems {
		y := legendY + float64(i*22)
		svg.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="6" fill="%s"/>`,
			legendX, y, item.color))
		svg.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" class="legend-text">%s</text>`,
			legendX+18, y+5, item.label))
		svg.WriteString("\n")
	}
	svg.WriteString(`</g>`)
	svg.WriteString("\n")

	// Add stats
	statsY := legendY + float64(len(legendItems)*22) + 20
	svg.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" class="legend-text">Total Dependencies: %d</text>`,
		legendX, statsY, len(g.Nodes)-1))
	svg.WriteString("\n")

	vulnerableCount := 0
	for _, node := range g.Nodes {
		if node.IsVulnerable {
			vulnerableCount++
		}
	}
	svg.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" class="legend-text" style="fill: %s; font-weight: 600;">Vulnerable: %d</text>`,
		legendX, statsY+18, "#f85149", vulnerableCount))
	svg.WriteString("\n")

	svg.WriteString(`</svg>`)

	_, err = f.WriteString(svg.String())
	return err
}

// Helper functions

func sanitizeID(s string) string {
	// Replace special characters with hyphens
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "@", "-at-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// Try to truncate at a reasonable point
	if idx := strings.LastIndex(s[:maxLen-3], "/"); idx > maxLen/2 {
		return "..." + s[idx:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func getColorByType(nodeType string, isVulnerable bool) string {
	if isVulnerable {
		return "#f85149" // Red for vulnerable
	}
	switch nodeType {
	case "go":
		return "#00ADD8"
	case "npm":
		return "#CB3837"
	case "python":
		return "#3776AB"
	case "maven":
		return "#B07219"
	default:
		return "#8b949e"
	}
}

func hasVulnerability(pkgName string, repos []repo.Assessment) bool {
	pkgLower := strings.ToLower(pkgName)
	// Clean up package name for better matching
	pkgClean := strings.TrimPrefix(pkgLower, "github.com/")
	pkgClean = strings.TrimPrefix(pkgClean, "gitlab.com/")

	for _, r := range repos {
		repoLower := strings.ToLower(r.Repo)
		// Check if package name contains or matches repo name
		if strings.Contains(pkgLower, repoLower) ||
			strings.Contains(repoLower, pkgLower) ||
			strings.Contains(pkgClean, repoLower) {
			if len(r.Vulnerabilities) > 0 {
				return true
			}
		}
	}
	return false
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}
