package repo

import (
	"fmt"
	"strings"
)

type ProgressBar struct {
	total    int
	current  int
	prefix   string
	width    int
	started  bool
}

func NewProgressBar(total int, prefix string) *ProgressBar {
	return &ProgressBar{
		total:   total,
		prefix:  prefix,
		width:   50,
		started: false,
	}
}

func (p *ProgressBar) Increment() {
	if !p.started {
		fmt.Println(p.prefix)
		p.started = true
	}
	p.current++
	p.Render()
}

func (p *ProgressBar) Render() {
	if p.total == 0 {
		return
	}

	percent := float64(p.current) / float64(p.total)
	filled := int(percent * float64(p.width))
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)
	
	fmt.Printf("\r[%s] %d/%d (%.0f%%)", 
		bar, p.current, p.total, percent*100)
	
	if p.current >= p.total {
		fmt.Println("\n") // Extra newline for spacing
	}
}

func (p *ProgressBar) Finish() {
	p.current = p.total
	p.Render()
}
