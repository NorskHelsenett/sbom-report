package main

import (
	"flag"
	"fmt"
	"os"

	"sbom-report/internal/api"
)

func main() {
	var (
		port   string
		dbPath string
	)

	flag.StringVar(&port, "port", "8080", "Server port")
	flag.StringVar(&dbPath, "db", "sbom-reports.db", "Database file path")
	flag.Parse()

	// Create server
	server, err := api.NewServer(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
		os.Exit(1)
	}

	// Run server
	addr := ":" + port
	if err := server.Run(addr); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
