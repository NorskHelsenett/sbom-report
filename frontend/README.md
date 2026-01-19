# SBOM Report Frontend

React-based frontend for the SBOM Report API.

## Prerequisites

- Node.js 18+ and npm
- Running SBOM Report API server (default: http://localhost:8080)

## Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The app will open at http://localhost:5173 and proxy API requests to http://localhost:8080.

## Available Scripts

- `npm run dev` - Start Vite development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build locally

## Features

- **Submit**: Submit Git repositories for SBOM analysis
- **Projects**: Browse submitted projects and their reports
- **Dependencies**: View all dependencies across projects
- **Stats**: View dependency statistics

## API Backend

Ensure the SBOM Report API server is running:

```bash
cd ..
go run cmd/server/main.go -port 8080
```

The frontend will automatically proxy `/api/*` requests to the backend server.
