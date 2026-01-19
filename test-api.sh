#!/bin/bash

# Simple test script for the SBOM Report API

API_URL="http://localhost:8080"

echo "Testing SBOM Report API..."
echo "=========================="
echo

# Test 1: Health Check
echo "1. Testing health check..."
curl -s "$API_URL/health" | jq .
echo
echo

# Test 2: List projects (should be empty initially)
echo "2. Listing projects (should be empty initially)..."
curl -s "$API_URL/api/v1/projects" | jq .
echo
echo

# Test 3: Submit a small repository
echo "3. Submitting a test repository..."
echo "   Note: This will take a few minutes as it clones and analyzes the repo"
curl -X POST "$API_URL/api/v1/submit" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/gin-gonic/gin",
    "name": "Gin Web Framework",
    "description": "A popular Go web framework"
  }' | jq .
echo
echo

# Test 4: List projects again
echo "4. Listing projects again..."
curl -s "$API_URL/api/v1/projects" | jq .
echo
echo

# Test 5: Get dependency stats
echo "5. Getting dependency statistics..."
curl -s "$API_URL/api/v1/dependencies/stats" | jq .
echo
echo

# Test 6: List Go dependencies
echo "6. Listing Go dependencies..."
curl -s "$API_URL/api/v1/dependencies?type=go" | jq .
echo
echo

echo "=========================="
echo "Tests completed!"
echo
echo "Visit $API_URL/swagger/index.html for interactive API documentation"
