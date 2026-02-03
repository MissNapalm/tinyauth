#!/bin/bash

echo "Building simple-auth..."

# Download dependencies
go mod download

# Build the binary
go build -o simple-auth main.go

echo "✓ Build complete! Binary: ./simple-auth"
echo ""
echo "To run:"
echo "  ./simple-auth"