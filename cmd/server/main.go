// Package main provides the entry point for the OSV MCP Server.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/StacklokLabs/osv-mcp/pkg/mcp"
	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

// getMCPServerPort returns the port number from MCP_PORT environment variable.
// If the environment variable is not set or contains an invalid value,
// it returns the default port 8080.
func getMCPServerPort() string {
	port := "8080"
	if envPort := os.Getenv("MCP_PORT"); envPort != "" {
		if portNum, err := strconv.Atoi(envPort); err == nil {
			if portNum >= 0 && portNum <= 65535 {
				port = envPort
			} else {
				log.Printf("Invalid MCP_PORT value: %s (must be between 0 and 65535), using default port 8080", envPort)
			}
		} else {
			log.Printf("Invalid MCP_PORT value: %s (must be a valid number), using default port 8080", envPort)
		}
	}
	return port
}

func main() {
	// Get port from environment variable or use default
	port := getMCPServerPort()

	// Parse command-line flags
	addr := flag.String("addr", ":"+port, "Address to listen on")
	flag.Parse()

	// Create OSV client
	osvClient := osv.NewClient()

	// Create MCP server
	mcpServer := mcp.NewServer(
		mcp.WithOSVClient(osvClient),
	)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- mcpServer.ServeSSE(*addr)
	}()

	// Wait for signal or error
	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Server error: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
	}

	log.Println("Shutting down server")
}
