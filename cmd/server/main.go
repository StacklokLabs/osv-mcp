package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/StacklokLabs/osv-mcp/pkg/mcp"
	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

func main() {
	// Parse command-line flags
	addr := flag.String("addr", ":8080", "Address to listen on")
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