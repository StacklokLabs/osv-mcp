package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/StacklokLabs/osv-mcp/pkg/mcp"
	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

func TestCreateServer(t *testing.T) {
	// Create OSV client
	osvClient := osv.NewClient()
	require.NotNil(t, osvClient)

	// Create MCP server
	mcpServer := mcp.NewServer(
		mcp.WithOSVClient(osvClient),
	)
	require.NotNil(t, mcpServer)

	// Verify server properties
	assert.Equal(t, mcp.ServerName, "osv-mcp")
	assert.Equal(t, mcp.ServerVersion, "0.1.0")
}

func TestGetMCPServerPort(t *testing.T) {
	// Save original env value and restore it after the test
	originalPort := os.Getenv("MCP_PORT")
	defer func() {
		if originalPort != "" {
			os.Setenv("MCP_PORT", originalPort)
		} else {
			os.Unsetenv("MCP_PORT")
		}
	}()

	tests := []struct {
		name     string
		envPort  string
		expected string
	}{
		{
			name:     "No environment variable set",
			envPort:  "",
			expected: "8080",
		},
		{
			name:     "Valid port number",
			envPort:  "3000",
			expected: "3000",
		},
		{
			name:     "Invalid port (non-numeric)",
			envPort:  "abc",
			expected: "8080",
		},
		{
			name:     "Invalid port (negative number)",
			envPort:  "-1",
			expected: "8080",
		},
		{
			name:     "Invalid port (too large)",
			envPort:  "70000",
			expected: "8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envPort != "" {
				os.Setenv("MCP_PORT", tt.envPort)
			} else {
				os.Unsetenv("MCP_PORT")
			}

			// Test the function
			port := getMCPServerPort()
			assert.Equal(t, tt.expected, port)
		})
	}
}
