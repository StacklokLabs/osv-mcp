package main

import (
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
