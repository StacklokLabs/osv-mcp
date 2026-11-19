package main

import (
	"os"
	"runtime/debug"
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
}

func TestResolveVersion(t *testing.T) {
	t.Parallel()

	const testVersion = "1.2.3"

	buildInfo := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}
	noBuildInfo := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name      string
		ldflags   string
		buildInfo func() (*debug.BuildInfo, bool)
		want      string
	}{
		{name: "ldflags wins", ldflags: testVersion, buildInfo: buildInfo("v9.9.9"), want: testVersion},
		{name: "go install module version", ldflags: devVersion, buildInfo: buildInfo("v" + testVersion), want: testVersion},
		{name: "local build", ldflags: devVersion, buildInfo: buildInfo("(devel)"), want: devVersion},
		{name: "no build info", ldflags: devVersion, buildInfo: noBuildInfo, want: devVersion},
		{name: "empty ldflags", ldflags: "", buildInfo: buildInfo(""), want: devVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, resolveVersion(tt.ldflags, tt.buildInfo))
		})
	}
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

func TestGetTransportMode(t *testing.T) {
	tests := []struct {
		env     string
		want    TransportMode
		wantErr bool
	}{
		{env: "", want: TransportHTTPStream},
		{env: "streamable-http", want: TransportHTTPStream},
		{env: " SSE ", want: TransportSSE},
		{env: "stdio", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv("MCP_TRANSPORT", tt.env)
			got, err := getTransportMode()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
