package mcp

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

const (
	testVulnID      = "TEST-2023-001"
	testVulnSummary = "Test vulnerability"
	testEcosystem   = "npm"
	testVersion     = "1.0.0"
)

// mockOSVClient is a mock implementation of the OSV client for testing
type mockOSVClient struct {
	queryFunc            func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error)
	queryBatchFunc       func(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error)
	getVulnerabilityFunc func(ctx context.Context, id string) (*osv.Vulnerability, error)
}

func (m *mockOSVClient) Query(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
	return m.queryFunc(ctx, req)
}

func (m *mockOSVClient) QueryBatch(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
	return m.queryBatchFunc(ctx, req)
}

func (m *mockOSVClient) GetVulnerability(ctx context.Context, id string) (*osv.Vulnerability, error) {
	return m.getVulnerabilityFunc(ctx, id)
}

// newMockOSVClient creates a new mock OSV client with default implementations
func newMockOSVClient() *mockOSVClient {
	return &mockOSVClient{
		queryFunc: func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
			_, _ = ctx, req
			return &osv.QueryResponse{
				Vulns: []osv.Vulnerability{
					{
						ID:       testVulnID,
						Summary:  testVulnSummary,
						Modified: time.Now(),
					},
				},
			}, nil
		},
		queryBatchFunc: func(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
			_, _ = ctx, req
			return &osv.QueryBatchResponse{
				Results: []osv.BatchQueryResult{
					{
						Vulns: []struct {
							ID       string    `json:"id"`
							Modified time.Time `json:"modified"`
						}{
							{
								ID:       testVulnID,
								Modified: time.Now(),
							},
						},
					},
				},
			}, nil
		},
		getVulnerabilityFunc: func(ctx context.Context, id string) (*osv.Vulnerability, error) {
			_, _ = ctx, id
			return &osv.Vulnerability{
				ID:       testVulnID,
				Summary:  testVulnSummary,
				Details:  "This is a test vulnerability",
				Modified: time.Now(),
			}, nil
		},
	}
}

// connect starts a client session against the server over the in-memory
// transport, so the tests exercise the schema, the decoding and the wire
// format rather than the handlers alone.
func connect(t *testing.T, server *Server) *mcp.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	ctx := context.Background()
	serverSession, err := server.mcpServer.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "osv-mcp-test", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	return session
}

// getTextContent extracts the text content from a CallToolResult
func getTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	require.NotEmpty(t, result.Content)
	text, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "first content block is %T, want text", result.Content[0])

	return text.Text
}

func TestToolDefinitions(t *testing.T) {
	t.Parallel()

	server := NewServer(WithOSVClient(newMockOSVClient()))
	session := connect(t, server)

	result, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 3)

	for _, tool := range result.Tools {
		t.Run(tool.Name, func(t *testing.T) {
			assert.NotEmpty(t, tool.Title, "tool %s should have a title", tool.Name)
			require.NotNil(t, tool.Annotations)
			assert.Equal(t, tool.Title, tool.Annotations.Title)
			assert.True(t, tool.Annotations.ReadOnlyHint, "tool %s should be read-only", tool.Name)
			require.NotNil(t, tool.Annotations.DestructiveHint)
			assert.False(t, *tool.Annotations.DestructiveHint, "tool %s should not be destructive", tool.Name)
			assert.True(t, tool.Annotations.IdempotentHint, "tool %s should be idempotent", tool.Name)
			require.NotNil(t, tool.Annotations.OpenWorldHint)
			assert.True(t, *tool.Annotations.OpenWorldHint, "tool %s should be open-world", tool.Name)
		})
	}
}

func TestToolSchemas(t *testing.T) {
	t.Parallel()

	server := NewServer(WithOSVClient(newMockOSVClient()))
	session := connect(t, server)

	result, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)

	schemas := make(map[string]map[string]any, len(result.Tools))
	for _, tool := range result.Tools {
		schema, ok := tool.InputSchema.(map[string]any)
		require.True(t, ok, "tool %s schema is %T", tool.Name, tool.InputSchema)
		schemas[tool.Name] = schema
	}

	// get_vulnerability requires an id; the query tools take every argument
	// optionally and validate the combinations in the handler.
	assert.Equal(t, []any{"id"}, schemas["get_vulnerability"]["required"])

	batch := schemas["query_vulnerabilities_batch"]
	assert.Equal(t, []any{"queries"}, batch["required"])
	properties, ok := batch["properties"].(map[string]any)
	require.True(t, ok)
	queries, ok := properties["queries"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(1), queries["minItems"], 0)

	// No tool rejects an argument it does not know about: that is how the
	// server behaved on mcp-go, where unknown arguments were ignored. An
	// absent additionalProperties leaves unknown members unconstrained.
	_, constrained := schemas["query_vulnerability"]["additionalProperties"]
	assert.False(t, constrained, "query_vulnerability should not constrain additional properties")
	_, constrained = queries["additionalProperties"]
	assert.False(t, constrained, "nested batch queries should accept unknown members")
}

func TestCallQueryVulnerability(t *testing.T) {
	t.Parallel()

	expectedPackageName := "test-package"

	mockClient := newMockOSVClient()
	mockClient.queryFunc = func(_ context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedPackageName, req.Package.Name)
		assert.Equal(t, testEcosystem, req.Package.Ecosystem)
		assert.Equal(t, testVersion, req.Version)

		return &osv.QueryResponse{
			Vulns: []osv.Vulnerability{
				{ID: testVulnID, Summary: testVulnSummary, Modified: time.Now()},
			},
		}, nil
	}

	session := connect(t, NewServer(WithOSVClient(mockClient)))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "query_vulnerability",
		Arguments: map[string]any{
			"package_name": expectedPackageName,
			"ecosystem":    testEcosystem,
			"version":      testVersion,
		},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getTextContent(t, result)
	assert.Contains(t, text, testVulnID)
	assert.Contains(t, text, testVulnSummary)
}

func TestCallQueryVulnerabilityWithPURL(t *testing.T) {
	t.Parallel()

	expectedPURL := "pkg:npm/lodash@4.17.21"

	mockClient := newMockOSVClient()
	mockClient.queryFunc = func(_ context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedPURL, req.Package.PURL)
		assert.Empty(t, req.Package.Name)
		assert.Empty(t, req.Package.Ecosystem)
		assert.Empty(t, req.Version)

		return &osv.QueryResponse{Vulns: []osv.Vulnerability{{ID: testVulnID}}}, nil
	}

	session := connect(t, NewServer(WithOSVClient(mockClient)))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "query_vulnerability",
		Arguments: map[string]any{"purl": expectedPURL},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	assert.Contains(t, getTextContent(t, result), testVulnID)
}

func TestCallQueryVulnerabilityWithCommit(t *testing.T) {
	t.Parallel()

	expectedCommit := "abc123def456"

	mockClient := newMockOSVClient()
	mockClient.queryFunc = func(_ context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedCommit, req.Commit)
		assert.Empty(t, req.Version)
		assert.Empty(t, req.Package.Name)
		assert.Empty(t, req.Package.Ecosystem)
		assert.Empty(t, req.Package.PURL)

		return &osv.QueryResponse{Vulns: []osv.Vulnerability{{ID: testVulnID}}}, nil
	}

	session := connect(t, NewServer(WithOSVClient(mockClient)))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "query_vulnerability",
		Arguments: map[string]any{"commit": expectedCommit},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	assert.Contains(t, getTextContent(t, result), testVulnID)
}

func TestCallQueryVulnerabilitiesBatch(t *testing.T) {
	t.Parallel()

	mockClient := newMockOSVClient()
	mockClient.queryBatchFunc = func(_ context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
		require.Len(t, req.Queries, 2)

		assert.Equal(t, "pkg-a", req.Queries[0].Package.Name)
		assert.Equal(t, testEcosystem, req.Queries[0].Package.Ecosystem)
		assert.Equal(t, "2.0.0", req.Queries[0].Version)

		assert.Equal(t, "abcdef123456", req.Queries[1].Commit)

		return &osv.QueryBatchResponse{
			Results: []osv.BatchQueryResult{
				{
					Vulns: []struct {
						ID       string    `json:"id"`
						Modified time.Time `json:"modified"`
					}{{ID: testVulnID, Modified: time.Now()}},
				},
				{},
			},
		}, nil
	}

	session := connect(t, NewServer(WithOSVClient(mockClient)))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "query_vulnerabilities_batch",
		Arguments: map[string]any{
			"queries": []any{
				map[string]any{"package_name": "pkg-a", "ecosystem": testEcosystem, "version": "2.0.0"},
				map[string]any{"commit": "abcdef123456"},
			},
		},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	assert.Contains(t, getTextContent(t, result), testVulnID)
}

func TestCallGetVulnerability(t *testing.T) {
	t.Parallel()

	session := connect(t, NewServer(WithOSVClient(newMockOSVClient())))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_vulnerability",
		Arguments: map[string]any{"id": testVulnID},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := getTextContent(t, result)
	assert.Contains(t, text, testVulnID)
	assert.Contains(t, text, testVulnSummary)
	assert.Contains(t, text, "This is a test vulnerability")
}

func TestBatchValidation(t *testing.T) {
	t.Parallel()

	t.Run("empty queries", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockOSVClient()
		mockClient.queryBatchFunc = func(context.Context, osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
			t.Error("OSV API should not be called for invalid input")
			return nil, nil
		}
		server := NewServer(WithOSVClient(mockClient))

		// The schema rejects an empty array before the handler runs, so call
		// the handler directly to cover the guard that also protects callers
		// in this package.
		result, _, err := server.handleQueryVulnerabilitiesBatch(context.Background(), nil, queryBatchArgs{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)
		assert.Contains(t, getTextContent(t, result), "must contain at least one query")
	})

	t.Run("empty queries rejected over the protocol", func(t *testing.T) {
		t.Parallel()

		session := connect(t, NewServer(WithOSVClient(newMockOSVClient())))

		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "query_vulnerabilities_batch",
			Arguments: map[string]any{"queries": []any{}},
		})
		require.NoError(t, err)
		assert.True(t, result.IsError, "an empty queries array should be rejected by the schema")
	})

	t.Run("query without package or commit", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockOSVClient()
		mockClient.queryBatchFunc = func(context.Context, osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
			t.Error("OSV API should not be called for invalid input")
			return nil, nil
		}
		session := connect(t, NewServer(WithOSVClient(mockClient)))

		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "query_vulnerabilities_batch",
			Arguments: map[string]any{
				"queries": []any{
					map[string]any{"package_name": "pkg", "ecosystem": testEcosystem, "version": testVersion},
					map[string]any{"version": testVersion},
				},
			},
		})
		require.NoError(t, err)
		require.True(t, result.IsError)
		assert.Contains(t, getTextContent(t, result), "must be specified in query 1")
	})

	t.Run("missing vulnerability id", func(t *testing.T) {
		t.Parallel()

		server := NewServer(WithOSVClient(newMockOSVClient()))

		result, _, err := server.handleGetVulnerability(context.Background(), nil, getVulnerabilityArgs{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)
		assert.Contains(t, getTextContent(t, result), "Vulnerability ID is required")
	})
}

func TestUnknownArgumentIsIgnored(t *testing.T) {
	t.Parallel()

	session := connect(t, NewServer(WithOSVClient(newMockOSVClient())))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "query_vulnerability",
		Arguments: map[string]any{
			"package_name": "pkg",
			"ecosystem":    testEcosystem,
			"comment":      "extra arguments were ignored before the migration too",
		},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	assert.Contains(t, getTextContent(t, result), testVulnID)
}

func TestWrongArgumentTypeIsRejected(t *testing.T) {
	t.Parallel()

	session := connect(t, NewServer(WithOSVClient(newMockOSVClient())))

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "query_vulnerability",
		Arguments: map[string]any{"package_name": 42, "ecosystem": testEcosystem},
	})
	require.NoError(t, err)
	assert.True(t, result.IsError, "a number where the schema says string should be rejected")
}

func TestStreamableHTTPTransport(t *testing.T) {
	t.Parallel()

	// The transport has to serve the sessionless 2026-07-28 revision and the
	// initialize-based revisions that came before it.
	for _, version := range []string{"2026-07-28", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			server := NewServer(WithOSVClient(newMockOSVClient()))
			httpServer := httptest.NewServer(server.streamableHTTPHandler())
			t.Cleanup(httpServer.Close)

			client := mcp.NewClient(&mcp.Implementation{Name: "osv-mcp-test", Version: "0.0.1"}, nil)
			session, err := client.Connect(context.Background(),
				&mcp.StreamableClientTransport{Endpoint: httpServer.URL + "/mcp"},
				&mcp.ClientSessionOptions{ProtocolVersion: version})
			require.NoError(t, err)
			t.Cleanup(func() { _ = session.Close() })

			assert.Equal(t, version, session.InitializeResult().ProtocolVersion)

			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "get_vulnerability",
				Arguments: map[string]any{"id": testVulnID},
			})
			require.NoError(t, err)
			require.False(t, result.IsError)
			assert.Contains(t, getTextContent(t, result), testVulnID)

			// A rejected call travels back as a tool error, not a transport
			// failure.
			result, err = session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "query_vulnerability",
				Arguments: map[string]any{"version": testVersion},
			})
			require.NoError(t, err)
			require.True(t, result.IsError)
			assert.Contains(t, getTextContent(t, result), "must be specified")
		})
	}
}

func TestSSETransport(t *testing.T) {
	t.Parallel()

	server := NewServer(WithOSVClient(newMockOSVClient()))
	httpServer := httptest.NewServer(server.sseHandler())
	t.Cleanup(httpServer.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "osv-mcp-test", Version: "0.0.1"}, nil)
	session, err := client.Connect(context.Background(),
		&mcp.SSEClientTransport{Endpoint: httpServer.URL + "/sse"}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	tools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, tools.Tools, 3)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_vulnerability",
		Arguments: map[string]any{"id": testVulnID},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	assert.Contains(t, getTextContent(t, result), testVulnID)
}

func TestSSEHandlerAdvertisesItsOwnEndpoint(t *testing.T) {
	t.Parallel()

	server := NewServer(WithOSVClient(newMockOSVClient()))
	httpServer := httptest.NewServer(server.sseHandler())
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/sse", nil)
	require.NoError(t, err)
	request.Header.Set("Accept", "text/event-stream")

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	require.Equal(t, http.StatusOK, response.StatusCode)

	// The client posts to whatever endpoint the stream names, so it has to
	// carry the session id the handler minted.
	reader := bufio.NewReader(response.Body)
	event, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "event: endpoint", strings.TrimSpace(event))

	endpoint, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(endpoint), "data: /sse?sessionid="),
		"endpoint event is %q", endpoint)
}

func TestServerVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []ServerOption
		want string
	}{
		{name: "default", want: DefaultVersion},
		{name: "WithVersion", opts: []ServerOption{WithVersion("1.2.3")}, want: "1.2.3"},
		{name: "empty WithVersion keeps default", opts: []ServerOption{WithVersion("")}, want: DefaultVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]ServerOption{WithOSVClient(newMockOSVClient())}, tt.opts...)
			session := connect(t, NewServer(opts...))

			require.NotNil(t, session.InitializeResult())
			require.NotNil(t, session.InitializeResult().ServerInfo)
			assert.Equal(t, tt.want, session.InitializeResult().ServerInfo.Version)
		})
	}
}
