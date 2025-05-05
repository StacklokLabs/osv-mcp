package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

// mockOSVClient is a mock implementation of the OSV client for testing
type mockOSVClient struct {
	queryFunc           func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error)
	queryBatchFunc      func(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error)
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
			return &osv.QueryResponse{
				Vulns: []osv.Vulnerability{
					{
						ID:      "TEST-2023-001",
						Summary: "Test vulnerability",
						Modified: time.Now(),
					},
				},
			}, nil
		},
		queryBatchFunc: func(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
			return &osv.QueryBatchResponse{
				Results: []osv.BatchQueryResult{
					{
						Vulns: []struct {
							ID       string    `json:"id"`
							Modified time.Time `json:"modified"`
						}{
							{
								ID:       "TEST-2023-001",
								Modified: time.Now(),
							},
						},
					},
				},
			}, nil
		},
		getVulnerabilityFunc: func(ctx context.Context, id string) (*osv.Vulnerability, error) {
			return &osv.Vulnerability{
				ID:      "TEST-2023-001",
				Summary: "Test vulnerability",
				Modified: time.Now(),
			}, nil
		},
	}
}

// getTextContent extracts the text content from a CallToolResult
func getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	
	textContent, ok := mcp.AsTextContent(result.Content[0])
	if !ok {
		return ""
	}
	
	return textContent.Text
}

func TestHandleQueryVulnerability(t *testing.T) {
	// Create mock OSV client
	mockClient := newMockOSVClient()
	
	// Set up expected query parameters
	expectedPackageName := "test-package"
	expectedEcosystem := "npm"
	expectedVersion := "1.0.0"
	
	// Override query function to check parameters
	mockClient.queryFunc = func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedPackageName, req.Package.Name)
		assert.Equal(t, expectedEcosystem, req.Package.Ecosystem)
		assert.Equal(t, expectedVersion, req.Version)
		
		return &osv.QueryResponse{
			Vulns: []osv.Vulnerability{
				{
					ID:      "TEST-2023-001",
					Summary: "Test vulnerability",
					Modified: time.Now(),
				},
			},
		}, nil
	}
	
	// Create server with mock client
	server := NewServer(WithOSVClient(mockClient))
	
	// Create tool request
	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]interface{}{
		"package_name": expectedPackageName,
		"ecosystem":    expectedEcosystem,
		"version":      expectedVersion,
	}
	
	// Call handler
	result, err := server.handleQueryVulnerability(context.Background(), request)
	
	// Check result
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	
	// Get text content
	text := getTextContent(result)
	assert.NotEmpty(t, text)
	
	// Parse result text as JSON
	var response osv.QueryResponse
	err = json.Unmarshal([]byte(text), &response)
	require.NoError(t, err)
	
	// Check response
	assert.Len(t, response.Vulns, 1)
	assert.Equal(t, "TEST-2023-001", response.Vulns[0].ID)
	assert.Equal(t, "Test vulnerability", response.Vulns[0].Summary)
}

func TestHandleQueryVulnerabilityWithPURL(t *testing.T) {
	// Create mock OSV client
	mockClient := newMockOSVClient()
	
	// Set up expected query parameters
	expectedPURL := "pkg:npm/test-package@1.0.0"
	
	// Override query function to check parameters
	mockClient.queryFunc = func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedPURL, req.Package.PURL)
		assert.Empty(t, req.Package.Name)
		assert.Empty(t, req.Package.Ecosystem)
		
		return &osv.QueryResponse{
			Vulns: []osv.Vulnerability{
				{
					ID:      "TEST-2023-001",
					Summary: "Test vulnerability",
					Modified: time.Now(),
				},
			},
		}, nil
	}
	
	// Create server with mock client
	server := NewServer(WithOSVClient(mockClient))
	
	// Create tool request
	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]interface{}{
		"purl": expectedPURL,
	}
	
	// Call handler
	result, err := server.handleQueryVulnerability(context.Background(), request)
	
	// Check result
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.NotEmpty(t, getTextContent(result))
}

func TestHandleQueryVulnerabilityWithCommit(t *testing.T) {
	// Create mock OSV client
	mockClient := newMockOSVClient()
	
	// Set up expected query parameters
	expectedCommit := "abcdef1234567890"
	
	// Override query function to check parameters
	mockClient.queryFunc = func(ctx context.Context, req osv.QueryRequest) (*osv.QueryResponse, error) {
		assert.Equal(t, expectedCommit, req.Commit)
		assert.Empty(t, req.Version)
		
		return &osv.QueryResponse{
			Vulns: []osv.Vulnerability{
				{
					ID:      "TEST-2023-001",
					Summary: "Test vulnerability",
					Modified: time.Now(),
				},
			},
		}, nil
	}
	
	// Create server with mock client
	server := NewServer(WithOSVClient(mockClient))
	
	// Create tool request
	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]interface{}{
		"commit": expectedCommit,
	}
	
	// Call handler
	result, err := server.handleQueryVulnerability(context.Background(), request)
	
	// Check result
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.NotEmpty(t, getTextContent(result))
}

func TestHandleQueryVulnerabilitiesBatch(t *testing.T) {
	// Create mock OSV client
	mockClient := newMockOSVClient()
	
	// Override query batch function to check parameters
	mockClient.queryBatchFunc = func(ctx context.Context, req osv.QueryBatchRequest) (*osv.QueryBatchResponse, error) {
		assert.Len(t, req.Queries, 2)
		assert.Equal(t, "test-package-1", req.Queries[0].Package.Name)
		assert.Equal(t, "npm", req.Queries[0].Package.Ecosystem)
		assert.Equal(t, "1.0.0", req.Queries[0].Version)
		assert.Equal(t, "test-package-2", req.Queries[1].Package.Name)
		assert.Equal(t, "npm", req.Queries[1].Package.Ecosystem)
		assert.Equal(t, "2.0.0", req.Queries[1].Version)
		
		return &osv.QueryBatchResponse{
			Results: []osv.BatchQueryResult{
				{
					Vulns: []struct {
						ID       string    `json:"id"`
						Modified time.Time `json:"modified"`
					}{
						{
							ID:       "TEST-2023-001",
							Modified: time.Now(),
						},
					},
				},
				{
					Vulns: []struct {
						ID       string    `json:"id"`
						Modified time.Time `json:"modified"`
					}{
						{
							ID:       "TEST-2023-002",
							Modified: time.Now(),
						},
					},
				},
			},
		}, nil
	}
	
	// Create server with mock client
	server := NewServer(WithOSVClient(mockClient))
	
	// Create tool request
	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]interface{}{
		"queries": []interface{}{
			map[string]interface{}{
				"package_name": "test-package-1",
				"ecosystem":    "npm",
				"version":      "1.0.0",
			},
			map[string]interface{}{
				"package_name": "test-package-2",
				"ecosystem":    "npm",
				"version":      "2.0.0",
			},
		},
	}
	
	// Call handler
	result, err := server.handleQueryVulnerabilitiesBatch(context.Background(), request)
	
	// Check result
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	
	// Get text content
	text := getTextContent(result)
	assert.NotEmpty(t, text)
	
	// Parse result text as JSON
	var response osv.QueryBatchResponse
	err = json.Unmarshal([]byte(text), &response)
	require.NoError(t, err)
	
	// Check response
	assert.Len(t, response.Results, 2)
	assert.Len(t, response.Results[0].Vulns, 1)
	assert.Equal(t, "TEST-2023-001", response.Results[0].Vulns[0].ID)
	assert.Len(t, response.Results[1].Vulns, 1)
	assert.Equal(t, "TEST-2023-002", response.Results[1].Vulns[0].ID)
}

func TestHandleGetVulnerability(t *testing.T) {
	// Create mock OSV client
	mockClient := newMockOSVClient()
	
	// Set up expected query parameters
	expectedID := "TEST-2023-001"
	
	// Override get vulnerability function to check parameters
	mockClient.getVulnerabilityFunc = func(ctx context.Context, id string) (*osv.Vulnerability, error) {
		assert.Equal(t, expectedID, id)
		
		return &osv.Vulnerability{
			ID:      expectedID,
			Summary: "Test vulnerability",
			Details: "This is a test vulnerability",
			Modified: time.Now(),
		}, nil
	}
	
	// Create server with mock client
	server := NewServer(WithOSVClient(mockClient))
	
	// Create tool request
	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]interface{}{
		"id": expectedID,
	}
	
	// Call handler
	result, err := server.handleGetVulnerability(context.Background(), request)
	
	// Check result
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	
	// Get text content
	text := getTextContent(result)
	assert.NotEmpty(t, text)
	
	// Parse result text as JSON
	var vuln osv.Vulnerability
	err = json.Unmarshal([]byte(text), &vuln)
	require.NoError(t, err)
	
	// Check response
	assert.Equal(t, expectedID, vuln.ID)
	assert.Equal(t, "Test vulnerability", vuln.Summary)
	assert.Equal(t, "This is a test vulnerability", vuln.Details)
}