package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuery(t *testing.T) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method and path
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/query", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode request body
		var req QueryRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		// Check request fields
		assert.Equal(t, "test-package", req.Package.Name)
		assert.Equal(t, "npm", req.Package.Ecosystem)
		assert.Equal(t, "1.0.0", req.Version)

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"vulns": [
				{
					"id": "TEST-2023-001",
					"summary": "Test vulnerability",
					"details": "This is a test vulnerability",
					"modified": "2023-01-01T00:00:00Z",
					"published": "2023-01-01T00:00:00Z",
					"references": [
						{
							"type": "ADVISORY",
							"url": "https://example.com/advisory/TEST-2023-001"
						}
					],
					"affected": [
						{
							"package": {
								"name": "test-package",
								"ecosystem": "npm"
							},
							"ranges": [
								{
									"type": "SEMVER",
									"events": [
										{
											"introduced": "0"
										},
										{
											"fixed": "1.0.1"
										}
									]
								}
							],
							"versions": ["1.0.0"]
						}
					]
				}
			]
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(WithBaseURL(server.URL + "/v1"))

	// Create query request
	req := QueryRequest{
		Version: "1.0.0",
		Package: Package{
			Name:      "test-package",
			Ecosystem: "npm",
		},
	}

	// Execute query
	resp, err := client.Query(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check response
	assert.Len(t, resp.Vulns, 1)
	vuln := resp.Vulns[0]
	assert.Equal(t, "TEST-2023-001", vuln.ID)
	assert.Equal(t, "Test vulnerability", vuln.Summary)
	assert.Equal(t, "This is a test vulnerability", vuln.Details)
	
	expectedModified, _ := time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")
	assert.Equal(t, expectedModified, vuln.Modified)
	
	assert.Len(t, vuln.References, 1)
	assert.Equal(t, "ADVISORY", vuln.References[0].Type)
	assert.Equal(t, "https://example.com/advisory/TEST-2023-001", vuln.References[0].URL)
	
	assert.Len(t, vuln.Affected, 1)
	assert.Equal(t, "test-package", vuln.Affected[0].Package.Name)
	assert.Equal(t, "npm", vuln.Affected[0].Package.Ecosystem)
}

func TestQueryBatch(t *testing.T) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method and path
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/querybatch", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode request body
		var req QueryBatchRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		// Check request fields
		assert.Len(t, req.Queries, 2)

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"results": [
				{
					"vulns": [
						{
							"id": "TEST-2023-001",
							"modified": "2023-01-01T00:00:00Z"
						}
					]
				},
				{
					"vulns": [
						{
							"id": "TEST-2023-002",
							"modified": "2023-01-02T00:00:00Z"
						}
					]
				}
			]
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(WithBaseURL(server.URL + "/v1"))

	// Create batch query request
	req := QueryBatchRequest{
		Queries: []QueryRequest{
			{
				Version: "1.0.0",
				Package: Package{
					Name:      "test-package-1",
					Ecosystem: "npm",
				},
			},
			{
				Version: "2.0.0",
				Package: Package{
					Name:      "test-package-2",
					Ecosystem: "npm",
				},
			},
		},
	}

	// Execute batch query
	resp, err := client.QueryBatch(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check response
	assert.Len(t, resp.Results, 2)
	
	assert.Len(t, resp.Results[0].Vulns, 1)
	assert.Equal(t, "TEST-2023-001", resp.Results[0].Vulns[0].ID)
	
	expectedModified1, _ := time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")
	assert.Equal(t, expectedModified1, resp.Results[0].Vulns[0].Modified)
	
	assert.Len(t, resp.Results[1].Vulns, 1)
	assert.Equal(t, "TEST-2023-002", resp.Results[1].Vulns[0].ID)
	
	expectedModified2, _ := time.Parse(time.RFC3339, "2023-01-02T00:00:00Z")
	assert.Equal(t, expectedModified2, resp.Results[1].Vulns[0].Modified)
}

func TestGetVulnerability(t *testing.T) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method and path
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/vulns/TEST-2023-001", r.URL.Path)

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"id": "TEST-2023-001",
			"summary": "Test vulnerability",
			"details": "This is a test vulnerability",
			"modified": "2023-01-01T00:00:00Z",
			"published": "2023-01-01T00:00:00Z",
			"references": [
				{
					"type": "ADVISORY",
					"url": "https://example.com/advisory/TEST-2023-001"
				}
			],
			"affected": [
				{
					"package": {
						"name": "test-package",
						"ecosystem": "npm"
					},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [
								{
									"introduced": "0"
								},
								{
									"fixed": "1.0.1"
								}
							]
						}
					],
					"versions": ["1.0.0"]
				}
			]
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(WithBaseURL(server.URL + "/v1"))

	// Execute get vulnerability
	vuln, err := client.GetVulnerability(context.Background(), "TEST-2023-001")
	require.NoError(t, err)
	require.NotNil(t, vuln)

	// Check response
	assert.Equal(t, "TEST-2023-001", vuln.ID)
	assert.Equal(t, "Test vulnerability", vuln.Summary)
	assert.Equal(t, "This is a test vulnerability", vuln.Details)
	
	expectedModified, _ := time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")
	assert.Equal(t, expectedModified, vuln.Modified)
	
	assert.Len(t, vuln.References, 1)
	assert.Equal(t, "ADVISORY", vuln.References[0].Type)
	assert.Equal(t, "https://example.com/advisory/TEST-2023-001", vuln.References[0].URL)
	
	assert.Len(t, vuln.Affected, 1)
	assert.Equal(t, "test-package", vuln.Affected[0].Package.Name)
	assert.Equal(t, "npm", vuln.Affected[0].Package.Ecosystem)
}