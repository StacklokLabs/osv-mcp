// Package mcp provides MCP server tools for OSV.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

const (
	// ServerName is the name of the MCP server
	ServerName = "osv-mcp"

	// ServerVersion is the version of the MCP server
	ServerVersion = "0.1.0"
	// ServerPort is the port the MCP server will listen on
	ServerPort = "8080"
)

// Server is an MCP server that provides OSV vulnerability information
type Server struct {
	mcpServer *server.MCPServer
	osvClient osv.OSVClient
}

// NewServer creates a new OSV MCP server
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		osvClient: osv.NewClient(),
	}

	for _, opt := range opts {
		opt(s)
	}

	mcpServer := server.NewMCPServer(ServerName, ServerVersion)

	// Register tools
	mcpServer.AddTool(
		mcp.NewToolWithRawSchema(
			"query_vulnerability",
			"Query for vulnerabilities affecting a specific package version or commit",
			json.RawMessage(`{
				"type": "object",
				"properties": {
					"commit": {
						"type": "string",
						"description": "The commit hash to query for. If specified, version should not be set."
					},
					"version": {
						"type": "string",
						"description": "The version string to query for. If specified, commit should not be set."
					},
					"package_name": {
						"type": "string",
						"description": "The name of the package."
					},
					"ecosystem": {
						"type": "string",
						"description": "The ecosystem for this package (e.g., PyPI, npm, Go)."
					},
					"purl": {
						"type": "string",
						"description": "The package URL for this package. If purl is used, package_name and ecosystem should not be set."
					}
				},
				"required": []
			}`),
		),
		s.handleQueryVulnerability,
	)

	mcpServer.AddTool(
		mcp.NewToolWithRawSchema(
			"query_vulnerabilities_batch",
			"Query for vulnerabilities affecting multiple packages or commits at once",
			json.RawMessage(`{
				"type": "object",
				"properties": {
					"queries": {
						"type": "array",
						"description": "Array of query objects",
						"items": {
							"type": "object",
							"properties": {
								"commit": {
									"type": "string",
									"description": "The commit hash to query for. If specified, version should not be set."
								},
								"version": {
									"type": "string",
									"description": "The version string to query for. If specified, commit should not be set."
								},
								"package_name": {
									"type": "string",
									"description": "The name of the package."
								},
								"ecosystem": {
									"type": "string",
									"description": "The ecosystem for this package (e.g., PyPI, npm, Go)."
								},
								"purl": {
									"type": "string",
									"description": "The package URL for this package. If purl is used, package_name and ecosystem should not be set."
								}
							}
						}
					}
				},
				"required": ["queries"]
			}`),
		),
		s.handleQueryVulnerabilitiesBatch,
	)

	mcpServer.AddTool(
		mcp.NewToolWithRawSchema(
			"get_vulnerability",
			"Get details for a specific vulnerability by ID",
			json.RawMessage(`{
				"type": "object",
				"properties": {
					"id": {
						"type": "string",
						"description": "The OSV vulnerability ID"
					}
				},
				"required": ["id"]
			}`),
		),
		s.handleGetVulnerability,
	)

	s.mcpServer = mcpServer
	return s
}

// ServerOption is a function that configures a Server
type ServerOption func(*Server)

// WithOSVClient sets the OSV client to use
func WithOSVClient(client osv.OSVClient) ServerOption {
	return func(s *Server) {
		s.osvClient = client
	}
}

// ServeSSE starts the MCP server using SSE
func (s *Server) ServeSSE(addr string) error {
	log.Printf("Starting OSV MCP server (SSE) on %s", addr)
	sseServer := server.NewSSEServer(s.mcpServer)
	return sseServer.Start(addr)
}

// ServeHTTPStream starts the MCP server using Streamable HTTP transport
func (s *Server) ServeHTTPStream(addr string) error {
	log.Printf("Starting OSV MCP server (Streamable HTTP) on %s", addr)

	httpSrv := server.NewStreamableHTTPServer(s.mcpServer,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true), // stateless mode
		server.WithHeartbeatInterval(30*time.Second),
	)

	return httpSrv.Start(addr)
}

// handleQueryVulnerability handles the query_vulnerability tool
func (s *Server) handleQueryVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	commit := mcp.ParseString(request, "commit", "")
	version := mcp.ParseString(request, "version", "")
	packageName := mcp.ParseString(request, "package_name", "")
	ecosystem := mcp.ParseString(request, "ecosystem", "")
	purl := mcp.ParseString(request, "purl", "")

	// Validate input
	if commit != "" && version != "" {
		return mcp.NewToolResultError("Both commit and version cannot be specified"), nil
	}

	if purl != "" && (packageName != "" || ecosystem != "") {
		return mcp.NewToolResultError("If purl is specified, package_name and ecosystem should not be specified"), nil
	}

	if purl == "" && (packageName == "" || ecosystem == "") && commit == "" {
		return mcp.NewToolResultError("Either purl, or both package_name and ecosystem, or commit must be specified"), nil
	}

	// Create query request
	queryReq := osv.QueryRequest{
		Commit:  commit,
		Version: version,
	}

	if purl != "" {
		queryReq.Package = osv.Package{
			PURL: purl,
		}
	} else if packageName != "" && ecosystem != "" {
		queryReq.Package = osv.Package{
			Name:      packageName,
			Ecosystem: ecosystem,
		}
	}

	// Query OSV API
	resp, err := s.osvClient.Query(ctx, queryReq)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to query OSV API", err), nil
	}

	// Format response
	result, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to marshal response", err), nil
	}

	return mcp.NewToolResultText(string(result)), nil
}

// handleQueryVulnerabilitiesBatch handles the query_vulnerabilities_batch tool
func (s *Server) handleQueryVulnerabilitiesBatch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments format"), nil
	}

	queriesRaw, ok := args["queries"].([]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid 'queries' parameter: must be array"), nil
	}

	// Convert queries to QueryRequest objects
	var queries []osv.QueryRequest
	for i, queryRaw := range queriesRaw {
		queryMap, ok := queryRaw.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid query at index %d", i)), nil
		}

		commit, _ := queryMap["commit"].(string)
		version, _ := queryMap["version"].(string)
		packageName, _ := queryMap["package_name"].(string)
		ecosystem, _ := queryMap["ecosystem"].(string)
		purl, _ := queryMap["purl"].(string)

		// Validate input
		if commit != "" && version != "" {
			return mcp.NewToolResultError(fmt.Sprintf("Both commit and version cannot be specified in query %d", i)), nil
		}

		if purl != "" && (packageName != "" || ecosystem != "") {
			return mcp.NewToolResultError(
				fmt.Sprintf("If purl is specified, package_name and ecosystem should not be specified in query %d", i),
			), nil
		}

		// Create query request
		queryReq := osv.QueryRequest{
			Commit:  commit,
			Version: version,
		}

		if purl != "" {
			queryReq.Package = osv.Package{
				PURL: purl,
			}
		} else if packageName != "" && ecosystem != "" {
			queryReq.Package = osv.Package{
				Name:      packageName,
				Ecosystem: ecosystem,
			}
		}

		queries = append(queries, queryReq)
	}

	// Query OSV API
	resp, err := s.osvClient.QueryBatch(ctx, osv.QueryBatchRequest{Queries: queries})
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to query OSV API", err), nil
	}

	// Format response
	result, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to marshal response", err), nil
	}

	return mcp.NewToolResultText(string(result)), nil
}

// handleGetVulnerability handles the get_vulnerability tool
func (s *Server) handleGetVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := mcp.ParseString(request, "id", "")
	if id == "" {
		return mcp.NewToolResultError("Vulnerability ID is required"), nil
	}

	// Get vulnerability from OSV API
	vuln, err := s.osvClient.GetVulnerability(ctx, id)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get vulnerability", err), nil
	}

	// Format response
	result, err := json.MarshalIndent(vuln, "", "  ")
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to marshal response", err), nil
	}

	return mcp.NewToolResultText(string(result)), nil
}
