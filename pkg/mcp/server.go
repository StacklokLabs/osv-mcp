// Package mcp provides MCP server tools for OSV.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
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

// Tool argument names shared by the query tools' input schemas and handlers.
const (
	argCommit      = "commit"
	argVersion     = "version"
	argPackageName = "package_name"
	argEcosystem   = "ecosystem"
	argPurl        = "purl"
	argID          = "id"
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

	// All tools are read-only queries against the OSV API.
	readOnlyAnnotations := func(title string) mcp.ToolAnnotation {
		return mcp.ToolAnnotation{
			Title:           title,
			ReadOnlyHint:    mcp.ToBoolPtr(true),
			DestructiveHint: mcp.ToBoolPtr(false),
			IdempotentHint:  mcp.ToBoolPtr(true),
			OpenWorldHint:   mcp.ToBoolPtr(true),
		}
	}

	// Register tools
	queryVulnTool := mcp.NewToolWithRawSchema(
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
	)
	queryVulnTool.Title = "Query Vulnerability"
	queryVulnTool.Annotations = readOnlyAnnotations(queryVulnTool.Title)
	mcpServer.AddTool(queryVulnTool, s.handleQueryVulnerability)

	queryBatchTool := mcp.NewToolWithRawSchema(
		"query_vulnerabilities_batch",
		"Query for vulnerabilities affecting multiple packages or commits at once",
		json.RawMessage(`{
				"type": "object",
				"properties": {
					"queries": {
						"type": "array",
						"description": "Array of query objects",
						"minItems": 1,
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
	)
	queryBatchTool.Title = "Query Vulnerabilities (Batch)"
	queryBatchTool.Annotations = readOnlyAnnotations(queryBatchTool.Title)
	mcpServer.AddTool(queryBatchTool, s.handleQueryVulnerabilitiesBatch)

	getVulnTool := mcp.NewToolWithRawSchema(
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
	)
	getVulnTool.Title = "Get Vulnerability"
	getVulnTool.Annotations = readOnlyAnnotations(getVulnTool.Title)
	mcpServer.AddTool(getVulnTool, s.handleGetVulnerability)

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
	log.Printf("WARNING: the SSE transport is deprecated by the MCP specification; use streamable-http instead")
	log.Printf("Starting OSV MCP server (SSE) on %s", addr)
	sseServer := server.NewSSEServer(s.mcpServer)
	return sseServer.Start(addr)
}

// ServeHTTPStream starts the MCP server using Streamable HTTP transport
func (s *Server) ServeHTTPStream(addr string) error {
	log.Printf("Starting OSV MCP server (Streamable HTTP) on %s", addr)

	httpSrv := server.NewStreamableHTTPServer(s.mcpServer,
		server.WithEndpointPath("/mcp"),
		// Every tool call is an independent OSV API query, so there's no
		// session state to keep. Stateless mode matches MCP 2026-07-28,
		// which removed protocol-level sessions.
		server.WithStateLess(true),
		server.WithHeartbeatInterval(30*time.Second),
	)

	return httpSrv.Start(addr)
}

// handleQueryVulnerability handles the query_vulnerability tool
func (s *Server) handleQueryVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	commit := mcp.ParseString(request, argCommit, "")
	version := mcp.ParseString(request, argVersion, "")
	packageName := mcp.ParseString(request, argPackageName, "")
	ecosystem := mcp.ParseString(request, argEcosystem, "")
	purl := mcp.ParseString(request, argPurl, "")

	queryReq, err := buildQueryRequest(commit, version, packageName, ecosystem, purl)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
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
	if len(queriesRaw) == 0 {
		return mcp.NewToolResultError("Invalid 'queries' parameter: must contain at least one query"), nil
	}

	// Convert queries to QueryRequest objects
	var queries []osv.QueryRequest
	for i, queryRaw := range queriesRaw {
		queryMap, ok := queryRaw.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid query at index %d", i)), nil
		}

		commit, _ := queryMap[argCommit].(string)
		version, _ := queryMap[argVersion].(string)
		packageName, _ := queryMap[argPackageName].(string)
		ecosystem, _ := queryMap[argEcosystem].(string)
		purl, _ := queryMap[argPurl].(string)

		queryReq, err := buildQueryRequest(commit, version, packageName, ecosystem, purl)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%v in query %d", err, i)), nil
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

// buildQueryRequest validates a single query's arguments and converts them to
// an OSV query request. The same rules apply to query_vulnerability and to
// each entry of query_vulnerabilities_batch.
func buildQueryRequest(commit, version, packageName, ecosystem, purl string) (osv.QueryRequest, error) {
	if commit != "" && version != "" {
		return osv.QueryRequest{}, errors.New("both commit and version cannot be specified")
	}
	if purl != "" && (packageName != "" || ecosystem != "") {
		return osv.QueryRequest{}, errors.New("if purl is specified, package_name and ecosystem should not be specified")
	}
	if purl == "" && (packageName == "" || ecosystem == "") && commit == "" {
		return osv.QueryRequest{}, errors.New("either purl, or both package_name and ecosystem, or commit must be specified")
	}

	req := osv.QueryRequest{
		Commit:  commit,
		Version: version,
	}
	if purl != "" {
		req.Package = osv.Package{PURL: purl}
	} else if packageName != "" && ecosystem != "" {
		req.Package = osv.Package{Name: packageName, Ecosystem: ecosystem}
	}
	return req, nil
}

// handleGetVulnerability handles the get_vulnerability tool
func (s *Server) handleGetVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := mcp.ParseString(request, argID, "")
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
