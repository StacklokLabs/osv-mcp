// Package mcp provides MCP server tools for OSV.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/StacklokLabs/osv-mcp/pkg/osv"
)

const (
	// ServerName is the name of the MCP server
	ServerName = "osv-mcp"

	// DefaultVersion is the version reported when none is set with WithVersion.
	DefaultVersion = "dev"

	// ServerPort is the port the MCP server will listen on
	ServerPort = "8080"
)

// Server is an MCP server that provides OSV vulnerability information
type Server struct {
	mcpServer *sdk.Server
	osvClient osv.OSVClient
	version   string
}

// queryArgs are the arguments shared by query_vulnerability and every entry of
// query_vulnerabilities_batch. All of them are optional in the schema: the
// combinations that make sense are enforced by buildQueryRequest so that the
// single and batch tools reject the same input with the same message.
type queryArgs struct {
	Commit      string `json:"commit,omitempty" jsonschema:"The commit hash to query for. If specified, version should not be set."`
	Version     string `json:"version,omitempty" jsonschema:"The version string to query for. If specified, commit should not be set."`
	PackageName string `json:"package_name,omitempty" jsonschema:"The name of the package."`
	Ecosystem   string `json:"ecosystem,omitempty" jsonschema:"The ecosystem for this package (e.g., PyPI, npm, Go)."`
	PURL        string `json:"purl,omitempty" jsonschema:"The package URL for this package. If purl is used, package_name and ecosystem should not be set."`
}

// queryBatchArgs is the input of query_vulnerabilities_batch.
type queryBatchArgs struct {
	Queries []queryArgs `json:"queries" jsonschema:"Array of query objects"`
}

// getVulnerabilityArgs is the input of get_vulnerability.
type getVulnerabilityArgs struct {
	ID string `json:"id" jsonschema:"The OSV vulnerability ID"`
}

// NewServer creates a new OSV MCP server
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		osvClient: osv.NewClient(),
		version:   DefaultVersion,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.mcpServer = sdk.NewServer(&sdk.Implementation{
		Name:    ServerName,
		Version: s.version,
	}, nil)

	querySchema := toolSchema[queryArgs]()
	batchSchema := toolSchema[queryBatchArgs]()
	// The queries field has always been a plain array of at least one entry,
	// while a Go slice infers "null or array" with no minimum length.
	queries := batchSchema.Properties["queries"]
	queries.Types = []string{"array"}
	queries.MinItems = jsonschema.Ptr(1)

	sdk.AddTool(s.mcpServer, &sdk.Tool{
		Name:        "query_vulnerability",
		Title:       "Query Vulnerability",
		Description: "Query for vulnerabilities affecting a specific package version or commit",
		Annotations: readOnlyAnnotations("Query Vulnerability"),
		InputSchema: querySchema,
	}, s.handleQueryVulnerability)

	sdk.AddTool(s.mcpServer, &sdk.Tool{
		Name:        "query_vulnerabilities_batch",
		Title:       "Query Vulnerabilities (Batch)",
		Description: "Query for vulnerabilities affecting multiple packages or commits at once",
		Annotations: readOnlyAnnotations("Query Vulnerabilities (Batch)"),
		InputSchema: batchSchema,
	}, s.handleQueryVulnerabilitiesBatch)

	sdk.AddTool(s.mcpServer, &sdk.Tool{
		Name:        "get_vulnerability",
		Title:       "Get Vulnerability",
		Description: "Get details for a specific vulnerability by ID",
		Annotations: readOnlyAnnotations("Get Vulnerability"),
		InputSchema: toolSchema[getVulnerabilityArgs](),
	}, s.handleGetVulnerability)

	return s
}

// toolSchema returns the input schema inferred from args, adjusted so that no
// object in it rejects unknown members: a client that sends an extra field had
// it ignored before the move to the official SDK, and still does.
func toolSchema[T any]() *jsonschema.Schema {
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		// The types above are fixed and simple; a failure here is a
		// programming error, and the SDK panics on bad schemas anyway.
		panic(fmt.Sprintf("osv-mcp: cannot infer the tool schema: %v", err))
	}
	allowUnknownArgs(schema)
	return schema
}

// allowUnknownArgs marks schema and every object nested in it as accepting
// additional properties.
func allowUnknownArgs(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}
	// A nil additionalProperties schema places no constraint on members the
	// struct does not declare; the inference fills in a "false" schema.
	schema.AdditionalProperties = nil
	for _, property := range schema.Properties {
		allowUnknownArgs(property)
	}
	allowUnknownArgs(schema.Items)
}

// readOnlyAnnotations describes a tool that only reads from the OSV API.
func readOnlyAnnotations(title string) *sdk.ToolAnnotations {
	no, yes := false, true
	return &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: &no,
		IdempotentHint:  true,
		OpenWorldHint:   &yes,
	}
}

// ServerOption is a function that configures a Server
type ServerOption func(*Server)

// WithVersion sets the server version reported to clients. An empty version
// leaves the default.
func WithVersion(version string) ServerOption {
	return func(s *Server) {
		if version != "" {
			s.version = version
		}
	}
}

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

	return http.ListenAndServe(addr, s.sseHandler())
}

// sseHandler serves the deprecated HTTP+SSE transport.
func (s *Server) sseHandler() http.Handler {
	handler := sdk.NewSSEHandler(func(*http.Request) *sdk.Server { return s.mcpServer }, nil)

	mux := http.NewServeMux()
	mux.Handle("/sse", handler)
	// Clients follow the endpoint event the handler sends on /sse, but some
	// older ones still post to the path mcp-go used, so serve that too.
	mux.Handle("/message", handler)

	return mux
}

// ServeHTTPStream starts the MCP server using Streamable HTTP transport
func (s *Server) ServeHTTPStream(addr string) error {
	log.Printf("Starting OSV MCP server (Streamable HTTP) on %s", addr)

	return http.ListenAndServe(addr, s.streamableHTTPHandler())
}

// streamableHTTPHandler serves the Streamable HTTP transport at /mcp.
func (s *Server) streamableHTTPHandler() http.Handler {
	// Every tool call is an independent OSV API query, so there's no session
	// state to keep. Stateless mode matches MCP 2026-07-28, which removed
	// protocol-level sessions.
	handler := sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return s.mcpServer },
		&sdk.StreamableHTTPOptions{Stateless: true},
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)

	return mux
}

// handleQueryVulnerability handles the query_vulnerability tool
func (s *Server) handleQueryVulnerability(
	ctx context.Context, _ *sdk.CallToolRequest, args queryArgs,
) (*sdk.CallToolResult, any, error) {
	queryReq, err := buildQueryRequest(args)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	resp, err := s.osvClient.Query(ctx, queryReq)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to query OSV API: %v", err)), nil, nil
	}

	return jsonResult(resp)
}

// handleQueryVulnerabilitiesBatch handles the query_vulnerabilities_batch tool
func (s *Server) handleQueryVulnerabilitiesBatch(
	ctx context.Context, _ *sdk.CallToolRequest, args queryBatchArgs,
) (*sdk.CallToolResult, any, error) {
	if len(args.Queries) == 0 {
		return errorResult("Invalid 'queries' parameter: must contain at least one query"), nil, nil
	}

	queries := make([]osv.QueryRequest, 0, len(args.Queries))
	for i, query := range args.Queries {
		queryReq, err := buildQueryRequest(query)
		if err != nil {
			return errorResult(fmt.Sprintf("%v in query %d", err, i)), nil, nil
		}

		queries = append(queries, queryReq)
	}

	resp, err := s.osvClient.QueryBatch(ctx, osv.QueryBatchRequest{Queries: queries})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to query OSV API: %v", err)), nil, nil
	}

	return jsonResult(resp)
}

// buildQueryRequest validates a query's arguments and converts them to an OSV
// query request. The same rules apply to query_vulnerability and to each entry
// of query_vulnerabilities_batch.
func buildQueryRequest(args queryArgs) (osv.QueryRequest, error) {
	commit, version := args.Commit, args.Version
	packageName, ecosystem, purl := args.PackageName, args.Ecosystem, args.PURL

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
func (s *Server) handleGetVulnerability(
	ctx context.Context, _ *sdk.CallToolRequest, args getVulnerabilityArgs,
) (*sdk.CallToolResult, any, error) {
	if args.ID == "" {
		return errorResult("Vulnerability ID is required"), nil, nil
	}

	vuln, err := s.osvClient.GetVulnerability(ctx, args.ID)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to get vulnerability: %v", err)), nil, nil
	}

	return jsonResult(vuln)
}

// errorResult returns a tool result that reports a failure to the client.
func errorResult(message string) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		IsError: true,
		Content: []sdk.Content{&sdk.TextContent{Text: message}},
	}
}

// jsonResult returns a tool result holding the JSON encoding of v.
func jsonResult(v any) (*sdk.CallToolResult, any, error) {
	result, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to marshal response: %v", err)), nil, nil
	}

	return &sdk.CallToolResult{
		Content: []sdk.Content{&sdk.TextContent{Text: string(result)}},
	}, nil, nil
}
