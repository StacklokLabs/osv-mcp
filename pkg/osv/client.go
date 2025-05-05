package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// BaseURL is the base URL for the OSV API
	BaseURL = "https://api.osv.dev/v1"
	
	// QueryEndpoint is the endpoint for querying vulnerabilities
	QueryEndpoint = "/query"
	
	// QueryBatchEndpoint is the endpoint for batch querying vulnerabilities
	QueryBatchEndpoint = "/querybatch"
	
	// VulnEndpoint is the endpoint for getting vulnerability details
	VulnEndpoint = "/vulns"
)

// OSVClient is the interface for the OSV API client
type OSVClient interface {
	Query(ctx context.Context, req QueryRequest) (*QueryResponse, error)
	QueryBatch(ctx context.Context, req QueryBatchRequest) (*QueryBatchResponse, error)
	GetVulnerability(ctx context.Context, id string) (*Vulnerability, error)
}

// Client is a client for the OSV API
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new OSV API client
func NewClient(opts ...ClientOption) *Client {
	client := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: BaseURL,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// WithHTTPClient sets the HTTP client to use
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithBaseURL sets the base URL to use
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// Package represents a package in the OSV API
type Package struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// QueryRequest represents a request to the OSV API query endpoint
type QueryRequest struct {
	Commit    string  `json:"commit,omitempty"`
	Version   string  `json:"version,omitempty"`
	Package   Package `json:"package,omitempty"`
	PageToken string  `json:"page_token,omitempty"`
}

// QueryBatchRequest represents a request to the OSV API batch query endpoint
type QueryBatchRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// Reference represents a reference in a vulnerability
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Event represents an event in a vulnerability's timeline
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Limit      string `json:"limit,omitempty"`
}

// Range represents a range of versions affected by a vulnerability
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Affected represents a package affected by a vulnerability
type Affected struct {
	Package           Package               `json:"package"`
	Ranges            []Range               `json:"ranges,omitempty"`
	Versions          []string              `json:"versions,omitempty"`
	EcosystemSpecific map[string]string     `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]string     `json:"database_specific,omitempty"`
}

// Vulnerability represents a vulnerability in the OSV API
type Vulnerability struct {
	ID           string     `json:"id"`
	Summary      string     `json:"summary,omitempty"`
	Details      string     `json:"details,omitempty"`
	Modified     time.Time  `json:"modified"`
	Published    time.Time  `json:"published,omitempty"`
	References   []Reference `json:"references,omitempty"`
	Affected     []Affected `json:"affected,omitempty"`
	SchemaVersion string    `json:"schema_version,omitempty"`
}

// QueryResponse represents a response from the OSV API query endpoint
type QueryResponse struct {
	Vulns         []Vulnerability `json:"vulns"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

// BatchQueryResult represents a single result in a batch query response
type BatchQueryResult struct {
	Vulns         []struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token,omitempty"`
}

// QueryBatchResponse represents a response from the OSV API batch query endpoint
type QueryBatchResponse struct {
	Results []BatchQueryResult `json:"results"`
}

// Query queries the OSV API for vulnerabilities matching the given request
func (c *Client) Query(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, QueryEndpoint)
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &queryResp, nil
}

// QueryBatch queries the OSV API for vulnerabilities matching the given batch request
func (c *Client) QueryBatch(ctx context.Context, req QueryBatchRequest) (*QueryBatchResponse, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, QueryBatchEndpoint)
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	var batchResp QueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &batchResp, nil
}

// GetVulnerability gets a vulnerability by ID
func (c *Client) GetVulnerability(ctx context.Context, id string) (*Vulnerability, error) {
	url := fmt.Sprintf("%s%s/%s", c.baseURL, VulnEndpoint, id)
	
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &vuln, nil
}