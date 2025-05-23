# OSV MCP Server

An MCP (Model Context Protocol) server that provides access to the [OSV (Open Source Vulnerabilities) database](https://osv.dev/).

## Overview

This project implements an SSE-based MCP server that allows LLM-powered applications to query the OSV database for vulnerability information. The server provides tools for:

1. Querying vulnerabilities for a specific package version or commit
2. Batch querying vulnerabilities for multiple packages or commits
3. Getting detailed information about a specific vulnerability by ID

## Installation

### Prerequisites

- Go 1.21 or later
- [Task](https://taskfile.dev/) (optional, for running tasks)
- [ko](https://ko.build/) (optional, for building container images)

### Building from source

```bash
# Clone the repository
git clone https://github.com/StacklokLabs/osv-mcp.git
cd osv-mcp

# Build the server
task build
```

## Usage

### Server Configuration

The server can be configured using environment variables:

- `MCP_PORT`: The port number to run the server on (default: 8080)
  - Must be a valid integer between 0 and 65535
  - If invalid or not set, the server will use port 8080

Example:
```bash
# Run on port 3000
MCP_PORT=3000 ./osv-mcp

# Run on default port 8080
./osv-mcp
```

### MCP Tools

The server provides the following MCP tools:

#### query_vulnerability

Query for vulnerabilities affecting a specific package version or commit.

**Input Schema:**
```json
{
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
```

#### query_vulnerabilities_batch

Query for vulnerabilities affecting multiple packages or commits at once.

**Input Schema:**
```json
{
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
}
```

#### get_vulnerability

Get details for a specific vulnerability by ID.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "description": "The OSV vulnerability ID"
    }
  },
  "required": ["id"]
}
```

## Examples

### Querying vulnerabilities for a package

```json
{
  "package_name": "lodash",
  "ecosystem": "npm",
  "version": "4.17.15"
}
```

### Querying vulnerabilities for a commit

```json
{
  "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
}
```

### Batch querying vulnerabilities

```json
{
  "queries": [
    {
      "package_name": "lodash",
      "ecosystem": "npm",
      "version": "4.17.15"
    },
    {
      "package_name": "jinja2",
      "ecosystem": "PyPI",
      "version": "2.4.1"
    }
  ]
}
```

### Getting vulnerability details

```json
{
  "id": "GHSA-vqj2-4v8m-8vrq"
}
```

## Development

### Running tests

```bash
task test
```

### Linting

```bash
task lint
```

### Formatting code

```bash
task fmt
```

## Contributing

We welcome contributions to this MCP server! If you'd like to contribute, please review
the [CONTRIBUTING guide](./CONTRIBUTING.md) for details on how to get started.

If you run into a bug or have a feature request, please
[open an issue](https://github.com/StacklokLabs/osv-mcp/issues) in the
repository or join us in the `#mcp-servers` channel on our
[community Discord server](https://discord.gg/stacklok).

## License

This project is licensed under the Apache v2 License - see the LICENSE file for details.