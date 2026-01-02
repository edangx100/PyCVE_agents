#!/bin/bash
# Start OSV MCP HTTP Server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment variables
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source <(grep -v '^#' "$PROJECT_ROOT/.env" | sed 's/#.*$//' | sed '/^$/d')
    set +a
fi

# Default configuration
OSV_MCP_HTTP_HOST="${OSV_MCP_HTTP_HOST:-0.0.0.0}"
OSV_MCP_HTTP_PORT="${OSV_MCP_HTTP_PORT:-3000}"
OSV_MCP_HTTP_PATH="${OSV_MCP_HTTP_PATH:-/mcp}"

echo "Starting OSV MCP HTTP Server..."
echo "  Host: $OSV_MCP_HTTP_HOST"
echo "  Port: $OSV_MCP_HTTP_PORT"
echo "  Path: $OSV_MCP_HTTP_PATH"
echo ""

# Start server
cd "$PROJECT_ROOT"
python -m src.mcp_servers.osv_http_server

# Executable permissions set (-rwx--x--x)