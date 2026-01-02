#!/usr/bin/env python3
"""Health check for OSV MCP HTTP Server."""

import sys
import os
import requests


def check_mcp_health():
    """Check if MCP HTTP server is running and accessible."""
    url = os.getenv("OSV_MCP_HTTP_URL", "http://localhost:3000/mcp")

    print(f"Checking MCP server health: {url}")

    try:
        # Try to connect with short timeout
        response = requests.get(url, timeout=5)

        # 200 = OK, 406 = Not Acceptable (expected for MCP endpoint with GET request)
        if response.status_code in (200, 406):
            print("✓ MCP server is running and accessible")
            if response.status_code == 406:
                print("  (406 response is expected - MCP endpoint requires proper protocol headers)")
            return 0
        else:
            print(f"✗ MCP server returned unexpected status code: {response.status_code}")
            return 1

    except requests.exceptions.ConnectionError:
        print("✗ MCP server is not running or not accessible")
        print(f"  Start it with: ./scripts/start_osv_mcp_server.sh")
        return 1
    except requests.exceptions.Timeout:
        print("✗ MCP server connection timed out")
        return 1
    except Exception as e:
        print(f"✗ Error checking MCP server: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(check_mcp_health())
