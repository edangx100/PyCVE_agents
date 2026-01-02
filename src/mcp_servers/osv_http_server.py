"""Self-contained OSV MCP HTTP Server using FastMCP.

This server provides OSV vulnerability database tools via HTTP streamable transport,
making it compatible with Docker-based agent execution.

Architecture:
- FastMCP provides the MCP protocol implementation over HTTP
- OSVClient handles REST API calls to api.osv.dev
- 4 tools exposed via @mcp.tool() decorator for agent consumption
- Runs on uvicorn ASGI server with streamable-http transport
"""

from fastmcp import FastMCP
import requests
import re
from typing import Optional

# creates an MCP server that will expose tools to agents
mcp = FastMCP("OSV Database API MCP Server")


class OSVClient:
    """Client for querying the OSV vulnerability database.

    OSV REST API at api.osv.dev.
    OSV (Open Source Vulnerabilities) is a distributed vulnerability database
    for open source projects.
    """

    def __init__(self):
        """Initialize OSV API endpoints."""
        # POST endpoint for querying package vulnerabilities by name/version
        self.package_url = "https://api.osv.dev/v1/query"
        # GET endpoint for querying specific CVE/vulnerability details
        self.cve_url = "https://api.osv.dev/v1/vulns/{cve_id}"

    def query_package(
        self, package: str, ecosystem: str, version: Optional[str] = None
    ):
        """Query OSV database for package vulnerabilities.

        Makes a POST request to /v1/query endpoint with package information.

        Args:
            package: Package name (e.g., "flask", "requests")
            ecosystem: Package ecosystem (e.g., "PyPI", "npm")
            version: Optional specific version to query

        Returns:
            dict: JSON response containing vulnerabilities list
        """
        # Build request payload with package metadata
        data = {"package": {"name": package, "ecosystem": ecosystem}}
        if version:
            data["version"] = version

        response = requests.post(self.package_url, json=data, timeout=30)
        # Raise exception for HTTP error status codes (4xx, 5xx)
        response.raise_for_status()
        return response.json()

    def query_cve(self, cve: str):
        """Query OSV database for specific CVE details.

        Makes a GET request to /v1/vulns/{cve_id} endpoint.

        Args:
            cve: CVE identifier (e.g., "CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx")

        Returns:
            dict: JSON response with CVE details, affected versions, fix info
        """
        # Format URL with CVE ID
        url = self.cve_url.format(cve_id=cve)
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def parse_versions(self, data: dict) -> list[str]:
        """Extract affected versions from OSV response.

        OSV response structure: {"affected": [{"versions": ["1.0", "1.1", ...]}]}

        Args:
            data: OSV API response JSON

        Returns:
            list[str]: Deduplicated list of affected version strings
        """
        versions = []
        if "affected" in data:
            for affected in data["affected"]:
                if "versions" in affected:
                    versions.extend(affected["versions"])
        return list(set(versions))

    def parse_fix_versions(self, data: dict) -> list[str]:
        """Extract fix versions from OSV response.

        Parses version ranges to find "fixed" events which indicate
        the version where the vulnerability was patched.

        OSV response structure:
        {"affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}]}

        Args:
            data: OSV API response JSON

        Returns:
            list[str]: Deduplicated list of version strings that include fixes
        """
        fix_versions = []
        if "affected" in data:
            for affected in data["affected"]:
                # Check for version ranges (used for semantic versioning)
                if "ranges" in affected:
                    for range_data in affected["ranges"]:
                        # Events array contains introduced/fixed markers
                        if "events" in range_data:
                            for event in range_data["events"]:
                                # "fixed" event marks version where vuln was patched
                                if "fixed" in event:
                                    fix_versions.append(event["fixed"])
        return list(set(fix_versions))



# ----------- MCP Tools Exposed via FastMCP for  query the OSV vulnerability database. ------- #
@mcp.tool()
def get_ecosystems() -> dict[str, str]:
    """Get all supported ecosystems.

    An ecosystem is a package manager or repository for a specific language.
    This tool helps agents discover which ecosystems they can query.

    Returns:
        Dictionary mapping ecosystem names to programming languages/OS.
        Use the exact ecosystem name when calling query_package_cve.

    Example:
        {"PyPI": "python", "npm": "javascript", ...}
    """
    # These ecosystem names must match OSV API requirements exactly
    return {
        "PyPI": "python",
        "npm": "javascript",
        "RubyGems": "ruby",
        "Maven": "java",         # Java/Maven Central
        "NuGet": "c#",           # .NET package manager
    }


@mcp.tool()
def query_package_cve(
    package: str, version: Optional[str] = None, ecosystem: str = "PyPI"
) -> list[dict]:
    """Query the OSV database for package CVEs.

    ALWAYS use this before installing packages to check for vulnerabilities.
    Check requirements.txt, pyproject.toml, uv.lock, etc.

    Args:
        package: Package name to query (e.g., "flask", "django")
        version: Specific version (optional, queries all versions if None)
        ecosystem: Package ecosystem (default: PyPI). See get_ecosystems() for supported values.

    Returns:
        List of CVE dictionaries with details and severity information.
        Format: [{"CVE-2024-1234": {"details": "...", "severity": [...]}}]

    Example:
        query_package_cve("requests", "2.25.0", "PyPI")
        Returns vulnerabilities for requests 2.25.0 in PyPI ecosystem
    """
    client = OSVClient()
    # Query OSV API for package vulnerabilities
    data = client.query_package(package, ecosystem, version)

    # Parse vulnerabilities from response
    cves = []
    if "vulns" in data:
        for vuln in data["vulns"]:
            # Extract CVE ID using regex pattern: CVE-YYYY-NNNNN
            cve_match = re.search(r"CVE-(\d+)-(\d+)", str(vuln))
            if cve_match:
                # Build CVE dictionary with ID as key
                cves.append({
                    cve_match.group(0): {  # Full CVE ID (e.g., "CVE-2024-1234")
                        "details": vuln.get("details", ""),
                        "severity": vuln.get("severity", [])  # Severity ratings (CVSS, etc.)
                    }
                })
    return cves


@mcp.tool()
def query_for_cve_affected(cve: str) -> list[str]:
    """Query OSV database for versions affected by a CVE.

    Given a CVE ID, returns all package versions known to be vulnerable.
    Useful for determining if a specific version is affected.

    Args:
        cve: CVE ID to query (e.g., "CVE-2024-1234" or "GHSA-xxxx-xxxx-xxxx")

    Returns:
        List of affected version strings (e.g., ["1.0.0", "1.0.1", "1.1.0"])

    Example:
        query_for_cve_affected("CVE-2024-1234")
        Returns: ["2.0.0", "2.0.1", "2.1.0"]  # All vulnerable versions
    """
    client = OSVClient()
    # Query OSV API for CVE details
    data = client.query_cve(cve)
    # Extract and return list of affected versions
    return client.parse_versions(data)


@mcp.tool()
def query_for_cve_fix_versions(cve: str) -> list[str]:
    """Query OSV database for versions that fix a CVE.

    Given a CVE ID, returns all package versions where the vulnerability
    was patched. Use this to determine the minimum safe version to upgrade to.

    Args:
        cve: CVE ID to query (e.g., "CVE-2024-1234" or "GHSA-xxxx-xxxx-xxxx")

    Returns:
        List of version strings that include the fix (e.g., ["2.2.0", "3.0.0"])

    Example:
        query_for_cve_fix_versions("CVE-2024-1234")
        Returns: ["2.2.0"]  # Version where vulnerability was fixed
    """
    client = OSVClient()
    data = client.query_cve(cve)
    # Extract and return list of versions containing the fix
    return client.parse_fix_versions(data)


def main():
    """Run the OSV MCP HTTP server.

    This function:
    1. Reads configuration from environment variables
    2. Creates a FastMCP HTTP app with streamable-http transport
    3. Starts uvicorn ASGI server to serve the MCP endpoint

    The server will be accessible to agents via HTTP requests to the /mcp endpoint.
    """
    import os
    import uvicorn
    from fastmcp.server.http import create_streamable_http_app

    host = os.getenv("OSV_MCP_HTTP_HOST", "0.0.0.0")
    port = int(os.getenv("OSV_MCP_HTTP_PORT", "3000"))
    mcp_path = os.getenv("OSV_MCP_HTTP_PATH", "/mcp")  # MCP endpoint path

    print("=" * 60)
    print("OSV MCP HTTP Server")
    print("=" * 60)
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"MCP Endpoint: http://{host if host != '0.0.0.0' else 'localhost'}:{port}{mcp_path}")
    print(f"Transport: streamable-http")
    print("=" * 60)
    print()

    # Create ASGI application with FastMCP, wraps MCP server with HTTP handling for streamable-http protocol
    app = create_streamable_http_app(
        server=mcp,                     # The FastMCP server instance with 4 tools
        streamable_http_path=mcp_path   # Path where MCP endpoint will be served
    )

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
