"""Docker workspace configuration and runtime utilities for PyCVE.

Manages Docker container setup, workspace paths, and MCP server integration
for running vulnerability fix agents in isolated environments.
"""
from __future__ import annotations

import os
import platform
import posixpath
from typing import Optional


def _parse_bool_env(value: str, default: bool = False) -> bool:
    """Parse environment variable as boolean (supports: 1, true, yes, y, on)."""
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _detect_platform() -> str:
    """Detect Docker platform string (linux/arm64 or linux/amd64) from machine architecture."""
    machine = platform.machine().lower()
    if "arm" in machine or "aarch64" in machine:
        return "linux/arm64"
    return "linux/amd64"


def _candidate_host_ports(base_port: int, max_attempts: int = 5) -> list[int]:
    """Generate list of sequential ports to try (base_port, base_port+1, ...)."""
    return [base_port + offset for offset in range(max_attempts)]


def _is_port_unavailable_error(exc: Exception) -> bool:
    """Check if exception indicates port is already in use."""
    message = str(exc).lower()
    return (
        ("port" in message and "not available" in message)
        or "address already in use" in message
        or "port is already allocated" in message
        or "failed to bind" in message
    )


def _load_docker_workspace_classes():
    """Load DockerWorkspace classes, supporting both new and legacy openhands module paths."""
    # Support both the new workspace module path and legacy SDK path.
    try:
        from openhands.workspace import DockerDevWorkspace, DockerWorkspace

        return DockerWorkspace, DockerDevWorkspace
    except ImportError:
        try:
            from openhands.sdk.workspace import DockerDevWorkspace, DockerWorkspace

            return DockerWorkspace, DockerDevWorkspace
        except ImportError:
            return None, None


def create_docker_workspace():
    """Create DockerWorkspace with resilient fallback strategy.

    Tries multiple configurations in order:
    1. Custom server image (DOCKER_SERVER_IMAGE)
    2. Default OpenHands server image
    3. Base image with workspace mount
    4. Minimal base image
    Falls back through different ports if port conflicts occur.
    """
    docker_workspace_cls, docker_dev_cls = _load_docker_workspace_classes()
    if docker_workspace_cls is None:
        raise RuntimeError(
            "DockerWorkspace is unavailable; install a newer openhands-sdk that includes it."
        )

    # Load Docker configuration from environment
    base_image = os.getenv("DOCKER_BASE_IMAGE", "python:3.11-slim")
    server_image = os.getenv("DOCKER_SERVER_IMAGE", "").strip()
    try:
        host_port = int(os.getenv("DOCKER_HOST_PORT", "8010"))
    except ValueError as exc:
        raise RuntimeError("DOCKER_HOST_PORT must be an integer.") from exc
    docker_platform = _detect_platform()
    # Runtime workspace root for per-run directories (not the mount point)
    workspace_root = os.getenv("DOCKER_WORKSPACE_ROOT", "/workspace")

    # Environment variables to forward to Docker containers
    forward_env = [
        "DOCKER_LLM_API_KEY",
        "DOCKER_LLM_MODEL",
        "DOCKER_LLM_BASE_URL",
        "DOCKER_LLM_NATIVE_TOOL_CALLING",
        # Forward OSV MCP configuration so fixer agents in containers can auto-build MCP config
        "OSV_MCP_ENABLED",
        "OSV_MCP_HTTP_ENABLED",
        "OSV_MCP_HTTP_URL",
        "OSV_MCP_HTTP_PORT",
        "OSV_MCP_HTTP_PATH",
        "OSV_MCP_HTTP_TRANSPORT",
        "COORDINATOR_USE_DOCKER",
    ]

    # Build prioritized list of workspace configurations to try
    # Each attempt uses different parameter combinations for compatibility
    attempts: list[dict[str, object]] = []

    # Priority 1: Custom server image if provided
    if server_image:
        attempts.append(
            {
                "server_image": server_image,
                "host_port": host_port,
                "platform": docker_platform,
                "forward_env": forward_env,
            }
        )

    # Priority 2: Default OpenHands server image
    attempts.append(
        {
            "server_image": "ghcr.io/openhands/agent-server:latest-python",
            "platform": docker_platform,
            "forward_env": forward_env,
        }
    )

    # Priority 3: Base image with workspace mount
    attempts.append(
        {
            "base_container_image": base_image,
            "workspace_mount_path": workspace_root,
            "host_port": host_port,
            "forward_env": forward_env,
        }
    )

    # Priority 4: Minimal fallback with just base image
    attempts.append({"base_container_image": base_image})

    # Try each port/config combination until one succeeds
    last_exc: Optional[Exception] = None
    for port in _candidate_host_ports(host_port):
        port_blocked = False
        for kwargs in attempts:
            candidate = dict(kwargs)
            if "host_port" in candidate:
                candidate["host_port"] = port
            try:
                return docker_workspace_cls(**candidate)
            except TypeError:
                # Retry without host_port if signature doesn't support it
                if "host_port" in candidate:
                    candidate.pop("host_port", None)
                try:
                    return docker_workspace_cls(**candidate)
                except Exception as exc:
                    last_exc = exc
                    if _is_port_unavailable_error(exc):
                        port_blocked = True
                        break
                    continue
            except Exception as exc:
                last_exc = exc
                if _is_port_unavailable_error(exc):
                    port_blocked = True
                    break
                continue
        # Skip to next port if current port is blocked
        if port_blocked:
            continue

    # Final fallback: Try DockerDevWorkspace if available
    if docker_dev_cls is not None:
        for port in _candidate_host_ports(host_port):
            try:
                return docker_dev_cls(
                    base_image=base_image,
                    host_port=port,
                    platform=docker_platform,
                    forward_env=forward_env,
                )
            except TypeError:
                # Retry with minimal params if full signature fails
                try:
                    return docker_dev_cls(base_image=base_image)
                except Exception as exc:
                    last_exc = exc
                    if _is_port_unavailable_error(exc):
                        continue
                    break
            except Exception as exc:
                last_exc = exc
                if _is_port_unavailable_error(exc):
                    continue
                break

    if last_exc:
        raise RuntimeError(
            "Unable to initialize DockerWorkspace with available parameters. "
            f"Last error: {last_exc}"
        ) from last_exc
    raise RuntimeError("Unable to initialize DockerWorkspace with available parameters.")


def docker_paths(run_id: str) -> tuple[str, str, str, str]:
    """Generate container paths for a fix run.

    Returns:
        (workspace_root, workspace_dir, repo_dir, artifacts_dir)
        Example: ("/workspace/workspace", "/workspace/workspace/run123",
                  "/workspace/workspace/run123/repo", "/workspace/workspace/run123/artifacts")
    """
    # Base runtime workspace (typically /workspace/workspace)
    workspace_root = os.getenv("DOCKER_WORKSPACE_ROOT", "/workspace")
    # Per-run isolated workspace
    workspace_dir = posixpath.join(workspace_root, run_id)
    # Directory where vulnerable repo is cloned
    repo_dir = posixpath.join(workspace_dir, "repo")
    # Directory for generated patches, reports, etc.
    artifacts_dir = posixpath.join(workspace_dir, "artifacts")
    return workspace_root, workspace_dir, repo_dir, artifacts_dir


def docker_delegate_enabled() -> bool:
    """Check if DelegateTool is enabled for spawning sub-agents."""
    return _parse_bool_env(os.getenv("DOCKER_ENABLE_DELEGATE", "false"))


def coordinator_use_docker() -> bool:
    """Check if coordinator should run agents in Docker (default: True)."""
    return _parse_bool_env(os.getenv("COORDINATOR_USE_DOCKER", "true"), default=True)


def osv_mcp_enabled() -> bool:
    """Check if OSV MCP integration is enabled."""
    return _parse_bool_env(os.getenv("OSV_MCP_ENABLED", "false"))


def osv_mcp_dir() -> Optional[str]:
    """Get OSV MCP directory path for stdio mode (local only)."""
    mcp_dir = os.getenv("OSV_MCP_DIR", "").strip()
    return mcp_dir if mcp_dir else None


def build_osv_mcp_config(for_container: bool = False) -> Optional[dict]:
    """Build MCP config dict if MCP is enabled and configured.

    Supports three modes:
    1. HTTP mode (OSV_MCP_HTTP_ENABLED=true):
       Connects to HTTP MCP server (works in local AND Docker modes)

    2. Local stdio mode (COORDINATOR_USE_DOCKER=false):
       Uses OSV_MCP_DIR from host filesystem (legacy, local only)

    3. Docker stdio mode (COORDINATOR_USE_DOCKER=true):
       Uses OSV_MCP_CONTAINER_PATH (legacy, doesn't work)

    Args:
        for_container: If True, use host.docker.internal for HTTP URLs.
                      If False, use localhost (for host-side agents).

    Returns:
        MCP config dict if available, None otherwise
    """
    if not osv_mcp_enabled():
        return None

    # Priority 1: HTTP mode (recommended, works in both local and Docker modes)
    http_enabled = _parse_bool_env(os.getenv("OSV_MCP_HTTP_ENABLED", "false"))
    if http_enabled:
        http_url = os.getenv("OSV_MCP_HTTP_URL", "").strip()
        if not http_url:
            # Auto-construct URL from components if full URL not provided
            port = os.getenv("OSV_MCP_HTTP_PORT", "3000")
            path = os.getenv("OSV_MCP_HTTP_PATH", "/mcp")
            http_url = f"http://localhost:{port}{path}"

        # Container→Host communication: Replace localhost with host.docker.internal
        # This allows containers to reach MCP server running on the host machine
        if for_container and "localhost" in http_url:
            http_url = http_url.replace("localhost", "host.docker.internal")

        transport = os.getenv("OSV_MCP_HTTP_TRANSPORT", "streamable-http")

        return {
            "mcpServers": {
                "osv": {
                    "url": http_url,
                    "transport": transport
                }
            }
        }

    # stdio mode (DEPRECATED - NOT SUPPORTED)
    # ⚠️ WARNING: This code path is kept for backward compatibility but WILL FAIL
    # stdio mode requires pyproject.toml in src/mcp_servers/ that doesn't exist
    # The "osv-server" command referenced below is not installed
    # DO NOT USE - Always use HTTP mode (OSV_MCP_HTTP_ENABLED=true)
    use_docker = coordinator_use_docker()

    if use_docker:
        # Docker stdio mode - NOT SUPPORTED
        container_path = os.getenv("OSV_MCP_CONTAINER_PATH", "").strip()
        if not container_path:
            return None
        mcp_dir = container_path
    else:
        # Local stdio mode - NOT SUPPORTED
        mcp_dir = osv_mcp_dir()
        if not mcp_dir:
            return None
        if not os.path.exists(mcp_dir):
            return None

    # Return legacy stdio config (will fail - osv-server doesn't exist)
    return {
        "mcpServers": {
            "osv": {
                "command": "uv",
                "args": ["--directory", mcp_dir, "run", "osv-server"],
                "env": {}
            }
        }
    }
