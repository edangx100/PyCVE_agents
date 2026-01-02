from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import sys
from typing import Optional

from . import audit
from .models import RunContext, RunResult, WorklistItem
from .requirements_parser import find_requirement_line

# ============================================================================
# File System Utilities
# ============================================================================


def sanitize_filename(value: str) -> str:
    """Make a safe filename segment from a package name."""
    # Replace unsafe characters and fall back to a stable placeholder.
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned or "package"


def write_text_file(path: str, content: str) -> bool:
    """Write text to disk, returning False on failure."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return True
    except OSError:
        return False


def read_text_file(path: str) -> str:
    """Read a text file, returning empty string on failure."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def read_json_file(path: str) -> Optional[object]:
    """Read JSON from disk, returning None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def files_differ(
    path_a: str,
    path_b: str,
    workspace: Optional[object] = None,
) -> Optional[bool]:
    """Return True if file contents differ, False if same, None if unreadable."""
    if workspace is None:
        # Local mode: read and compare file contents directly
        try:
            with open(path_a, "r", encoding="utf-8") as handle:
                content_a = handle.read()
            with open(path_b, "r", encoding="utf-8") as handle:
                content_b = handle.read()
        except OSError:
            return None
        return content_a != content_b

    # Docker mode: use cmp command for binary comparison
    result = audit.run_command(["cmp", "-s", path_a, path_b], workspace=workspace)
    if result.returncode == 0:
        return False  # Files are identical
    if result.returncode == 1:
        return True  # Files differ
    return None  # Error occurred


# ============================================================================
# Requirements File Management
# ============================================================================


def revert_requirements(
    backup_path: str,
    requirements_path: str,
    workspace: Optional[object] = None,
) -> bool:
    """Restore requirements.txt from the backup file."""
    if workspace is None:
        # Local mode: use shutil to copy backup
        if not os.path.isfile(backup_path):
            return False
        try:
            shutil.copyfile(backup_path, requirements_path)
        except OSError:
            return False
        return True

    # Docker mode: use cp command
    result = audit.run_command(["cp", backup_path, requirements_path], workspace=workspace)
    return result.returncode == 0


# ============================================================================
# Patch Notes Generation
# ============================================================================


def append_verification_notes(
    patch_notes_path: str,
    status: str,
    before_count: Optional[int],
    after_count: Optional[int],
    reverted: bool,
    notes: list[str],
) -> None:
    """Append verification results to the patch notes file."""
    before_display = "unknown" if before_count is None else str(before_count)
    after_display = "unknown" if after_count is None else str(after_count)
    extra_notes = "; ".join(note for note in notes if note)
    # Keep the verification block structured so it can be parsed later.
    lines = [
        "",
        "Verification",
        f"- status: {status}",
        f"- before: {before_display}",
        f"- after: {after_display}",
        f"- reverted: {'yes' if reverted else 'no'}",
    ]
    if extra_notes:
        lines.append(f"- notes: {extra_notes}")
    try:
        with open(patch_notes_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")
    except OSError:
        return


def write_fallback_patch_notes(
    item: WorklistItem,
    requirements_path: str,
    backup_path: str,
    patch_notes_path: str,
) -> None:
    """Write minimal patch notes if the Fixer agent failed to create them."""
    # Capture before/after requirement lines for basic auditing context.
    before_line = find_requirement_line(backup_path, item.name)
    after_line = find_requirement_line(requirements_path, item.name)
    vuln_block = ", ".join(item.vuln_ids) if item.vuln_ids else "(none)"
    notes = [
        f"# Package: {item.name}",
        "",
        "## Vulnerabilities",
        vuln_block,
        "",
        "## Before",
        before_line or "(unknown)",
        "",
        "## After",
        after_line or "(unknown)",
        "",
        "## Notes",
        "Coordinator generated patch notes because the Fixer agent did not write them.",
    ]
    if os.path.isfile(backup_path):
        notes.append(f"Backup created at {backup_path}")
    write_text_file(patch_notes_path, "\n".join(notes) + "\n")


# ============================================================================
# Patch Verification
# ============================================================================


def spot_check_fix(
    package_name: str,
    requirements_path: str,
    backup_path: str,
    artifacts_dir: str,
    workspace_dir: str,
    patch_notes_path: str,
    before_audit_path: str,
    workspace: Optional[object] = None,
) -> tuple[str, Optional[int], Optional[int], bool]:
    """Re-run pip-audit and compare vulnerabilities for a single package."""
    status = "verified: failed"
    before_count: Optional[int] = None
    after_count: Optional[int] = None
    reverted = False
    notes: list[str] = []

    # Step 1: Check if requirements.txt was actually modified
    changed = files_differ(backup_path, requirements_path, workspace=workspace)
    if changed is False:
        # No change means there's nothing to verify.
        notes.append("no edit applied; spot-check skipped")
        append_verification_notes(
            patch_notes_path,
            status,
            before_count,
            after_count,
            reverted,
            notes,
        )
        return status, before_count, after_count, reverted

    # Step 2: Load baseline vulnerability count from before-patch audit
    before_payload = read_json_file(before_audit_path)
    if before_payload is None:
        notes.append("baseline audit missing or unreadable")
    else:
        # Baseline count gives us the "before" vulnerability total for the package.
        before_count = audit.count_package_vulns(before_payload, package_name)

    # Step 3: Re-run pip-audit with the patched requirements
    venv_dir = (
        posixpath.join(workspace_dir, ".venv")
        if workspace is not None
        else os.path.join(workspace_dir, ".venv")
    )
    # Re-run pip-audit against the updated requirements.txt in the same venv.
    audit_result = audit.run_pip_audit_json(
        venv_dir,
        requirements_path,
        workspace=workspace,
    )
    audit_notes: list[str] = []
    if audit_result.returncode not in (None, 0):
        audit_notes.append(f"pip-audit exit code: {audit_result.returncode}")
    if audit_result.stderr:
        audit_notes.extend(audit_result.stderr)
    if audit_notes:
        notes.append("; ".join(audit_notes))
    if not audit_result.ok or audit_result.audit_json is None:
        notes.append("pip-audit spot-check failed")
        append_verification_notes(
            patch_notes_path,
            status,
            before_count,
            after_count,
            reverted,
            notes,
        )
        return status, before_count, after_count, reverted

    # Step 4: Save spot-check audit results to artifacts
    spotcheck_name = f"pip_audit_spotcheck_{sanitize_filename(package_name)}.json"
    spotcheck_path = os.path.join(artifacts_dir, spotcheck_name)
    if not write_text_file(spotcheck_path, audit_result.audit_json):
        notes.append("unable to save spot-check audit artifact")

    # Step 5: Parse the after-patch vulnerability count
    try:
        after_payload = json.loads(audit_result.audit_json)
    except json.JSONDecodeError:
        after_payload = None
        notes.append("spot-check JSON parse failed")

    if after_payload is not None:
        after_count = audit.count_package_vulns(after_payload, package_name)

    # Step 6: Compare before/after counts and decide on action
    if before_count is None or after_count is None:
        notes.append("unable to compare vulnerability counts")
    else:
        # Decide outcome based on whether vuln count went down, up, or stayed flat.
        if after_count < before_count:
            # Success: vulnerability was removed
            status = "verified: vuln removed"
        elif after_count > before_count:
            # Failure: vulnerability count increased, revert the change
            notes.append("vulnerability count increased")
            reverted = revert_requirements(
                backup_path,
                requirements_path,
                workspace=workspace,
            )
            if reverted:
                notes.append("requirements.txt reverted to backup")
            else:
                notes.append("failed to revert requirements.txt")
        else:
            # Neutral: no change in vulnerability count
            notes.append("vulnerability count unchanged")

    append_verification_notes(
        patch_notes_path,
        status,
        before_count,
        after_count,
        reverted,
        notes,
    )
    return status, before_count, after_count, reverted


# ============================================================================
# Summary Report Building
# ============================================================================


def parse_patch_status(notes: str) -> Optional[str]:
    """Extract the verification status line from patch notes."""
    # Scan the verification section for the status line.
    for line in notes.splitlines():
        cleaned = line.strip()
        if cleaned.lower().startswith("- status:"):
            return cleaned.split(":", 1)[1].strip()
    return None


def order_vuln_ids(vuln_ids: list[str]) -> list[str]:
    """Sort vulnerability IDs with CVEs first while de-duplicating."""
    seen: set[str] = set()
    cves: list[str] = []
    others: list[str] = []
    for vuln_id in vuln_ids:
        if not vuln_id:
            continue
        cleaned = str(vuln_id).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        # Separate CVE IDs from other vulnerability IDs (e.g., GHSA, PYSEC)
        if cleaned.upper().startswith("CVE-"):
            cves.append(cleaned)
        else:
            others.append(cleaned)
    # Preserve input order within each bucket.
    return cves + others


def build_summary_rows(
    worklist: list[WorklistItem],
    artifacts_dir: str,
) -> tuple[list[tuple[str, str, str, str]], int, int]:
    """Build result rows + fixed/skipped counts for SUMMARY.md."""
    rows: list[tuple[str, str, str, str]] = []
    fixed_count = 0
    for item in worklist:
        # Check if patch notes exist for this package
        patch_path = os.path.join(
            artifacts_dir,
            f"PATCH_NOTES_{sanitize_filename(item.name)}.md",
        )
        patch_link = "none"
        status = None
        if os.path.isfile(patch_path):
            patch_link = f"[{os.path.basename(patch_path)}]({os.path.basename(patch_path)})"
            status = parse_patch_status(read_text_file(patch_path))
        # Treat only verified removals as "fixed" for summary counts.
        action = "fixed" if status == "verified: vuln removed" else "skipped"
        if action == "fixed":
            fixed_count += 1
        vuln_ids = ", ".join(order_vuln_ids(item.vuln_ids)) or "unknown"
        rows.append((item.name, vuln_ids, action, patch_link))
    skipped_count = max(0, len(worklist) - fixed_count)
    return rows, fixed_count, skipped_count


# ============================================================================
# Metadata Collection
# ============================================================================


def collect_tool_versions(
    venv_dir: Optional[str],
    workspace: Optional[object] = None,
) -> dict[str, str]:
    """Collect tool version strings for the summary metadata."""
    versions: dict[str, str] = {}
    venv_exists = False
    if venv_dir:
        if workspace is None:
            venv_exists = os.path.isdir(venv_dir)
        else:
            venv_exists = audit.workspace_dir_exists(workspace, venv_dir)

    if venv_dir and venv_exists:
        # Use venv's Python to match the actual audit environment
        venv_python = audit.venv_python(venv_dir, force_posix=workspace is not None)
        versions["python"] = (
            run_version_cmd([venv_python, "-V"], workspace=workspace) or "unknown"
        )
        versions["pip"] = (
            run_version_cmd(
                [venv_python, "-m", "pip", "--version"],
                workspace=workspace,
            )
            or "unknown"
        )
        versions["pip_audit"] = (
            run_version_cmd(
                [venv_python, "-m", "pip_audit", "--version"],
                workspace=workspace,
            )
            or "unknown"
        )
    else:
        # No venv: use system Python or Docker container's Python
        if workspace is None:
            # Local mode: use current Python interpreter
            versions["python"] = f"Python {sys.version.split()[0]}"
            versions["pip"] = (
                run_version_cmd([sys.executable, "-m", "pip", "--version"]) or "unknown"
            )
            versions["pip_audit"] = (
                run_version_cmd([sys.executable, "-m", "pip_audit", "--version"]) or "unknown"
            )
        else:
            # Docker mode: use container's Python binary
            python_bin = os.getenv("DOCKER_PYTHON_BIN", "python")
            versions["python"] = (
                run_version_cmd([python_bin, "-V"], workspace=workspace) or "unknown"
            )
            versions["pip"] = (
                run_version_cmd(
                    [python_bin, "-m", "pip", "--version"],
                    workspace=workspace,
                )
                or "unknown"
            )
            versions["pip_audit"] = (
                run_version_cmd(
                    [python_bin, "-m", "pip_audit", "--version"],
                    workspace=workspace,
                )
                or "unknown"
            )

    # Check for uv package manager availability
    if workspace is None:
        if shutil.which("uv"):
            # Report uv only when present on PATH.
            versions["uv"] = run_version_cmd(["uv", "--version"]) or "unknown"
    else:
        uv_version = run_version_cmd(["uv", "--version"], workspace=workspace)
        if uv_version:
            versions["uv"] = uv_version
    return versions


def run_version_cmd(
    args: list[str],
    cwd: Optional[str] = None,
    workspace: Optional[object] = None,
) -> Optional[str]:
    """Run a command and return the first non-empty output line."""
    try:
        result = audit.run_command(args, cwd=cwd, workspace=workspace)
    except FileNotFoundError:
        return None
    # Prefer stdout, fall back to stderr for commands that print versions there.
    output = result.stdout.strip() or result.stderr.strip()
    if not output:
        return None
    return output.splitlines()[0].strip()


def git_commit_hash(
    repo_dir: str,
    workspace: Optional[object] = None,
) -> Optional[str]:
    """Return the git commit hash for the cloned repo."""
    try:
        result = audit.run_command(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            workspace=workspace,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    # Best-effort: empty stdout is treated as unknown.
    return result.stdout.strip() or None


# ============================================================================
# MCP Status Collection
# ============================================================================


def collect_mcp_status(agent: Optional[object] = None) -> dict:
    """Collect detailed MCP status for SUMMARY.md.

    Args:
        agent: Optional agent object to check for available tools

    Returns:
        Dictionary with MCP status information
    """
    from .docker_runtime import build_osv_mcp_config, osv_mcp_enabled, coordinator_use_docker

    # Default status: MCP not configured
    status = {
        "enabled": False,
        "transport_mode": "none",
        "endpoint": "none",
        "server_url": None,
        "directory_path": None,
        "tools_expected": 4,
        "tools_available": 0,
        "tool_names": [],
        "status": "UNAVAILABLE",
        "error": "not configured",
    }

    # Check if MCP is enabled
    if not osv_mcp_enabled():
        return status

    status["enabled"] = True
    status["error"] = "none"

    # Get MCP configuration
    mcp_config = build_osv_mcp_config()
    if not mcp_config:
        status["status"] = "ERROR"
        status["error"] = "configuration build failed"
        return status

    # Extract transport mode and endpoint details
    osv_config = mcp_config.get("mcpServers", {}).get("osv", {})

    if "url" in osv_config:
        # HTTP transport mode: MCP server accessible via HTTP
        status["transport_mode"] = "HTTP"
        status["server_url"] = osv_config.get("url", "unknown")
        status["endpoint"] = status["server_url"]
        transport_type = osv_config.get("transport", "streamable-http")
        status["transport_type"] = transport_type
    elif "command" in osv_config:
        # stdio transport mode: MCP server runs as subprocess
        use_docker = coordinator_use_docker()
        if use_docker:
            # stdio doesn't work well in Docker (no subprocess communication)
            status["transport_mode"] = "stdio (Docker)"
            container_path = os.getenv("OSV_MCP_CONTAINER_PATH", "unknown")
            status["directory_path"] = container_path
            status["endpoint"] = container_path
            status["error"] = "stdio mode doesn't work in Docker"
        else:
            # stdio works in local mode
            status["transport_mode"] = "stdio (local)"
            host_path = os.getenv("OSV_MCP_DIR", "unknown")
            status["directory_path"] = host_path
            status["endpoint"] = host_path

    # Verify OSV tools are available in the agent
    if agent and hasattr(agent, "tools"):
        osv_tools = []
        for tool in agent.tools:
            tool_name = None
            # Extract tool name from different tool object formats
            if hasattr(tool, "name"):
                tool_name = tool.name
            elif isinstance(tool, dict) and "name" in tool:
                tool_name = tool["name"]

            # Collect tools that start with "osv"
            if tool_name and tool_name.lower().startswith("osv"):
                osv_tools.append(tool_name)

        status["tools_available"] = len(osv_tools)
        status["tool_names"] = sorted(osv_tools)

        # Determine overall status based on tool count
        if status["tools_available"] >= status["tools_expected"]:
            status["status"] = "OK"
        elif status["tools_available"] > 0:
            status["status"] = "PARTIAL"
            status["error"] = f"expected {status['tools_expected']} tools, found {status['tools_available']}"
        else:
            status["status"] = "ERROR"
            status["error"] = "no OSV tools discovered"
    else:
        # Can't verify tools without agent object
        status["status"] = "CONFIGURED"
        status["error"] = "tool availability unknown (no agent provided)"

    return status


# ============================================================================
# Summary Report Assembly
# ============================================================================


def build_summary_text(
    context: RunContext,
    result: RunResult,
    workspace: Optional[object] = None,
) -> str:
    """Build the Markdown summary body for the run."""
    # Gather all metadata for the summary
    commit_hash = git_commit_hash(context.repo_dir, workspace=workspace) or "unknown"
    versions = collect_tool_versions(result.venv_dir, workspace=workspace)
    rows, fixed_count, skipped_count = build_summary_rows(
        worklist=result.worklist,
        artifacts_dir=context.artifacts_dir,
    )
    before_display = "unknown" if result.before_count is None else str(result.before_count)
    after_display = "unknown" if result.after_count is None else str(result.after_count)

    # Collect detailed MCP status for the summary
    mcp_info = collect_mcp_status(agent=None)

    # Build Markdown report with metadata, status, and results table
    lines = [
        "# PyCVE Summary",
        "",
        "## Run Metadata",
        f"- run_id: {context.run_id}",
        f"- timestamp: {context.run_started_at}",
        f"- repo_url: {context.repo_url}",
        f"- commit: {commit_hash}",
        f"- python: {versions.get('python', 'unknown')}",
        f"- pip: {versions.get('pip', 'unknown')}",
        f"- pip-audit: {versions.get('pip_audit', 'unknown')}",
    ]
    if "uv" in versions:
        lines.append(f"- uv: {versions.get('uv', 'unknown')}")

    # Add run status section
    lines.extend(
        [
            "",
            "## Status",
            f"- status: {result.status}",
        ]
    )
    # Include skip/failure metadata so stub summaries explain why the run stopped.
    if result.reason_code:
        lines.append(f"- reason_code: {result.reason_code}")
    if result.reason_detail:
        lines.append(f"- reason_detail: {result.reason_detail}")

    # Add vulnerability counts and fix statistics
    lines.extend(
        [
            f"- vulnerabilities_before: {before_display}",
            f"- vulnerabilities_after: {after_display}",
            f"- packages_fixed: {fixed_count}",
            f"- packages_skipped: {skipped_count}",
            "",
            "## MCP",
            f"- enabled: {'true' if mcp_info['enabled'] else 'false'}",
            f"- transport_mode: {mcp_info['transport_mode']}",
            f"- endpoint: {mcp_info['endpoint']}",
            f"- tools_expected: {mcp_info['tools_expected']}",
            f"- tools_available: {mcp_info['tools_available']}",
            f"- status: {mcp_info['status']}",
            f"- error: {mcp_info['error']}",
            "",
            "## Results",
            "| package | vuln_ids | action | patch_notes |",
            "| --- | --- | --- | --- |",
        ]
    )

    # Format results table rows
    if rows:
        for package, vuln_ids, action, patch_link in rows:
            lines.append(f"| {package} | {vuln_ids} | {action} | {patch_link} |")
    else:
        lines.append("| (none) | (none) | (none) | (none) |")
    return "\n".join(lines) + "\n"
