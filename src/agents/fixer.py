from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from openhands.sdk import Agent, Tool
from openhands.tools.delegate.registration import register_agent
from openhands.tools.file_editor import FileEditorTool

from src.agents.coordinator.docker_runtime import osv_mcp_enabled, build_osv_mcp_config, coordinator_use_docker


# Prevent duplicate registrations when Coordinator is constructed repeatedly.
_REGISTERED = False


def _display_list(items: list[str]) -> str:
    if not items:
        return "(none)"
    return ", ".join(items)


@dataclass
class FixerTask:
    package: str
    current_spec: str
    vuln_ids: list[str]
    fix_version: Optional[str]
    requirements_path: str
    requirements_before_path: str
    patch_notes_path: str
    raw_line: Optional[str] = None
    line_no: Optional[int] = None

    def prompt(self) -> str:
        # Build a deterministic instruction block for the Fixer agent.
        spec_display = self.current_spec or "(unpinned)"
        fix_display = self.fix_version or "(unknown)"
        fix_target = self.fix_version or "FIX_VERSION"
        line_display = self.raw_line or "(unknown line)"
        line_hint = f" (line {self.line_no})" if self.line_no else ""
        return (
            "You are the Fixer agent. Use FileEditorTool to edit files and write patch notes.\n"
            "Context:\n"
            f"- package: {self.package}\n"
            f"- current spec: {spec_display}\n"
            f"- requirement line: {line_display}{line_hint}\n"
            f"- vulnerabilities: {_display_list(self.vuln_ids)}\n"
            f"- suggested fix version: {fix_display}\n"
            "Paths:\n"
            f"- requirements: {self.requirements_path}\n"
            f"- backup: {self.requirements_before_path}\n"
            f"- patch notes: {self.patch_notes_path}\n"
            "Steps:\n"
            "1) Read the requirements file.\n"
            "2) Before editing, write an exact copy to the backup path.\n"
            "3) If the fix version is unknown, do not edit requirements; write patch notes "
            "stating the package was skipped because no fix version was provided.\n"
            "4) Otherwise, update ONLY the requirement line for the package so the version "
            f"spec is >= {fix_target}. If it was unpinned, set it to "
            f"{self.package}>={fix_target}. Keep all other lines unchanged.\n"
            "5) Write patch notes with these sections:\n"
            "   - Package: package name\n"
            "   - Vulnerabilities: list of CVE/GHSA IDs\n"
            "   - Before: original requirement line\n"
            "   - After: updated requirement line\n"
            "   - Notes: backup creation and any other notes\n"
            "   - OSV Enrichment: IMPORTANT - Check if pre-fetched OSV enrichment data is provided below "
            "(look for '=== PRE-FETCHED OSV ENRICHMENT DATA ===' section).\n"
            "     * If pre-fetched data is provided: Use that data directly in your patch notes.\n"
            "     * If pre-fetched data is NOT provided AND you have access to OSV tools "
            "(query_for_cve_affected, query_for_cve_fix_versions, query_package_cve), "
            "query each vulnerability ID for advisory summary, affected ranges, and fixed versions.\n"
            "     * If neither pre-fetched data nor OSV tools are available, "
            "write: 'OSV Enrichment: unavailable (MCP not configured)'\n"
            "Include the exact before/after requirement line and note the backup creation.\n"
        )


def create_fixer_agent(agent_llm, mcp_config=None, filter_tools_regex=None) -> Agent:
    """Create a Fixer agent with FileEditorTool and optional MCP tools.

    Args:
        agent_llm: LLM configuration for the agent
        mcp_config: Optional MCP configuration dict (for OSV enrichment)
        filter_tools_regex: Optional regex filter for MCP tools

    Returns:
        Agent configured with FileEditorTool and optional MCP tools
    """
    # Fixer needs FileEditorTool for editing requirements.txt and writing patch notes
    tools = [
        Tool(name=FileEditorTool.name),
    ]

    # Auto-build MCP config if not provided but OSV MCP is enabled
    # This ensures DelegateTool-spawned agents also get MCP access
    if mcp_config is None and osv_mcp_enabled():
        # In Docker mode, fixer agents run inside containers and need host.docker.internal
        # In local mode, fixer agents run on host and need localhost
        use_docker = coordinator_use_docker()
        mcp_config = build_osv_mcp_config(for_container=use_docker)
        # Filter to allow FileEditorTool AND OSV MCP tools
        # OSV tool names: get_ecosystems, query_package_cve, query_for_cve_affected, query_for_cve_fix_versions
        filter_tools_regex = r"^(file_editor|get_ecosystems|query_.*cve.*|query_for_cve.*)" if mcp_config else None

    # Try to create agent with MCP config if available
    if mcp_config:
        try:
            return Agent(
                llm=agent_llm,
                tools=tools,
                mcp_config=mcp_config,
                filter_tools_regex=filter_tools_regex,
            )
        except TypeError:
            # Fallback for older SDK versions that don't support mcp_config
            pass

    # Fallback: agent without MCP
    return Agent(
        llm=agent_llm,
        tools=tools,
    )


def register_fixer_agent() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    # Register once so DelegateTool can spawn this agent by name.
    register_agent(
        name="fixer",
        factory_func=create_fixer_agent,
        description="Fixer agent that edits requirements.txt and writes patch notes.",
    )
    _REGISTERED = True
