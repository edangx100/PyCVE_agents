#!/usr/bin/env python3
"""Worker tasks for the Coordinator agent.

This module contains the specific task execution and data processing methods
used by the Coordinator class, separated for better readability and maintainability.
"""
from __future__ import annotations

import json
import os
import posixpath
import shlex
import threading
import time
from typing import Generator, Optional

from openhands.sdk import Agent, Conversation
from openhands.sdk.event import ObservationEvent
from openhands.sdk.conversation.response_utils import get_agent_final_response
from openhands.tools.terminal import TerminalTool

from . import artifacts, audit, reporting
from .models import (
    RequirementEntry,
    RequirementsParseResult,
    WorklistItem,
)
from .docker_runtime import osv_mcp_enabled
from src.agents.fixer import FixerTask


class CoordinatorWorkers:
    """Base class containing worker task methods for the Coordinator.

    This class provides specific task execution methods like running pip-audit,
    fixing packages, and processing events. It's designed to be inherited by
    the Coordinator class to maintain a clean separation of concerns.
    """

    @staticmethod
    def _timestamp() -> str:
        """Return a formatted timestamp for log messages."""
        return time.strftime("%H:%M:%S")

    def _prefetch_osv_enrichment(
        self,
        vuln_ids: list[str],
        package: str,
        workspace: object,
        coordinator_agent: Agent,
    ) -> Optional[str]:
        """Pre-fetch OSV enrichment data using coordinator agent's MCP tools.

        Hybrid Pre-Fetch:
        The coordinator queries OSV before delegating to the fixer, then passes enrichment data as text.
        Works around MCP config not being passed through DelegateTool to sub-agents.

        Args:
            vuln_ids: List of vulnerability IDs (CVE/GHSA) to query
            package: Package name for context
            workspace: Workspace object for conversation
            coordinator_agent: The coordinator agent (possibly in Docker) with OSV tools

        Returns:
            Formatted enrichment text to include in fixer prompt, or None if unavailable
        """
        # Only pre-fetch if OSV MCP is enabled
        if not osv_mcp_enabled():
            return None

        # Check if coordinator agent has MCP config (MCP tools are loaded dynamically by SDK)
        has_mcp_config = (
            hasattr(coordinator_agent, "mcp_config") and
            coordinator_agent.mcp_config and
            isinstance(coordinator_agent.mcp_config, dict) and
            "mcpServers" in coordinator_agent.mcp_config
        )

        if not has_mcp_config:
            print("[osv-prefetch] MCP config not found on coordinator agent, skipping pre-fetch")
            return None

        print(f"[osv-prefetch] MCP config detected: {list(coordinator_agent.mcp_config.get('mcpServers', {}).keys())}")

        if not vuln_ids:
            return None

        print(f"[osv-prefetch] Pre-fetching OSV data for {len(vuln_ids)} vulnerabilities")

        # Create a temporary conversation to query OSV
        try:
            print("[osv-prefetch] Creating temporary conversation for OSV query...")
            conversation = Conversation(agent=coordinator_agent, workspace=workspace)

            # Build query prompt asking coordinator to use OSV tools
            query_prompt = (
                f"Query the OSV database for package '{package}' vulnerabilities.\n"
                f"For each of these vulnerability IDs: {', '.join(vuln_ids)}\n\n"
                "Use the available OSV query tools to gather:\n"
                "1. Advisory summary/description\n"
                "2. Affected version ranges\n"
                "3. Fixed versions\n"
                "4. Severity if available\n\n"
                "Format the results as a structured list with one entry per CVE.\n"
                "Example format:\n"
                "CVE-2024-12345:\n"
                "  Summary: Brief description\n"
                "  Affected: version ranges\n"
                "  Fixed: fixed versions\n"
                "  Severity: HIGH/MEDIUM/LOW\n\n"
                "If a tool is not available or a query fails, note that in the output."
            )

            print(f"[osv-prefetch] Sending query for {len(vuln_ids)} vulnerabilities...")
            conversation.send_message(query_prompt)
            print("[osv-prefetch] Running conversation to execute OSV queries...")
            conversation.run()
            print(f"[osv-prefetch] Conversation completed. Event count: {len(conversation.events) if hasattr(conversation, 'events') else 0}")

            # Extract the agent's final response using OpenHands SDK utility
            enrichment_text = ""
            if hasattr(conversation, "events") and conversation.events:
                enrichment_text = get_agent_final_response(conversation.events)

            if enrichment_text and enrichment_text.strip():
                print(f"[osv-prefetch] Successfully fetched {len(enrichment_text)} chars of OSV data")
                print(f"[osv-prefetch] Preview: {enrichment_text[:200]}...")
                return enrichment_text
            else:
                print("[osv-prefetch] No enrichment data returned from OSV query")
                return None

        except Exception as e:
            print(f"[osv-prefetch] Error pre-fetching OSV data: {e}")
            return None

    @staticmethod
    def _drain_events(
        conversation: Conversation,
        events_seen: int,
    ) -> tuple[int, bool, list[str]]:
        """Collect new terminal output lines since the last drain call."""
        # Extract terminal output from any new events since last drain.
        lines: list[str] = []
        new_error = False

        events = list(getattr(conversation.state, "events", []))
        for event in events[events_seen:]:
            text, is_error = CoordinatorWorkers._extract_terminal_output(event)
            if is_error:
                new_error = True
            if not text:
                continue
            for line in CoordinatorWorkers._split_output(text):
                lines.append(line)

        return len(events), new_error, lines

    @staticmethod
    def _extract_terminal_output(event: object) -> tuple[Optional[str], bool]:
        """Return terminal text + error flag if the event is a TerminalTool observation."""
        # Pull terminal output from ObservationEvent if it came from TerminalTool.
        if not isinstance(event, ObservationEvent):
            return None, False
        if getattr(event, "tool_name", None) != TerminalTool.name:
            return None, False

        obs = getattr(event, "observation", None)
        if obs is None:
            return None, False

        is_error = bool(getattr(obs, "is_error", False))
        text = CoordinatorWorkers._observation_text(obs)
        return text, is_error

    @staticmethod
    def _observation_text(observation: object) -> Optional[str]:
        """Normalize observation payloads into a single text blob."""
        # Observation payloads vary; check common fields before falling back.
        parts = []
        if isinstance(observation, dict):
            for key in ("stdout", "stderr", "content", "output", "text"):
                value = observation.get(key)
                if value:
                    parts.append(value)
        else:
            for attr in ("stdout", "stderr", "content", "output", "text"):
                value = getattr(observation, attr, None)
                if value:
                    parts.append(value)

        if not parts:
            return str(observation)

        return "\n".join(str(part) for part in parts if part)

    @staticmethod
    def _split_output(text: str) -> list[str]:
        """Normalize newlines and drop empty output lines."""
        # Normalize CRLF and return non-empty output lines.
        cleaned = text.replace("\r", "\n")
        return [line.rstrip("\n") for line in cleaned.splitlines() if line.strip()]

    @staticmethod
    def _read_workspace_file(workspace: object, path: str) -> Optional[str]:
        # Read files inside the remote workspace via a simple cat command.
        result = workspace.execute_command(f"cat {shlex.quote(path)}")
        if result.exit_code != 0:
            return None
        return result.stdout

    @staticmethod
    def _download_workspace_file(
        workspace: object,
        source_path: str,
        destination_path: str,
    ) -> bool:
        # Pull a file from the container to the host artifacts directory.
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        try:
            result = workspace.file_download(source_path, destination_path)
        except Exception:
            return False
        return bool(getattr(result, "success", False))

    def build_worklist_from_audit(
        self,
        audit_path: str,
        parse_result: RequirementsParseResult,
    ) -> list[WorklistItem]:
        """Build a direct-dependency worklist from pip-audit JSON output."""
        try:
            with open(audit_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return []

        # Map normalized direct requirement names for fast lookups.
        direct_map = {
            audit.normalize_name(entry.name): entry for entry in parse_result.editable
        }
        worklist: list[WorklistItem] = []
        seen: set[str] = set()

        for item in audit.extract_audit_items(payload):
            name = item.get("name") or item.get("package") or item.get("dependency")
            if not name:
                continue
            normalized = audit.normalize_name(str(name))
            # Only keep vulnerabilities tied to direct requirements.
            if normalized not in direct_map:
                continue
            if normalized in seen:
                continue

            entry = direct_map[normalized]
            vulns = item.get("vulns")
            if vulns is None:
                vulns = item.get("vulnerabilities")
            # Skip clean dependencies so the worklist stays vulnerability-only.
            if not isinstance(vulns, list) or not vulns:
                continue
            vuln_ids: list[str] = []
            fix_versions: list[str] = []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                # Collect IDs and aliases for display, plus any fix versions.
                vuln_id = vuln.get("id") or vuln.get("cve") or vuln.get("name")
                if vuln_id:
                    vuln_ids.append(str(vuln_id))
                for alias in audit.string_list(vuln.get("aliases")):
                    vuln_ids.append(alias)
                fixes = vuln.get("fix_versions")
                if fixes is None:
                    fixes = vuln.get("fixed_versions")
                for fix in audit.string_list(fixes):
                    fix_versions.append(fix)

            # Prefer the audited version, else fall back to the requirement spec.
            current_version = str(item.get("version") or "").strip()
            if not current_version:
                current_version = entry.spec or "unknown"

            worklist.append(
                WorklistItem(
                    name=entry.name,
                    spec=entry.spec,
                    current_version=current_version,
                    vuln_ids=audit.unique_strings(vuln_ids),
                    fix_versions=audit.unique_strings(fix_versions),
                    is_editable=True,
                    skip_reason=None,
                )
            )
            seen.add(normalized)

        return worklist

    def worklist_table_rows(self) -> list[list[str]]:
        """Format the latest worklist into UI table rows."""
        rows: list[list[str]] = []
        for item in self.latest_worklist:
            # Show the first suggested fix version as a quick hint.
            vuln_ids = ", ".join(item.vuln_ids) if item.vuln_ids else "unknown"
            suggested_fix = f">={item.fix_versions[0]}" if item.fix_versions else "unknown"
            rows.append(
                [
                    item.name,
                    vuln_ids,
                    item.current_version,
                    suggested_fix,
                ]
            )
        return rows

    def run_pip_audit_stream(
        self,
        requirements_path: str,
        workspace_dir: str,
        artifacts_dir: str,
        workspace: object,
    ) -> Generator[str, None, None]:
        """Install pip-audit into a venv, run it, and stream progress lines."""
        yield "[scan] Starting baseline pip-audit"

        venv_dir = posixpath.join(workspace_dir, ".venv")
        if not audit.workspace_dir_exists(workspace, venv_dir):
            yield f"[scan] Creating venv at {venv_dir}"

        # Run pip-audit inside the container and capture JSON for artifacts.
        baseline = audit.run_baseline_audit(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
            workspace=workspace,
        )
        if baseline.error:
            yield f"[scan] FAILED: {baseline.error}"
            if baseline.error_stderr:
                yield f"[scan][stderr] {baseline.error_stderr}"
            return False

        if baseline.audit.returncode not in (None, 0):
            yield f"[scan] pip-audit exit code: {baseline.audit.returncode}"

        if not baseline.audit.ok or baseline.audit.audit_json is None:
            yield "[scan] FAILED: pip-audit produced no JSON output"
            for note in baseline.audit.stderr:
                if note:
                    yield f"[scan][stderr] {note}"
            return False

        for note in baseline.audit.stderr:
            if note:
                yield f"[scan][stderr] {note}"

        # Persist the baseline audit JSON on the host for downstream steps.
        audit_ok, artifact_path = artifacts.write_audit_json(
            artifacts_dir=artifacts_dir,
            filename="pip_audit_before.json",
            content=baseline.audit.audit_json,
        )
        if not audit_ok:
            yield "[scan] FAILED: unable to write pip-audit artifact"
            return False
        yield f"[scan] Saved artifact: {artifact_path}"

        vuln_count = baseline.audit.vuln_count
        if vuln_count is None:
            yield "[scan] Vulnerability count unavailable (JSON parse failed)"
        else:
            yield f"[scan] Vulnerabilities found: {vuln_count}"
        return True

    def run_final_audit_stream(
        self,
        requirements_path: str,
        workspace_dir: str,
        artifacts_dir: str,
        before_audit_path: str,
        workspace: object,
    ) -> Generator[str, None, tuple[bool, Optional[int], Optional[int]]]:
        """Run a final pip-audit and write after/alias artifacts."""
        yield "[final] Starting final pip-audit"

        final = audit.run_final_audit(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
            workspace=workspace,
        )
        if final.venv_missing:
            yield "[final] FAILED: venv not found; cannot run final pip-audit"
            return False, None, None

        if final.audit.returncode not in (None, 0):
            yield f"[final][stderr] pip-audit exit code: {final.audit.returncode}"
        for note in final.audit.stderr:
            if note:
                yield f"[final][stderr] {note}"
        if not final.audit.ok or final.audit.audit_json is None:
            yield "[final] FAILED: pip-audit produced no JSON output"
            return False, None, None

        # Write the final audit payload and alias for downstream consumers.
        audit_ok, after_path = artifacts.write_audit_json(
            artifacts_dir=artifacts_dir,
            filename="pip_audit_after.json",
            content=final.audit.audit_json,
        )
        if not audit_ok:
            yield "[final] FAILED: unable to write after audit JSON"
            return False, None, None
        yield f"[final] Saved artifact: {after_path}"

        alias_path = os.path.join(artifacts_dir, "pip_audit.json")
        if not artifacts.write_audit_alias(after_path, alias_path):
            yield "[final] FAILED: unable to write pip_audit.json alias"
            return False, None, None
        yield f"[final] Saved alias: {alias_path}"

        before_raw = reporting.read_text_file(before_audit_path)
        before_count = audit.count_vulnerabilities(before_raw) if before_raw else None
        after_count = audit.count_vulnerabilities(final.audit.audit_json)
        # Surface counts for the UI even if JSON parsing fails.
        if before_count is None or after_count is None:
            yield "[final] Vulnerability counts unavailable (JSON parse failed)"
        else:
            yield f"[final] Vulnerabilities before: {before_count} | after: {after_count}"
        return True, before_count, after_count

    def _run_fixer_once(
        self,
        item: WorklistItem,
        entry: Optional[RequirementEntry],
        requirements_path: str,
        artifacts_dir: str,
        workspace_dir: str,
        workspace: object,
        coordinator_agent: Agent,
        fixer_agent: Agent,
        use_delegate: bool,
        container_artifacts_dir: str,
    ) -> Generator[str, None, tuple[Optional[str], str]]:
        # Package up a single fix request with file paths and context.
        fix_version = item.fix_versions[0] if item.fix_versions else None
        patch_notes_name = f"PATCH_NOTES_{reporting.sanitize_filename(item.name)}.md"
        container_patch_notes_path = posixpath.join(container_artifacts_dir, patch_notes_name)
        patch_notes_path = os.path.join(artifacts_dir, patch_notes_name)
        backup_path = posixpath.join(
            posixpath.dirname(requirements_path),
            "requirements_before.txt",
        )
        task = FixerTask(
            package=item.name,
            current_spec=item.spec,
            vuln_ids=item.vuln_ids,
            fix_version=fix_version,
            requirements_path=requirements_path,
            requirements_before_path=backup_path,
            patch_notes_path=container_patch_notes_path,
            raw_line=entry.raw if entry else None,
            line_no=entry.line_no if entry else None,
        )
        fixer_prompt = task.prompt()

        # Hybrid Pre-Fetch: Pre-fetch OSV enrichment data using coordinator's MCP tools
        # before delegating to fixer. This works around DelegateTool not passing MCP config to sub-agents.
        osv_enrichment = None
        if use_delegate and osv_mcp_enabled():
            osv_enrichment = self._prefetch_osv_enrichment(
                vuln_ids=item.vuln_ids,
                package=item.name,
                workspace=workspace,
                coordinator_agent=coordinator_agent,
            )

        # Append pre-fetched enrichment to fixer prompt if available
        if osv_enrichment:
            fixer_prompt += (
                "\n\n"
                "=== PRE-FETCHED OSV ENRICHMENT DATA ===\n"
                "The coordinator has pre-fetched the following OSV enrichment data for you.\n"
                "Include this information in the 'OSV Enrichment' section of your patch notes:\n\n"
                f"{osv_enrichment}\n"
                "=== END OSV ENRICHMENT DATA ===\n"
            )

        # Create and send the fixer conversation
        if use_delegate:
            # Delegate the task to a Fixer sub-agent so only FileEditorTool is used.
            yield f"[{self._timestamp()}] [fixer] Delegating fix for {item.name} to fixer agent"
            conversation = Conversation(agent=coordinator_agent, workspace=workspace)
            coordinator_prompt = (
                "You are the Coordinator agent. Use DelegateTool to spawn a sub-agent "
                "with id 'fixer' using agent type 'fixer'. "
                "Delegate the following task to the fixer agent exactly.\n"
                "BEGIN FIXER PROMPT\n"
                f"{fixer_prompt}\n"
                "END FIXER PROMPT"
            )
            conversation.send_message(coordinator_prompt)
        else:
            yield f"[{self._timestamp()}] [fixer] Running fixer agent for {item.name}"
            conversation = Conversation(agent=fixer_agent, workspace=workspace)
            conversation.send_message(fixer_prompt)

        # Stream agent output in real-time
        run_errors = []

        def _run() -> None:
            try:
                conversation.run()
            except Exception as exc:
                run_errors.append(exc)

        runner = threading.Thread(target=_run, daemon=True)
        runner.start()

        # Drain events while the agent runs
        events_seen = 0
        while runner.is_alive():
            events_seen, new_error, lines = self._drain_events(conversation, events_seen)
            for line in lines:
                prefix = f"[{self._timestamp()}] [fixer][error]" if new_error else f"[{self._timestamp()}] [fixer]"
                yield f"{prefix} {line}"
            time.sleep(0.2)

        runner.join()

        # Final drain after the agent finishes
        events_seen, new_error, lines = self._drain_events(conversation, events_seen)
        for line in lines:
            prefix = f"[{self._timestamp()}] [fixer][error]" if new_error else f"[{self._timestamp()}] [fixer]"
            yield f"{prefix} {line}"

        if run_errors:
            yield f"[{self._timestamp()}] [fixer] FAILED: {run_errors[0]}"

        # Download and process patch notes
        yield f"[{self._timestamp()}] [fixer] Downloading patch notes"
        patch_notes = ""
        if self._download_workspace_file(
            workspace,
            container_patch_notes_path,
            patch_notes_path,
        ):
            patch_notes = reporting.read_text_file(patch_notes_path)
            yield f"[{self._timestamp()}] [fixer] Patch notes downloaded successfully"
        else:
            yield f"[{self._timestamp()}] [fixer] Patch notes not found, creating fallback"

        if not patch_notes.strip():
            # Create fallback patch notes so verification can append results.
            local_backup_path = os.path.join(artifacts_dir, "requirements_before.txt")
            local_requirements_path = os.path.join(artifacts_dir, "requirements_after.txt")
            self._download_workspace_file(workspace, backup_path, local_backup_path)
            self._download_workspace_file(
                workspace,
                requirements_path,
                local_requirements_path,
            )
            reporting.write_fallback_patch_notes(
                item,
                local_requirements_path,
                local_backup_path,
                patch_notes_path,
            )
            patch_notes = reporting.read_text_file(patch_notes_path)
            yield f"[{self._timestamp()}] [fixer] Fallback patch notes created"

        yield (patch_notes or None), patch_notes_path
