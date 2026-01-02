#!/usr/bin/env python3
from __future__ import annotations

import os
import posixpath
import shlex
import threading
import time
import uuid
from typing import Generator, Optional

from dotenv import load_dotenv
from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.sdk.workspace import LocalWorkspace
from openhands.tools.delegate import DelegateTool
from openhands.tools.terminal import TerminalTool

from . import artifacts, audit, reporting, requirements_parser
from .models import (
    RequirementEntry,
    RequirementsParseResult,
    RunContext,
    RunResult,
    WorklistItem,
)
from .coordinator_workers import CoordinatorWorkers
from .docker_runtime import (
    build_osv_mcp_config,
    coordinator_use_docker,
    create_docker_workspace,
    docker_delegate_enabled,
    docker_paths,
    osv_mcp_enabled,
)
from src.agents.fixer import create_fixer_agent, register_fixer_agent


class Coordinator(CoordinatorWorkers):
    """Orchestrate cloning + dependency scanning through an OpenHands agent."""

    # Stage definitions for progress tracking (Task 23)
    STAGE_PREFLIGHT = ("Preflight", 5)
    STAGE_CLONE = ("Clone", 15)
    STAGE_PARSE = ("Parse", 25)
    STAGE_SCAN = ("Scan", 40)
    STAGE_FIX = ("Fix", 60)
    STAGE_VERIFY = ("Verify", 80)
    STAGE_WRITE = ("Write", 95)
    STAGE_DONE = ("Done", 100)

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None) -> None:
        # Load OpenRouter credentials and model config for the Coordinator agent.
        load_dotenv()
        api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not found in .env")

        model = model or os.getenv("COORDINATOR_AND_FIXER__MODEL", "openrouter/minimax/minimax-m2.1")
        openrouter_model = f"openrouter/{model}"
        # Disable native tool calling for minimax models due to duplicate JSON bug
        native_tool_calling = True
        if "minimax" in model.lower():
            native_tool_calling = False
        self.llm = LLM(model=openrouter_model, api_key=api_key, native_tool_calling=native_tool_calling)
        self.agent = self._build_agent(include_delegate=True)
        self._preflight_check_tools(self.agent, expect_delegate=True)
        self.latest_worklist: list[WorklistItem] = []
        self.latest_patch_notes: str = ""
        self.patch_notes_paths: list[str] = []
        self.latest_cve_summary: str = "CVE summary: pending"
        self.latest_summary: str = ""
        self.latest_summary_path: str = ""
        self.latest_artifacts_dir: str = ""
        register_fixer_agent()
        # Local fixer agent for Docker runs when DelegateTool is unavailable.
        # Give fixer agent access to MCP for OSV enrichment
        mcp_config = build_osv_mcp_config() if osv_mcp_enabled() else None
        # Filter to allow FileEditorTool AND OSV MCP tools
        # OSV tool names: get_ecosystems, query_package_cve, query_for_cve_affected, query_for_cve_fix_versions
        filter_tools_regex = r"^(file_editor|get_ecosystems|query_.*cve.*|query_for_cve.*)" if mcp_config else None
        self.fixer_agent = create_fixer_agent(self.llm, mcp_config=mcp_config, filter_tools_regex=filter_tools_regex)

    def _build_agent(self, include_delegate: bool, for_container: bool = False) -> Agent:
        tools = [
            # TerminalTool for git/pip-audit runs; 
            # DelegateTool to spawn the Fixer.
            Tool(
                name=TerminalTool.name,
                params={"terminal_type": "subprocess"},
            ),
        ]
        if include_delegate:
            tools.append(Tool(name=DelegateTool.name))

        # Build MCP configuration if enabled
        mcp_config = None
        tool_filter = None

        if osv_mcp_enabled():
            mcp_config = build_osv_mcp_config(for_container=for_container)
            if mcp_config:
                # Filter to allow built-in tools AND OSV MCP tools (block other MCP tools)
                # Built-in tools: terminal, delegate
                # OSV tool names: get_ecosystems, query_package_cve, query_for_cve_affected, query_for_cve_fix_versions
                filter_regex = r"^(terminal|delegate|get_ecosystems|query_.*cve.*|query_for_cve.*)"
                tool_filter = filter_regex

                # Log MCP mode and configuration
                http_enabled = os.getenv("OSV_MCP_HTTP_ENABLED", "false").lower() in ("1", "true", "yes")

                if http_enabled:
                    http_url = mcp_config["mcpServers"]["osv"].get("url", "unknown")
                    transport = mcp_config["mcpServers"]["osv"].get("transport", "unknown")
                    print(f"[mcp] MCP enabled (HTTP mode): {http_url}")
                    print(f"[mcp] Transport: {transport}")
                else:
                    use_docker = coordinator_use_docker()
                    if use_docker:
                        container_path = os.getenv("OSV_MCP_CONTAINER_PATH", "").strip()
                        print(f"[mcp] MCP enabled (Docker stdio mode): {container_path}")
                        print("[mcp] WARNING: stdio mode doesn't work in Docker, use HTTP mode")
                    else:
                        host_path = os.getenv("OSV_MCP_DIR", "")
                        print(f"[mcp] MCP enabled (local stdio mode): {host_path}")

                print(f"[mcp] Tool filter: {filter_regex}")
            else:
                print("[mcp] WARNING: OSV_MCP_ENABLED=true but configuration incomplete")
                print("[mcp] Continuing without MCP enrichment")

        # Build agent with MCP config if available
        try:
            # Only pass mcp_config and filter_tools_regex if MCP is enabled
            if mcp_config:
                return Agent(
                    llm=self.llm,
                    tools=tools,
                    mcp_config=mcp_config,
                    filter_tools_regex=tool_filter,
                )
            else:
                return Agent(
                    llm=self.llm,
                    tools=tools,
                )
        except TypeError:
            # Fallback for older SDK versions that don't support mcp_config/filter_tools_regex
            print("[mcp] WARNING: SDK doesn't support mcp_config/filter_tools_regex parameters")
            print("[mcp] Continuing without MCP support")
            return Agent(
                llm=self.llm,
                tools=tools,
            )

    def _preflight_check_tools(self, agent: Agent, expect_delegate: bool) -> None:
        """Verify that required built-in tools are available.

        Args:
            agent: The agent to check
            expect_delegate: Whether DelegateTool should be present

        Raises:
            RuntimeError: If required built-in tools are missing
        """
        # Get available tools from agent
        available_tools = set()
        if hasattr(agent, "tools") and agent.tools:
            for tool in agent.tools:
                if hasattr(tool, "name"):
                    available_tools.add(tool.name)
                elif isinstance(tool, dict) and "name" in tool:
                    available_tools.add(tool["name"])

        # Check for required built-in tools
        required_tools = [TerminalTool.name]
        if expect_delegate:
            required_tools.append(DelegateTool.name)

        missing_tools = [tool for tool in required_tools if tool not in available_tools]

        if missing_tools:
            error_msg = (
                f"[mcp] FATAL: Required built-in tools are missing: {', '.join(missing_tools)}\n"
                f"[mcp] Available tools: {', '.join(sorted(available_tools)) if available_tools else 'none'}\n"
                f"[mcp] This indicates that tool filtering is incorrectly configured.\n"
                f"[mcp] Built-in tools must ALWAYS be available, only MCP tools should be filtered."
            )
            print(error_msg)
            raise RuntimeError(f"Required built-in tools missing: {', '.join(missing_tools)}")

        # Report available tools
        print(f"[mcp] Built-in tools verified: {', '.join(required_tools)}")

        # Check for OSV tools (optional, continues without OSV enrichmentif missing)
        if osv_mcp_enabled():
            osv_tools = [tool for tool in available_tools if tool.lower().startswith("osv")]
            if osv_tools:
                print(f"[mcp] OSV tools available: {', '.join(sorted(osv_tools))}")
            else:
                print("[mcp] WARNING: OSV MCP enabled but no OSV tools discovered")
                print("[mcp] Continuing without MCP enrichment")

    def clone_repo_stream(
        self,
        # Required input for git clone; validated before any workspace work starts.
        repo_url: str,
        workspace_root: str,
        run_id: Optional[str] = None,
        artifacts_root: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """Clone a repo in an agent workspace, then parse requirements and run pip-audit."""
        # Stream a git clone (and follow-on parse) while the agent runs in OpenHands.
        repo_url_value = repo_url.strip() if repo_url else ""
        repo_url_display = repo_url_value or "unknown"
        run_id = run_id or self._new_run_id()
        run_started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        # Decide whether this run uses Docker and derive the workspace paths.
        use_docker = coordinator_use_docker()
        if use_docker:
            (
                workspace_root,
                workspace_dir,
                repo_dir,
                container_artifacts_dir,
            ) = docker_paths(run_id)
        else:
            # Local runs mirror the Docker path layout under the local workspace root.
            workspace_root = workspace_root or os.path.join(os.getcwd(), "workspace")
            workspace_dir = os.path.join(workspace_root, run_id)
            repo_dir = os.path.join(workspace_dir, "repo")
            container_artifacts_dir = os.path.join(workspace_dir, "artifacts")
        # Reset per-run state so callers always see the latest artifacts.
        self.latest_worklist = []
        self.latest_patch_notes = ""
        self.patch_notes_paths = []
        self.latest_cve_summary = "CVE summary: pending"
        self.latest_summary = ""
        self.latest_summary_path = ""
        self.latest_artifacts_dir = ""

        # Each run gets an isolated workspace to keep artifacts and venvs separate.
        artifacts_dir = artifacts.init_artifacts_dir(artifacts_root, run_id)
        self.latest_artifacts_dir = artifacts_dir
        context = RunContext(
            run_id=run_id,
            run_started_at=run_started_at,
            repo_url=repo_url_display,
            repo_dir=repo_dir,
            workspace_root=workspace_root,
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
        )

        # Emit stage progress
        yield self._emit_stage(self.STAGE_PREFLIGHT)
        yield f"[artifacts] Directory: {artifacts_dir}"
        yield f"[clone] Run ID: {run_id}"
        yield f"[clone] Workspace: {workspace_dir}"
        yield f"[clone] Repo URL: {repo_url_display}"

        if not repo_url_value:
            yield "[clone] FAILED: repo URL is required."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="missing_repo_url",
                reason_detail="repo URL is required",
            )
            yield "[run] COMPLETE: failed"
            return

        # Choose the workspace implementation based on COORDINATOR_USE_DOCKER.
        if use_docker:
            try:
                # DockerWorkspace creation can fail if the SDK is too old or ports are busy.
                workspace = create_docker_workspace()
            except RuntimeError as exc:
                yield f"[clone] FAILED: {exc}"
                self._write_stub_run_artifacts(
                    context=context,
                    status="FAILED",
                    reason_code="docker_workspace_unavailable",
                    reason_detail=str(exc),
                )
                yield "[run] COMPLETE: failed"
                return
        else:
            workspace = LocalWorkspace(working_dir=workspace_root)

        try:
            # Docker runs can optionally disable DelegateTool if the server lacks it.
            if use_docker:
                # Only enable delegation when the Docker agent-server preloads DelegateTool.
                delegate_enabled = docker_delegate_enabled()
                active_agent = self._build_agent(include_delegate=delegate_enabled, for_container=True)
                self._preflight_check_tools(active_agent, expect_delegate=delegate_enabled)
            else:
                # Local runs: respect DOCKER_ENABLE_DELEGATE setting
                delegate_enabled = docker_delegate_enabled()
                active_agent = self.agent
            with workspace:
                yield from self._run_in_workspace(
                    workspace=workspace,
                    agent=active_agent,
                    fixer_agent=self.fixer_agent,
                    delegate_enabled=delegate_enabled,
                    repo_url_value=repo_url_value,
                    context=context,
                    workspace_dir=workspace_dir,
                    repo_dir=repo_dir,
                    container_artifacts_dir=container_artifacts_dir,
                    artifacts_dir=artifacts_dir,
                )
        except Exception as exc:
            yield f"[clone] FAILED: {exc}"
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="workspace_run_failed",
                reason_detail=str(exc),
            )
            yield "[run] COMPLETE: failed"
        return

    def _run_in_workspace(
        self,
        *,
        workspace: object,
        agent: Agent,
        fixer_agent: Agent,
        delegate_enabled: bool,
        repo_url_value: str,
        context: RunContext,
        workspace_dir: str,
        repo_dir: str,
        container_artifacts_dir: str,
        artifacts_dir: str,
    ) -> Generator[str, None, None]:
        init_cmd = (
            f"mkdir -p {shlex.quote(workspace_dir)} "
            f"{shlex.quote(container_artifacts_dir)}"
        )
        init_result = workspace.execute_command(init_cmd)
        if init_result.exit_code != 0:
            yield "[clone] FAILED: unable to initialize workspace directory."
            if init_result.stderr:
                yield f"[clone][error] {init_result.stderr.strip()}"
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="workspace_init_failed",
                reason_detail=init_result.stderr.strip() or "workspace init failed",
            )
            yield "[run] COMPLETE: failed"
            return

        # Emit stage progress
        yield self._emit_stage(self.STAGE_CLONE)
        # Ask the agent to run the clone command in the workspace directory.
        conversation = Conversation(agent=agent, workspace=workspace)
        safe_url = shlex.quote(repo_url_value)
        safe_repo_dir = shlex.quote(repo_dir)
        clone_cmd = f"git clone --progress {safe_url} {safe_repo_dir}"
        task = (
            "You are the Coordinator agent. Use TerminalTool to clone the repo. "
            f"Run exactly this command: {clone_cmd}. "
            "Return a short success or failure message once the clone completes."
        )

        conversation.send_message(task)

        run_errors = []
        terminal_error = False
        # Collect run exceptions and terminal failures separately for reporting.

        def _run() -> None:
            # Run the agent loop in a background thread so we can stream events.
            try:
                conversation.run()
            except Exception as exc:
                run_errors.append(exc)

            """
            Main thread                         Background thread
            -----------                         -----------------
            conversation.send_message(task)        |
            runner = Thread(target=_run)           |
            runner.start()    -------------------->|  _run() calls conversation.run()
            while runner.is_alive():               |  (blocking: LLM I/O + TerminalTool)
            _drain_events(conversation)            |  conversation.state.events <- events
            yield lines to caller                  |  (terminal output, progress)
            sleep(0.2)                             |
                                                   | runner finishes (conversation.run returns / errors)
            runner.join()  (wait for completion) <-|
            final _drain_events(conversation)      |
            continue with post-run logic           |
            """         

        runner = threading.Thread(target=_run, daemon=True)
        runner.start()

        # Drain terminal output as events arrive.
        events_seen = 0
        while runner.is_alive():
            events_seen, new_error, lines = self._drain_events(conversation, events_seen)
            terminal_error = terminal_error or new_error
            for line in lines:
                prefix = f"[{self._timestamp()}] [clone][error]" if new_error else f"[{self._timestamp()}] [clone]"
                yield f"{prefix} {line}"
            time.sleep(0.2)

        runner.join()

        # Final drain after the agent finishes.
        events_seen, new_error, lines = self._drain_events(conversation, events_seen)
        terminal_error = terminal_error or new_error
        for line in lines:
            prefix = f"[{self._timestamp()}] [clone][error]" if new_error else f"[{self._timestamp()}] [clone]"
            yield f"{prefix} {line}"

        if run_errors:
            yield f"[clone] FAILED: {run_errors[0]}"
            # Persist stub artifacts so the UI still has downloadable files on failure.
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail=str(run_errors[0]),
            )
            yield "[run] COMPLETE: failed"
            return

        if terminal_error:
            yield "[clone] FAILED: git clone reported an error."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail="git clone reported an error",
            )
            yield "[run] COMPLETE: failed"
            return

        repo_check = audit.run_command(
            ["test", "-d", posixpath.join(repo_dir, ".git")],
            workspace=workspace,
        )
        if repo_check.returncode == 0:
            yield f"[clone] SUCCESS: {repo_dir}"
        else:
            # Protect downstream steps from running on an incomplete checkout.
            yield "[clone] FAILED: repo directory not found after clone."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail="repo directory not found after clone",
            )
            yield "[run] COMPLETE: failed"
            return

        # Emit stage progress
        yield self._emit_stage(self.STAGE_PARSE)
        # Parse requirements.txt and gate on directives before later stages.
        requirements_path = posixpath.join(repo_dir, "requirements.txt")
        requirements_check = audit.run_command(
            ["test", "-f", requirements_path],
            workspace=workspace,
        )
        if requirements_check.returncode != 0:
            yield f"[parse] SKIPPED: requirements.txt not found at {requirements_path}"
            self._write_stub_run_artifacts(
                context=context,
                status="SKIPPED",
                reason_code="missing_requirements",
                reason_detail="requirements.txt not found",
            )
            yield "[run] COMPLETE: skipped"
            return

        requirements_text = self._read_workspace_file(workspace, requirements_path)
        if requirements_text is None:
            yield f"[parse] FAILED: unable to read {requirements_path}"
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="requirements_read_failed",
                reason_detail="unable to read requirements.txt",
            )
            yield "[run] COMPLETE: failed"
            return

        yield f"[parse] Found requirements.txt at {requirements_path}"
        parse_result = requirements_parser.parse_requirements_text(requirements_text)
        if parse_result.editable:
            yield f"[parse] Editable requirements: {len(parse_result.editable)}"
            for entry in parse_result.editable:
                spec = f" {entry.spec}" if entry.spec else ""
                yield f"[parse][editable] L{entry.line_no}: {entry.name}{spec}"
        else:
            yield "[parse] Editable requirements: 0"

        if parse_result.unknown:
            yield f"[parse] Unsupported/unknown lines: {len(parse_result.unknown)}"
            for entry in parse_result.unknown:
                yield f"[parse][unknown] L{entry.line_no}: {entry.raw}"

        if parse_result.directives:
            yield f"[parse] Directives found: {len(parse_result.directives)}"
            for entry in parse_result.directives:
                yield f"[parse][directive] L{entry.line_no}: {entry.raw}"
            if parse_result.skip_reason:
                yield f"[parse] SKIPPED: {parse_result.skip_reason}"
            # Skip processing when directives imply non-editable requirements sources.
            self._write_stub_run_artifacts(
                context=context,
                status="SKIPPED",
                reason_code="directives_detected",
                reason_detail=parse_result.skip_reason or "directive detected",
            )
            yield "[run] COMPLETE: skipped"
            return

        # Emit stage progress
        yield self._emit_stage(self.STAGE_SCAN)
        scan_ok = yield from self.run_pip_audit_stream(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
            workspace=workspace,
        )
        worklist: list[WorklistItem] = []
        before_count: Optional[int] = None
        after_count: Optional[int] = None
        final_ok = True
        if scan_ok:
            # Build and emit the direct-dependency worklist based on the audit JSON.
            audit_path = os.path.join(artifacts_dir, "pip_audit_before.json")
            worklist = self.build_worklist_from_audit(audit_path, parse_result)
            self.latest_worklist = worklist
            yield f"[worklist] Direct requirements: {len(parse_result.editable)}"
            yield f"[worklist] Vulnerable direct packages: {len(worklist)}"
            for item in worklist:
                # Format a terse worklist line for streaming logs.
                spec = item.spec or "(unpinned)"
                vuln_ids = ", ".join(item.vuln_ids) if item.vuln_ids else "unknown"
                fix_versions = ", ".join(item.fix_versions) if item.fix_versions else "unknown"
                yield f"[worklist] {item.name} {spec} -> {vuln_ids} | fixes: {fix_versions}"
            if worklist:
                # Emit stage progress
                yield self._emit_stage(self.STAGE_FIX)
                if delegate_enabled:
                    yield "[fix] DelegateTool enabled for Docker runtime."
                else:
                    yield "[fix] DelegateTool disabled; running Fixer directly."
                # iterate through the full worklist and fix packages serially.
                # Map normalized names to requirement entries so fixer prompts have line context.
                entry_map = {
                    audit.normalize_name(entry.name): entry for entry in parse_result.editable
                }
                total = len(worklist)
                fix_label = "Delegating" if delegate_enabled else "Fixing"
                yield f"[fix] Starting fix loop: {total} package(s)"
                for index, target in enumerate(worklist, start=1):
                    entry = entry_map.get(audit.normalize_name(target.name))
                    # Emit progress so the UI can render a package-level progress bar.
                    yield f"[fix] Progress: {index}/{total} ({target.name})"
                    yield f"[fix] {fix_label} package: {target.name}"
                    # Stream fixer output in real-time
                    fixer_gen = self._run_fixer_once(
                        item=target,
                        entry=entry,
                        requirements_path=requirements_path,
                        artifacts_dir=artifacts_dir,
                        workspace_dir=workspace_dir,
                        workspace=workspace,
                        coordinator_agent=agent,
                        fixer_agent=fixer_agent,
                        use_delegate=delegate_enabled,
                        container_artifacts_dir=container_artifacts_dir,
                    )
                    # Yield all streaming logs from the fixer
                    patch_notes, patch_path = None, ""
                    for item_or_result in fixer_gen:
                        if isinstance(item_or_result, tuple):
                            # This is the final return value
                            patch_notes, patch_path = item_or_result
                        else:
                            # This is a streaming log line
                            yield item_or_result
                    if os.path.isfile(patch_path):
                        # Track patch note paths so downstream UI can list all artifacts.
                        self.patch_notes_paths.append(patch_path)
                    if patch_notes is not None:
                        # Spot-check the fix by re-running pip-audit and updating patch notes.
                        before_audit_path = os.path.join(
                            artifacts_dir,
                            "pip_audit_before.json",
                        )
                        backup_path = posixpath.join(
                            posixpath.dirname(requirements_path),
                            "requirements_before.txt",
                        )
                        status, before_count, after_count, reverted = reporting.spot_check_fix(
                            package_name=target.name,
                            requirements_path=requirements_path,
                            backup_path=backup_path,
                            artifacts_dir=artifacts_dir,
                            workspace_dir=workspace_dir,
                            patch_notes_path=patch_path,
                            before_audit_path=before_audit_path,
                            workspace=workspace,
                        )
                        before_display = "unknown" if before_count is None else str(before_count)
                        after_display = "unknown" if after_count is None else str(after_count)
                        revert_note = " (reverted)" if reverted else ""
                        yield (
                            f"[verify] {target.name}: {status} "
                            f"(before {before_display}, after {after_display}){revert_note}"
                        )
                        # Cache patch notes for the UI to display the latest fix result.
                        self.latest_patch_notes = reporting.read_text_file(patch_path)
                        yield f"[fix] Patch notes saved: {patch_path}"
                    else:
                        self.latest_patch_notes = ""
                        yield "[fix] Patch notes not generated"
            # Emit stage progress
            yield self._emit_stage(self.STAGE_VERIFY)
            # After all fixes, run a final audit and write the "after" artifacts.
            final_ok, before_count, after_count = yield from self.run_final_audit_stream(
                requirements_path=requirements_path,
                workspace_dir=workspace_dir,
                artifacts_dir=artifacts_dir,
                before_audit_path=audit_path,
                workspace=workspace,
            )
            # Emit stage progress
            yield self._emit_stage(self.STAGE_WRITE)
            if final_ok:
                # Build cve_status.json and surface fixed/remaining counts to the UI.
                cve_path = os.path.join(artifacts_dir, "cve_status.json")
                cve_ok, fixed_count, remaining_count = artifacts.write_cve_status(
                    before_audit_path=audit_path,
                    after_audit_path=os.path.join(artifacts_dir, "pip_audit_after.json"),
                    artifacts_dir=artifacts_dir,
                )
                if cve_ok:
                    yield f"[cve] Saved artifact: {cve_path}"
                    fixed_display = "unknown" if fixed_count is None else str(fixed_count)
                    remaining_display = "unknown" if remaining_count is None else str(remaining_count)
                    self.latest_cve_summary = (
                        f"CVE summary: fixed {fixed_display}, remaining {remaining_display}"
                    )
                    yield (
                        f"[cve] Fixed: {fixed_display} | Remaining: {remaining_display}"
                    )
                else:
                    self.latest_cve_summary = "CVE summary: unavailable"
                    yield "[cve] FAILED: unable to write cve_status.json"
                    # Ensure the CVE artifact exists even if the normal write failed.
                    artifacts.ensure_stub_cve_status(
                        artifacts_dir=artifacts_dir,
                        reason_code="cve_status_failed",
                        reason_detail="unable to write cve_status.json",
                    )
            else:
                self.latest_cve_summary = "CVE summary: unavailable"
                # Backfill stub audit + CVE artifacts so downloads remain available.
                artifacts.ensure_stub_audit_artifacts(
                    artifacts_dir=artifacts_dir,
                    reason_code="final_audit_failed",
                    reason_detail="final pip-audit failed",
                )
                artifacts.ensure_stub_cve_status(
                    artifacts_dir=artifacts_dir,
                    reason_code="final_audit_failed",
                    reason_detail="final pip-audit failed",
                )
            summary_status = "SUCCESS" if scan_ok and final_ok else "FAILED"
            result = RunResult(
                status=summary_status,
                before_count=before_count,
                after_count=after_count,
                worklist=worklist,
                venv_dir=posixpath.join(workspace_dir, ".venv"),
            )
            summary_text = reporting.build_summary_text(context, result, workspace=workspace)
            summary_ok, summary_path = artifacts.write_summary(artifacts_dir, summary_text)
            if summary_ok:
                self.latest_summary = summary_text
                self.latest_summary_path = summary_path
                yield f"[summary] Saved artifact: {summary_path}"
            else:
                yield "[summary] FAILED: unable to write SUMMARY.md"
        else:
            # Clear any previous worklist if the scan failed.
            self.latest_worklist = []
            self.latest_cve_summary = "CVE summary: unavailable"
            # Write stub artifacts + summary to keep outputs consistent for failed runs.
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="baseline_audit_failed",
                reason_detail="baseline pip-audit failed",
            )
        # Task 23: Emit stage progress
        yield self._emit_stage(self.STAGE_DONE)
        status = "success" if scan_ok and final_ok else "failed"
        yield f"[run] COMPLETE: {status}"

    @staticmethod
    def _new_run_id() -> str:
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _emit_stage(stage: tuple[str, int]) -> str:
        """Emit a stage progress message for the UI."""
        stage_name, progress = stage
        return f"[stage] {stage_name} | {progress}%"

    def _write_stub_run_artifacts(
        self,
        context: RunContext,
        status: str,
        reason_code: str,
        reason_detail: str,
    ) -> None:
        """Write stub artifacts + summary for skipped/failed runs."""
        result = RunResult(
            status=status,
            before_count=None,
            after_count=None,
            worklist=[],
            venv_dir=None,
            # Preserve skip/failure reason so the SUMMARY can explain stub artifacts.
            reason_code=reason_code,
            reason_detail=reason_detail,
        )
        summary_text = reporting.build_summary_text(context, result)
        summary_path = artifacts.write_stub_run_artifacts(
            context=context,
            status=status,
            reason_code=reason_code,
            reason_detail=reason_detail,
            summary_text=summary_text,
        )
        if summary_path:
            self.latest_summary = summary_text
            self.latest_summary_path = summary_path
        self.latest_cve_summary = (
            "CVE summary: skipped" if status.upper() == "SKIPPED" else "CVE summary: unavailable"
        )
