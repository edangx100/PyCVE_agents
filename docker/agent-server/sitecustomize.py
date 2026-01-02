"""Agent-server startup hooks for PyCVE Docker runs."""

import os
import sys

# Log to file immediately when module loads
with open("/tmp/sitecustomize.log", "a") as f:
    f.write("=== SITECUSTOMIZE MODULE LOADING ===\n")
    f.write(f"sys.path: {sys.path}\n")
    f.flush()

print("[DEBUG sitecustomize] MODULE LOADED")
print(f"[DEBUG sitecustomize] sys.path={sys.path}")

# Add project root to path so we can import from src
sys.path.insert(0, '/workspace')
print("[DEBUG sitecustomize] Added /workspace to sys.path")

with open("/tmp/sitecustomize.log", "a") as f:
    f.write("Added /workspace to sys.path\n")
    f.flush()

from openhands.sdk import Agent, Tool
from openhands.tools.delegate import DelegateTool
from openhands.tools.delegate.registration import register_agent
from openhands.tools.file_editor import FileEditorTool


def _create_fixer_agent(agent_llm):
    """Create fixer agent with FileEditorTool and optional MCP for OSV enrichment."""
    with open("/tmp/sitecustomize_debug.log", "a") as f:
        f.write(f"[DEBUG] _create_fixer_agent called with llm={agent_llm}\n")
        f.flush()
    tools = [Tool(name=FileEditorTool.name)]

    # Try to import and build MCP config for OSV enrichment
    try:
        from src.agents.coordinator.docker_runtime import build_osv_mcp_config, osv_mcp_enabled

        osv_enabled = osv_mcp_enabled()
        with open("/tmp/sitecustomize_debug.log", "a") as f:
            f.write(f"[DEBUG] osv_mcp_enabled()={osv_enabled}\n")
            f.flush()

        if osv_enabled:
            # Pass for_container=True since sitecustomize.py runs inside Docker containers
            mcp_config = build_osv_mcp_config(for_container=True)
            with open("/tmp/sitecustomize_debug.log", "a") as f:
                f.write(f"[DEBUG] mcp_config={mcp_config}\n")
                f.flush()
            # OSV tool names: get_ecosystems, query_package_cve, query_for_cve_affected, query_for_cve_fix_versions
            tool_filter = r"^(file_editor|get_ecosystems|query_.*cve.*|query_for_cve.*)" if mcp_config else None
            with open("/tmp/sitecustomize_debug.log", "a") as f:
                f.write(f"[DEBUG] tool_filter={tool_filter}\n")
                f.flush()

            if mcp_config:
                try:
                    with open("/tmp/sitecustomize_debug.log", "a") as f:
                        f.write(f"[DEBUG] Creating Agent with MCP\n")
                        f.flush()
                    agent = Agent(
                        llm=agent_llm,
                        tools=tools,
                        mcp_config=mcp_config,
                        tool_filter=tool_filter,
                    )
                    with open("/tmp/sitecustomize_debug.log", "a") as f:
                        f.write(f"[DEBUG] Agent with MCP created successfully!\n")
                        f.flush()
                    return agent
                except TypeError as e:
                    # Fallback for older SDK versions
                    with open("/tmp/sitecustomize_debug.log", "a") as f:
                        f.write(f"[DEBUG] TypeError creating Agent: {e}\n")
                        f.flush()
                    pass
            else:
                with open("/tmp/sitecustomize_debug.log", "a") as f:
                    f.write(f"[DEBUG] mcp_config is None, using fallback\n")
                    f.flush()
    except ImportError as e:
        with open("/tmp/sitecustomize_debug.log", "a") as f:
            f.write(f"[DEBUG] ImportError: {e}\n")
            f.flush()
        pass
    except Exception as e:
        with open("/tmp/sitecustomize_debug.log", "a") as f:
            f.write(f"[DEBUG] Exception: {e}\n")
            import traceback
            f.write(traceback.format_exc())
            f.flush()

    # Fallback: basic fixer agent without MCP
    with open("/tmp/sitecustomize_debug.log", "a") as f:
        f.write(f"[DEBUG] Creating fallback Agent WITHOUT MCP\n")
        f.flush()
    return Agent(
        llm=agent_llm,
        tools=tools,
    )


# Importing DelegateTool registers it with the tool registry for the server.
_ = DelegateTool

with open("/tmp/sitecustomize.log", "a") as f:
    f.write("About to register fixer agent\n")
    f.flush()

print("[DEBUG sitecustomize] About to register fixer agent")
try:
    # Expose the Fixer agent type so DelegateTool can spawn it by name.
    register_agent(
        name="fixer",
        factory_func=_create_fixer_agent,
        description="Fixer agent that edits requirements.txt and writes patch notes.",
    )
    with open("/tmp/sitecustomize.log", "a") as f:
        f.write("✓ Fixer agent registered successfully\n")
        f.flush()
    print("[DEBUG sitecustomize] Fixer agent registered successfully")
except ValueError as e:
    # Ignore duplicate registration when the server reloads.
    with open("/tmp/sitecustomize.log", "a") as f:
        f.write(f"ValueError during registration: {e}\n")
        f.flush()
    print(f"[DEBUG sitecustomize] ValueError during registration (duplicate?): {e}")
    pass
except Exception as e:
    with open("/tmp/sitecustomize.log", "a") as f:
        f.write(f"ERROR during registration: {e}\n")
        f.flush()
    print(f"[DEBUG sitecustomize] Error during registration: {e}")
    raise

with open("/tmp/sitecustomize.log", "a") as f:
    f.write("=== MODULE INITIALIZATION COMPLETE ===\n\n")
    f.flush()

print("[DEBUG sitecustomize] MODULE INITIALIZATION COMPLETE")
