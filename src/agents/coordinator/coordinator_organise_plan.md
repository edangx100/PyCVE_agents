# Coordinator setup

## Modules breakdown
1. **__init__.py** - Package initialization that exports the Coordinator class

2. **artifacts.py** - Artifact management
   - Handles writing/reading JSON files (pip-audit results, CVE status)
   - Manages stub artifacts for skipped/failed runs
   - Builds CVE status payloads comparing before/after vulnerability counts

3. **coordinator.py** - Main orchestration (752 lines)
   - Coordinator class that manages the entire fix pipeline
   - Stages: Clone → Parse → Scan → Fix → Verify → Write
   - Handles both Docker and local execution modes
   - Integrates with OpenHands SDK agents
   - Supports MCP (Model Context Protocol) for OSV enrichment
   - Manages agent building, preflight checks, and workspace setup
   - Inherits worker methods from CoordinatorWorkers base class

4. **coordinator_workers.py** - Worker task implementations (571 lines)
   - CoordinatorWorkers base class with specialized task execution
   - Event processing (_drain_events, _extract_terminal_output)
   - Workspace file operations (_read_workspace_file, _download_workspace_file)
   - OSV enrichment pre-fetching (_prefetch_osv_enrichment)
   - Audit execution (run_pip_audit_stream, run_final_audit_stream)
   - Fix execution (_run_fixer_once with streaming output)
   - Worklist generation and formatting

5. **reporting.py** - Report generation
   - Builds summary markdown files
   - Performs spot-check verification of fixes
   - Collects tool versions and MCP status
   - Handles patch notes and verification notes

6. **audit.py** - Vulnerability scanning
   - Creates and manages Python virtual environments
   - Runs pip-audit in baseline and final modes
   - Counts vulnerabilities and parses JSON output

7. **models.py** - Data structures
   - RequirementEntry, DirectiveEntry, RequirementsParseResult
   - WorklistItem, RunContext, RunResult

8. **requirements_parser.py** - Requirements.txt parsing
   - Parses PEP 440 requirement specifications
   - Detects directives (VCS URLs, local paths, etc.)
   - Identifies editable vs non-editable requirements

9. **docker_runtime.py** - Docker integration
   - Creates Docker workspaces with fallback strategies
   - Builds MCP configuration (HTTP and stdio modes)
   - Manages container paths and environment forwarding


## Related modules (outside coordinator package)
- `src/agents/fixer.py`: Fixer agent that edits requirements.txt and writes patch notes. Enhanced with MCP support for OSV enrichment (Task 21).
- `docker/agent-server/sitecustomize.py`: Agent-server startup hooks for Docker mode. Registers fixer agent with MCP support for delegated execution.

## ASCII diagram
```
+-----------------------------------------------------+
|                 coordinator.py                      |
|  Coordinator class (inherits CoordinatorWorkers)    |
|  public API + pipeline orchestration                |
|  clone -> parse -> audit -> fix -> finalize         |
|  + agent init + MCP config + tool verification      |
|  + creates fixer agent with MCP for enrichment      |
+-----+--------+--------+--------+--------+-----------+
      |        |        |        |        |
      |        |        |        |        +-------------+
      |        |        |        |                      |
      |        |        |        v                      v
      |        |        |   +-------------------------------+
      |        |        |   |    coordinator_workers.py     |
      |        |        |   | CoordinatorWorkers base class |
      |        |        |   | - run_pip_audit_stream()      |
      |        |        |   | - run_final_audit_stream()    |
      |        |        |   | - _run_fixer_once()           |
      |        |        |   | - _prefetch_osv_enrichment()  |
      |        |        |   | - event processing helpers    |
      |        |        |   | - workspace file operations   |
      |        |        |   +-------------------------------+
      |        |        |             |
      v        v        v             v
+----------------+  +------------+  +----------------------+  +------------------+
| docker_runtime |  | audit.py   |  |   reporting.py       |  | requirements     |
| .py            |  |            |  |   summary + verify   |  | _parser.py       |
| MCP config     |  | venv +     |  +----------------------+  +------------------+
| HTTP/stdio     |  | pip-audit  |                |                    |
| Docker setup   |  +------------+                |                    |
+----------------+       |                        |                    |
      |                  |                        |                    |
      +------------------+------------------------+--------------------+
                                   |
                                   v
                  +---------------------------------------------+
                  |              artifacts.py                   |
                  |  audit JSON, SUMMARY.md, stubs, cve_status  |
                  +---------------------------------------------+
                                   |
                                   v
                  +---------------------------------------------+
                  |                 models.py                   |
                  | RunContext / RunResult / RequirementEntry / |
                  | WorklistItem                                |
                  +---------------------------------------------+

Related agents (used by coordinator):
+---------------------------------------------+
|              fixer.py                       |
|  (src/agents/fixer.py)                      |
|  - Edits requirements.txt                   |
|  - Writes patch notes with OSV enrichment   |
|  - Receives MCP config from coordinator     |
|  - Queries OSV tools for CVE details        |
|  - FileEditorTool + optional MCP tools      |
+---------------------------------------------+
          ↑
          | created & delegated by
          |
    coordinator.py
```
