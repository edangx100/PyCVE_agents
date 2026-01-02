# PyCVE - Python CVE Scanner & Auto-Fixer

*Automated vulnerability scanning, fixing, and reporting powered by Agents and secure Docker-sandbox execution.*  
Uses OpenHands Software Agent SDK: https://openhands.dev/blog/introducing-the-openhands-software-agent-sdk

## Features

![PyCVE architecture](./PyCVE%20architecture.jpg)

- Scans `requirements.txt` for known vulnerabilities using pip-audit
- Fixer agents are launched by coordinator agent to implement necessary fixes.
- Detailed reports and patch notes for each fix
- Docker sandbox for safe isolated execution
- Local MCP server that enriches vulnerability data using OSV (https://osv.dev/).
- Gradio web UI for easy interaction
- Flexible model selection via OpenRouter — validated here with:
   - minimax/minimax-m2.1
   - z-ai/glm-4.7 

## Project Structure

```
PyCVE/
├── src/
│   ├── agents/
│   │   ├── coordinator/              # Coordinator agent
│   │   │   ├── __init__.py
│   │   │   ├── coordinator.py        # Main coordinator logic
│   │   │   ├── coordinator_workers.py # Worker processes
│   │   │   ├── artifacts.py          # Artifact generation
│   │   │   ├── audit.py              # pip-audit integration
│   │   │   ├── docker_runtime.py     # Docker workspace management
│   │   │   ├── models.py             # Data models
│   │   │   ├── reporting.py          # Report generation
│   │   │   └── requirements_parser.py # requirements.txt parsing
│   │   ├── __init__.py
│   │   └── fixer.py                  # Fixer agent
│   └── mcp_servers/
│       ├── __init__.py
│       ├── osv_http_server.py        # HTTP MCP server (FastMCP)
│       └── check_mcp_health.py       # MCP health check utility
├── docker/
│   └── agent-server/
│       ├── Dockerfile                # Agent server container image
│       └── sitecustomize.py          # Python startup customization
├── scripts/
│   └── start_osv_mcp_server.sh       # MCP server launcher
├── fixtures/                          # Test repositories
│   ├── repo_with_directives/
│   ├── repo_with_vulns/
│   └── repo_without_requirements/
├── artifacts/                         # Generated scan artifacts
├── workspace/                         # Agent working directories
├── app.py                            # Gradio web UI
├── start_pycve.sh                    # Main launcher (MCP + UI)
├── test_e2e_integration.py           # End-to-end integration tests
├── .env.example                      # Environment template
├── .env                              # Configuration (git-ignored)
├── requirements.txt                  # Python dependencies
├── README.md                         # Project overview
└── USER_GUIDE.md                     # Detailed user guide
```

## Quick Start

### Prerequisites

- Python 3.12
- Docker (for sandboxed scanning)
- OpenRouter API key

### Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd PyCVE
```

2. Install dependencies (using uv - Astral):
```bash
# Create and activate a uv virtual environment
# See https://docs.astral.sh/uv/pip/environments/
uv venv .venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

3. Configure environment variables (see [Configuration](#configuration))

4. Start PyCVE (MCP server + Gradio UI):
```bash
./start_pycve.sh
```

> **Important:** If `OSV_MCP_HTTP_ENABLED=true` in your `.env`, you MUST use `./start_pycve.sh` to start both the MCP server and Gradio app. Using `python app.py` alone will cause enrichment features to fail.

## Configuration

PyCVE is configured entirely through `.env` file. Use the provided example as a starting point:

```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

**Quick Start .env:**
```bash
# Minimal configuration to get started
OPENROUTER_API_KEY=sk-or-v1-your-key-here
COORDINATOR_AND_FIXER__MODEL=minimax/minimax-m2.1
COORDINATOR_USE_DOCKER=true
DOCKER_MOUNT_DIR=/path/to/your/PyCVE
OSV_MCP_ENABLED=false  # Start without MCP, enable later
```

### Essential Configuration

```bash
# OpenRouter API Key (required)
# Get your API key from: https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### Model Configuration

PyCVE supports **any OpenRouter-compatible model**.  
To change models, just update `.env` for variables:
- `COORDINATOR_AND_FIXER__MODEL` or 
- `DOCKER_LLM_MODEL`:

#### Model for Coordinator and Fixer agents

```bash
# Format: provider/model-name
COORDINATOR_AND_FIXER__MODEL=minimax/minimax-m2.1
```

#### Model variables actively used when `COORDINATOR_USE_DOCKER`=true

```bash
DOCKER_LLM_MODEL=openrouter/minimax/minimax-m2.1  # Important Note: includes 'openrouter/' prefix

DOCKER_LLM_API_KEY=sk-or-v1-your-key-here         # Same as OPENROUTER_API_KEY
DOCKER_LLM_BASE_URL=https://openrouter.ai/api/v1
DOCKER_LLM_NATIVE_TOOL_CALLING=false              # Disable for minimax (true will lead to duplicate JSON bug)
```

#### Why DOCKER_LLM_* Variables Exist 

PyCVE supports two runtime modes with different architectures (see [Two runtime modes: Docker Mode or Local Mode](#two-runtime-modes-docker-mode-or-local-mode)).

**1. COORDINATOR_USE_DOCKER=true (Remote Agent Server)**
A three-layer system where coordinator and fixer agents run in separate processes with isolated LLM configurations.  
In Docker mode the Agent Server inside the container uses DOCKER_LLM_MODEL to configure the LLM for the Fixer agents it spawns.

**2. COORDINATOR_USE_DOCKER=false (Local Mode)**
A single-process architecture where all agents run locally on your host machine.

```
═══════════════════════════════════════════════════════════════════════════════════════════════════════════
 DOCKER MODE (COORDINATOR_USE_DOCKER=true)      │  LOCAL MODE (COORDINATOR_USE_DOCKER=false)
═══════════════════════════════════════════════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────┐    │    ┌──────────────────────────────────────────┐
│ CLIENT LAYER (Your Host Machine)         │    │    │ SINGLE PROCESS (Your Host Machine)       │
│                                          │    │    │                                          │
│  Coordinator Agent                       │    │    │  Coordinator Agent                       │
│  ├─ Uses: OPENROUTER_API_KEY             │    │    │  ├─ Uses: OPENROUTER_API_KEY             │
│  ├─ Uses: COORDINATOR_AND_FIXER__MODEL     │    │    │  ├─ Uses: COORDINATOR_AND_FIXER__MODEL     │
│  └─ Creates: Conversation                │    │    │  ├─ Creates: Conversation                │
│              + DockerWorkspace           │    │    │  │           + LocalWorkspace            │
│                                          │    │    │  │                                       │
└──────────────────┬───────────────────────┘    │    │  │  Fixer Agents (in-process)            │
                   │ WebSocket/HTTP             │    │  │  ├─ Share same LLM config             │
                   ↓                            │    │  │  ├─ No isolation                      │
┌──────────────────────────────────────────┐    │    │  │  └─ Direct function calls             │
│ AGENT SERVER LAYER (Docker Containers)   │    │    │  │                                       │
│                                          │    │    │  └─ Workspace: Local filesystem          │
│  pycve-agent-server:mcp container        │    │    │     └─ Cloned repos, requirements.txt    │
│  ├─ Runs: python -m openhands            │    │    │                                          │
│  │         .agent_server                 │    │    │  DOCKER_LLM_* variables IGNORED          │
│  ├─ Uses: DOCKER_LLM_API_KEY             │    │    │                                          │
│  ├─ Uses: DOCKER_LLM_MODEL               │    │    └──────────────────────────────────────────┘
│  ├─ Uses: DOCKER_LLM_BASE_URL            │    │
│  ├─ Uses: DOCKER_LLM_NATIVE_TOOL_CALLING │    │
│  └─ Manages: Fixer agents                │    │
│              with DelegateTool           │    │
│                                          │    │
└──────────────────┬───────────────────────┘    │
                   │                            │
                   ↓                            │
┌──────────────────────────────────────────┐    │
│ WORKSPACE LAYER (Container Filesystem)   │    │
│                                          │    │
│  /workspace (mounted via                 │    │
│              DOCKER_MOUNT_DIR)           │    │
│  ├─ Cloned repos                         │    │
│  ├─ requirements.txt files               │    │
│  └─ Fixer agent operations               │    │
│                                          │    │
└──────────────────────────────────────────┘    │
                                                │
═══════════════════════════════════════════════════════════════════════════════════════════════════════════
```

**Supported models:**
- `minimax/minimax-m2.1` https://openrouter.ai/minimax/minimax-m2.1
- `z-ai/glm-4.7` https://openrouter.ai/z-ai/glm-4.7
- Any other model supported by OpenRouter

**Switching models:** To change models, update the appropriate env var(s) based on your mode:
- Local mode:  `COORDINATOR_AND_FIXER__MODEL`
- Docker mode: `COORDINATOR_AND_FIXER__MODEL` and `DOCKER_LLM_MODEL`



### Two runtime modes: Docker Mode or Local Mode

**Key Differences:**

| Aspect | Docker Mode | Local Mode |
|--------|-------------|------------|
| **Architecture** | 3-layer (Client → Agent Server → Workspace) | Single process |
| **Isolation** | Containers provide security sandbox | No isolation |
| **LLM Config** | `DOCKER_LLM_*` for fixer agents | `COORDINATOR_AND_FIXER__MODEL` for all |
| **Communication** | WebSocket/HTTP between layers | Direct function calls |
| **Workspace** | Docker container filesystem | Local filesystem |
| **Model Prefix** | Requires `openrouter/` prefix | No prefix needed |


**How It Works:**

**Docker Mode (`COORDINATOR_USE_DOCKER=true`):**
1. Coordinator runs on your host machine using `OPENROUTER_API_KEY` and `COORDINATOR_AND_FIXER__MODEL`
2. Creates a `DockerWorkspace` which spawns `pycve-agent-server:mcp` containers
3. Containers receive `DOCKER_LLM_*` env vars via `forward_env` configuration
4. Fixer agents run inside containers using Docker-specific LLM settings
5. Client and server communicate via WebSocket for real-time event streaming
6. Workspace operations happen in isolated container filesystem

**Local Mode (`COORDINATOR_USE_DOCKER=false`):**
1. Everything runs in a single Python process on your host machine
2. Creates a `LocalWorkspace` pointing to your local filesystem
3. Uses only `OPENROUTER_API_KEY` and `COORDINATOR_AND_FIXER__MODEL`
4. Fixer agents spawn as in-process Python objects (no DelegateTool needed)
5. Direct function calls between coordinator and fixer agents
6. `DOCKER_LLM_*` variables are completely ignored
7. All operations happen directly on your local filesystem


### Runtime Mode

```bash
# Toggle Docker workspace usage
COORDINATOR_USE_DOCKER=true   # Use Docker sandbox (recommended)
# COORDINATOR_USE_DOCKER=false  # Use local workspace (for development)
```

### Docker Configuration

**Important:** Docker mode requires different LLM configuration.

```bash
# Host directory to mount into Docker
# IMPORTANT: Update this to your actual PyCVE project directory
DOCKER_MOUNT_DIR=/path/to/PyCVE


# use the defaults below; no changes needed

# Container workspace paths — use the defaults 
DOCKER_WORKSPACE_ROOT=/workspace/workspace
OH_CONVERSATIONS_PATH=/workspace/workspace/conversations
OH_BASH_EVENTS_DIR=/workspace/workspace/bash_events

# Docker images — use the defaults
DOCKER_BASE_IMAGE=python:3.11-slim
DOCKER_SERVER_IMAGE=pycve-agent-server:mcp

# Enable DelegateTool for sub-agent spawning — use the defaults
DOCKER_ENABLE_DELEGATE=true
```

**Critical Docker Setup Steps:**

1. **Build custom Docker image** (required for DelegateTool support):
   ```bash
   docker build -t pycve-agent-server:mcp -f Dockerfile.agent-server .
   ```

2. **Set DOCKER_MOUNT_DIR** to your actual project path:
   ```bash
   # Example:
   DOCKER_MOUNT_DIR=/home/username/projects/PyCVE
   ```
**Important Note:**
**DOCKER_MOUNT_DIR must be absolute**: Relative paths will fail

3. **Configure Docker mode LLM variables** (see LLM configuration above)

### MCP (Model Context Protocol) Configuration

> **⚠️ IMPORTANT:** This project **ONLY supports HTTP mode** for MCP.  
stdio mode is **NOT supported** and will not work.  
Always use HTTP mode as documented below.

**HTTP Mode Configuration:**

```bash
# Enable MCP
OSV_MCP_ENABLED=true

# use the defaults below; no changes needed

# Enable HTTP mode — use the defaults
OSV_MCP_HTTP_ENABLED=true
OSV_MCP_HTTP_URL=http://localhost:3000/mcp
OSV_MCP_HTTP_PORT=3000
OSV_MCP_HTTP_PATH=/mcp
OSV_MCP_HTTP_TRANSPORT=streamable-http
OSV_MCP_HTTP_HOST=0.0.0.0
```

**MCP server:**

Option 1 - Script to start both MCP server + Gradio app (recommended):
```bash
./start_pycve.sh
```

Option 2 - Script to start MCP server only (for testing/debugging):
```bash
./scripts/start_osv_mcp_server.sh
```

**Check server health:**
```bash
python -m src.mcp_servers.check_mcp_health
```

**Why HTTP Only?**
- ✅ Works in both local AND Docker modes
- ✅ No filesystem access required
- ✅ Compatible with DelegateTool architecture
- ✅ Reliable and tested
- ❌ stdio mode is NOT supported (missing required pyproject.toml configuration)

### Complete Environment Variable Reference

For quick reference, here's every environment variable used by PyCVE:

#### API & Model Configuration
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENROUTER_API_KEY` | ✅ Yes | - | OpenRouter API key for LLM access |
| `COORDINATOR_AND_FIXER__MODEL` | ✅ Yes | `minimax/minimax-m2.1` | Model for Coordinator & Fixer agents (local mode) |
| `DOCKER_LLM_API_KEY` | Docker only | Same as `OPENROUTER_API_KEY` | API key for Docker mode |
| `DOCKER_LLM_MODEL` | Docker only | `openrouter/minimax/minimax-m2.1` | Model for Docker mode (note `openrouter/` prefix) |
| `DOCKER_LLM_BASE_URL` | Docker only | `https://openrouter.ai/api/v1` | LLM API endpoint for Docker |
| `DOCKER_LLM_NATIVE_TOOL_CALLING` | No | `false` | Enable native tool calling (use `false` for minimax) |

#### Runtime Mode
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COORDINATOR_USE_DOCKER` | ✅ Yes | `true` | Use Docker sandbox (recommended) vs local workspace |

#### Docker Configuration
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DOCKER_MOUNT_DIR` | If Docker | - | Host directory to mount (must be absolute path) |
| `DOCKER_WORKSPACE_ROOT` | No | `/workspace/workspace` | Workspace root inside container |
| `OH_CONVERSATIONS_PATH` | No | `/workspace/workspace/conversations` | Agent conversation storage path |
| `OH_BASH_EVENTS_DIR` | No | `/workspace/workspace/bash_events` | Bash event logging directory |
| `DOCKER_BASE_IMAGE` | No | `python:3.11-slim` | Base Docker image |
| `DOCKER_SERVER_IMAGE` | No | `pycve-agent-server:mcp` | Custom agent-server image |
| `DOCKER_ENABLE_DELEGATE` | No | `true` | Enable DelegateTool (required for multi-agent) |

#### MCP Configuration (HTTP Mode - ONLY supported mode)
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OSV_MCP_ENABLED` | No | `false` | Enable MCP for OSV enrichment |
| `OSV_MCP_HTTP_ENABLED` | If MCP | `true` | Enable HTTP transport (required) |
| `OSV_MCP_HTTP_URL` | If HTTP | `http://localhost:3000/mcp` | MCP server endpoint URL |
| `OSV_MCP_HTTP_PORT` | If HTTP | `3000` | MCP server port |
| `OSV_MCP_HTTP_PATH` | If HTTP | `/mcp` | MCP endpoint path |
| `OSV_MCP_HTTP_TRANSPORT` | If HTTP | `streamable-http` | MCP transport protocol |
| `OSV_MCP_HTTP_HOST` | If HTTP | `0.0.0.0` | MCP server bind address |

#### ⚠️ Unsupported stdio Mode Variables
These variables exist in code but are **NOT supported** - do not use:
- `OSV_MCP_DIR` - stdio mode directory (NOT supported)
- `OSV_MCP_CONTAINER_PATH` - stdio mode container path (NOT supported)


## Usage

### Web UI

1. Start both MCP server + Gradio app:
```bash
./start_pycve.sh
```

   > **Note:** If MCP is disabled (`OSV_MCP_HTTP_ENABLED=false`), you can use `python app.py` instead.

2. Open browser to `http://localhost:7860`

3. Enter GitHub repository URL

4. Click "Run Scan"

5. Monitor progress and download artifacts when complete

### Artifacts

After a scan completes, the following artifacts are generated in `artifacts/<run_id>/`:

- `SUMMARY.md` - Complete scan report with vulnerability counts
- `cve_status.json` - Structured CVE data (before/after/fixed/remaining)
- `pip_audit_before.json` - Initial pip-audit scan results
- `pip_audit_after.json` - Post-fix pip-audit scan results
- `PATCH_NOTES_<package>.md` - Individual fix notes for each package

## Architecture

### Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          User (Gradio Web UI)                           │
│                     http://localhost:7860                               │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ GitHub Repo URL
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       COORDINATOR AGENT                                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Stage 1: Preflight (5%)    - Validate inputs                      │  │
│  │ Stage 2: Clone (15%)       - Clone repo to workspace              │  │
│  │ Stage 3: Parse (25%)       - Parse requirements.txt               │  │
│  │ Stage 4: Scan (40%)        - Run pip-audit baseline               │  │
│  │          ├─ Build worklist of vulnerable packages                 │  │
│  │          └─ Pre-fetch OSV data (if MCP enabled) ───────┐          │  │
│  │                                                        │          │  │
│  │ Stage 5: Fix (60%)         - Delegate to Fixer ────────┼──┐       │  │
│  │          └─ One Fixer per package (parallel)           │  │       │  │
│  │                                                        │  │       │  │
│  │ Stage 6: Verify (80%)      - Run pip-audit after       │  │       │  │
│  │ Stage 7: Write (95%)       - Generate artifacts        │  │       │  │
│  │ Stage 8: Done (100%)       - Return results            │  │       │  │
│  └────────────────────────────────────────────────────────┼──┼───────┘  │
│                                                           │  │          │
│  Built-in Tools:                                          │  │          │
│  • TerminalTool (git, pip-audit, etc.)                    │  │          │
│  • FileEditorTool (edit requirements.txt)                 │  │          │
│  • DelegateTool (spawn Fixer agents)                      │  │          │
│  • TaskTrackerTool (log progress)                         │  │          │
│                                                           │  │          │
│  MCP Tools (if enabled):                                  │  │          │
│  • osv_query_package_cve ◄────────────────────────────────┘  │          │
│  • osv_query_for_cve_affected                                │          │
│  • osv_query_for_cve_fix_versions                            │          │
│  • osv_get_ecosystems                                        │          │
└──────────────────────────────────────────────────────────────┼──────────┘
                                                               │
                ┌──────────────────────────────────────────────┘
                │ DelegateTool spawns Fixer (one per package)
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         FIXER AGENT                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Input: Package name, current version, vulnerabilities,            │  │
│  │        fix version, OSV pre-fetched data (text)                   │  │
│  │                                                                   │  │
│  │ Actions:                                                          │  │
│  │  1. Create requirements_before.txt backup                         │  │
│  │  2. Update package spec in requirements.txt                       │  │
│  │  3. Extract OSV enrichment from pre-fetched data                  │  │
│  │  4. Write PATCH_NOTES_<package>.md with:                          │  │
│  │     • Before/after versions                                       │  │
│  │     • Vulnerabilities fixed                                       │  │
│  │     • OSV enrichment (advisory, ranges, fixes)                    │  │
│  │                                                                   │  │
│  │ Output: Patch notes returned to Coordinator                       │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Built-in Tools:                                                        │
│  • FileEditorTool (edit requirements.txt, write patch notes)            │
│  • TerminalTool (verify changes)                                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    WORKSPACE (Docker or Local)                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ workspace/<run_id>/                                               │  │
│  │ └── repo/                  ← Cloned repository                    │  │
│  │     ├── requirements.txt   ← Modified with fixes                  │  │
│  │     ├── requirements_before.txt ← Backup                          │  │
│  │     └── .venv/             ← Virtual environment                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Docker Mode (COORDINATOR_USE_DOCKER=true):                             │
│  • Runs in pycve-agent-server:mcp container                             │
│  • Isolated from host system                                            │
│  • Mounted at /workspace                                                │
│                                                                         │
│  Local Mode (COORDINATOR_USE_DOCKER=false):                             │
│  • Runs directly on host                                                │
│  • workspace/ in project directory                                      │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    MCP SERVER (Optional)                                │
│                    http://localhost:3000/mcp                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ FastMCP v2.14.1 - HTTP Transport (Streamable)                     │  │
│  │                                                                   │  │
│  │ OSV API Tools:                                                    │  │
│  │  • osv_query_package_cve(ecosystem, package, vuln_id)             │  │
│  │  • osv_query_for_cve_affected(vulnerability_id)                   │  │
│  │  • osv_query_for_cve_fix_versions(ecosystem, package, vuln_id)    │  │
│  │  • osv_get_ecosystems()                                           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Note: Only HTTP mode supported (stdio NOT supported)                   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    ARTIFACTS (Output)                                   │
│                    artifacts/<run_id>/                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ • SUMMARY.md                  - Complete scan report              │  │
│  │ • cve_status.json             - CVE status (before/after/fixed)   │  │
│  │ • pip_audit_before.json       - Initial scan results              │  │
│  │ • pip_audit_after.json        - Post-fix scan results             │  │
│  │ • pip_audit.json              - Alias to pip_audit_after.json     │  │
│  │ • PATCH_NOTES_<package>.md    - One per fixed package             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Downloadable via Gradio UI                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Agent Roles

1. **Coordinator Agent** - Orchestrates the workflow:
   - Clones repository
   - Parses requirements.txt
   - Runs pip-audit
   - Builds worklist of vulnerable packages
   - **Pre-fetches OSV data**
   - Delegates fixes to Fixer agent
   - Generates reports

2. **Fixer Agent** - Fixes individual packages:
   - Updates requirement specifications
   - Creates backups
   - Writes patch notes
   - **Extracts pre-fetched OSV data** and enriches patch notes


### MCP Integration

#### HTTP MCP Server

PyCVE includes a self-contained HTTP MCP server for OSV enrichment:

**Features:**
- 4 OSV tools: `get_ecosystems`, `query_package_cve`, `query_for_cve_affected`, `query_for_cve_fix_versions`
- Works in local AND Docker modes
- Streamable HTTP transport
- FastMCP v2.14.1

**Why Local MCP Server was setup**

PyCVE uses a hybrid architecture to work around MCP limitations with DelegateTool:

**The Problem:**
- OpenHands DelegateTool doesn't pass MCP configuration to delegated agents
- Fixer agent (spawned via DelegateTool) can't access MCP tools directly
- Standard MCP client patterns don't work in multi-agent architectures

**The Solution**
1. **Coordinator Pre-Fetch**: Coordinator agent queries OSV using its MCP tools
2. **Text-Based Data Passing**: OSV data formatted as text and embedded in Fixer's task prompt
3. **Extraction**: Fixer extracts pre-fetched data using `get_agent_final_response()` utility
4. **Enrichment**: Fixer includes extracted data in patch notes










