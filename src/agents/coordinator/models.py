from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RequirementEntry:
    """Parsed requirement from requirements.txt (e.g., 'package>=1.0.0')."""
    name: str  # Package name
    spec: str  # Version specifier (e.g., '>=1.0.0')
    line_no: int  # Line number in file
    raw: str  # Original line text


@dataclass
class DirectiveEntry:
    """Non-package line in requirements.txt (e.g., -e, --index-url)."""
    line_no: int  # Line number in file
    raw: str  # Original line text


@dataclass
class RequirementsParseResult:
    """Result from parsing a requirements.txt file."""
    editable: list[RequirementEntry] = field(default_factory=list)  # Editable installs (-e)
    directives: list[DirectiveEntry] = field(default_factory=list)  # Other directives
    unknown: list[DirectiveEntry] = field(default_factory=list)  # Unparseable lines
    skip_reason: Optional[str] = None  # Reason if parsing was skipped


@dataclass
class WorklistItem:
    """Package that needs vulnerability remediation."""
    name: str  # Package name
    spec: str  # Current version specifier
    current_version: str  # Installed version
    vuln_ids: list[str]  # CVE/vulnerability IDs
    fix_versions: list[str]  # Versions that fix the vulnerabilities
    is_editable: bool  # Whether installed as editable (-e)
    skip_reason: Optional[str] = None  # Reason if skipped


@dataclass
class RunContext:
    """Execution context and paths for a remediation run."""
    run_id: str  # Unique identifier for this run
    run_started_at: str  # ISO timestamp of run start
    repo_url: str  # Git repository URL
    repo_dir: str  # Local clone directory
    workspace_root: str  # Root workspace directory
    workspace_dir: str  # Working directory for this run
    artifacts_dir: str  # Output artifacts directory


@dataclass
class RunResult:
    """Final result of a vulnerability remediation run."""
    status: str  # Run status (success, failure, partial, etc.)
    before_count: Optional[int]  # Vulnerabilities before remediation
    after_count: Optional[int]  # Vulnerabilities after remediation
    worklist: list[WorklistItem] = field(default_factory=list)  # Packages processed
    summary_path: str = ""  # Path to SUMMARY.md file
    cve_summary: str = ""  # CVE summary text
    venv_dir: Optional[str] = None  # Virtual environment directory
    # Optional skip/failure reason that gets surfaced in SUMMARY.md.
    reason_code: Optional[str] = None  # Machine-readable reason code
    reason_detail: Optional[str] = None  # Human-readable detail
