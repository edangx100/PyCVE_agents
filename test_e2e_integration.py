#!/usr/bin/env python3
"""
End-to-End Integration Test for PyCVE
Tests all scenarios with different MCP modes and repository types.

⚠️ NOTE: This project ONLY supports HTTP mode for MCP.
stdio mode is NOT supported and has been removed from tests.

Test Matrix:
- 3 repository types (vulns, directives, no requirements.txt)
- 2 MCP modes (HTTP, disabled)
= 6 total test cases
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
import time

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from dotenv import load_dotenv, set_key

PROJECT_ROOT = Path(__file__).parent
FIXTURES_DIR = PROJECT_ROOT / "fixtures"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


class TestCase:
    """Represents a single test case"""
    def __init__(self, name: str, repo_name: str, mcp_mode: str,
                 use_docker: bool, expected_status: str):
        self.name = name
        self.repo_name = repo_name
        self.mcp_mode = mcp_mode  # "http", "disabled" (stdio NOT supported)
        self.use_docker = use_docker
        self.expected_status = expected_status
        self.repo_url = f"file://{FIXTURES_DIR / repo_name}"

    def __str__(self):
        return f"{self.name} (MCP: {self.mcp_mode}, Docker: {self.use_docker})"


class TestRunner:
    """Runs end-to-end integration tests"""

    def __init__(self):
        self.results: List[Dict] = []
        self.env_file = PROJECT_ROOT / ".env"
        self.original_env = self._backup_env()

    def _backup_env(self) -> Dict[str, str]:
        """Backup current environment variables"""
        load_dotenv(self.env_file)
        return {
            "OSV_MCP_ENABLED": os.getenv("OSV_MCP_ENABLED", "false"),
            "OSV_MCP_HTTP_ENABLED": os.getenv("OSV_MCP_HTTP_ENABLED", "false"),
            "COORDINATOR_USE_DOCKER": os.getenv("COORDINATOR_USE_DOCKER", "false"),
        }

    def _restore_env(self):
        """Restore original environment variables"""
        for key, value in self.original_env.items():
            set_key(self.env_file, key, value)

    def _configure_env(self, test_case: TestCase):
        """Configure environment for a specific test case"""
        print(f"\n{'='*80}")
        print(f"Configuring environment for: {test_case}")
        print(f"{'='*80}")

        if test_case.mcp_mode == "http":
            set_key(self.env_file, "OSV_MCP_ENABLED", "true")
            set_key(self.env_file, "OSV_MCP_HTTP_ENABLED", "true")
        else:  # disabled
            set_key(self.env_file, "OSV_MCP_ENABLED", "false")
            set_key(self.env_file, "OSV_MCP_HTTP_ENABLED", "false")

        set_key(self.env_file, "COORDINATOR_USE_DOCKER",
                "true" if test_case.use_docker else "false")

        # Reload environment
        load_dotenv(self.env_file, override=True)

        print(f"  OSV_MCP_ENABLED: {os.getenv('OSV_MCP_ENABLED')}")
        print(f"  OSV_MCP_HTTP_ENABLED: {os.getenv('OSV_MCP_HTTP_ENABLED')}")
        print(f"  COORDINATOR_USE_DOCKER: {os.getenv('COORDINATOR_USE_DOCKER')}")

    def _run_coordinator(self, test_case: TestCase) -> Tuple[bool, str, Path]:
        """Run coordinator for a test case"""
        print(f"\nRunning coordinator for: {test_case.repo_url}")

        try:
            # Import here to get fresh environment
            from src.agents.coordinator import Coordinator

            # Create coordinator
            coordinator = Coordinator()

            # Setup paths
            workspace_root = str(PROJECT_ROOT / "workspace")
            artifacts_root = str(ARTIFACTS_DIR)

            # Run coordinator and consume the stream
            final_status = None
            run_id = None
            for line in coordinator.clone_repo_stream(
                test_case.repo_url,
                workspace_root=workspace_root,
                artifacts_root=artifacts_root,
            ):
                # Print progress
                if line.startswith("[stage]") or line.startswith("[run]"):
                    print(f"  {line}")

                # Extract run_id from clone message
                if line.startswith("[clone] Run ID:"):
                    run_id = line.split("Run ID:")[1].strip()

                # Capture final status
                if line.startswith("[run] COMPLETE:"):
                    final_status = line

            # If we didn't get run_id from stream, try to find the latest in artifacts
            if not run_id:
                artifacts = sorted(ARTIFACTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
                if artifacts:
                    run_id = artifacts[0].name

            artifacts_path = ARTIFACTS_DIR / run_id if run_id else None

            print(f"  Run ID: {run_id}")
            print(f"  Status: {final_status or 'UNKNOWN'}")
            print(f"  Artifacts: {artifacts_path}")

            return True, run_id, artifacts_path

        except Exception as e:
            print(f"  ERROR running coordinator: {e}")
            import traceback
            traceback.print_exc()
            return False, str(e), None

    def _verify_artifacts(self, test_case: TestCase, artifacts_path: Path) -> Dict:
        """Verify artifacts are generated correctly"""
        print(f"\nVerifying artifacts in: {artifacts_path}")

        verification = {
            "artifacts_exist": artifacts_path.exists(),
            "summary_exists": False,
            "cve_status_exists": False,
            "pip_audit_before_exists": False,
            "pip_audit_after_exists": False,
            "patch_notes_found": [],
            "status_correct": False,
            "mcp_mode_correct": False,
            "enrichment_present": False,
            "option4_verified": False,
        }

        if not artifacts_path.exists():
            print(f"  ❌ Artifacts directory does not exist")
            return verification

        # Check SUMMARY.md
        summary_path = artifacts_path / "SUMMARY.md"
        verification["summary_exists"] = summary_path.exists()
        if summary_path.exists():
            print(f"  ✅ SUMMARY.md exists")
            summary_content = summary_path.read_text()

            # Check status
            if test_case.expected_status in summary_content:
                verification["status_correct"] = True
                print(f"  ✅ Status is {test_case.expected_status}")
            else:
                print(f"  ❌ Expected status {test_case.expected_status} not found")

            # Check MCP mode
            if test_case.mcp_mode == "http":
                if "MCP Mode: HTTP" in summary_content or "http://" in summary_content.lower():
                    verification["mcp_mode_correct"] = True
                    print(f"  ✅ MCP mode is HTTP")
                else:
                    print(f"  ❌ MCP mode not showing HTTP")
            else:  # disabled
                if "MCP Status: disabled" in summary_content or "not configured" in summary_content.lower():
                    verification["mcp_mode_correct"] = True
                    print(f"  ✅ MCP is disabled")
                else:
                    print(f"  ❌ MCP not showing as disabled")
        else:
            print(f"  ❌ SUMMARY.md does not exist")

        # Check cve_status.json
        cve_status_path = artifacts_path / "cve_status.json"
        verification["cve_status_exists"] = cve_status_path.exists()
        if cve_status_path.exists():
            print(f"  ✅ cve_status.json exists")
        else:
            print(f"  ⚠️  cve_status.json does not exist (may be expected for SKIP/FAILED)")

        # Check pip_audit files
        pip_audit_before = artifacts_path / "pip_audit_before.json"
        pip_audit_after = artifacts_path / "pip_audit_after.json"
        verification["pip_audit_before_exists"] = pip_audit_before.exists()
        verification["pip_audit_after_exists"] = pip_audit_after.exists()

        if pip_audit_before.exists():
            print(f"  ✅ pip_audit_before.json exists")
        if pip_audit_after.exists():
            print(f"  ✅ pip_audit_after.json exists")

        # Check patch notes
        patch_notes = list(artifacts_path.glob("PATCH_NOTES_*.md"))
        verification["patch_notes_found"] = [p.name for p in patch_notes]
        if patch_notes:
            print(f"  ✅ Found {len(patch_notes)} patch notes files")

            # Check for OSV enrichment in patch notes (if MCP enabled - HTTP mode only)
            if test_case.mcp_mode == "http":
                for patch_note in patch_notes:
                    content = patch_note.read_text()
                    if "OSV Enrichment" in content and "unavailable" not in content:
                        verification["enrichment_present"] = True
                        print(f"  ✅ OSV enrichment found in {patch_note.name}")
                        break

                if not verification["enrichment_present"]:
                    print(f"  ⚠️  No OSV enrichment found in patch notes (MCP may have failed)")
        else:
            print(f"  ⚠️  No patch notes found (may be expected for SKIP/FAILED)")

        return verification

    def _verify_option4(self, test_case: TestCase, artifacts_path: Path) -> bool:
        """Verify Option 4 (Hybrid Pre-Fetch) implementation"""
        if test_case.mcp_mode != "http":
            return True  # Not applicable for disabled MCP (only HTTP mode supported)

        print(f"\nVerifying Option 4 implementation:")

        # Check for coordinator pre-fetch in logs
        # This would require capturing coordinator logs, which we can add

        # Check patch notes for enrichment data
        patch_notes = list(artifacts_path.glob("PATCH_NOTES_*.md"))
        if not patch_notes:
            print(f"  ⚠️  No patch notes to verify Option 4")
            return False

        for patch_note in patch_notes:
            content = patch_note.read_text()

            # Look for OSV enrichment section
            if "OSV Enrichment" in content:
                if "unavailable" not in content.lower():
                    print(f"  ✅ Option 4: Enrichment data found in {patch_note.name}")

                    # Check for specific OSV data elements
                    if any(marker in content for marker in ["Advisory", "Affected", "Fixed", "GHSA-", "CVE-"]):
                        print(f"  ✅ Option 4: OSV data elements present")
                        return True
                    else:
                        print(f"  ⚠️  Option 4: Enrichment section exists but missing data")
                else:
                    print(f"  ❌ Option 4: Enrichment marked as unavailable")

        return False

    def run_test(self, test_case: TestCase) -> Dict:
        """Run a single test case"""
        print(f"\n{'='*80}")
        print(f"RUNNING TEST: {test_case}")
        print(f"{'='*80}")

        result = {
            "test_case": str(test_case),
            "repo": test_case.repo_name,
            "mcp_mode": test_case.mcp_mode,
            "use_docker": test_case.use_docker,
            "expected_status": test_case.expected_status,
            "passed": False,
            "coordinator_success": False,
            "verification": {},
        }

        try:
            # Configure environment
            self._configure_env(test_case)

            # Run coordinator
            success, run_id, artifacts_path = self._run_coordinator(test_case)
            result["coordinator_success"] = success
            result["run_id"] = run_id

            if not success:
                print(f"❌ Coordinator failed")
                return result

            # Verify artifacts
            verification = self._verify_artifacts(test_case, artifacts_path)
            result["verification"] = verification

            # Verify Option 4 (if applicable - only for HTTP mode)
            if test_case.mcp_mode == "http":
                option4_ok = self._verify_option4(test_case, artifacts_path)
                verification["option4_verified"] = option4_ok

            # Determine if test passed
            result["passed"] = (
                verification["artifacts_exist"] and
                verification["summary_exists"] and
                verification["status_correct"] and
                verification["mcp_mode_correct"]
            )

            if result["passed"]:
                print(f"\n✅ TEST PASSED: {test_case}")
            else:
                print(f"\n❌ TEST FAILED: {test_case}")
                print(f"   Verification: {verification}")

        except Exception as e:
            print(f"\n❌ TEST EXCEPTION: {test_case}")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
            result["error"] = str(e)

        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all test cases"""

        # Define test cases
        # NOTE: All tests use local mode (use_docker=False) to avoid Docker filesystem access issues
        # with file:// URLs. Docker mode is tested separately with actual remote repos.
        # ⚠️ stdio mode is NOT supported and has been removed from tests.
        test_cases = [
            # Repo with vulnerabilities - 2 MCP modes (HTTP only, stdio NOT supported)
            TestCase(
                name="Vulns + HTTP + Local",
                repo_name="repo_with_vulns",
                mcp_mode="http",
                use_docker=False,
                expected_status="SUCCESS"
            ),
            TestCase(
                name="Vulns + MCP Disabled",
                repo_name="repo_with_vulns",
                mcp_mode="disabled",
                use_docker=False,
                expected_status="SUCCESS"
            ),

            # Repo with directives - should SKIP
            TestCase(
                name="Directives + HTTP + Local",
                repo_name="repo_with_directives",
                mcp_mode="http",
                use_docker=False,
                expected_status="SKIPPED"
            ),
            TestCase(
                name="Directives + MCP Disabled",
                repo_name="repo_with_directives",
                mcp_mode="disabled",
                use_docker=False,
                expected_status="SKIPPED"
            ),

            # Repo without requirements.txt - should generate stubs
            TestCase(
                name="No Reqs + HTTP + Local",
                repo_name="repo_without_requirements",
                mcp_mode="http",
                use_docker=False,
                expected_status="SKIPPED"
            ),
            TestCase(
                name="No Reqs + MCP Disabled",
                repo_name="repo_without_requirements",
                mcp_mode="disabled",
                use_docker=False,
                expected_status="SKIPPED"
            ),
        ]

        print(f"\n{'='*80}")
        print(f"PyCVE End-to-End Integration Test Suite")
        print(f"Testing {len(test_cases)} scenarios")
        print(f"{'='*80}")

        results = []
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n\n{'#'*80}")
            print(f"# TEST {i}/{len(test_cases)}")
            print(f"{'#'*80}")

            result = self.run_test(test_case)
            results.append(result)
            self.results.append(result)

            # Small delay between tests
            time.sleep(2)

        return results

    def print_summary(self):
        """Print test summary"""
        print(f"\n\n{'='*80}")
        print(f"TEST SUMMARY")
        print(f"{'='*80}")

        total = len(self.results)
        passed = sum(1 for r in self.results if r.get("passed", False))
        failed = total - passed

        print(f"\nTotal Tests: {total}")
        print(f"Passed: {passed} ✅")
        print(f"Failed: {failed} ❌")
        print(f"Success Rate: {passed/total*100:.1f}%")

        if failed > 0:
            print(f"\nFailed Tests:")
            for result in self.results:
                if not result.get("passed", False):
                    print(f"  ❌ {result['test_case']}")
                    if "error" in result:
                        print(f"     Error: {result['error']}")

        print(f"\n{'='*80}")

        # Save results to JSON
        results_file = PROJECT_ROOT / "test_e2e_results.json"
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"Results saved to: {results_file}")

        return passed == total

    def cleanup(self):
        """Cleanup after tests"""
        print(f"\nCleaning up...")
        self._restore_env()
        print(f"Environment restored")


def main():
    """Main test entry point"""
    runner = TestRunner()

    try:
        # Run all tests
        runner.run_all_tests()

        # Print summary
        all_passed = runner.print_summary()

        # Exit with appropriate code
        sys.exit(0 if all_passed else 1)

    except KeyboardInterrupt:
        print(f"\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nTest suite failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        runner.cleanup()


if __name__ == "__main__":
    main()
