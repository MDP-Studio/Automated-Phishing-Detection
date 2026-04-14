"""
Diagnostic API health checks shared by the CLI tool, the legacy
test_apis.py script, and the /api/diagnose dashboard endpoint.

See `src/diagnostics/api_checks.py` for the actual checks. This package
exists to give the three call sites one source of truth instead of three
drifting copies (cycle 10 audit item #10).
"""
from src.diagnostics.api_checks import (
    CheckResult,
    CheckStatus,
    run_all_checks,
)

__all__ = ["CheckResult", "CheckStatus", "run_all_checks"]
