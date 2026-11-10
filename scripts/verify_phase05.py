"""Run the Phase 05 release checks and save sanitized, machine-readable actual results.

The most important check is the boundary: nothing under backend/app, backend/migrations,
docs/openapi.json or frontend/ may differ from the Phase 04 head, so the gateway's
cryptography, detection, policy, release and audit logic provably did not change.

    python -B scripts/verify_phase05.py            # writes docs/evidence/phase-05-checks.json
"""
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PHASE_04_HEAD = "3662f4fc46cc2648609cecf8fd63886fd2b78d2a"
BOUNDARY = ["backend/app", "backend/migrations", "docs/openapi.json", "frontend"]


def clean(text: str) -> str:
    for path, replacement in [(str(ROOT), "<workspace>"), (str(Path.home()), "<user-profile>"), (tempfile.gettempdir(), "<temp>")]:
        text = text.replace(path, replacement).replace(path.replace("\\", "/"), replacement)
    return text


def tail(text: str, lines: int = 14) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def references_to_agent() -> list[str]:
    hits = []
    for folder in ("backend/app", "frontend/src"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".ts", ".tsx", ".json", ".css"}:
                if "rootsentinel_agent" in path.read_text(encoding="utf-8", errors="ignore"):
                    hits.append(str(path.relative_to(ROOT)))
    return hits


def main() -> int:
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    npm = "npm.cmd" if os.name == "nt" else "npm"
    external = tempfile.mkdtemp(prefix="rs-verify-")
    dist_env = dict(env, ROOTSENTINEL_FRONTEND_DIST=str(Path(external) / "dist"))
    pytest_base = ["-m", "pytest", "-p", "no:cacheprovider", "-q"]
    checks = [
        ("backend", [sys.executable, "-B", *pytest_base, "--basetemp", str(Path(external) / "backend-tests")], env),
        ("agent", [sys.executable, "-B", *pytest_base, "--basetemp", str(Path(external) / "agent-tests")], env),
        (".", [sys.executable, "-B", "scripts/fixtures.py"], env),
        (".", [sys.executable, "-B", "scripts/frontend_contracts.py", "--check"], env),
        (".", [sys.executable, "-B", "scripts/source_corpus.py"], env),
        (".", [sys.executable, "-B", "scripts/audit_publication.py"], env),
        ("frontend", [npm, "run", "typecheck"], env),
        ("frontend", [npm, "test"], env),
        ("frontend", [npm, "run", "build"], dist_env),
        (".", ["git", "diff", "--check"], env),
        (".", ["git", "diff", "--exit-code", PHASE_04_HEAD, "--", *BOUNDARY], env),
        (".", ["git", "diff", "--exit-code", PHASE_04_HEAD, "--", "backend/app/crypto", "backend/tests/test_crypto.py", "fixtures/manifest.json"], env),
    ]
    results = []
    for cwd, command, run_env in checks:
        # Fixed argument lists (no shell) run with the developer's own environment; nothing comes from untrusted input.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        result = subprocess.run(command, cwd=ROOT / cwd, env=run_env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
        display = ["python" if part == sys.executable else str(part).replace(external, "<external-temp>") for part in command]
        output = tail(clean(result.stdout + result.stderr))
        if any(part.endswith("audit_publication.py") for part in display):
            try:
                audit = json.loads(result.stdout)
                output = f"candidates={audit['candidate_count']} findings={len(audit['findings'])} " + json.dumps(audit["findings"])
            except ValueError:
                pass
        results.append({"cwd": cwd, "command": display, "exit_code": result.returncode, "output": output})
        print(" ".join(display), "PASS" if result.returncode == 0 else "FAIL")
    hits = references_to_agent()
    results.append({"cwd": ".", "command": ["internal", "no backend/app or frontend/src file references rootsentinel_agent"],
                    "exit_code": 1 if hits else 0, "output": ", ".join(hits) or "no references"})
    print("independence check", "FAIL" if hits else "PASS")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = {"observed_at_utc": datetime.now(timezone.utc).isoformat(), "head_at_observation": head, "compared_against": PHASE_04_HEAD,
              "boundary_paths_unchanged": BOUNDARY,
              "environment": {"os": platform.system(), "architecture": platform.machine(), "python": platform.python_version(),
                              "node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(),
                              "dependencies": {name: importlib.metadata.version(name) for name in ["fastapi", "sqlalchemy", "alembic", "pydantic", "argon2-cffi", "pytest"]}},
              "checks": results, "local_checks_passed": all(r["exit_code"] == 0 for r in results),
              "not_observed": ["hosted Linux CI", "Python 3.12", "PostgreSQL", "hosted Windows CI"],
              "publication": "Not performed by this script."}
    (ROOT / "docs/evidence/phase-05-checks.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["local_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
