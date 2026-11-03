"""Run release checks and save sanitized, machine-readable actual results."""
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def clean(text):
    for path, replacement in [(str(ROOT), "<workspace>"), (str(Path.home()), "<user-profile>")]:
        text = text.replace(path, replacement).replace(path.replace("\\", "/"), replacement)
    return text


def main():
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    npm = "npm.cmd" if os.name == "nt" else "npm"
    checks = [
        ("backend", [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q"]),
        (".", [sys.executable, "-B", "scripts/fixtures.py"]),
        (".", [sys.executable, "-m", "pip", "check"]),
        ("frontend", [npm, "run", "typecheck"]),
        ("frontend", [npm, "run", "build"]),
        (".", ["git", "diff", "--check"]),
        (".", ["git", "diff", "--exit-code", "566c2df540e013a56010af7cd1485e55832da6ac", "--", "backend/app/crypto", "backend/tests/test_crypto.py", "fixtures/manifest.json"]),
    ]
    results = []
    for cwd, command in checks:
        result = subprocess.run(command, cwd=ROOT / cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        display = ["python" if part == sys.executable else part for part in command]
        output = clean(result.stdout + result.stderr)
        results.append({"cwd": cwd, "command": display, "exit_code": result.returncode, "output": output})
        print(" ".join(display), "PASS" if result.returncode == 0 else "FAIL")
    report = {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "pre_checkpoint_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "environment": {"os": platform.system(), "architecture": platform.machine(), "python": platform.python_version(),
                        "dependencies": {name: importlib.metadata.version(name) for name in ["fastapi", "sqlalchemy", "alembic", "pydantic", "argon2-cffi", "pytest"]}},
        "checks": results, "local_checks_passed": all(r["exit_code"] == 0 for r in results),
        "postgresql_test_url_present": bool(env.get("ROOTSENTINEL_TEST_POSTGRES_URL")),
        "publication": "Not performed by this script; see phase-03.md and checkpoint evidence."}
    (ROOT / "docs/evidence/phase-03-checks.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["local_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
