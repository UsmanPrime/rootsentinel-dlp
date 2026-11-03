"""Bounded publication checks; reports locations, never matched secret values.

This complements manual review. Pattern scans cannot prove absence of every secret.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "github_token": rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",
    "aws_access_key": rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "credential_url": rb"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@",
    "private_windows_path": rb"[A-Za-z]:[\\/](?:Users[\\/]|OneDrive[^\r\n]*|tools[\\/])",
    "private_posix_home": rb"/(?:home|Users)/[a-zA-Z0-9_.-]+/",
}
FORBIDDEN_SUFFIXES = {".docx", ".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pyc", ".log"}
FORBIDDEN_PARTS = {"node_modules", "__pycache__", ".venv", ".aws", ".codex", ".agents", "runtime", "private", "secrets", "dist", "uploads", "snapshots"}


def audit():
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    findings, inventory = [], {}
    for name in sorted(set(filter(None, names))):
        path = ROOT / name
        if not path.exists():
            findings.append({"file": name, "rule": "missing_file"})
            continue
        if path.is_symlink() or path.suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_PARTS.intersection(path.relative_to(ROOT).parts) or (path.name.startswith(".env") and path.name != ".env.example"):
            findings.append({"file": name, "rule": "private_or_generated_file"})
        data = path.read_bytes()
        inventory[name] = hashlib.sha256(data).hexdigest()
        for rule, pattern in RULES.items():
            for match in re.finditer(pattern, data):
                findings.append({"file": name, "rule": rule, "line": data[:match.start()].count(b"\n") + 1})
    return {"candidate_count": len(inventory), "findings": findings,
            "scope": "Tracked and non-ignored candidates; credential/private-path patterns and file types. Manual diff review is also required.",
            "files": sorted(inventory)}


if __name__ == "__main__":
    result = audit()
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result["findings"]))
