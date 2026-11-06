"""Payload-free quarantine report. No bytes, paths, original names or credentials."""
from __future__ import annotations

from datetime import datetime, timezone
import json


def build_report(entry: dict, view: dict | None, *, held_file: bool) -> bytes:
    scan = (view or {}).get("scan") or {}
    decision = scan.get("decision") or {}
    matches = (scan.get("detection") or {}).get("matches") or []
    best = max(matches, key=lambda m: m.get("matched_bytes", 0), default=None)
    report = {
        "report_version": 1,
        "entry": entry["id"],
        "label": entry["label"],
        "size": entry["size"],
        "sha256": entry["sha256"],
        "transfer_id": entry.get("transfer"),
        "transfer_state": (view or {}).get("state", entry.get("tstate")),
        "decision_outcome": decision.get("outcome"),
        "decision_reason": decision.get("reason", entry.get("reason")),
        "incident_id": (view or {}).get("incident_id") or entry.get("incident"),
        "matching_versions": len(matches),
        "exact_match": any(m.get("exact") for m in matches),
        "best_coverage": best.get("coverage") if best else None,
        "file_held_in_quarantine": held_file,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Metadata only. The file was not delivered. No payload is included in this report.",
    }
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
