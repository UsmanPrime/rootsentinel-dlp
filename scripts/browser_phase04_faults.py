"""Fault injection restricted to the ephemeral browser harness, never an operator DB."""
from pathlib import Path
import sqlite3


def inject(state: Path, operation: str, identifier: str | None = None):
    root = state.resolve(strict=True)
    if not (root / "browser-session.json").is_file():
        raise ValueError("Browser harness marker required")
    candidates = list(root.glob("session-*/runtime/database/rootsentinel.sqlite3"))
    if len(candidates) != 1 or root not in candidates[0].resolve().parents:
        raise ValueError("Exactly one contained browser database required")
    with sqlite3.connect(candidates[0]) as connection:
        users = {row[0] for row in connection.execute("SELECT username FROM users")}
        if users != {"browser-admin", "browser-analyst", "browser-employee", "browser-other"}:
            raise ValueError("Refusing non-harness database")
        if operation == "expire":
            cursor = connection.execute("UPDATE transfers SET expires_at='2000-01-01 00:00:00.000000' WHERE id=? AND state='ALLOWED'", (identifier,))
            assert cursor.rowcount == 1
        elif operation == "expire-session":
            connection.execute("UPDATE sessions SET expires_at='2000-01-01 00:00:00.000000'")
        elif operation == "audit-mac":
            # Audit events have immutable triggers. Corrupt the mutable head instead;
            # no security trigger is disabled even inside this disposable harness.
            cursor = connection.execute("UPDATE audit_heads SET mac=? WHERE id=1", ("0" * 64,))
            assert cursor.rowcount == 1
        else:
            raise ValueError("Unsupported browser fault")
