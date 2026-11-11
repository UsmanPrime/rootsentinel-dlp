"""Scan-time measurement for the detection profiles against a running gateway (synthetic inputs only).

Signs in, reads the active policy, then times POST /api/v1/scans for inputs of several sizes: an unrelated
stream (no match) and a shifted copy of the synthetic source sample padded with the same stream (a
content-defined match when the seed asset is registered). The time is the whole request as a client sees
it: upload, snapshot, both fingerprints, lookups, decision and persistence.

  python -B scripts/benchmark_cdc.py --base-url http://127.0.0.1:8000 --origin https://example.invalid \
      --username NAME --password-file FILE [--runs 3] [--gate-bytes 65536 --gate-seconds 3]

The password comes from a one-line file outside the repository and is never printed.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
from app.synthetic import source_sample  # noqa: E402
from smoke_public import Gateway, header  # noqa: E402

SIZES = (65536, 262144, 1048576)


def stream(size: int) -> bytes:
    out, counter = bytearray(), 0
    while len(out) < size:
        out += sha256(b"rs-cdc-gear-v1 benchmark" + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:size])


def inputs(size: int) -> dict[str, bytes]:
    copy = b"!" + source_sample()
    return {"unrelated": stream(size), "shifted_copy": copy + stream(size - len(copy))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--origin")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--gate-bytes", type=int, default=65536, help="inputs up to this size must stay under --gate-seconds")
    parser.add_argument("--gate-seconds", type=float, default=3.0)
    parser.add_argument("--out", type=Path, help="write the JSON result here (outside the repository)")
    args = parser.parse_args(argv)
    gateway = Gateway(args.base_url, args.origin or args.base_url)
    password = args.password_file.read_text(encoding="utf-8").strip()
    status, headers, body = gateway.json("POST", "/api/v1/auth/login", json_body={"username": args.username, "password": password})
    if status != 200:
        print(f"sign-in failed with status {status}", file=sys.stderr)
        return 2
    cookie = header(headers, "set-cookie") or ""
    gateway.cookie, gateway.csrf = cookie.split("rs_session=", 1)[1].split(";", 1)[0], body["csrf_token"]
    _, _, policy = gateway.json("GET", "/api/v1/policies/active")
    result = {"policy": {k: policy.get(k) for k in ("number", "rule_set", "threshold", "cdc_threshold")}, "runs": args.runs, "rows": []}
    worst_gated = 0.0
    for size in SIZES:
        for name, data in inputs(size).items():
            times, last = [], None
            for _ in range(args.runs):
                started = time.perf_counter()
                status, _, last = gateway.json("POST", f"/api/v1/scans?filename={name}.bin", body=data,
                                               extra={"Content-Type": "application/octet-stream"}, timeout=300)
                times.append(time.perf_counter() - started)
                if status != 201:
                    print(f"scan of {name} ({size} bytes) failed with status {status}", file=sys.stderr)
                    return 2
            evidence = {e["profile_id"]: (e["chunk_count"], max((m["matched_bytes"] for m in e["matches"]), default=0))
                        for e in last["detection"].get("profiles", [])}
            row = {"input": name, "bytes": size, "median_s": round(statistics.median(times), 3), "max_s": round(max(times), 3),
                   "outcome": last["decision"]["outcome"], "reason": last["decision"]["reason"],
                   "profiles": {k: {"chunks": v[0], "largest_match_bytes": v[1]} for k, v in evidence.items()}}
            result["rows"].append(row)
            if size <= args.gate_bytes:
                worst_gated = max(worst_gated, max(times))
            print(f"{name:13} {size:8d} B  median {row['median_s']:7.3f} s  max {row['max_s']:7.3f} s  {row['outcome']} {row['reason']}")
    result["gate"] = {"bytes": args.gate_bytes, "seconds": args.gate_seconds, "worst_s": round(worst_gated, 3), "pass": worst_gated < args.gate_seconds}
    print(f"gate: inputs up to {args.gate_bytes} B under {args.gate_seconds} s: worst {worst_gated:.3f} s: {'PASS' if result['gate']['pass'] else 'FAIL'}")
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["gate"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
