# Testing and evaluation

## Phase 01 commands

From `backend`: `python -B -m unittest discover -s tests -v` (no dependencies).
After installing the pinned test environment: `python -m pytest`.
From repository root: `python -B scripts/fixtures.py`.
From `frontend`: `npm ci --ignore-scripts --no-audit --no-fund`,
`npm run typecheck`, `npm run build`.

The test suite uses unittest cases discovered by both runners. It checks standard
SHA-256 vectors; exact chunk boundaries; short reads; raw encoding; independent
descriptor bytes and three-leaf tree expectations; every leaf for specified and
additional deterministic tree sizes; malformed proofs; empty trees; maximum/oversize
inputs; file mutations; ordering; and safe external path configuration.

`scripts/fixtures.py` constructs only synthetic bytes in memory. Its default mode
checks `fixtures/manifest.json`. `--write-manifest` deliberately updates the manifest
but never writes payload files. Do not use that flag to hide unexplained test drift.

## Required later security scenarios

Each result must record objective, fixture, expected decision, observed decision,
evidence, limitation, test command, commit/environment and actual pass/fail.

| Scenario | Expected baseline behavior |
|---|---|
| Exact and renamed protected file | BLOCK; release returns no payload |
| Ordinary distinct file | ALLOW; returned bytes have scanned digest |
| Empty file | Scan valid; protected registration rejected |
| Small/large files | Exact matching remains correct within 10 MiB bound |
| Single-byte change in multiblock file | Remaining aligned qualifying blocks trigger BLOCK |
| Aligned partial copy / embedding | BLOCK at configured threshold |
| One-byte boundary shift | Document expected fixed-block miss, not fake prevention |
| Encoding and line endings | Raw-byte differences; report lost matches honestly |
| Shared content | All implicated assets shown; no unique-ownership inference |
| Valid/corrupt proofs | Success/failure against separately trusted manifest |
| Concurrency | Isolated decisions; overload rejected; no duplicate delivery |
| Interrupted/oversized uploads | No release; cleanup; 413 for excess bytes |
| Malformed names, symlinks, traversal | Reject unsafe admission; no escaped file access |
| Policy precedence/admin override | Exact block wins; no privileged P0 bypass |
| Unauthorized/API cross-session access | Denied without evidence disclosure |
| Audit edits/reordering | Verification fails without attacker knowing audit key |
| Audit tail deletion | Detected against retained checkpoint; state residual limitation |
| TOCTOU mutation | Only frozen checked bytes can be delivered |
| Agent/network disconnection | No delivery on unknown decision; idempotent retry |
| Outside-gateway copy | Explicitly not prevented; do not invent a gateway event |
| Stale registry/policy | Rescan or deny before release |

No transfer, policy, auth, agent or audit test is claimed as passed in Phase 01.

## Benchmark protocol (later phase)

Use synthetic files of 0 B, 100 B, 1 KiB, 8 KiB, 1 MiB and 10 MiB. Compare fixed
chunk sizes 256 B, 1 KiB, 4 KiB offline without changing the product's v1 profile.
Perform five warm-ups and thirty measured repetitions; retain raw results,
environment and commit. Report median/p95/range, throughput, peak memory, fingerprint
storage, proof size and proof verification time. Separate cold public starts.

Measure precision/recall/FPR against labelled ground truth. Use N/A for zero
denominators. Separate detector recall from correct enforcement of its decision:
a correctly enforced ALLOW may still be a false negative. CDC comparisons require
a real validated implementation; no placeholder results. A two-second warm local
1 MiB target is unmeasured, not an achieved benchmark.
