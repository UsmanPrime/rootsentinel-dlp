# Contributing

Use small changes tied to the current approved phase. Describe the behavior and
actual tests run. Do not fabricate contributions, benchmarks, test outputs or commits.

Before committing: inspect the diff, run relevant backend/frontend checks, verify
synthetic fixture manifests, and check that no runtime data, secrets, instructor
documents or sensitive paths are staged. Public evidence must be sanitized.

Backend checks run from `backend`; frontend checks run from `frontend`. See
docs/testing.md and docs/developer-guide.md. Stop the project's dev server before
reinstalling dependencies on Windows. Keep runtime data outside OneDrive.

Cryptographic or filesystem changes require another team member's review before
release. Document specification changes first, preserve old profile semantics, and
add tests that would fail for the bug being fixed. Frontend policy decisions must
not replace server authorization. New features must not weaken failure behavior.

The owner completed onboarding of the verified-empty remote. Preserve this local
history and working files. Publishing and deployment require explicit authorization.
Do not add a license until the team has selected one.
