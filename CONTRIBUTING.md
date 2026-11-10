# Contributing

Use small changes tied to the current approved phase. Describe the behavior and
actual tests run. Do not fabricate contributions, benchmarks, test outputs or commits.

Before committing: inspect the diff, run relevant backend/frontend checks, verify
synthetic fixture manifests, and check that no runtime data, secrets, instructor
documents or sensitive paths are staged. Public evidence must be sanitized.

Backend checks run from `backend`; frontend checks run from `frontend`. See
[testing](docs/testing.md) and the [developer guide](docs/developer-guide.md). Stop
the project's dev server before reinstalling dependencies on Windows. Keep runtime
data outside OneDrive.

Cryptographic or filesystem changes require another team member's review before
release. Document specification changes first, preserve old profile semantics, and
add tests that would fail for the bug being fixed. Frontend policy decisions must
not replace server authorization. New features must not weaken failure behavior.

`main` is protected. Work on a branch and merge only after CI passes. A push to
`main` deploys the hosted demo once its checks pass, so treat every push to `main`
as a deploy ([deployment](docs/deployment.md)). Do not add a license until the team
has selected one.
