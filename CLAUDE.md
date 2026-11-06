# RootSentinel DLP — Claude Code Instructions

## Project
- Existing repository: `https://github.com/UsmanPrime/rootsentinel-dlp`
- Work only in this repository; do not create a replacement repository.
- Project: Hash-Based Data Loss Prevention (DLP).
- Read `ROOTSENTINEL_CLAUDE_HANDOFF.md` and the relevant `docs/evidence/` reports before planning work.

## Non-negotiable workflow
- Work one approved phase at a time. Do not begin the next phase until the user explicitly approves it.
- Before multi-file work, inspect the codebase and tests, then present a concise plan and risks.
- At the end of a phase, report PASS / PARTIAL / BLOCKED, exact changed files, tests actually run, CI result and URL, commit SHA, publication state, limitations, and remaining work. Then stop.
- Never state that a test, CI job, deployment, or Git operation succeeded unless you actually verified its result.
- Explain important design decisions in clear language so the user can defend the implementation in a university demo and interview.

## Security and architecture constraints
- The local staging-directory gateway is mandatory P0 under the instructor requirements.
- Keep the public browser workflow independently functional; do not make it depend on the local staging agent.
- Anonymous/public visitor workflows use synthetic fixtures only. Authenticated local/admin workflows may support bounded real uploads.
- Do not claim a directory watcher alone prevents arbitrary data exfiltration. Describe the actual controlled enforcement boundary.
- Do not claim protection against host compromise, key compromise, or arbitrary bypass paths unless implemented and tested.
- Be explicit about fixed-size chunk/block matching limitations, including shifted, encoded, compressed, or transformed content.
- Preserve the cryptographic core unless a verified defect or approved requirement justifies changing it.
- Protect secrets and real user data. Never print or commit `.env` contents, credentials, tokens, private keys, database dumps, or sensitive runtime data.
- Be careful with OneDrive synchronization; inspect ignore rules and local runtime storage behavior.

## Git and change safety
- No force-push, history rewrite, destructive reset, or overwriting remote history.
- Do not create/delete/restore branches, merge, rebase, deploy, or change global/system configuration unless explicitly authorized.
- Never add Co-Authored-By, Claude-Session or other AI attribution trailers to commits or pull request descriptions.
- Do not modify instructor specification files.
- Do not create paid resources or add paid dependencies/services without explicit approval.
- For audit-only tasks, make no file edits. Stop if unexpected divergence or uncommitted changes are found.

## Quality standards
- Read relevant implementation, tests, and docs before changing code.
- Prefer minimal, focused changes and existing dependencies.
- Add or update tests for security-sensitive behavior and negative cases.
- Verify both allowed and denied paths, including stale/expired/tampered cases where relevant.
- Keep evidence reproducible. Distinguish automated accessibility checks from a full accessibility audit.
- Do not overstate performance, security, compliance, or production readiness.

## User preferences
- User works primarily in Windows PowerShell.
- Give exact working directories and commands.
- Use direct, practical explanations; avoid filler and generic praise.
- Keep the user informed before consequential actions and wait for approval at phase boundaries.
