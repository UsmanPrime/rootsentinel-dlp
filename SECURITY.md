# Security scope

This is a university prototype in development, not an endpoint protection product.
Phase 02 provides authenticated local detection and policy evaluation, with real
registry/evidence persistence. It has no release enforcement and must not be relied
on to prevent real data loss. Public-demo mode denies operational API access.

Only use synthetic data in public demonstrations. Never put real source assets,
session tokens, passwords, keys, connection strings or private paths in issues,
logs, screenshots or commits. Do not upload original instructor DOCX files.

Report suspected vulnerabilities privately to the repository owner through an
available private GitHub reporting channel. If none is enabled, contact the owner
to establish a private channel before sharing sensitive reproduction details.
No reporting email or enabled private-reporting feature is assumed here.

Known boundaries: fixed chunks miss some modified content; hashes reveal equality;
Merkle proofs require a trusted root; the future gateway controls only its own
release path; host compromise is outside the threat model. See docs/threat-model.md
and docs/authentication.md. Use only synthetic inputs while validating this phase.
