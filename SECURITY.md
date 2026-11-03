# Security scope

This is a university prototype in development, not an endpoint protection product.
Phase 01 provides a fingerprint/proof library and a non-operational UI preview.
Do not rely on it to prevent real data loss.

Only use synthetic data in public demonstrations. Never put real source assets,
session tokens, passwords, keys, connection strings or private paths in issues,
logs, screenshots or commits. Do not upload original instructor DOCX files.

Report suspected vulnerabilities privately to the repository owner through an
available private GitHub reporting channel. If none is enabled, contact the owner
to establish a private channel before sharing sensitive reproduction details.
No reporting email or enabled private-reporting feature is assumed here.

Known boundaries: fixed chunks miss some modified content; hashes reveal equality;
Merkle proofs require a trusted root; the future gateway controls only its own
release path; host compromise is outside the threat model. See docs/architecture.md.
