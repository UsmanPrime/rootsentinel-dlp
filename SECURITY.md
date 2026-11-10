# Security scope

This is a university prototype, not an endpoint protection product. The application
provides authenticated detection, policy evaluation and a controlled single-use
release gateway, both locally and on the hosted presenter demo. It withholds blocked
files and verifies approved snapshot bytes before sending. It does not control other
applications or arbitrary operating-system or network exfiltration. `public_demo` mode
denies operational API access, and the hosted demo has no anonymous access: every
account is provisioned by the operator.

Only use synthetic data in public demonstrations. Never put real source assets,
session tokens, passwords, keys, connection strings or private paths in issues,
logs, screenshots or commits. Do not upload original instructor DOCX files.

Report suspected vulnerabilities privately to the repository owner through an
available private GitHub reporting channel. If none is enabled, contact the owner
to establish a private channel before sharing sensitive reproduction details.
No reporting email or enabled private-reporting feature is assumed here.

Known boundaries: fixed chunks miss shifted, encoded, compressed and otherwise
transformed content; hashes reveal equality; Merkle proofs require a trusted root;
the gateway controls only its own release path; host compromise and key compromise
are outside the threat model. See the [threat model](docs/threat-model.md),
[authentication](docs/authentication.md) and [deployment](docs/deployment.md). Use
only synthetic inputs when validating changes.
