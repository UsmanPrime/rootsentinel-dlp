# Research references and verification status

The following primary-source pages were inspected in Phase 00. This is a record
of that review, not a claim they were fetched again during restricted Phase 01.
Recheck hosting quotas and dependency/security advisories before deployment.

| Source | Application |
|---|---|
| [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | SHA-256 definition; no claim of validated deployment |
| [Python hashlib](https://docs.python.org/3/library/hashlib.html) | Standard-library hashing |
| [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1) | Ordered Merkle tree shape, domain separation and inclusion verification |
| [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) | Planned HMAC audit authentication |
| [Microsoft document fingerprinting](https://learn.microsoft.com/en-us/purview/sit-document-fingerprinting) | Industry context; not equivalent to this fixed-block algorithm |
| [FastCDC, USENIX ATC 2016](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia) | CDC performance/redundancy trade-offs; published metrics are not our results |
| [Restic design](https://restic.readthedocs.io/en/stable/100_references.html#backups-and-deduplication) | Practical content-defined boundaries and insertion resilience |
| [OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | Input limits, untrusted names, private storage |
| [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Exclude source/secrets; sanitize metadata; protect audit information |
| [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Session lifecycle and cookie protections |
| [MITRE ATT&CK Exfiltration](https://attack.mitre.org/tactics/TA0010/) | Alternative channels, transformations and residual bypasses |
| [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) | Integrity/audit control context, not compliance certification |
| [Python OS](https://docs.python.org/3.12/library/os.html) | Platform-specific filesystem capabilities |
| [Watchdog quickstart](https://watchdog.readthedocs.io/en/stable/quickstart.html) | Observation is not enforcement; polling chosen initially |
| [FastAPI WebSockets](https://fastapi.tiangolo.com/advanced/websockets/) | P1 notification option; REST remains authoritative |
| [WCAG 2.2 quick reference](https://www.w3.org/WAI/WCAG22/quickref/) | Accessibility target, not an audited conformance claim |
| [Render free services](https://render.com/docs/free) | Idle sleep, ephemeral storage, quotas and free DB expiry |
| [Neon plans](https://neon.com/docs/introduction/plans) | Persistent free-tier PostgreSQL candidate, subject to quotas |

High confidence: normative algorithm definitions and directly inspected documented
behavior. Conditional confidence: future hosting feasibility and target latency.
Experimental hypothesis: CDC improves this project's shift resistance; it requires
our own implemented comparison. Fixed-size blocks remain v1 for simplicity and
testability. No independently measured detection/performance result exists yet.
