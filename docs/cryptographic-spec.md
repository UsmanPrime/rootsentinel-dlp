# Cryptographic specification, version 1

## Public contract

Profile `rs-fixed-sha256-v1`, specification version `1`, chunk size 1024 bytes,
maximum file size 10 MiB. All input is raw bytes: no filename contribution, text
decoding, newline conversion, Unicode normalization or whitespace trimming.

`fingerprint_bytes(bytes)` and `fingerprint_stream(binary_stream)` return an
immutable `Fingerprint(manifest, chunks)`. Streams are read from their current
position through EOF and remain owned by the caller. Short reads are reassembled
into profile-defined blocks. This library does not provide snapshot isolation.

`Manifest` JSON fields:

| Field | Type / meaning |
|---|---|
| spec_version | integer 1; booleans rejected |
| profile_id | exact profile identifier |
| file_size | integer 0 through 10485760 |
| chunk_size | integer 1024 |
| chunk_count | ceil(file_size / 1024), zero for empty files |
| file_sha256 | 64 lowercase hex characters |
| merkle_root | 64 lowercase hex characters |

Registry asset IDs belong to the persistence/API layer, not this deterministic
core manifest. The same input has the same cryptographic result across registrations.

## Fingerprints and descriptors

Whole-file digest: `SHA256(file_bytes)`. Matching key used by the detector in `backend/app/detection.py`:
`(profile_id, chunk_length, SHA256(chunk_bytes))`. Do not use the Merkle leaf as the
matching key because a leaf also commits to the protected file's chunk index.

Chunks are non-overlapping, ordered from offset zero. The final chunk may be short;
there is no empty trailing chunk. A descriptor is exactly 44 bytes:

```text
uint64_be(index) || uint32_be(length) || SHA256(chunk_bytes)
```

Chunk JSON contains `index`, `length`, `sha256`. Offset is derived as `index * 1024`.
Indices must be contiguous in fingerprints and lengths must agree with file size.

## Tree

With `H = hashlib.sha256`, apply the ordered tree shape from
[RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1):

```text
root([]) = H(empty_bytes)
root([descriptor]) = H(0x00 || descriptor)
root(D), n > 1 = H(0x01 || root(D[:k]) || root(D[k:]))
k = largest power of two strictly less than n
```

Prefixes separate leaves from internal nodes. Odd trees split recursively: do not
duplicate or pad nodes. RootSentinel's descriptor is a project-specific payload;
this is not a Certificate Transparency protocol implementation.

Empty file: zero chunks, file hash and root both
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
No empty-tree inclusion proof exists. The registry rejects empty protected assets
(`EMPTY_PROTECTED_ASSET`, HTTP 422), while scanning an empty outbound file remains valid input.

## Proofs and trust

`create_proof(fingerprint, index)` returns `spec_version`, `profile_id`, `tree_size`,
`chunk`, and a bottom-up `siblings` array of lowercase digest strings. There is
**no root in the proof package**. Directions derive from index and tree size.

`verify_proof(proof, trusted_manifest, chunk_bytes=None)` returns a boolean and
rejects malformed input. It validates manifest sizes, index bounds, profile,
descriptor length and sibling count; traverses per RFC 9162 §2.1.3.2; consumes the
complete path; and compares the computed root. Maximum path length is 14 for the
supported file limit. Missing/extra siblings, uppercase/nonhex hashes, unknown
fields and unsupported versions are rejected.

If chunk bytes are provided, their digest and length must match the descriptor.
Otherwise only descriptor inclusion is verified. The caller must obtain the
expected manifest from an authorized registry or independently retained baseline.
A successful proof does not authenticate an attacker-selected manifest.

`verify_file(bytes, trusted_manifest)` recomputes the complete manifest. Inclusion
does not by itself check the manifest's whole-file hash: a proof covers a selected
descriptor; whole-file verification covers all bytes.

## Security claims

- Digests identify bytes subject to SHA-256's cryptographic assumptions; they do
  not encrypt data or establish ownership.
- A Merkle proof establishes ordered inclusion under a trusted root, not release
  permission or the secrecy of file content.
- Fingerprints reveal equality and can support guesses of predictable content.
- SHA-256 is unkeyed. Session tokens and audit keys are separate secrets with their own lifecycles.
- No claim of FIPS validation is made merely because `hashlib` implements SHA-256.

## Fixed independent examples

For `abc`, file SHA-256 is
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`;
the single-leaf root is
`a34106b7957e189e60f1bd7506a867159d5ea04a8bbcdeb379425343f842f6bf`.

For `A` repeated 1024 bytes, then `B` repeated 1024 bytes, then one `C`, root is
`b77f5d4eb26d8387914ce5dd21753f67c1594343db08d9ffab1ace114aae98de`.
Its shape is `node(node(leaf0, leaf1), leaf2)`.

## Phase 03 keyed audit extension

The file fingerprint/Merkle specification above is unchanged. SHA-256 file hashes are
unkeyed; the audit protocol separately uses HMAC-SHA-256 with 32-byte random secret keys.
Canonical serialization, length/domain prefixes, sequence linkage, rotation and checkpoint
verification are fully specified in [audit-spec.md](audit-spec.md). Independent reference
HMAC tests do not reuse the production MAC helper. Download preflight independently hashes
the actual immutable delivery bytes and compares both digest and byte length with the
approved scan manifest; the same buffer is sent.

## Audit transparency log: tree and signed tree heads

The fingerprint tree above (`crypto/merkle.py`, profile `rs-fixed-sha256-v1`) is unchanged. The audit log uses a
second, separate tree in `backend/app/crypto/transparency.py`, built exactly as RFC 9162 section 2.1 defines it. The
two trees share no code and no domain: an asset proof can never be presented as an audit proof.

### Tree (RFC 9162 section 2.1.1)

| Item | Definition |
|---|---|
| Hash | SHA-256, 32 bytes |
| Empty tree | `SHA-256("")` |
| Leaf hash | `SHA-256(0x00 || leaf_data)` |
| Node hash | `SHA-256(0x01 || left || right)` |
| Split | a tree of `n > 1` leaves splits at `k`, the largest power of two smaller than `n`; `MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n]))` |
| Leaf order | leaf index = audit sequence number minus 1; one leaf per audit event, no gaps |

`leaf_data` for one audit event is the concatenation of three parts:

1. the byte length of the canonical event text as an unsigned 32-bit big-endian integer (4 bytes);
2. the canonical event text itself, ASCII, exactly the string stored in `audit_events.canonical` and defined in the
   [audit protocol](audit-spec.md#event-encoding) (sorted keys, no whitespace, ASCII only);
3. the 32 raw bytes of that event's HMAC (the stored value is 64 lowercase hex characters).

The leaf therefore binds both what the event says and the keyed MAC that links it into the chain.

### Proofs

| Proof | Generation | Verification |
|---|---|---|
| Inclusion of leaf `m` in a tree of size `n` | `PATH(m, D[n])`, RFC 9162 section 2.1.3.1 | section 2.1.3.2 |
| Consistency of size `m` with size `n` | `PROOF(m, D[n])`, section 2.1.4.1 | section 2.1.4.2 |

Two cases outside the RFC text are fixed here. Equal sizes are consistent only with an empty path and equal roots. A
first size of zero is never accepted: an empty tree proves nothing about a later one. Every proof value is a 32-byte
hash, written as 64 lowercase hex characters in the API.

An inclusion path does not by itself identify the tree size: two sizes that give a leaf the same path shape accept
the same path. The size is bound by the signed tree head, whose root belongs to exactly one size.

### Signed tree head

A tree head has five fields. The signed bytes are the 17-byte domain prefix `RootSentinelSTH || 0x00 || 0x01`
followed by the five fields as canonical JSON: keys in the order `key_id`, `log_id`, `root_hash`, `timestamp`,
`tree_size`; no whitespace; ASCII only.

| Field | Value |
|---|---|
| `log_id` | the audit stream id (a UUID string) |
| `tree_size` | number of leaves, a JSON integer from 1 to 20000 |
| `root_hash` | 64 lowercase hex characters |
| `timestamp` | UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ`, the same form as event timestamps |
| `key_id` | 64 lowercase hex characters: SHA-256 of the 32 raw public key bytes |

Example of the signed bytes (the two prefix bytes shown as escapes):

```text
RootSentinelSTH\x00\x01{"key_id":"<64 hex>","log_id":"6f1c0f0e-5a53-4f0b-9c38-0d6d1c2e9a11","root_hash":"<64 hex>","timestamp":"2026-11-10T12:00:00.000000Z","tree_size":64}
```

The signature is Ed25519 (RFC 8032) over those bytes, 64 bytes, written as 128 lowercase hex characters. It is made
with the `cryptography` library; the browser verifies it with WebCrypto and `scripts/witness.py` with `cryptography`
again, from its own copy of this encoding. A verifier must check two things: that `key_id` is the SHA-256 of the
public key it trusts, and that the signature verifies under that key.

### Signing key lifecycle

| Stage | Rule |
|---|---|
| Generation | `python -m app.audit_keys init-transparency <absolute private path>` on the operator's machine. The seed comes from the library's key generator. The command prints the key id and the path, never key bytes, and never overwrites a file |
| Storage | A JSON file, mode 0600 in a 0700 directory: `{"version":1,"algorithm":"Ed25519","active_id":<key id>,"keys":{<key id>:<base64 of the 32-byte seed>}}`. It is a separate file from the HMAC keyring and is named by `ROOTSENTINEL_TRANSPARENCY_KEY_FILE`. It is read with the same checks as the keyring (regular file, no links, no group or other access, Windows ACL check). It must not be inside the runtime or source tree |
| Use | Only the active key signs. The public keys of all keys in the file are served by `GET /api/v1/transparency/key` |
| Public key for a witness | `python -m app.audit_keys public-transparency <path>` prints the public keys only. A witness pins them in a local file |
| Rotation, by key id | Stop the worker, back up the file, run `python -m app.audit_keys rotate-transparency <same path>`, restart. The new key becomes active; earlier keys stay in the file so that earlier heads still verify. Each head names the key that signed it. Up to 32 keys. Give the new public key to every witness before it is used |
| Missing key | No head can be signed, so nothing is accepted for release and no release is made (`TRANSPARENCY_KEY_UNAVAILABLE`). The hosted container refuses to start without the file |
| Compromise | A holder of the seed can sign any head for any tree. Stop the service, remove the key from use, start a new audit stream in a new database under a new key, and tell every witness to distrust heads under the old key id that it has not already saved. Heads a witness saved before the compromise stay meaningful; later ones do not. Rotation alone does not undo a compromise, because the old key still verifies |

### Published vectors and tests

`backend/tests/test_transparency_tree.py` checks every root, every inclusion proof and every consistency proof for
tree sizes 1 to 128 against a reference written directly from the RFC definitions, and the roots and proofs used by the
Certificate Transparency reference implementation for the eight inputs "", `00`, `10`, `2021`, `3031`, `40414243`,
`5051525354555657`, `606162636465666768696a6b6c6d6e6f` (root of all eight:
`5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328`). The same vectors are checked by the browser
code (`frontend/src/lib/transparency.test.ts`) and the witness (`backend/tests/test_witness.py`). RFC 8032 test 1
fixes the key derivation.
