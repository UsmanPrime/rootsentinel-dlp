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

## Content-defined profile rs-cdc-gear-v1

A second detection profile, separate from everything above. It adds no field to the manifest, no leaf to
the Merkle tree and no proof. `rs-fixed-sha256-v1`, its manifests, descriptors, roots and fixed examples
are unchanged. The code is `backend/app/crypto/cdc.py`; the cut-point rule and the matching are in the
[detection specification](detection-spec.md#content-defined-chunks-rs-cdc-gear-v1).

### Gear table derivation

The rolling hash maps each byte value to a 64-bit constant. The published FastCDC table is a list of
random numbers. This profile derives its table from SHA-256 instead, so that anyone can recompute it and
no constant has to be trusted:

```text
domain  = the 38 ASCII bytes "RootSentinel rs-cdc-gear-v1 gear table"
block_c = SHA-256(domain || uint32_be(c))            for c = 0, 1, ..., 63
Gear[4c + k] = uint64_be(block_c[8k : 8k + 8])       for k = 0, 1, 2, 3
```

That is SHA-256 in counter mode over a fixed domain string: 64 digests of 32 bytes give 256 values of 8
bytes. `Gear[b]` is the value for byte `b`.

| Check | Value |
|---|---|
| `Gear[0]` | `0x7bf93287f471c4d9` |
| `Gear[255]` | `0x6a0ae301002d122c` |
| SHA-256 of the table (the 256 values as big-endian 64-bit integers, 2,048 bytes) | `6a80b73d855e1aaaba9dc9b54d5e9bd4047e1d2b1ea9803fb0e4b33ee28c1d13` |

The 256 values are distinct. The same hash is reported by `GET /api/v1/detection/profiles`.

### Rolling hash and masks

```text
fp = 0 at the first hashed byte of a chunk (512 bytes after the chunk start)
fp = ((fp << 1) + Gear[byte]) mod 2^64 for each following byte
cut before the byte whose update gives  fp & MASK == 0
MASK_S = 0x0000d93003530000   13 one-bits   used while the chunk is shorter than 2,048 bytes
MASK_L = 0x0000d90003500000    9 one-bits   used from 2,048 bytes on
```

`MASK_S` is the 13-bit mask printed in the paper (MaskA of Algorithm 2). `MASK_L` is the paper's 11-bit
MaskL with its two lowest one-bits (bits 16 and 17) cleared, which leaves 9 bits that are a subset of
`MASK_S`. Thirteen and nine bits are normalization level 2 around an 11-bit (2 KiB) expected size: two
bits more before the normal size, two bits fewer after it. The one-bits of `MASK_S` are bits 16, 17, 20,
22, 24, 25, 36, 37, 40, 43, 44, 46 and 47; `MASK_L` is the same without bits 16, 17, 36 and 37. They are
spread out as in the paper, up to bit 47, so that a decision depends on up to 48 preceding bytes and not
only on the last few.

A chunk identifier is `SHA-256(chunk_bytes)`. Unlike a fixed-profile descriptor it carries no index and
no length: the same content is the same chunk at any offset, which is the purpose of this profile.

### Security claims of this profile

- The gear hash is not a cryptographic hash and is not used as one. It only chooses boundaries. Anyone
  can compute where a file will be cut, and can construct content with no cut point or with many. The
  minimum and maximum chunk sizes bound the result either way.
- A match is SHA-256 equality of whole chunks. It shows that a run of bytes is identical to a registered
  run, subject to SHA-256's assumptions. It proves neither origin nor intent.
- Content-defined chunk rows are not committed to by any Merkle root or manifest. Their integrity is the
  integrity of the database row, protected against accidental change by insert-only triggers.
- Chunk hashes reveal equality and can support guesses of predictable content, as fixed block hashes do.

### Vectors

`fixtures/cdc-vectors.json` is a vector file of its own. It records the table hash, the first and last
four table values, the masks, and for nine inputs the exact cut points and chunk hashes: the empty input,
one byte, 512 and 513 bytes, a 65,536-byte SHA-256 counter stream, that stream with one byte in front and
with its first 100 bytes removed, 20,000 zero bytes and the synthetic source sample. Every input is
rebuilt from a rule written in the file; no payload is stored. `scripts/cdc_vectors.py` checks the file
and refuses to write it unless a second implementation, transcribed from the paper without any
optimisation, produces the same cut points. `backend/tests/test_cdc.py` recomputes the table from the rule
above, pins literal cut points and checks the chunking properties. The Phase 01 vectors
(`fixtures/manifest.json`, `backend/tests/test_crypto.py`) are untouched.

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
