# Cryptographic specification — v1

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

Registry asset IDs belong to the later persistence/API layer, not this deterministic
core manifest. The same input has the same cryptographic result across registrations.

## Fingerprints and descriptors

Whole-file digest: `SHA256(file_bytes)`. Matching key for a later detector:
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
No empty-tree inclusion proof exists. Future registry policy will reject empty
protected assets, while scanning an empty outbound file remains valid input.

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
- SHA-256 is unkeyed. Later session and audit secrets have separate lifecycles.
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
