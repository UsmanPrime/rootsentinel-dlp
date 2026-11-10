/**
 * Browser-side checks for the audit transparency log. Everything here recomputes what the server claims:
 * RFC 9162 leaf and node hashes, inclusion and consistency proofs (sections 2.1.3.2 and 2.1.4.2), and the
 * Ed25519 signature of a signed tree head. Only WebCrypto is used; nothing is sent anywhere.
 */
import type { TreeHeadView } from "./contracts";

type Bytes = Uint8Array<ArrayBuffer>;

export function fromHex(value: string): Bytes {
  if (!/^(?:[0-9a-f]{2})*$/.test(value)) throw new Error("INVALID_HEX");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(value.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(value: Uint8Array): string {
  return Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
}

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function ascii(text: string): Bytes {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code > 127) throw new Error("NOT_ASCII");
    out[i] = code;
  }
  return out;
}

/** The server's canonical JSON: keys sorted, no whitespace, ASCII only (other characters as \uXXXX). */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("NOT_AN_INTEGER");
    return String(value);
  }
  if (typeof value === "string")
    return JSON.stringify(value).replace(
      /[\u0080-\uffff]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  if (Array.isArray(value))
    return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(record)
        .sort()
        .map((key) => canonicalJson(key) + ":" + canonicalJson(record[key]))
        .join(",") +
      "}"
    );
  }
  throw new Error("NOT_JSON");
}

/** Leaf hash of one audit event: SHA-256(0x00 || u32be(len(canonical)) || canonical || 32 MAC bytes). */
export async function eventLeafHash(
  event: unknown,
  mac: string,
): Promise<string> {
  const canonical = ascii(canonicalJson(event));
  const rawMac = fromHex(mac);
  if (rawMac.length !== 32) throw new Error("INVALID_MAC");
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, canonical.length);
  return toHex(
    await sha256(concat(new Uint8Array([0]), length, canonical, rawMac)),
  );
}

async function node(left: Bytes, right: Bytes): Promise<Bytes> {
  return sha256(concat(new Uint8Array([1]), left, right));
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** RFC 9162 section 2.1.3.2. Sizes stay far below 2^31, so integer bit operations are exact. */
export async function verifyInclusion(
  leafHash: string,
  index: number,
  size: number,
  path: string[],
  root: string,
): Promise<boolean> {
  if (!Number.isInteger(index) || !Number.isInteger(size)) return false;
  if (index < 0 || index >= size) return false;
  let fn = index,
    sn = size - 1,
    r = fromHex(leafHash);
  for (const step of path) {
    const p = fromHex(step);
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = await node(p, r);
      if (!(fn & 1))
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
    } else r = await node(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && same(r, fromHex(root));
}

/** RFC 9162 section 2.1.4.2 for 0 < first < second; equal sizes need equal roots and an empty path. */
export async function verifyConsistency(
  first: number,
  second: number,
  firstRoot: string,
  secondRoot: string,
  path: string[],
): Promise<boolean> {
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first < 1 || first > second) return false;
  if (first === second) return path.length === 0 && firstRoot === secondRoot;
  if (!path.length) return false;
  const steps = path.map(fromHex);
  if ((first & (first - 1)) === 0) steps.unshift(fromHex(firstRoot));
  let fn = first - 1,
    sn = second - 1;
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = steps[0],
    sr = steps[0];
  for (const c of steps.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = await node(c, fr);
      sr = await node(c, sr);
      if (!(fn & 1))
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
    } else sr = await node(sr, c);
    fn >>= 1;
    sn >>= 1;
  }
  return (
    same(fr, fromHex(firstRoot)) && same(sr, fromHex(secondRoot)) && sn === 0
  );
}

/** The exact signed bytes: the domain prefix, then the five fields as canonical JSON. */
export function headBytes(head: TreeHeadView): Bytes {
  const fields = {
    key_id: head.key_id,
    log_id: head.log_id,
    root_hash: head.root_hash,
    timestamp: head.timestamp,
    tree_size: head.tree_size,
  };
  return concat(
    ascii("RootSentinelSTH"),
    new Uint8Array([0, 1]),
    ascii(canonicalJson(fields)),
  );
}

export type SignatureCheck = "valid" | "invalid" | "unsupported";

/**
 * Checks that the key id is the SHA-256 of the public key and that the Ed25519 signature covers this head.
 * "unsupported" means this browser has no WebCrypto Ed25519, so nothing was checked.
 */
export async function verifyHead(
  head: TreeHeadView,
  publicKey: string,
): Promise<SignatureCheck> {
  let key: CryptoKey;
  try {
    const raw = fromHex(publicKey);
    if (toHex(await sha256(raw)) !== head.key_id) return "invalid";
    key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    return name === "NotSupportedError" || name === "TypeError"
      ? "unsupported"
      : "invalid";
  }
  try {
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      fromHex(head.signature),
      headBytes(head),
    );
    return valid ? "valid" : "invalid";
  } catch {
    return "invalid";
  }
}

const STORE = "rootsentinel.tree-head";
export type SavedHead = {
  log_id: string;
  tree_size: number;
  root_hash: string;
};

/** The last head this browser accepted. Storage can be unavailable or blocked, so every access is guarded. */
export function loadSavedHead(): SavedHead | null {
  try {
    const value = JSON.parse(localStorage.getItem(STORE) ?? "null");
    if (
      value &&
      typeof value.log_id === "string" &&
      Number.isInteger(value.tree_size) &&
      value.tree_size > 0 &&
      /^[0-9a-f]{64}$/.test(value.root_hash)
    )
      return {
        log_id: value.log_id,
        tree_size: value.tree_size,
        root_hash: value.root_hash,
      };
  } catch {
    /* unreadable or blocked storage is the same as nothing saved */
  }
  return null;
}

export function saveHead(head: SavedHead | null): boolean {
  try {
    if (head)
      localStorage.setItem(
        STORE,
        JSON.stringify({
          log_id: head.log_id,
          tree_size: head.tree_size,
          root_hash: head.root_hash,
        }),
      );
    else localStorage.removeItem(STORE);
    return true;
  } catch {
    return false;
  }
}
