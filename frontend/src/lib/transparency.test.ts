// @vitest-environment node
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import {
  canonicalJson,
  eventLeafHash,
  fromHex,
  headBytes,
  loadSavedHead,
  saveHead,
  toHex,
  verifyConsistency,
  verifyHead,
  verifyInclusion,
} from "./transparency";
import type { TreeHeadView } from "./contracts";

// Roots and proofs used by the Certificate Transparency reference implementation (RFC 6962 and RFC 9162 trees
// are the same). Leaf inputs: "", 00, 10, 2021, 3031, 40414243, 5051525354555657, 60..6f.
const ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
const LEAF_1 = ROOTS[0]; // SHA-256(0x00 || "")
const LEAF_2 =
  "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7";
const PATH_1_OF_8 = [
  LEAF_2,
  "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
  "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
];
const PATH_2_OF_5 = [
  LEAF_1,
  "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
  "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
];
const CONSISTENCY_6_8 = [
  "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
  "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
];
const CONSISTENCY_2_5 = [
  "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
  "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
];

beforeAll(() => {
  if (!globalThis.crypto?.subtle)
    vi.stubGlobal("crypto", webcrypto as unknown as Crypto);
});
afterEach(() => vi.unstubAllGlobals());

function flip(hex: string) {
  return (hex[0] === "0" ? "1" : "0") + hex.slice(1);
}

describe("inclusion proofs (RFC 9162 2.1.3.2)", () => {
  it("accepts the published vectors", async () => {
    expect(await verifyInclusion(LEAF_1, 0, 1, [], ROOTS[0])).toBe(true);
    expect(await verifyInclusion(LEAF_1, 0, 8, PATH_1_OF_8, ROOTS[7])).toBe(
      true,
    );
    expect(await verifyInclusion(LEAF_2, 1, 5, PATH_2_OF_5, ROOTS[4])).toBe(
      true,
    );
  });
  it("rejects a changed leaf, root, path, index or size", async () => {
    expect(
      await verifyInclusion(flip(LEAF_1), 0, 8, PATH_1_OF_8, ROOTS[7]),
    ).toBe(false);
    expect(
      await verifyInclusion(LEAF_1, 0, 8, PATH_1_OF_8, flip(ROOTS[7])),
    ).toBe(false);
    expect(await verifyInclusion(LEAF_1, 1, 8, PATH_1_OF_8, ROOTS[7])).toBe(
      false,
    );
    expect(
      await verifyInclusion(LEAF_1, 0, 8, PATH_1_OF_8.slice(1), ROOTS[7]),
    ).toBe(false);
    expect(await verifyInclusion(LEAF_1, 0, 4, PATH_1_OF_8, ROOTS[7])).toBe(
      false,
    );
    expect(await verifyInclusion(LEAF_1, 8, 8, PATH_1_OF_8, ROOTS[7])).toBe(
      false,
    );
    expect(await verifyInclusion(LEAF_1, -1, 8, PATH_1_OF_8, ROOTS[7])).toBe(
      false,
    );
    expect(await verifyInclusion(LEAF_1, 0.5, 8, PATH_1_OF_8, ROOTS[7])).toBe(
      false,
    );
  });
});

describe("consistency proofs (RFC 9162 2.1.4.2)", () => {
  it("accepts the published vectors", async () => {
    expect(await verifyConsistency(1, 8, ROOTS[0], ROOTS[7], PATH_1_OF_8)).toBe(
      true,
    );
    expect(
      await verifyConsistency(6, 8, ROOTS[5], ROOTS[7], CONSISTENCY_6_8),
    ).toBe(true);
    expect(
      await verifyConsistency(2, 5, ROOTS[1], ROOTS[4], CONSISTENCY_2_5),
    ).toBe(true);
    expect(await verifyConsistency(8, 8, ROOTS[7], ROOTS[7], [])).toBe(true);
  });
  it("rejects a rewritten, forked, smaller or unproven tree", async () => {
    expect(
      await verifyConsistency(6, 8, flip(ROOTS[5]), ROOTS[7], CONSISTENCY_6_8),
    ).toBe(false);
    expect(
      await verifyConsistency(6, 8, ROOTS[5], flip(ROOTS[7]), CONSISTENCY_6_8),
    ).toBe(false);
    expect(
      await verifyConsistency(
        6,
        8,
        ROOTS[5],
        ROOTS[7],
        CONSISTENCY_6_8.slice(0, 2),
      ),
    ).toBe(false);
    expect(
      await verifyConsistency(5, 8, ROOTS[5], ROOTS[7], CONSISTENCY_6_8),
    ).toBe(false);
    expect(
      await verifyConsistency(8, 6, ROOTS[7], ROOTS[5], CONSISTENCY_6_8),
    ).toBe(false);
    expect(await verifyConsistency(6, 8, ROOTS[5], ROOTS[7], [])).toBe(false);
    expect(await verifyConsistency(0, 8, ROOTS[0], ROOTS[7], [])).toBe(false);
    expect(await verifyConsistency(8, 8, ROOTS[7], ROOTS[6], [])).toBe(false);
    expect(await verifyConsistency(8, 8, ROOTS[7], ROOTS[7], [ROOTS[7]])).toBe(
      false,
    );
  });
});

describe("canonical encoding", () => {
  it("matches the server: sorted keys, no whitespace, ASCII escapes", () => {
    expect(
      canonicalJson({ b: 1, a: { d: null, c: "x" }, list: [2, "y"], t: true }),
    ).toBe('{"a":{"c":"x","d":null},"b":1,"list":[2,"y"],"t":true}');
    expect(canonicalJson("café ✓ 😀 \u007f")).toBe(
      '"caf\\u00e9 \\u2713 \\ud83d\\ude00 \u007f"',
    );
    expect(canonicalJson('quote " slash \\ line\n')).toBe(
      '"quote \\" slash \\\\ line\\n"',
    );
    expect(() => canonicalJson(1.5)).toThrow();
    expect(() => canonicalJson(undefined)).toThrow();
  });
  it("hashes an event leaf as 0x00, the length, the canonical bytes and the MAC", async () => {
    const event = { sequence: 1, kind: "X" };
    const canonical = '{"kind":"X","sequence":1}';
    const data = new Uint8Array(1 + 4 + canonical.length + 32);
    data[4] = canonical.length;
    data.set(new TextEncoder().encode(canonical), 5);
    data.fill(0xab, 5 + canonical.length);
    const expected = toHex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", data)),
    );
    expect(await eventLeafHash(event, "ab".repeat(32))).toBe(expected);
    expect(await eventLeafHash(event, "cd".repeat(32))).not.toBe(expected);
    await expect(eventLeafHash(event, "ab".repeat(31))).rejects.toThrow();
    expect(() => fromHex("zz")).toThrow();
  });
});

describe("signed tree heads", () => {
  async function signedHead() {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const publicKey = new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey),
    );
    const keyId = toHex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)),
    );
    const head: TreeHeadView = {
      log_id: "6f1c0f0e-5a53-4f0b-9c38-0d6d1c2e9a11",
      tree_size: 64,
      root_hash: "11".repeat(32),
      timestamp: "2026-11-10T12:00:00.000000Z",
      key_id: keyId,
      signature: "",
    };
    head.signature = toHex(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          pair.privateKey,
          headBytes(head),
        ),
      ),
    );
    return { head, publicKey: toHex(publicKey) };
  }

  it("signs exactly the documented bytes", () => {
    const head: TreeHeadView = {
      log_id: "L",
      tree_size: 7,
      root_hash: "R",
      timestamp: "T",
      key_id: "K",
      signature: "ignored",
    };
    expect(new TextDecoder().decode(headBytes(head))).toBe(
      'RootSentinelSTH\u0000\u0001{"key_id":"K","log_id":"L","root_hash":"R","timestamp":"T","tree_size":7}',
    );
  });
  it("accepts a valid head and rejects every change", async () => {
    const { head, publicKey } = await signedHead();
    expect(await verifyHead(head, publicKey)).toBe("valid");
    expect(await verifyHead({ ...head, tree_size: 65 }, publicKey)).toBe(
      "invalid",
    );
    expect(
      await verifyHead({ ...head, root_hash: "12".repeat(32) }, publicKey),
    ).toBe("invalid");
    expect(
      await verifyHead({ ...head, signature: flip(head.signature) }, publicKey),
    ).toBe("invalid");
    expect(await verifyHead({ ...head, signature: "zz" }, publicKey)).toBe(
      "invalid",
    );
    const other = await signedHead();
    expect(await verifyHead(head, other.publicKey)).toBe("invalid"); // the key id does not name this key
    expect(
      await verifyHead({ ...head, key_id: other.head.key_id }, other.publicKey),
    ).toBe("invalid");
  });
  it("says so when the browser has no Ed25519", async () => {
    const { head, publicKey } = await signedHead();
    const unsupported = new Error("Unrecognized name.");
    unsupported.name = "NotSupportedError";
    vi.stubGlobal("crypto", {
      subtle: {
        digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
        importKey: () => Promise.reject(unsupported),
      },
    });
    expect(await verifyHead(head, publicKey)).toBe("unsupported");
  });
});

describe("the saved head", () => {
  const head = { log_id: "L", tree_size: 9, root_hash: "ab".repeat(32) };
  function storage(initial: Record<string, string> = {}) {
    const values = new Map(Object.entries(initial));
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => void values.set(k, v),
      removeItem: (k: string) => void values.delete(k),
    });
    return values;
  }
  it("round-trips and can be forgotten", () => {
    storage();
    expect(loadSavedHead()).toBeNull();
    expect(saveHead({ ...head, extra: "ignored" } as typeof head)).toBe(true);
    expect(loadSavedHead()).toEqual(head);
    expect(saveHead(null)).toBe(true);
    expect(loadSavedHead()).toBeNull();
  });
  it("ignores malformed stored values", () => {
    for (const bad of [
      "{not json",
      "[]",
      '{"log_id":1}',
      JSON.stringify({ ...head, tree_size: 0 }),
      JSON.stringify({ ...head, root_hash: "xyz" }),
    ]) {
      storage({ "rootsentinel.tree-head": bad });
      expect(loadSavedHead()).toBeNull();
    }
  });
  it("survives storage that throws or does not exist", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    });
    expect(loadSavedHead()).toBeNull();
    expect(saveHead(head)).toBe(false);
    expect(saveHead(null)).toBe(false);
    vi.stubGlobal("localStorage", undefined);
    expect(loadSavedHead()).toBeNull();
    expect(saveHead(head)).toBe(false);
  });
});
