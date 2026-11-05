import { webcrypto } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { verifyDownload } from "./Gateway";
afterEach(() => vi.unstubAllGlobals());
it("independently hashes actual downloaded bytes before saving", async () => {
  vi.stubGlobal("crypto", webcrypto);
  const bytes = new TextEncoder().encode("abc").buffer;
  expect(
    await verifyDownload(
      bytes,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      3,
    ),
  ).toHaveLength(64);
});
it.each(["digest", "length"])(
  "rejects a response %s mismatch",
  async (field) => {
    vi.stubGlobal("crypto", webcrypto);
    const data = new TextEncoder().encode("abc").buffer;
    await expect(
      verifyDownload(
        data,
        field === "digest"
          ? "0".repeat(64)
          : "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        field === "length" ? 4 : 3,
      ),
    ).rejects.toThrow("verification failed");
  },
);
