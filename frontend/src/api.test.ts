import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, fixture, jsonBody } from "./api";
import { errorMessage } from "./lib/errors";
afterEach(() => vi.unstubAllGlobals());
describe("HTTP boundary", () => {
  it("sends same-origin cookies and CSRF only in the request header", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({ valid: true })));
    vi.stubGlobal("fetch", fetcher);
    expect(
      await api("/integrity/verify", jsonBody({ proof: {} }), "synthetic-csrf"),
    ).toEqual({ valid: true });
    const [path, init] = fetcher.mock.calls[0];
    expect(path).toBe("/api/v1/integrity/verify");
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe(
      "synthetic-csrf",
    );
    expect(localStorage.length).toBe(0);
  });
  it.each([400, 403, 409, 413, 429, 503])(
    "does not expose arbitrary server error text (%s)",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            new Response(
              JSON.stringify({
                error: { code: "<script>private payload</script>" },
              }),
              { status },
            ),
          ),
      );
      try {
        await api("/scans");
        throw new Error("expected failure");
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect(errorMessage(error)).not.toContain("private payload");
      }
    },
  );
  it("clears authenticated state on 401 but not invalid-login errors", async () => {
    const listener = vi.fn();
    window.addEventListener("rootsentinel:session-expired", listener);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation(() =>
          Promise.resolve(new Response("{}", { status: 401 })),
        ),
    );
    await expect(api("/auth/login")).rejects.toBeInstanceOf(ApiError);
    expect(listener).not.toHaveBeenCalled();
    await expect(api("/transfers")).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledOnce();
    window.removeEventListener("rootsentinel:session-expired", listener);
  });
  it("accepts empty logout responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    );
    expect(await api("/auth/logout")).toBeUndefined();
  });
  it("keeps renamed fixtures byte-identical and uneven fixtures genuinely uneven", () => {
    expect(fixture("protected")).toEqual(fixture("renamed"));
    expect(fixture("odd").byteLength).toBe(2049);
    expect(fixture("empty").byteLength).toBe(0);
  });
});
