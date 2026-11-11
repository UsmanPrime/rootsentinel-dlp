import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import {
  assetEvidence,
  CDC_PROFILE,
  comparison,
  FIXED_PROFILE,
  profileEvidence,
  VerdictExplanation,
} from "./Verdict";
import type { PolicyView, ScanView } from "../lib/contracts";
import { SessionProvider } from "../lib/session";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const manifest = {
  spec_version: 1,
  profile_id: FIXED_PROFILE,
  file_size: 8503,
  chunk_size: 1024,
  chunk_count: 9,
  file_sha256: "a".repeat(64),
  merkle_root: "b".repeat(64),
};

/** The shape the server returns for a shifted copy judged by rs-policy-v2: fixed blocks miss, chunks match. */
const shifted: ScanView = {
  id: "s",
  actor_id: "u",
  filename: "shifted.py",
  snapshot_id: "n",
  created_at: "2026-11-11T00:00:00Z",
  policy_id: "p2",
  release_authorized: false,
  decision: {
    outcome: "BLOCK",
    reason: "CDC_THRESHOLD_MET",
    qualifying_versions: ["v1"],
  },
  detection: {
    manifest,
    registry_revision: 1,
    matches: [],
    profiles: [
      { profile_id: FIXED_PROFILE, chunk_count: 9, matches: [] },
      {
        profile_id: CDC_PROFILE,
        chunk_count: 4,
        matches: [
          {
            asset_id: "a1",
            version_id: "v1",
            matched_bytes: 7216,
            matched_chunks: 3,
            coverage: { numerator: 7216, denominator: 8503 },
            intervals: [[1287, 8503]],
          },
        ],
      },
    ],
  },
};

const policyV2: PolicyView = {
  id: "p2",
  number: 2,
  threshold: 1024,
  block_enabled: true,
  actor_id: null,
  created_at: "2026-11-11T00:00:00Z",
  rule_set: "rs-policy-v2",
  cdc_threshold: 2048,
};

const legacy: ScanView = {
  ...shifted,
  policy_id: "p1",
  decision: {
    outcome: "BLOCK",
    reason: "BLOCK_THRESHOLD_MET",
    qualifying_versions: ["v1"],
  },
  detection: {
    manifest,
    registry_revision: 1,
    matches: [
      {
        asset_id: "a1",
        version_id: "v1",
        exact: false,
        matched_bytes: 2048,
        coverage: { numerator: 2048, denominator: 8503 },
        intervals: [
          [0, 1024],
          [1024, 2048],
        ],
        blocks: [
          {
            length: 1024,
            sha256: "1".repeat(64),
            source_indices: [1, 2],
            outbound_indices: [0, 1],
          },
        ],
      },
    ],
  },
};

describe("per-profile evidence is taken from the scan, never invented", () => {
  it("lists one row per evaluated profile for each matched asset", () => {
    expect(assetEvidence(shifted)).toEqual([
      {
        asset_id: "a1",
        version_id: "v1",
        exact: false,
        largest: 7216,
        rows: [
          {
            profile_id: FIXED_PROFILE,
            matched_bytes: 0,
            matched_chunks: 0,
            chunk_count: 9,
            share: 0,
          },
          {
            profile_id: CDC_PROFILE,
            matched_bytes: 7216,
            matched_chunks: 3,
            chunk_count: 4,
            share: 7216 / 8503,
          },
        ],
      },
    ]);
  });
  it("derives the fixed profile's row when a record carries no profile list", () => {
    expect(profileEvidence(legacy).map((p) => p.profile_id)).toEqual([
      FIXED_PROFILE,
    ]);
    const [entry] = assetEvidence(legacy);
    expect(entry.rows).toEqual([
      {
        profile_id: FIXED_PROFILE,
        matched_bytes: 2048,
        matched_chunks: 2,
        chunk_count: 9,
        share: 2048 / 8503,
      },
    ]);
  });
  it("compares each profile with its own threshold", () => {
    expect(comparison(shifted, policyV2)).toBe(
      "Fixed blocks: largest single-asset match 0 bytes < threshold 1,024 bytes. " +
        "Content-defined chunks: largest single-asset match 7,216 bytes ≥ threshold 2,048 bytes.",
    );
    expect(comparison(legacy, { ...policyV2, cdc_threshold: null })).toBe(
      "Fixed blocks: largest single-asset match 2,048 bytes ≥ threshold 1,024 bytes.",
    );
    expect(comparison(shifted, undefined)).toContain(
      "Content-defined chunks: largest single-asset match 7,216 bytes.",
    );
    expect(
      comparison(
        {
          ...legacy,
          detection: { ...legacy.detection, matches: [] },
        },
        policyV2,
      ),
    ).toBe("No protected block or chunk matched this file.");
    expect(
      comparison(
        {
          ...legacy,
          decision: { ...legacy.decision, reason: "EXACT_PROTECTED_FILE" },
        },
        policyV2,
      ),
    ).toBe("Exact matches block regardless of the thresholds.");
  });
});

describe("the Why this decision panel", () => {
  function serve(policy: PolicyView) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string) =>
        Promise.resolve(
          new Response(
            JSON.stringify(
              String(url).endsWith("/policies/active")
                ? policy
                : String(url).endsWith("/auth/session")
                  ? {
                      user: { id: "u", username: "analyst", role: "ANALYST" },
                      csrf_token: "c",
                    }
                  : {
                      id: "a1",
                      label: "Token vault",
                      current_version: 1,
                      retired: false,
                      created_at: policy.created_at,
                    },
            ),
            { headers: { "Content-Type": "application/json" } },
          ),
        ),
      ),
    );
  }
  it("shows which profile matched, with bytes and chunk counts per profile", async () => {
    serve(policyV2);
    render(
      <SessionProvider>
        <MemoryRouter>
          <VerdictExplanation scan={shifted} privileged />
        </MemoryRouter>
      </SessionProvider>,
    );
    await waitFor(() => expect(screen.getByText("Token vault")).toBeTruthy());
    const text = document.body.textContent ?? "";
    expect(text).toContain("Content-defined threshold met");
    expect(text).toContain("rule set rs-policy-v2");
    expect(text).toContain("content-defined threshold 2,048 bytes");
    expect(text).toContain("7.0 KiB matched");
    expect(text).toContain("3 of 4 chunks");
    expect(text).toContain("0 of 9 blocks");
    expect(text).toContain("84.9% of this file");
    expect(text).not.toContain("were not evaluated");
  });
  it("says that content-defined chunks were not evaluated under rs-policy-v1", async () => {
    serve({
      ...policyV2,
      id: "p1",
      rule_set: "rs-policy-v1",
      cdc_threshold: null,
    });
    render(
      <SessionProvider>
        <MemoryRouter>
          <VerdictExplanation scan={legacy} privileged={false} />
        </MemoryRouter>
      </SessionProvider>,
    );
    await waitFor(() =>
      expect(document.body.textContent).toContain("rule set rs-policy-v1 ·"),
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("Content-defined chunks were not evaluated");
    expect(text).toContain("2 of 9 blocks");
    expect(text).not.toContain("of 4 chunks");
  });
});
