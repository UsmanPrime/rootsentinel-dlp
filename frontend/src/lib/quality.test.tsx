import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import {
  EnvironmentProvider,
  environmentLabel,
  parseHealth,
  useEnvironment,
} from "./environment";
import { transferLabel } from "./files";
import { sortIncidents } from "../features/incidents/Incidents";
import { coverageShare, matchedBlockCount } from "../components/Verdict";
import type { MatchView } from "./contracts";

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

function Badge() {
  return <span>{environmentLabel(useEnvironment().hosted).badge}</span>;
}

function health(body: object) {
  return vi.fn().mockResolvedValue(new Response(JSON.stringify(body)));
}

describe("hosted badge comes from the server's /health, never from the hostname", () => {
  it("shows Hosted demo when the server reports a hosted deployment", async () => {
    const fetcher = health({
      status: "ok",
      hosted: true,
      commit: "abcdef1",
      max_upload_bytes: 1048576,
    });
    vi.stubGlobal("fetch", fetcher);
    render(
      <EnvironmentProvider>
        <Badge />
      </EnvironmentProvider>,
    );
    await waitFor(() => expect(screen.getByText("Hosted demo")).toBeTruthy());
    expect(fetcher.mock.calls[0][0]).toBe("/health");
  });
  it("shows Local when the server reports a local deployment", async () => {
    vi.stubGlobal("fetch", health({ status: "ok", hosted: false }));
    render(
      <EnvironmentProvider>
        <Badge />
      </EnvironmentProvider>,
    );
    await waitFor(() => expect(screen.getByText("Local")).toBeTruthy());
  });
  it("shows a neutral label when /health is unreachable or does not say", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    render(
      <EnvironmentProvider>
        <Badge />
      </EnvironmentProvider>,
    );
    expect(screen.getByText("Workspace")).toBeTruthy();
  });
  it("accepts only well-formed values", () => {
    expect(
      parseHealth({ hosted: "yes", commit: "$(rm)", max_upload_bytes: 12 }),
    ).toEqual({
      hosted: null,
      commit: "unknown",
      maxUploadBytes: 10485760,
      visitorMode: false,
      visitorUploadBytes: 65536,
    });
    expect(
      parseHealth({ hosted: true, commit: "0123abc", max_upload_bytes: 2048 }),
    ).toEqual({
      hosted: true,
      commit: "0123abc",
      maxUploadBytes: 2048,
      visitorMode: false,
      visitorUploadBytes: 65536,
    });
    expect(
      parseHealth({
        visitor_mode: true,
        visitor_upload_bytes: 4096,
        max_upload_bytes: 8192,
      }),
    ).toMatchObject({ visitorMode: true, visitorUploadBytes: 4096 });
    // Only the literal true turns the visitor entry on; a truthy string does not.
    expect(parseHealth({ visitor_mode: "true" }).visitorMode).toBe(false);
  });
});

describe("transfer labels follow the server's label rule", () => {
  it.each([
    ["report.txt", "report.txt"],
    ["Quarterly report (final).pdf", "Quarterly report (final).pdf"],
    ["../../etc/passwd", "etc_passwd"],
    ["naïve résumé.txt", "naive resume.txt"],
    ["名前.txt", "txt"],
    [".hidden", "hidden"],
    ["...", "candidate.bin"],
    ["", "candidate.bin"],
  ])("%s becomes %s", (name, expected) => {
    expect(transferLabel(name)).toBe(expected);
  });
  it("never exceeds 120 characters", () => {
    expect(transferLabel("a".repeat(300)).length).toBe(120);
  });
});

describe("verdict numbers come from the match evidence", () => {
  const match: MatchView = {
    asset_id: "a",
    version_id: "v",
    exact: false,
    matched_bytes: 2048,
    coverage: { numerator: 2048, denominator: 8192 },
    intervals: [[0, 2048]],
    blocks: [
      {
        length: 1024,
        sha256: "1".repeat(64),
        source_indices: [2],
        outbound_indices: [0, 5],
      },
      {
        length: 1024,
        sha256: "2".repeat(64),
        source_indices: [3],
        outbound_indices: [1, 5],
      },
    ],
  };
  it("counts distinct outbound blocks once", () => {
    expect(matchedBlockCount(match)).toBe(3);
  });
  it("computes the share of the submitted file", () => {
    expect(coverageShare(match)).toBe(0.25);
    expect(
      coverageShare({ ...match, coverage: { numerator: 0, denominator: 0 } }),
    ).toBe(0);
  });
});

describe("incident sorting applies to the rows on the page", () => {
  const rows = [
    {
      id: "1",
      transfer_id: "t",
      severity: "MEDIUM",
      status: "RESOLVED",
      revision: 1,
      created_at: "2026-11-10T01:00:00Z",
    },
    {
      id: "2",
      transfer_id: "t",
      severity: "HIGH",
      status: "OPEN",
      revision: 1,
      created_at: "2026-11-10T03:00:00Z",
    },
    {
      id: "3",
      transfer_id: "t",
      severity: "HIGH",
      status: "INVESTIGATING",
      revision: 1,
      created_at: "2026-11-10T02:00:00Z",
    },
  ];
  it("sorts by severity, then by identifier for a stable order", () => {
    expect(
      sortIncidents(rows, { column: "severity", direction: "descending" }).map(
        (r) => r.id,
      ),
    ).toEqual(["3", "2", "1"]);
  });
  it("sorts by status workflow order", () => {
    expect(
      sortIncidents(rows, { column: "status", direction: "ascending" }).map(
        (r) => r.id,
      ),
    ).toEqual(["2", "3", "1"]);
  });
  it("sorts by time and does not change the input", () => {
    expect(
      sortIncidents(rows, { column: "created_at", direction: "ascending" }).map(
        (r) => r.id,
      ),
    ).toEqual(["1", "3", "2"]);
    expect(rows.map((r) => r.id)).toEqual(["1", "2", "3"]);
  });
});
