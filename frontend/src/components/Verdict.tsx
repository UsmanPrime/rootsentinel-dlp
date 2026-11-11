import { Link } from "react-router-dom";
import type {
  AssetView,
  MatchView,
  PolicyPage,
  PolicyView,
  ProfileEvidence,
  ScanView,
} from "../lib/contracts";
import { useGet } from "../lib/hooks";
import { bytes, short } from "../lib/errors";
import { CoverageBar } from "./CoverageBar";

export const FIXED_PROFILE = "rs-fixed-sha256-v1";
export const CDC_PROFILE = "rs-cdc-gear-v1";

/** What a profile's units are called in the interface. */
export const PROFILE_NAMES: Record<string, { name: string; unit: string }> = {
  [FIXED_PROFILE]: { name: "Fixed 1 KiB blocks", unit: "blocks" },
  [CDC_PROFILE]: { name: "Content-defined chunks", unit: "chunks" },
};

/** Distinct outbound chunk positions that matched a protected block. */
export function matchedBlockCount(match: MatchView) {
  return new Set(match.blocks.flatMap((block) => block.outbound_indices)).size;
}

export function coverageShare(match: {
  coverage: { numerator: number; denominator: number };
}) {
  const { numerator, denominator } = match.coverage;
  return denominator ? numerator / denominator : 0;
}

/**
 * The per-profile evidence of a scan. The server lists every profile the policy evaluated; a record read through
 * an older contract has none, and then the fixed profile's entry is derived from the block matches.
 */
export function profileEvidence(scan: ScanView): ProfileEvidence[] {
  const listed = scan.detection.profiles ?? [];
  if (listed.length) return listed;
  return [
    {
      profile_id: FIXED_PROFILE,
      chunk_count: scan.detection.manifest.chunk_count,
      matches: scan.detection.matches.map((match) => ({
        asset_id: match.asset_id,
        version_id: match.version_id,
        matched_bytes: match.matched_bytes,
        matched_chunks: matchedBlockCount(match),
        coverage: match.coverage,
        intervals: match.intervals,
      })),
    },
  ];
}

export type ProfileRow = {
  profile_id: string;
  matched_bytes: number;
  matched_chunks: number;
  chunk_count: number;
  share: number;
};

export type AssetEvidence = {
  asset_id: string;
  version_id: string;
  exact: boolean;
  largest: number;
  rows: ProfileRow[];
};

/**
 * One entry per matched asset version, with one row per evaluated profile (zeros when that profile found nothing
 * for the version). Sorted by the largest matched byte count of any profile.
 */
export function assetEvidence(scan: ScanView): AssetEvidence[] {
  const evidence = profileEvidence(scan);
  const versions = new Map<string, AssetEvidence>();
  for (const profile of evidence)
    for (const match of profile.matches)
      if (!versions.has(match.version_id))
        versions.set(match.version_id, {
          asset_id: match.asset_id,
          version_id: match.version_id,
          exact: scan.detection.matches.some(
            (m) => m.version_id === match.version_id && m.exact,
          ),
          largest: 0,
          rows: [],
        });
  for (const entry of versions.values()) {
    entry.rows = evidence.map((profile) => {
      const match = profile.matches.find(
        (m) => m.version_id === entry.version_id,
      );
      return {
        profile_id: profile.profile_id,
        matched_bytes: match?.matched_bytes ?? 0,
        matched_chunks: match?.matched_chunks ?? 0,
        chunk_count: profile.chunk_count,
        share: match ? coverageShare(match) : 0,
      };
    });
    entry.largest = Math.max(...entry.rows.map((row) => row.matched_bytes));
  }
  return [...versions.values()].sort(
    (a, b) => b.largest - a.largest || a.version_id.localeCompare(b.version_id),
  );
}

function largestFor(entries: AssetEvidence[], profile: string) {
  return Math.max(
    0,
    ...entries.flatMap((entry) =>
      entry.rows
        .filter((row) => row.profile_id === profile)
        .map((row) => row.matched_bytes),
    ),
  );
}

/** The sentence that compares the evidence with the thresholds of the policy the scan was judged by. */
export function comparison(
  scan: ScanView,
  policy: PolicyView | undefined,
): string {
  const entries = assetEvidence(scan);
  const reason = scan.decision.reason;
  if (reason === "EXACT_PROTECTED_FILE")
    return "Exact matches block regardless of the thresholds.";
  if (!entries.length) return "No protected block or chunk matched this file.";
  const evaluated = profileEvidence(scan).map((p) => p.profile_id);
  const fixed = largestFor(entries, FIXED_PROFILE);
  const parts = [
    policy
      ? `Fixed blocks: largest single-asset match ${fixed.toLocaleString()} bytes ${fixed >= policy.threshold ? "≥" : "<"} threshold ${policy.threshold.toLocaleString()} bytes.`
      : `Fixed blocks: largest single-asset match ${fixed.toLocaleString()} bytes.`,
  ];
  if (evaluated.includes(CDC_PROFILE)) {
    const content = largestFor(entries, CDC_PROFILE);
    const threshold = policy?.cdc_threshold;
    parts.push(
      threshold
        ? `Content-defined chunks: largest single-asset match ${content.toLocaleString()} bytes ${content >= threshold ? "≥" : "<"} threshold ${threshold.toLocaleString()} bytes.`
        : `Content-defined chunks: largest single-asset match ${content.toLocaleString()} bytes.`,
    );
  }
  return parts.join(" ");
}

const RULES: Record<string, string> = {
  EXACT_PROTECTED_FILE:
    "Exact protected file: the whole file equals registered protected bytes, so it is always blocked.",
  BLOCK_THRESHOLD_MET:
    "Block threshold met: one protected asset matched at least the policy's minimum number of bytes in fixed blocks.",
  CDC_THRESHOLD_MET:
    "Content-defined threshold met: one protected asset matched at least the policy's minimum number of bytes in content-defined chunks. Fixed blocks did not reach their threshold.",
  NO_QUALIFYING_MATCH:
    "No qualifying match: no protected asset reached a policy threshold.",
  INVALID_EVALUATION_CONTEXT:
    "The evaluation context was invalid, so no decision authorizes release.",
};

function AssetName({ id, privileged }: { id: string; privileged: boolean }) {
  const asset = useGet<AssetView>(privileged ? `/assets/${id}` : null);
  if (!privileged) return <>Protected reference {short(id)}</>;
  return (
    <Link to={`/assets/${id}`}>
      {asset.data?.label ?? `Protected asset ${short(id)}`}
    </Link>
  );
}

/**
 * Explains a recorded decision from the scan's own fields: the rule (decision reason), the profiles the policy
 * evaluated, each matching asset with its matched bytes, matched chunks and share of the submitted file per profile,
 * and the policy version, rule set and thresholds it was judged by.
 */
export function VerdictExplanation({
  scan,
  privileged,
}: {
  scan: ScanView;
  privileged: boolean;
}) {
  const active = useGet<PolicyView>("/policies/active");
  const history = useGet<PolicyPage>(
    privileged && active.data && active.data.id !== scan.policy_id
      ? "/policies/history?limit=100"
      : null,
  );
  const policy =
    active.data?.id === scan.policy_id
      ? active.data
      : history.data?.items.find((item) => item.id === scan.policy_id);
  const evaluated = profileEvidence(scan).map((p) => p.profile_id);
  const entries = assetEvidence(scan);
  const reason = scan.decision.reason;
  return (
    <section className="verdict-why" aria-labelledby="verdict-why-title">
      <h2 id="verdict-why-title">Why this decision</h2>
      <p className="why-rule">
        <strong>{scan.decision.outcome}</strong>{" "}
        {RULES[reason] ?? `Recorded reason: ${reason.replaceAll("_", " ")}.`}
      </p>
      <dl className="why-facts">
        <div>
          <dt>Policy</dt>
          <dd>
            {policy ? (
              <>
                Version {policy.number} · rule set{" "}
                {policy.rule_set ?? "rs-policy-v1"} · block threshold{" "}
                {policy.threshold.toLocaleString()} bytes
                {policy.cdc_threshold
                  ? ` · content-defined threshold ${policy.cdc_threshold.toLocaleString()} bytes`
                  : ""}{" "}
                · partial matching {policy.block_enabled ? "on" : "off"}
                {active.data?.id !== scan.policy_id && " (no longer active)"}
              </>
            ) : active.loading || history.loading ? (
              "Reading policy…"
            ) : (
              <>
                Policy {short(scan.policy_id)} (an earlier version; its details
                need an analyst role)
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Profiles evaluated</dt>
          <dd>
            {evaluated.map((id) => (
              <code className="profile-id" key={id}>
                {id}
              </code>
            ))}
            {!evaluated.includes(CDC_PROFILE) && (
              <span className="muted">
                {" "}
                Content-defined chunks were not evaluated: this policy uses rule
                set rs-policy-v1.
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt>Comparison</dt>
          <dd>{comparison(scan, policy)}</dd>
        </div>
        <div>
          <dt>Registry</dt>
          <dd>Revision r{scan.detection.registry_revision} at evaluation</dd>
        </div>
      </dl>
      {entries.length > 0 && (
        <ul className="why-matches">
          {entries.slice(0, 5).map((entry) => (
            <li key={entry.version_id}>
              <div className="why-match-head">
                <AssetName id={entry.asset_id} privileged={privileged} />
                <span className="muted">
                  {entry.exact ? "exact file" : "partial match"}
                </span>
              </div>
              {entry.rows.map((row) => (
                <div className="why-profile" key={row.profile_id}>
                  <div className="why-profile-name">
                    <span>
                      {PROFILE_NAMES[row.profile_id]?.name ?? row.profile_id}
                    </span>
                    <code className="profile-id">{row.profile_id}</code>
                  </div>
                  <div className="why-match-numbers">
                    <span>
                      <strong>{bytes(row.matched_bytes)}</strong> matched
                    </span>
                    <span>
                      <strong>{row.matched_chunks}</strong> of {row.chunk_count}{" "}
                      {PROFILE_NAMES[row.profile_id]?.unit ?? "chunks"}
                    </span>
                    <span>
                      <strong>{(row.share * 100).toFixed(1)}%</strong> of this
                      file
                    </span>
                  </div>
                  <CoverageBar share={row.share} />
                </div>
              ))}
            </li>
          ))}
        </ul>
      )}
      {entries.length > 5 && (
        <p className="tiny muted">
          {entries.length - 5} more matching assets are listed in the evidence
          below.
        </p>
      )}
    </section>
  );
}
