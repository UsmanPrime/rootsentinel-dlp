import { Link } from "react-router-dom";
import type {
  AssetView,
  MatchView,
  PolicyPage,
  PolicyView,
  ScanView,
} from "../lib/contracts";
import { useGet } from "../lib/hooks";
import { bytes, short } from "../lib/errors";
import { CoverageBar } from "./CoverageBar";

/** Distinct outbound chunk positions that matched a protected block. */
export function matchedBlockCount(match: MatchView) {
  return new Set(match.blocks.flatMap((block) => block.outbound_indices)).size;
}

export function coverageShare(match: MatchView) {
  const { numerator, denominator } = match.coverage;
  return denominator ? numerator / denominator : 0;
}

const RULES: Record<string, string> = {
  EXACT_PROTECTED_FILE:
    "Exact protected file: the whole file equals registered protected bytes, so it is always blocked.",
  BLOCK_THRESHOLD_MET:
    "Block threshold met: one protected asset matched at least the policy's minimum number of bytes.",
  NO_QUALIFYING_MATCH:
    "No qualifying match: no protected asset reached the policy threshold.",
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
 * Explains a recorded decision from the scan's own fields: the rule (decision reason), each matching asset with its
 * matched bytes, matched blocks and share of the submitted file, and the policy version and threshold it was judged by.
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
  const matches = [...scan.detection.matches].sort(
    (a, b) => b.matched_bytes - a.matched_bytes,
  );
  const largest = matches[0];
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
                Version {policy.number} · threshold{" "}
                {policy.threshold.toLocaleString()} bytes · block matching{" "}
                {policy.block_enabled ? "on" : "off"}
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
          <dt>Comparison</dt>
          <dd>
            {reason === "EXACT_PROTECTED_FILE"
              ? "Exact matches block regardless of the threshold."
              : largest && policy
                ? `Largest single-asset match ${largest.matched_bytes.toLocaleString()} bytes ${largest.matched_bytes >= policy.threshold ? "≥" : "<"} threshold ${policy.threshold.toLocaleString()} bytes.`
                : largest
                  ? `Largest single-asset match ${largest.matched_bytes.toLocaleString()} bytes.`
                  : "No protected block matched this file."}
          </dd>
        </div>
        <div>
          <dt>Registry</dt>
          <dd>Revision r{scan.detection.registry_revision} at evaluation</dd>
        </div>
      </dl>
      {matches.length > 0 && (
        <ul className="why-matches">
          {matches.slice(0, 5).map((match) => {
            const share = coverageShare(match);
            return (
              <li key={match.version_id}>
                <div className="why-match-head">
                  <AssetName id={match.asset_id} privileged={privileged} />
                  <span className="muted">
                    {match.exact ? "exact file" : "block match"}
                  </span>
                </div>
                <div className="why-match-numbers">
                  <span>
                    <strong>{bytes(match.matched_bytes)}</strong> matched
                  </span>
                  <span>
                    <strong>{matchedBlockCount(match)}</strong> of{" "}
                    {scan.detection.manifest.chunk_count} blocks
                  </span>
                  <span>
                    <strong>{(share * 100).toFixed(1)}%</strong> of this file
                  </span>
                </div>
                <CoverageBar share={share} />
              </li>
            );
          })}
        </ul>
      )}
      {matches.length > 5 && (
        <p className="tiny muted">
          {matches.length - 5} more matching assets are listed in the evidence
          below.
        </p>
      )}
    </section>
  );
}
