import { Link } from "react-router-dom";
import type { ScanView } from "../lib/contracts";
import { bytes, reasonText, short } from "../lib/errors";
import { Hash, Status } from "./ui";
import { CoverageBar } from "./CoverageBar";
import {
  CDC_PROFILE,
  coverageShare,
  matchedBlockCount,
  profileEvidence,
} from "./Verdict";
import { useSession } from "../lib/session";

export function Evidence({ scan }: { scan: ScanView }) {
  const { auth } = useSession();
  const privileged = auth!.user.role !== "EMPLOYEE";
  // Present only when the policy that judged this scan evaluated the content-defined profile.
  const content = profileEvidence(scan).find(
    (profile) => profile.profile_id === CDC_PROFILE,
  );
  return (
    <div className="evidence">
      <div className="evidence-verdict">
        <Status value={scan.decision.outcome} />
        <p>
          {reasonText[scan.decision.reason] ??
            "Review the recorded policy decision."}
        </p>
      </div>
      <div className="evidence-meta">
        <div>
          <span>File size</span>
          <strong>{bytes(scan.detection.manifest.file_size)}</strong>
        </div>
        <div>
          <span>Chunks</span>
          <strong>{scan.detection.manifest.chunk_count}</strong>
        </div>
        <div>
          <span>Registry revision</span>
          <strong>r{scan.detection.registry_revision}</strong>
        </div>
        <div>
          <span>Policy record</span>
          <Link to="/policies" title={scan.policy_id}>
            <code>{short(scan.policy_id)}</code>
          </Link>
        </div>
      </div>
      <Hash value={scan.detection.manifest.file_sha256} />
      <Hash label="Merkle root" value={scan.detection.manifest.merkle_root} />
      <h3>
        Fixed-block matches{" "}
        <span className="count">{scan.detection.matches.length}</span>
      </h3>
      {!scan.detection.matches.length && (
        <p className="muted">
          No fixed 1 KiB block of this file is registered.{" "}
          {content
            ? "Fixed blocks miss content that was shifted; the content-defined matches are listed below."
            : "Fixed blocks miss shifted, encoded or compressed content."}
        </p>
      )}
      {scan.detection.matches.slice(0, 20).map((match) => (
        <details className="match" key={match.version_id}>
          <summary>
            <span>
              {match.exact ? "Exact file match" : "Block match"} ·{" "}
              {bytes(match.matched_bytes)} · {matchedBlockCount(match)}{" "}
              {matchedBlockCount(match) === 1 ? "block" : "blocks"}
            </span>
            <strong>
              {match.coverage.denominator
                ? (
                    (match.coverage.numerator / match.coverage.denominator) *
                    100
                  ).toFixed(1)
                : "0"}
              % coverage
            </strong>
          </summary>
          <p>
            {privileged ? (
              <Link to={"/assets/" + match.asset_id}>
                Protected asset {short(match.asset_id)} ↗
              </Link>
            ) : (
              <>Protected reference {short(match.asset_id)}</>
            )}{" "}
            · version <code>{short(match.version_id)}</code>
          </p>
          <CoverageBar share={coverageShare(match)} />
          <p className="tiny muted">
            Counted outbound byte intervals:{" "}
            {match.intervals
              .slice(0, 20)
              .map(([start, end]) => `[${start}, ${end})`)
              .join(", ")}
            . Shared blocks do not establish unique ownership.
          </p>
          {match.blocks.slice(0, 8).map((block) => (
            <div className="block-reference" key={block.sha256 + block.length}>
              <code>{block.sha256}</code>
              <span>
                {block.length} bytes · source chunks{" "}
                {block.source_indices.slice(0, 12).join(", ")} → outbound{" "}
                {block.outbound_indices.slice(0, 12).join(", ")}
              </span>
            </div>
          ))}
          <p className="tiny muted">
            Display bounded to 8 block groups and 20 intervals. Full evidence
            remains available through the authorized API.
          </p>
        </details>
      ))}
      {scan.detection.matches.length > 20 && (
        <p>
          Showing the first 20 matching versions; full evidence is available
          through the API.
        </p>
      )}
      {content && (
        <>
          <h3>
            Content-defined chunk matches{" "}
            <span className="count">{content.matches.length}</span>
          </h3>
          <p className="tiny muted">
            Profile <code>{content.profile_id}</code> cut this file into{" "}
            {content.chunk_count} chunks at positions chosen by the content, so
            a copy with bytes added or removed in front still shares chunks.
          </p>
          {!content.matches.length && (
            <p className="muted">No chunk of this file is registered.</p>
          )}
          {content.matches.slice(0, 20).map((match) => (
            <details className="match" key={match.version_id}>
              <summary>
                <span>
                  Chunk match · {bytes(match.matched_bytes)} ·{" "}
                  {match.matched_chunks} of {content.chunk_count} chunks
                </span>
                <strong>
                  {(coverageShare(match) * 100).toFixed(1)}% coverage
                </strong>
              </summary>
              <p>
                {privileged ? (
                  <Link to={"/assets/" + match.asset_id}>
                    Protected asset {short(match.asset_id)} ↗
                  </Link>
                ) : (
                  <>Protected reference {short(match.asset_id)}</>
                )}{" "}
                · version <code>{short(match.version_id)}</code>
              </p>
              <CoverageBar share={coverageShare(match)} />
              <p className="tiny muted">
                Matched byte runs of this file:{" "}
                {match.intervals
                  .slice(0, 20)
                  .map(([start, end]) => `[${start}, ${end})`)
                  .join(", ")}
                . Display bounded to 20 runs. Shared chunks do not establish
                unique ownership.
              </p>
            </details>
          ))}
        </>
      )}
    </div>
  );
}
