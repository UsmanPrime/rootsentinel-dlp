import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Check, Play, RotateCcw } from "lucide-react";
import { api, fixture, jsonBody } from "../../api";
import {
  Failure,
  Hash,
  Notice,
  PageHeader,
  Panel,
  Status,
} from "../../components/ui";
import { useAction, useTitle } from "../../lib/hooks";
import { useSession } from "../../lib/session";
import type {
  AuditVerification,
  IntegrityView,
  ProofView,
  TransferView,
  VersionView,
} from "../../lib/contracts";
import { tamperProof } from "../integrity/Integrity";

export default function Guide() {
  useTitle("Guided demonstration");
  const { auth } = useSession();
  const action = useAction();
  const [step, setStep] = useState(0);
  const [asset, setAsset] = useState<VersionView>();
  const [proofResult, setProofResult] = useState<{
    valid: boolean;
    tampered: boolean;
  }>();
  const [transfer, setTransfer] = useState<TransferView>();
  const [audit, setAudit] = useState<AuditVerification>();
  const retryKey = useRef<string | null>(null);
  const steps = [
    "Understand the boundary",
    "Register a synthetic asset",
    "Inspect the commitment",
    "Verify inclusion",
    "Test a tampered proof",
    "Submit a renamed copy",
    "Investigate the block",
    "Submit a benign sample",
    "Verify release and audit",
  ];
  function move(n: number) {
    setStep(n);
    action.clear();
    retryKey.current = null;
  }
  async function run() {
    if (step === 1) {
      const v = await action.run(() =>
        api<VersionView>(
          `/assets?label=${encodeURIComponent("Guided synthetic source " + crypto.randomUUID().slice(0, 8))}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: fixture("protected"),
          },
          auth!.csrf_token,
        ),
      );
      if (v) setAsset(v);
    }
    if ((step === 3 || step === 4) && asset) {
      const value = await action.run(async () => {
        const proof = await api<ProofView>(
          `/assets/${asset.asset_id}/versions/${asset.id}/proofs/0`,
        );
        return api<IntegrityView>(
          "/integrity/verify",
          jsonBody({
            asset_id: asset.asset_id,
            version_id: asset.id,
            proof: step === 4 ? tamperProof(proof) : proof,
          }),
          auth!.csrf_token,
        );
      });
      if (value) setProofResult({ valid: value.valid, tampered: step === 4 });
    }
    if (step === 5 || step === 7) {
      retryKey.current ??= crypto.randomUUID();
      const value = await action.run(() =>
        api<TransferView>(
          `/transfers?filename=${step === 5 ? "renamed-guide-copy.txt" : "public-guide-note.txt"}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/octet-stream",
              "Idempotency-Key": retryKey.current!,
            },
            body: fixture(step === 5 ? "protected" : "benign"),
          },
          auth!.csrf_token,
        ),
      );
      if (value) setTransfer(value);
    }
    if (step === 8) {
      const value = await action.run(() =>
        api<AuditVerification>(
          "/audit/verify",
          { method: "POST" },
          auth!.csrf_token,
        ),
      );
      if (value) setAudit(value);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="LIVE CLASSROOM WALKTHROUGH"
        title="Evidence, step by step"
        description="A guided path through real operations. Every result below comes from the backend."
        actions={
          <button
            className="button secondary"
            disabled={action.busy}
            onClick={() => {
              move(0);
              setAsset(undefined);
              setProofResult(undefined);
              setTransfer(undefined);
              setAudit(undefined);
            }}
          >
            <RotateCcw size={15} />
            Restart guide
          </button>
        }
      />
      <div className="guide-layout">
        <nav className="guide-steps" aria-label="Demonstration steps">
          {steps.map((name, n) => (
            <button
              key={name}
              aria-current={step === n ? "step" : undefined}
              disabled={action.busy}
              onClick={() => move(n)}
            >
              <span>{String(n + 1).padStart(2, "0")}</span>
              {name}
            </button>
          ))}
        </nav>
        <Panel
          title={steps[step]}
          subtitle={`Step ${step + 1} of ${steps.length}`}
        >
          {step === 0 && (
            <>
              <p>
                RootSentinel identifies exact protected bytes and matching
                fixed-size blocks. A controlled gateway withholds blocked
                transfers and verifies approved bytes before release.
              </p>
              <p>
                Follow this guide with an administrator-provisioned synthetic
                account. It adds a labeled asset and transfer records; it does
                not delete or alter existing evidence.
              </p>
              <Notice>
                Only transfers submitted through this gateway are enforced.
                Folder, email, USB and arbitrary network activity remain outside
                its boundary.
              </Notice>
            </>
          )}
          {step === 1 && (
            <>
              <p>
                Register the same eight-block synthetic source used by the
                gateway samples. Registration calculates all fingerprints
                server-side and creates immutable registry history.
              </p>
              {auth!.user.role === "ADMIN" ? (
                <button
                  className="button primary"
                  disabled={action.busy || !!asset}
                  onClick={() => void run()}
                >
                  <Play size={15} />
                  Register guide sample
                </button>
              ) : (
                <Notice>
                  An administrator must register the sample. Your role can use
                  the gateway, but this setup action is restricted.
                </Notice>
              )}
              {asset && (
                <Notice tone="success">
                  Registered version {asset.number}.{" "}
                  <Link to={`/assets/${asset.asset_id}`}>
                    Inspect the asset
                  </Link>
                  .
                </Notice>
              )}
            </>
          )}
          {step === 2 && (
            <>
              {asset ? (
                <>
                  <Hash
                    value={asset.manifest.file_sha256}
                    label="Server-computed SHA-256"
                  />
                  <Hash
                    value={asset.manifest.merkle_root}
                    label="Registered Merkle root"
                  />
                  <Link
                    className="button secondary"
                    target="_blank"
                    rel="noopener"
                    to={`/integrity?asset=${asset.asset_id}&version=${asset.id}`}
                  >
                    Open interactive explorer ↗
                  </Link>
                </>
              ) : (
                <Notice>Complete registration in step 2 first.</Notice>
              )}
              <p>
                SHA-256 identifies exact file bytes. Merkle inclusion binds an
                ordered descriptor to the trusted root. Register the three-chunk
                sample from Assets to examine an uneven tree.
              </p>
            </>
          )}
          {(step === 3 || step === 4) && (
            <>
              <p>
                {step === 3
                  ? "Retrieve chunk 0’s actual proof and verify it against the registered trusted root."
                  : "Change one sibling hash in a copy of the proof. The server must reject it; the registered root and stored descriptors stay unchanged."}
              </p>
              <button
                className="button primary"
                disabled={action.busy || !asset}
                onClick={() => void run()}
              >
                {step === 3 ? "Verify original proof" : "Verify tampered copy"}
              </button>
              {proofResult && proofResult.tampered === (step === 4) && (
                <Notice>
                  <strong>{proofResult.valid ? "VERIFIED" : "REJECTED"}</strong>{" "}
                  — actual backend verification result.
                </Notice>
              )}
            </>
          )}
          {step === 5 && (
            <>
              <p>
                A new filename does not change content identity. Submit the
                protected fixture with a renamed filename.
              </p>
              <button
                className="button primary"
                disabled={action.busy || !asset}
                onClick={() => void run()}
              >
                Evaluate renamed copy
              </button>
              {transfer?.filename === "renamed-guide-copy.txt" && (
                <p>
                  <Status value={transfer.state} />{" "}
                  <Link
                    to={`/transfers/${transfer.id}`}
                    target="_blank"
                    rel="noopener"
                  >
                    Inspect actual evidence ↗
                  </Link>
                </p>
              )}
            </>
          )}
          {step === 6 && (
            <>
              <p>
                A qualifying BLOCK creates an incident tied to the actual scan.
                Review its protected-version references, matched bytes, policy
                version and registry revision. A block is not proof of malicious
                intent.
              </p>
              {transfer?.incident_id ? (
                <Link
                  className="button primary"
                  target="_blank"
                  rel="noopener"
                  to={`/incidents/${transfer.incident_id}`}
                >
                  Open associated incident ↗
                </Link>
              ) : (
                <Notice>
                  Create the renamed protected transfer in step 6 to obtain an
                  incident.
                </Notice>
              )}
              <p>
                Record an investigation note. Closing an incident never makes
                the transfer releasable.
              </p>
            </>
          )}
          {step === 7 && (
            <>
              <p>
                Evaluate a public synthetic note. The backend decides its actual
                result against the current registry and policy; this guide does
                not assume ALLOW.
              </p>
              <button
                className="button primary"
                disabled={action.busy}
                onClick={() => void run()}
              >
                Evaluate benign sample
              </button>
              {transfer?.filename === "public-guide-note.txt" && (
                <p>
                  <Status value={transfer.state} />{" "}
                  <Link
                    target="_blank"
                    rel="noopener"
                    to={`/transfers/${transfer.id}`}
                  >
                    Open transfer and verified download ↗
                  </Link>
                </p>
              )}
            </>
          )}
          {step === 8 && (
            <>
              <p>
                Use the transfer’s verified download action. The backend checks
                the exact bytes, and the browser independently compares the
                response digest and length before saving.
              </p>
              {transfer && (
                <Link
                  className="button secondary"
                  target="_blank"
                  rel="noopener"
                  to={`/transfers/${transfer.id}`}
                >
                  Open transfer ↗
                </Link>
              )}
              <p>
                A completed server send does not prove recipient storage. Review
                the audit sequence and perform a fresh integrity check.
              </p>
              <button
                className="button primary"
                disabled={action.busy || auth!.user.role === "EMPLOYEE"}
                onClick={() => void run()}
              >
                <Check size={15} />
                Verify audit chain
              </button>
              {audit && (
                <p>
                  <Status value={audit.valid ? "VERIFIED" : "FAILED"} /> Through
                  sequence {audit.through_sequence}
                </p>
              )}
            </>
          )}
          <Failure error={action.error} />
          {action.busy && (
            <Notice>Waiting for the real backend operation…</Notice>
          )}
          <div className="guide-actions">
            <button
              className="button secondary"
              disabled={step === 0 || action.busy}
              onClick={() => move(step - 1)}
            >
              Previous
            </button>
            {step < steps.length - 1 ? (
              <button
                className="button secondary"
                disabled={action.busy}
                onClick={() => move(step + 1)}
              >
                Next step
                <ArrowRight size={15} />
              </button>
            ) : (
              <Link className="button secondary" to="/">
                Exit guide
              </Link>
            )}
          </div>
        </Panel>
      </div>
      <Panel
        title="Known boundaries and useful counterexamples"
        className="limitations"
      >
        <div id="limitations" />
        <ul className="explanation-list">
          <li>
            One-byte prefixes shift fixed chunk boundaries and can defeat block
            matching.
          </li>
          <li>
            Encoding and line-ending changes alter raw bytes. Compressed or
            encrypted inputs are not decoded.
          </li>
          <li>
            Shared blocks establish byte equality, not exclusive ownership or
            intent.
          </li>
          <li>
            HMAC verification relies on server-held keys and independently
            protected checkpoints.
          </li>
          <li>
            Local polling and explicit refresh are not real-time streaming.
          </li>
        </ul>
        <Link className="text-link" to="/transfers">
          Explore the synthetic fixtures →
        </Link>
      </Panel>
    </>
  );
}
