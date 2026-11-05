import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Download,
  FileUp,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { api, fixture, request } from "../../api";
import type {
  PolicyView,
  TransferPage,
  TransferView,
} from "../../lib/contracts";
import { useAction, useGet, useTitle } from "../../lib/hooks";
import { useSession } from "../../lib/session";
import { bytes, date, reasonText, short } from "../../lib/errors";
import { Evidence } from "../../components/Evidence";
import {
  Empty,
  Failure,
  Loading,
  Notice,
  PageHeader,
  Pager,
  Panel,
  Status,
  Table,
} from "../../components/ui";

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function verifyDownload(
  data: ArrayBuffer,
  expected: string,
  size: number,
) {
  const digest = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", data)),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  if (data.byteLength !== size || digest !== expected)
    throw new Error("Browser byte verification failed");
  return digest;
}

export default function Gateway() {
  useTitle("Transfer gateway");
  const { id } = useParams();
  return id ? <TransferDetail key={id} id={id} /> : <TransferList />;
}

function TransferList() {
  const { auth } = useSession();
  const navigate = useNavigate();
  const action = useAction();
  const [selection, setSelection] = useState("benign");
  const [file, setFile] = useState<File | null>(null);
  const [offset, setOffset] = useState(0);
  const key = useRef<string | null>(null);
  const [validation, setValidation] = useState("");
  const policy = useGet<PolicyView>("/policies/active");
  const list = useGet<TransferPage>(`/transfers?limit=10&offset=${offset}`);
  function changeInput() {
    key.current = null;
    setValidation("");
    action.clear();
  }
  async function submit() {
    if (file && file.size > 10485760) {
      setValidation("Choose a file no larger than 10 MiB.");
      return;
    }
    key.current ??= crypto.randomUUID();
    const result = await action.run(() =>
      api<TransferView>(
        `/transfers?filename=${selection === "renamed" && !file ? "renamed-copy.txt" : "candidate.bin"}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "Idempotency-Key": key.current!,
          },
          body: file ?? fixture(selection),
        },
        auth!.csrf_token,
      ),
    );
    if (result) navigate("/transfers/" + result.id);
  }
  return (
    <>
      <PageHeader
        eyebrow="CONTROLLED EGRESS"
        title="Transfer gateway"
        description="Freeze the bytes. Evaluate the evidence. Release only what is approved."
      />
      <div className="gateway-grid">
        <Panel
          title="Submit a transfer"
          subtitle="Authenticated local workflow · 10 MiB limit"
        >
          <div className="step-track" aria-label="Transfer workflow">
            <span className="current">01 Select input</span>
            <span>02 Evaluate</span>
            <span>03 Verify release</span>
          </div>
          <div className="form-stack">
            <label>
              Synthetic input
              <select
                value={selection}
                disabled={action.busy}
                onChange={(e) => {
                  setSelection(e.target.value);
                  setFile(null);
                  changeInput();
                }}
              >
                <option value="benign">Benign public note</option>
                <option value="protected">Exact protected sample</option>
                <option value="renamed">Renamed protected copy</option>
                <option value="partial">Aligned partial copy</option>
                <option value="modified">Single-byte modification</option>
                <option value="shifted">
                  One-byte prefix: known blind spot
                </option>
                <option value="empty">Empty file</option>
              </select>
            </label>
            <label className="file-picker">
              <FileUp size={24} />
              <strong>Or choose a local synthetic file</strong>
              <span>The original filename is not used as a storage path.</span>
              <input
                type="file"
                disabled={action.busy}
                onChange={(e) => {
                  setFile(e.target.files?.[0] ?? null);
                  changeInput();
                }}
              />
            </label>
            <div className="selected-file">
              <span>{file ? file.name : selection + ".txt"}</span>
              <strong>
                {bytes(file?.size ?? fixture(selection).byteLength)}
              </strong>
            </div>
            <Failure error={action.error} />
            {validation && <Notice tone="error">{validation}</Notice>}
            {action.busy && (
              <Notice>
                Receiving and evaluating the actual input. No bytes have been
                released.
              </Notice>
            )}
            <button
              className="button primary full"
              disabled={action.busy}
              onClick={() => void submit()}
            >
              {action.busy
                ? "Evaluating transfer…"
                : action.error
                  ? "Retry the same submission"
                  : "Evaluate transfer"}
              <ArrowRight size={16} />
            </button>
            <p className="tiny muted">
              A network retry reuses the same idempotency key. Changing the
              input starts a new request. Register the protected sample before
              demonstrating a match.
            </p>
          </div>
        </Panel>
        <Panel
          title="Policy at a glance"
          subtitle="The server makes every decision"
        >
          <Failure error={policy.error} retry={policy.refresh} />
          {policy.loading && <Loading />}
          {policy.data && (
            <>
              <span className="scope-chip">VERSION {policy.data.number}</span>
              <ol className="policy-steps">
                <li>
                  <span>01</span>
                  <div>
                    <strong>Exact protected match</strong>
                    <p>Always BLOCK, including renamed files.</p>
                  </div>
                </li>
                <li>
                  <span>02</span>
                  <div>
                    <strong>
                      Block matching{" "}
                      {policy.data.block_enabled ? "enabled" : "disabled"}
                    </strong>
                    <p>
                      Threshold: {policy.data.threshold.toLocaleString()}{" "}
                      matching bytes per asset.
                    </p>
                  </div>
                </li>
                <li>
                  <span>03</span>
                  <div>
                    <strong>Otherwise evaluate ALLOW</strong>
                    <p>
                      Release also checks expiry, current revisions, snapshot
                      identity and audit integrity.
                    </p>
                  </div>
                </li>
              </ol>
              <Link className="text-link" to="/policies">
                Inspect the policy <ArrowRight size={14} />
              </Link>
            </>
          )}
          <div className="safety-note">
            <ShieldCheck size={18} />
            <p>
              No administrator bypass. ALLOW is never a promise of universal
              data-loss prevention.
            </p>
          </div>
        </Panel>
      </div>
      <Panel
        title="Transfer history"
        subtitle="Authorized records · newest first"
        actions={
          <button
            className="icon-button"
            aria-label="Refresh transfer history"
            onClick={list.refresh}
          >
            <RefreshCw size={16} />
          </button>
        }
      >
        <Failure error={list.error} retry={list.refresh} />
        {list.loading && <Loading />}
        {list.data && (
          <>
            {list.data.items.length ? (
              <Table label="Transfer history">
                <thead>
                  <tr>
                    <th scope="col">File / record</th>
                    <th scope="col">Size</th>
                    <th scope="col">State</th>
                    <th scope="col">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((t) => (
                    <tr key={t.id}>
                      <td>
                        <Link className="record-link" to={"/transfers/" + t.id}>
                          <strong>{t.filename}</strong>
                          <code>{short(t.id)} ↗</code>
                        </Link>
                      </td>
                      <td>{bytes(t.file_size)}</td>
                      <td>
                        <Status value={t.state} />
                      </td>
                      <td className="muted">{date(t.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <Empty title="No transfers yet">
                Choose a synthetic input above to begin.
              </Empty>
            )}
            <Pager
              offset={offset}
              count={list.data.items.length}
              change={setOffset}
            />
          </>
        )}
      </Panel>
    </>
  );
}

function TransferDetail({ id }: { id: string }) {
  const { auth } = useSession();
  const record = useGet<TransferView>("/transfers/" + id);
  const action = useAction();
  const [verified, setVerified] = useState<string | null>(null);
  const [integrityFailure, setIntegrityFailure] = useState(false);
  const data = record.data;
  useEffect(() => {
    if (data?.state !== "SCANNING") return;
    const timer = setTimeout(record.refresh, 3000);
    return () => clearTimeout(timer);
  }, [data?.state, data, record.refresh]);
  async function download() {
    await action.run(async () => {
      try {
        const response = await request(
          "/transfers/" + id + "/release",
          { method: "POST" },
          auth!.csrf_token,
        );
        const buffer = await response.arrayBuffer();
        let digest: string;
        try {
          digest = await verifyDownload(
            buffer,
            data!.file_sha256,
            data!.file_size,
          );
        } catch {
          setIntegrityFailure(true);
          return;
        }
        setVerified(digest);
        saveBlob(
          new Blob([buffer], { type: "application/octet-stream" }),
          `rootsentinel-${id}.bin`,
        );
      } finally {
        record.refresh();
      }
    });
  }
  return (
    <>
      <Link className="back-link" to="/transfers">
        <ArrowLeft size={14} />
        Transfer gateway
      </Link>
      <PageHeader
        eyebrow="TRANSFER EVIDENCE"
        title={data?.filename ?? "Transfer record"}
        description={`Record ${id}`}
        actions={
          <button
            className="button secondary"
            onClick={record.refresh}
            disabled={record.loading || action.busy}
          >
            <RefreshCw size={15} />
            Refresh state
          </button>
        }
      />
      <Failure error={record.error} retry={record.refresh} />
      {record.loading && <Loading label="Reading transfer evidence" />}
      {data && (
        <>
          <div
            className={`verdict-banner ${data.state === "BLOCKED" ? "blocked" : ""}`}
          >
            <div>
              <Status value={data.state} />
              <h2>
                {data.state === "BLOCKED"
                  ? "Protected bytes withheld"
                  : data.state === "ALLOWED"
                    ? "Eligible for verified release"
                    : data.state === "STREAM_FINISHED"
                      ? "Server send completed"
                      : "Review the transfer state"}
              </h2>
              <p>
                {reasonText[data.reason] ??
                  "The server enforces this state. A fresh transfer is required if authorization is no longer valid."}
              </p>
            </div>
            <div className="verdict-actions">
              {data.release_eligible && (
                <button
                  className="button primary"
                  disabled={action.busy}
                  onClick={() => void download()}
                >
                  <Download size={17} />
                  {action.busy ? "Verifying release…" : "Verified download"}
                </button>
              )}
              {!data.release_eligible && (
                <Link className="button secondary" to="/transfers">
                  Submit a new transfer <ArrowRight size={15} />
                </Link>
              )}
            </div>
          </div>
          <Failure error={action.error} />
          {integrityFailure && (
            <Notice tone="error">
              Browser integrity verification failed. No download was saved.
              Inspect the transfer and report the failure.
            </Notice>
          )}
          {verified && (
            <Notice tone="success">
              Received response bytes matched the approved SHA-256 and length.
              Recipient storage is not confirmed. A retry requires a new
              transfer.
            </Notice>
          )}
          <div className="detail-grid">
            <Panel
              title="Detection evidence"
              subtitle="Server-computed fingerprints and matching intervals"
            >
              {data.scan ? (
                <Evidence scan={data.scan} />
              ) : (
                <Empty title="No completed scan">
                  This transfer has no persisted detection result. Release is
                  unavailable.
                </Empty>
              )}
            </Panel>
            <div className="side-stack">
              <Panel title="Release conditions">
                <dl className="metadata">
                  <dt>Created</dt>
                  <dd>{date(data.created_at)}</dd>
                  <dt>Release expires</dt>
                  <dd>{date(data.expires_at)}</dd>
                  <dt>Size</dt>
                  <dd>{bytes(data.file_size)}</dd>
                  <dt>Owner</dt>
                  <dd>
                    <code>{short(data.actor_id)}</code>
                  </dd>
                  <dt>Use</dt>
                  <dd>Single attempt</dd>
                </dl>
                <p className="tiny muted">
                  A completed server send is not proof of recipient storage. A
                  changed policy or registry can invalidate an earlier ALLOW.
                </p>
              </Panel>
              {data.incident_id && (
                <Panel title="Investigation">
                  <p>
                    This policy block created an incident. It does not establish
                    malicious intent.
                  </p>
                  <code className="wrap">{data.incident_id}</code>
                  {auth!.user.role !== "EMPLOYEE" && (
                    <Link
                      className="button secondary full"
                      to={"/incidents/" + data.incident_id}
                    >
                      Open incident <ArrowRight size={15} />
                    </Link>
                  )}
                </Panel>
              )}
              <Link className="text-link" to="/guide#limitations">
                Understand detection limits ↗
              </Link>
            </div>
          </div>
        </>
      )}
    </>
  );
}
