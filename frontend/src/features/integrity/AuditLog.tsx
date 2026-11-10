import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError } from "../../api";
import {
  Empty,
  Failure,
  Hash,
  Loading,
  Notice,
  PageHeader,
  Panel,
  Status,
  Table,
} from "../../components/ui";
import { useGet, useTitle } from "../../lib/hooks";
import { date } from "../../lib/errors";
import type {
  AuditPage,
  ConsistencyProofView,
  InclusionProofView,
  TransparencyKeyView,
  TreeHeadView,
} from "../../lib/contracts";
import {
  eventLeafHash,
  loadSavedHead,
  saveHead,
  verifyConsistency,
  verifyHead,
  verifyInclusion,
  type SavedHead,
  type SignatureCheck,
} from "../../lib/transparency";

type Consistency =
  | { state: "first" }
  | {
      state: "same" | "grew" | "smaller" | "inconsistent" | "other-log";
      saved: SavedHead;
    }
  | { state: "unavailable" };

type Inclusion =
  | {
      state: "valid" | "invalid";
      sequence: number;
      steps: number;
      leaf: string;
    }
  | { state: "uncovered"; sequence: number };

type Row = { event: Record<string, unknown>; mac: string };

const PAGE = 10;

/** Compare the head this browser saved earlier with the current one. Never throws. */
async function compare(head: TreeHeadView): Promise<Consistency> {
  const saved = loadSavedHead();
  if (!saved) return { state: "first" };
  if (saved.log_id !== head.log_id) return { state: "other-log", saved };
  if (saved.tree_size > head.tree_size) return { state: "smaller", saved };
  if (saved.tree_size === head.tree_size)
    return {
      state: saved.root_hash === head.root_hash ? "same" : "inconsistent",
      saved,
    };
  try {
    const proof = await api<ConsistencyProofView>(
      `/transparency/proof/consistency?first=${saved.tree_size}&second=${head.tree_size}`,
    );
    const valid = await verifyConsistency(
      saved.tree_size,
      head.tree_size,
      saved.root_hash,
      head.root_hash,
      proof.path,
    );
    return { state: valid ? "grew" : "inconsistent", saved };
  } catch {
    return { state: "unavailable" };
  }
}

export default function AuditLog({ tabs }: { tabs: ReactNode }) {
  useTitle("Integrity explorer");
  const head = useGet<TreeHeadView>("/transparency/sth");
  const keys = useGet<TransparencyKeyView>("/transparency/key");
  const [after, setAfter] = useState(0);
  const events = useGet<AuditPage>(
    `/audit/events?limit=${PAGE}&after=${after}`,
  );
  const [signature, setSignature] = useState<SignatureCheck>();
  const [consistency, setConsistency] = useState<Consistency>();
  const [stored, setStored] = useState(true);
  const [inclusion, setInclusion] = useState<Inclusion>();
  const [checking, setChecking] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const noHead = head.error instanceof ApiError && head.error.status === 404;

  useEffect(() => {
    let live = true;
    setSignature(undefined);
    setConsistency(undefined);
    const current = head.data;
    const publicKey = keys.data?.keys.find(
      (k) => k.key_id === current?.key_id,
    )?.public_key;
    if (!current || !keys.data) return;
    void (async () => {
      const checked: SignatureCheck = publicKey
        ? await verifyHead(current, publicKey)
        : "invalid";
      const compared = await compare(current);
      if (!live) return;
      setSignature(checked);
      setConsistency(compared);
      // Remember this head only when nothing contradicts it. An unverifiable signature is not saved either.
      if (
        checked === "valid" &&
        ["first", "same", "grew"].includes(compared.state)
      )
        setStored(saveHead(current));
    })();
    return () => {
      live = false;
    };
  }, [head.data, keys.data]);

  async function check(row: Row) {
    const current = head.data;
    const sequence = Number(row.event.sequence);
    if (!current || checking) return;
    setFailure(null);
    setInclusion(undefined);
    if (sequence > current.tree_size) {
      setInclusion({ state: "uncovered", sequence });
      return;
    }
    setChecking(true);
    try {
      const leaf = await eventLeafHash(row.event, row.mac);
      const proof = await api<InclusionProofView>(
        `/transparency/proof/inclusion?leaf_index=${sequence - 1}&tree_size=${current.tree_size}`,
      );
      const valid = await verifyInclusion(
        leaf,
        sequence - 1,
        current.tree_size,
        proof.path,
        current.root_hash,
      );
      setInclusion({
        state: valid ? "valid" : "invalid",
        sequence,
        steps: proof.path.length,
        leaf,
      });
    } catch (error) {
      setFailure(error);
    } finally {
      setChecking(false);
    }
  }

  const rows = (events.data?.events ?? []) as Row[];
  return (
    <>
      <PageHeader
        eyebrow="CRYPTOGRAPHIC EVIDENCE"
        title="Integrity explorer"
        description="The audit events form a Merkle tree. The gateway signs its root; this page checks the signature and the proofs in your browser."
      />
      {tabs}
      <Failure
        error={(noHead ? null : head.error) || keys.error || failure}
        retry={() => {
          head.refresh();
          keys.refresh();
        }}
      />
      <Panel
        title="Latest signed tree head"
        subtitle="Written at every release, at every 64th event and on request. Stored append-only in the database."
        actions={
          <button
            className="button secondary small"
            onClick={() => {
              head.refresh();
              events.refresh();
              setInclusion(undefined);
            }}
          >
            Reload
          </button>
        }
      >
        {(head.loading || keys.loading) && (
          <Loading label="Loading the signed tree head" />
        )}
        {noHead && (
          <Empty title="No tree head has been signed yet">
            A head is signed at the first release, at the 64th event, or when an
            administrator requests one.
          </Empty>
        )}
        {head.data && (
          <>
            <div className="context-strip">
              {signature === undefined && <Status value="CHECKING" />}
              {signature === "valid" && <Status value="VERIFIED" />}
              {signature === "invalid" && <Status value="FAILED" />}
              {signature === "unsupported" && <Status value="NOT_CHECKED" />}
              <span>
                Tree size <strong>{head.data.tree_size}</strong>
              </span>
              <span>
                Signed <strong>{date(head.data.timestamp)}</strong>
              </span>
            </div>
            {signature === "valid" && (
              <p>
                This browser verified the Ed25519 signature over the head, and
                that the key id is the SHA-256 of the public key.
              </p>
            )}
            {signature === "invalid" && (
              <Notice tone="error">
                The signature does not verify with the published key. Do not
                rely on this tree head.
              </Notice>
            )}
            {signature === "unsupported" && (
              <Notice>
                This browser cannot verify Ed25519 signatures (WebCrypto Ed25519
                is not available), so the signature was not checked here. The
                proofs below are still checked against the root shown.
              </Notice>
            )}
            <Hash value={head.data.root_hash} label="Root hash" />
            <Hash value={head.data.key_id} label="Key id" />
            <Hash value={head.data.signature} label="Signature" />
          </>
        )}
      </Panel>
      {head.data && (
        <Panel
          title="Consistency with the last head this browser saw"
          subtitle="A log may only grow. The earlier head is kept in this browser's local storage."
          actions={
            <button
              className="button secondary small"
              onClick={() => {
                setStored(saveHead(null));
                setConsistency({ state: "first" });
              }}
            >
              Forget saved head
            </button>
          }
        >
          {!consistency && <Loading label="Checking consistency" />}
          {consistency?.state === "first" && (
            <p>
              No earlier head is saved in this browser, so there is nothing to
              compare with yet. The current head is saved once its signature
              verifies.
            </p>
          )}
          {consistency?.state === "same" && (
            <div className="context-strip">
              <Status value="VERIFIED" />
              <span>
                Unchanged since the last visit: size{" "}
                <strong>{consistency.saved.tree_size}</strong>, same root.
              </span>
            </div>
          )}
          {consistency?.state === "grew" && (
            <div className="context-strip">
              <Status value="VERIFIED" />
              <span>
                The log only grew: size{" "}
                <strong>{consistency.saved.tree_size}</strong> to{" "}
                <strong>{head.data.tree_size}</strong>. The consistency proof
                verifies, so every earlier event is still in place.
              </span>
            </div>
          )}
          {consistency?.state === "smaller" && (
            <Notice tone="error">
              The log is smaller than the head this browser saved (size{" "}
              {consistency.saved.tree_size}, now {head.data.tree_size}). Events
              were removed or the database was rolled back.
            </Notice>
          )}
          {consistency?.state === "inconsistent" && (
            <Notice tone="error">
              The current head is not consistent with the head this browser
              saved at size {consistency.saved.tree_size}. Earlier events were
              changed or replaced.
            </Notice>
          )}
          {consistency?.state === "other-log" && (
            <Notice>
              The saved head belongs to a different log (another database or a
              new audit stream). Use Forget saved head to start again with this
              one.
            </Notice>
          )}
          {consistency?.state === "unavailable" && (
            <Notice tone="error">
              The consistency proof could not be loaded, so the comparison was
              not made.
            </Notice>
          )}
          {!stored && (
            <Notice>
              This browser does not allow local storage here, so no head is kept
              between visits.
            </Notice>
          )}
        </Panel>
      )}
      <Panel
        title="Inclusion of one event"
        subtitle="Choose an event. Its leaf hash is recomputed here from the event and its HMAC, then followed to the signed root."
      >
        <Failure error={events.error} retry={events.refresh} />
        {events.loading && <Loading label="Loading audit events" rows={5} />}
        {inclusion?.state === "valid" && (
          <div className="context-strip" role="status">
            <Status value="VERIFIED" />
            <span>
              Event <strong>{inclusion.sequence}</strong> is in the tree of size{" "}
              <strong>{head.data?.tree_size}</strong> ({inclusion.steps} proof
              steps).
            </span>
          </div>
        )}
        {inclusion?.state === "invalid" && (
          <Notice tone="error">
            Event {inclusion.sequence} does not lead to the signed root. The
            event shown here is not the one the tree head commits to.
          </Notice>
        )}
        {inclusion?.state === "uncovered" && (
          <Notice>
            Event {inclusion.sequence} is newer than the latest signed head. It
            is covered by the next head.
          </Notice>
        )}
        {inclusion && inclusion.state !== "uncovered" && (
          <Hash value={inclusion.leaf} label="Leaf hash computed here" />
        )}
        {!!rows.length && (
          <Table label="Audit events on this page">
            <thead>
              <tr>
                <th scope="col">Sequence</th>
                <th scope="col">Event</th>
                <th scope="col">Time</th>
                <th scope="col">Check</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={String(row.event.sequence)}>
                  <td>{String(row.event.sequence)}</td>
                  <td>{String(row.event.kind).replaceAll("_", " ")}</td>
                  <td>{date(String(row.event.timestamp))}</td>
                  <td>
                    <button
                      className="button secondary small"
                      aria-label={`Check inclusion of event ${String(row.event.sequence)}`}
                      disabled={!head.data || checking}
                      onClick={() => void check(row)}
                    >
                      Check inclusion
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {events.data && !rows.length && (
          <Empty title="No events on this page">
            There are no audit events after sequence {after}.
          </Empty>
        )}
        <div className="button-row">
          <button
            className="button secondary small"
            disabled={after === 0}
            onClick={() => setAfter(Math.max(0, after - PAGE))}
          >
            Earlier events
          </button>
          <button
            className="button secondary small"
            disabled={rows.length < PAGE}
            onClick={() => setAfter(after + PAGE)}
          >
            Later events
          </button>
        </div>
      </Panel>
    </>
  );
}
