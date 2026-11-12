import { useEffect, useState } from "react";
import { api } from "../../api";
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
  InclusionProofView,
  TransparencyKeyView,
  TreeHeadView,
} from "../../lib/contracts";
import {
  eventLeafHash,
  verifyHead,
  verifyInclusion,
  type SignatureCheck,
} from "../../lib/transparency";

type Row = { event: Record<string, unknown>; mac: string };
type Check =
  | { sequence: number; state: "valid" | "invalid" | "uncovered" }
  | undefined;

/** A visitor's own audit events, and the signed tree head that covers them. Nothing of any other sandbox. */
export default function SandboxAudit() {
  useTitle("My audit trail");
  const events = useGet<AuditPage>("/visitor/audit/events?limit=100");
  const head = useGet<TreeHeadView>("/visitor/transparency/sth");
  const keys = useGet<TransparencyKeyView>("/visitor/transparency/key");
  const [signature, setSignature] = useState<SignatureCheck>();
  const [check, setCheck] = useState<Check>();
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    const current = head.data;
    const publicKey = keys.data?.keys.find(
      (k) => k.key_id === current?.key_id,
    )?.public_key;
    setSignature(undefined);
    if (!current || !keys.data) return;
    const result: Promise<SignatureCheck> = publicKey
      ? verifyHead(current, publicKey)
      : Promise.resolve("invalid");
    void result.then((value) => {
      if (live) setSignature(value);
    });
    return () => {
      live = false;
    };
  }, [head.data, keys.data]);

  async function verify(row: Row) {
    const current = head.data;
    const sequence = Number(row.event.sequence);
    if (!current || busy) return;
    setFailure(null);
    if (sequence > current.tree_size) {
      setCheck({ sequence, state: "uncovered" });
      return;
    }
    setBusy(true);
    try {
      const leaf = await eventLeafHash(row.event, row.mac);
      const proof = await api<InclusionProofView>(
        `/visitor/transparency/proof/inclusion?leaf_index=${sequence - 1}&tree_size=${current.tree_size}`,
      );
      const valid = await verifyInclusion(
        leaf,
        sequence - 1,
        current.tree_size,
        proof.path,
        current.root_hash,
      );
      setCheck({ sequence, state: valid ? "valid" : "invalid" });
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  }
  const rows = (events.data?.events ?? []) as Row[];
  const noHead = head.error != null;
  return (
    <>
      <PageHeader
        eyebrow="YOUR SANDBOX"
        title="My audit trail"
        description="The audit events your visitor session produced, and the signed tree head that covers them. Other visitors' events and real accounts' events are not shown."
      />
      <Failure error={events.error} retry={events.refresh} />
      <Panel
        title="Signed tree head"
        subtitle="The gateway signs the root of the whole audit tree; your events are leaves of it"
      >
        {head.loading && <Loading label="Reading the tree head" />}
        {noHead && (
          <Notice>
            No signed tree head exists yet. One is signed when a release
            completes, at every 64th event and when an administrator asks.
          </Notice>
        )}
        {head.data && (
          <dl className="facts">
            <div>
              <dt>Tree size</dt>
              <dd>{head.data.tree_size}</dd>
            </div>
            <div>
              <dt>Root</dt>
              <dd>
                <Hash value={head.data.root_hash} />
              </dd>
            </div>
            <div>
              <dt>Signature</dt>
              <dd>
                <Status
                  value={
                    signature === undefined
                      ? "CHECKING"
                      : signature === "valid"
                        ? "VERIFIED"
                        : signature === "unsupported"
                          ? "UNSUPPORTED"
                          : "FAILED"
                  }
                />
              </dd>
            </div>
          </dl>
        )}
      </Panel>
      <Panel title="Your events" subtitle="Oldest first, up to 100">
        <Failure error={failure} />
        {events.loading && <Loading label="Reading your events" />}
        {!events.loading && rows.length === 0 && (
          <Empty title="No events yet">
            Evaluate a transfer and your events appear here.
          </Empty>
        )}
        {rows.length > 0 && (
          <Table label="Visitor audit events">
            <thead>
              <tr>
                <th scope="col">Sequence</th>
                <th scope="col">Event</th>
                <th scope="col">Time</th>
                <th scope="col">Proof</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const sequence = Number(row.event.sequence);
                const result = check?.sequence === sequence ? check : undefined;
                return (
                  <tr key={String(row.event.id)}>
                    <td>#{sequence}</td>
                    <td>
                      <Status value={String(row.event.kind)} />
                    </td>
                    <td>{date(String(row.event.timestamp))}</td>
                    <td>
                      <button
                        className="button secondary small"
                        disabled={busy || !head.data}
                        onClick={() => void verify(row)}
                      >
                        Verify inclusion
                      </button>{" "}
                      {result &&
                        (result.state === "valid"
                          ? "Included in the signed head"
                          : result.state === "uncovered"
                            ? "Not covered by the latest head yet"
                            : "Proof failed")}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Panel>
    </>
  );
}
