import { useState } from "react";
import { CheckCheck, LockKeyhole } from "lucide-react";
import { api } from "../../api";
import {
  Dialog,
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
import { useAction, useGet, useTitle } from "../../lib/hooks";
import { date, short } from "../../lib/errors";
import { useSession } from "../../lib/session";
import type { AuditVerification } from "../../lib/contracts";

type Event = {
  event: {
    id: string;
    stream_id: string;
    sequence: number;
    timestamp: string;
    kind: string;
    actor_id: string | null;
    resource_id: string | null;
    key_id: string;
    previous_mac: string;
    details: Record<string, string | number>;
  };
  mac: string;
};
export default function Audit() {
  useTitle("Activity and audit");
  const { auth } = useSession();
  const action = useAction();
  const [cursors, setCursors] = useState([0]);
  const [verification, setVerification] = useState<AuditVerification>();
  const [checkpoint, setCheckpoint] = useState(false);
  const [retained, setRetained] = useState(false);
  const [selected, setSelected] = useState<Event>();
  const events = useGet<{ events: Event[] }>(
    `/audit/events?limit=10&after=${cursors[cursors.length - 1]}`,
  );
  return (
    <>
      <PageHeader
        eyebrow="AUTHENTICATED SECURITY RECORD"
        title="Activity & audit"
        description="Ordered events, HMAC linkage, and independently retained checkpoints. Verification is explicit, not assumed."
        actions={
          <button
            className="button primary"
            disabled={action.busy}
            onClick={() =>
              void action
                .run(() =>
                  api<AuditVerification>(
                    "/audit/verify",
                    { method: "POST" },
                    auth!.csrf_token,
                  ),
                )
                .then((v) => {
                  if (v) {
                    setVerification(v);
                    events.refresh();
                  }
                })
            }
          >
            <CheckCheck size={16} />
            Verify audit integrity
          </button>
        }
      />
      <Failure error={action.error || events.error} retry={events.refresh} />
      {verification && (
        <Panel title="Verification result">
          <div className="context-strip">
            <Status value={verification.valid ? "VERIFIED" : "FAILED"} />
            <span>
              Through sequence <strong>{verification.through_sequence}</strong>
            </span>
            <span>
              Checkpoint{" "}
              <strong>
                {verification.checkpoint_sequence ?? "None available"}
              </strong>
            </span>
          </div>
          <p>
            {verification.valid
              ? "The checked chain and available trusted checkpoint are consistent."
              : `Verification failed: ${verification.reason}. First invalid sequence: ${verification.first_invalid_sequence ?? "not localized"}.`}
          </p>
          <small className="muted break">
            Stream {verification.stream_id}. This result is a point-in-time
            check, not continuous monitoring.
          </small>
        </Panel>
      )}
      <Panel
        title="Security event chain"
        subtitle="Ascending sequence order. Open an event to inspect its authenticated fields."
        actions={
          <button className="button secondary small" onClick={events.refresh}>
            Refresh
          </button>
        }
      >
        {events.loading && <Loading />}
        {events.data &&
          (events.data.events.length ? (
            <Table label="Audit event chain">
              <thead>
                <tr>
                  <th>Sequence</th>
                  <th>Event</th>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Key ID</th>
                </tr>
              </thead>
              <tbody>
                {events.data.events.map((row) => (
                  <tr key={row.event.sequence}>
                    <td>
                      <button
                        className="text-button mono"
                        onClick={() => setSelected(row)}
                      >
                        #{row.event.sequence}
                      </button>
                    </td>
                    <td>{row.event.kind.replaceAll("_", " ")}</td>
                    <td>{date(row.event.timestamp)}</td>
                    <td className="mono">
                      {row.event.actor_id
                        ? short(row.event.actor_id)
                        : "System"}
                    </td>
                    <td>
                      <code>{row.event.key_id}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Empty title="No further audit events">
              Security operations append actual events. Refresh after using the
              gateway.
            </Empty>
          ))}
        <nav className="pager" aria-label="Audit pagination">
          <span>Page {cursors.length}</span>
          <div>
            <button
              className="button secondary small"
              disabled={cursors.length === 1}
              onClick={() => setCursors(cursors.slice(0, -1))}
            >
              Previous
            </button>
            <button
              className="button secondary small"
              disabled={!events.data || events.data.events.length < 10}
              onClick={() =>
                setCursors([
                  ...cursors,
                  events.data!.events.at(-1)!.event.sequence,
                ])
              }
            >
              Next
            </button>
          </div>
        </nav>
      </Panel>
      <div className="two-column">
        <Panel title="What is authenticated?">
          <p>
            Each canonical event includes a stream ID, sequence, timestamp, key
            identifier and previous event MAC. HMAC-SHA-256 authenticates the
            versioned encoding using a server-held key.
          </p>
          <p className="help-text">
            Key IDs are labels, not secrets. Historical verification requires
            retained old keys after rotation. No key material is sent to this
            interface.
          </p>
        </Panel>
        <Panel title="Where trust ends">
          <p>
            A chain can expose modified content and missing middle events. A
            separately trusted checkpoint is needed to expose relevant tail
            truncation.
          </p>
          <p className="help-text">
            An attacker controlling the host, HMAC keys, or both the database
            and trusted checkpoint is outside this guarantee. These records are
            not tamper-proof.
          </p>
          {auth!.user.role === "ADMIN" && (
            <button
              className="button secondary"
              onClick={() => setCheckpoint(true)}
            >
              <LockKeyhole size={16} />
              Retain checkpoint
            </button>
          )}
          {retained && (
            <Notice tone="success">
              The backend retained a checkpoint in its configured external
              store.
            </Notice>
          )}
        </Panel>
      </div>
      <Dialog
        open={checkpoint}
        title="Retain a trusted checkpoint"
        close={() => setCheckpoint(false)}
        busy={action.busy}
      >
        <p>
          The server verifies the chain and writes checkpoint metadata to the
          configured independent location. Protect that storage separately from
          the database.
        </p>
        <Failure error={action.error} />
        <div className="dialog-actions">
          <button
            className="button secondary"
            disabled={action.busy}
            onClick={() => setCheckpoint(false)}
          >
            Cancel
          </button>
          <button
            className="button primary"
            disabled={action.busy}
            onClick={() =>
              void action
                .run(() =>
                  api(
                    "/audit/checkpoint",
                    { method: "POST" },
                    auth!.csrf_token,
                  ),
                )
                .then((v) => {
                  if (v) {
                    setCheckpoint(false);
                    setRetained(true);
                    events.refresh();
                  }
                })
            }
          >
            Confirm checkpoint
          </button>
        </div>
      </Dialog>
      <Dialog
        open={!!selected}
        title={
          selected ? `Audit event #${selected.event.sequence}` : "Audit event"
        }
        close={() => setSelected(undefined)}
      >
        {selected && (
          <>
            <dl className="facts">
              <div>
                <dt>Category</dt>
                <dd>{selected.event.kind}</dd>
              </div>
              <div>
                <dt>Resource</dt>
                <dd className="break mono">
                  {selected.event.resource_id ?? "No resource reference"}
                </dd>
              </div>
              <div>
                <dt>Actor</dt>
                <dd className="break mono">
                  {selected.event.actor_id ?? "System"}
                </dd>
              </div>
              <div>
                <dt>Key identifier</dt>
                <dd>{selected.event.key_id}</dd>
              </div>
            </dl>
            <Hash value={selected.mac} label="Event HMAC" />
            <Hash value={selected.event.previous_mac} label="Previous HMAC" />
            <dl className="event-details">
              {Object.entries(selected.event.details).map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd className="break">{v}</dd>
                </div>
              ))}
            </dl>
          </>
        )}
      </Dialog>
    </>
  );
}
