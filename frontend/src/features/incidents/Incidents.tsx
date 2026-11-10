import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { Download, MessageSquare } from "lucide-react";
import { api, jsonBody } from "../../api";
import { Evidence } from "../../components/Evidence";
import {
  Dialog,
  Empty,
  Failure,
  Loading,
  PageHeader,
  Pager,
  Panel,
  SortHeader,
  Status,
  Table,
  nextSort,
  type SortDirection,
} from "../../components/ui";
import { useToast } from "../../lib/toast";
import { useAction, useGet, useTitle } from "../../lib/hooks";
import { date, short } from "../../lib/errors";
import { useSession } from "../../lib/session";
import type { IncidentView } from "../../lib/contracts";
import { saveBlob } from "../../lib/files";

type Summary = Pick<
  IncidentView,
  "id" | "transfer_id" | "severity" | "status" | "revision" | "created_at"
>;
export default function Incidents() {
  useTitle("Incidents");
  const { id } = useParams();
  return id ? <Detail key={id} id={id} /> : <Listing />;
}
function Listing() {
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState("");
  const [order, setOrder] = useState("newest");
  const [sort, setSort] = useState<{
    column: string;
    direction: SortDirection;
  }>({
    column: "created_at",
    direction: "descending",
  });

  const result = useGet<{ items: Summary[] }>(
    `/incidents?limit=10&offset=${offset}&order=${order}${status ? `&status=${status}` : ""}${severity ? `&severity=${severity}` : ""}`,
  );
  const rows = sortIncidents(result.data?.items ?? [], sort);
  const filtered = Boolean(status || severity);
  return (
    <>
      <PageHeader
        eyebrow="INVESTIGATION WORKSPACE"
        title="Incidents"
        description="Policy-blocked transfers with preserved evidence. A match is an observation, not a conclusion of malicious intent."
      />
      <Panel
        title="Investigation queue"
        subtitle="Severity follows the recorded match type. Filters apply before pagination."
      >
        <div className="filter-bar">
          <label className="inline-label">
            Status
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">All statuses</option>
              <option>OPEN</option>
              <option>INVESTIGATING</option>
              <option>RESOLVED</option>
            </select>
          </label>
          <label className="inline-label">
            Severity
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">All severities</option>
              <option>HIGH</option>
              <option>MEDIUM</option>
            </select>
          </label>
          <label className="inline-label">
            Order
            <select
              value={order}
              onChange={(e) => {
                setOrder(e.target.value);
                setOffset(0);
              }}
            >
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </label>
          <button className="button secondary small" onClick={result.refresh}>
            Refresh
          </button>
        </div>
        <Failure error={result.error} retry={result.refresh} />
        {result.loading && <Loading rows={5} />}
        {result.data &&
          (result.data.items.length ? (
            <Table label="Incident queue">
              <caption className="sr-only">
                Incident queue. Column sorting applies to the incidents on this
                page.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Incident</th>
                  <SortHeader
                    label="Severity"
                    column="severity"
                    sort={sort}
                    change={(c) => setSort(nextSort(sort, c))}
                  />
                  <SortHeader
                    label="Status"
                    column="status"
                    sort={sort}
                    change={(c) => setSort(nextSort(sort, c))}
                  />
                  <SortHeader
                    label="Observed"
                    column="created_at"
                    sort={sort}
                    change={(c) => setSort(nextSort(sort, c))}
                  />
                  <th scope="col">Transfer</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.id}>
                    <td>
                      <Link className="row-link mono" to={`/incidents/${i.id}`}>
                        {short(i.id)}
                      </Link>
                    </td>
                    <td>
                      <Status value={i.severity} />
                    </td>
                    <td>
                      <Status value={i.status} />
                    </td>
                    <td>{date(i.created_at)}</td>
                    <td>
                      <Link className="mono" to={`/transfers/${i.transfer_id}`}>
                        {short(i.transfer_id)}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Empty
              title="No incidents in this view"
              action={
                filtered ? (
                  <button
                    className="button secondary"
                    onClick={() => {
                      setStatus("");
                      setSeverity("");
                      setOffset(0);
                    }}
                  >
                    Clear filters
                  </button>
                ) : (
                  <Link className="button secondary" to="/transfers">
                    Open the transfer gateway
                  </Link>
                )
              }
            >
              {filtered
                ? "No incident matches these filters. Clear them to see the whole queue."
                : "Submit a protected synthetic transfer to create a real policy-blocked incident."}
            </Empty>
          ))}
        {result.data && (
          <Pager
            offset={offset}
            count={result.data.items.length}
            change={setOffset}
          />
        )}
      </Panel>
      <p className="help-text">
        HIGH denotes an exact protected-file match. MEDIUM denotes a qualifying
        block match. Both require context and analyst judgment.
      </p>
    </>
  );
}
const SEVERITY_RANK: Record<string, number> = { HIGH: 2, MEDIUM: 1 };
const STATUS_RANK: Record<string, number> = {
  OPEN: 0,
  INVESTIGATING: 1,
  RESOLVED: 2,
};
/** Sorts the incidents already on this page; the server's own filters and order decide which ones those are. */
export function sortIncidents(
  items: Summary[],
  sort: { column: string; direction: SortDirection },
): Summary[] {
  const key = (i: Summary): number | string =>
    sort.column === "severity"
      ? (SEVERITY_RANK[i.severity] ?? 0)
      : sort.column === "status"
        ? (STATUS_RANK[i.status] ?? 0)
        : i.created_at;
  const sign = sort.direction === "ascending" ? 1 : -1;
  return [...items].sort((a, b) => {
    const x = key(a),
      y = key(b);
    return (x < y ? -1 : x > y ? 1 : a.id < b.id ? -1 : 1) * sign;
  });
}

function Detail({ id }: { id: string }) {
  const { auth } = useSession();
  const result = useGet<IncidentView>(`/incidents/${id}`);
  const action = useAction();
  const toast = useToast();
  const [edit, setEdit] = useState(false);
  const [resolutionError, setResolutionError] = useState("");
  function update(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fields = new FormData(e.currentTarget);
    if (
      fields.get("status") === "RESOLVED" &&
      !String(fields.get("resolution") ?? "").trim()
    ) {
      setResolutionError(
        "Enter a resolution reason before closing this incident.",
      );
      return;
    }
    setResolutionError("");
    void action
      .run(() =>
        api<IncidentView>(
          `/incidents/${id}`,
          {
            ...jsonBody({
              expected_revision: result.data!.revision,
              status: fields.get("status"),
              note: fields.get("note"),
              resolution: fields.get("resolution"),
            }),
            method: "PATCH",
          },
          auth!.csrf_token,
        ),
      )
      .then((v) => {
        if (v) {
          setEdit(false);
          result.refresh();
          toast(`Investigation saved as ${v.status.toLowerCase()}`);
        }
      });
  }
  return (
    <>
      <Link className="back-link" to="/incidents">
        ← Investigation queue
      </Link>
      <PageHeader
        eyebrow="INCIDENT EVIDENCE"
        title={`Incident ${short(id)}`}
        description="Review the observation, preserve context, and record a reasoned investigation outcome."
        actions={
          result.data && (
            <>
              <button
                className="button secondary"
                disabled={action.busy}
                onClick={() =>
                  void action.run(async () => {
                    const evidence = await api(`/exports/incidents/${id}`);
                    saveBlob(
                      new Blob([JSON.stringify(evidence, null, 2)], {
                        type: "application/json",
                      }),
                      `incident-${id}.json`,
                    );
                    toast("Evidence exported as JSON");
                  })
                }
              >
                <Download size={16} />
                Export evidence
              </button>
              <button className="button primary" onClick={() => setEdit(true)}>
                <MessageSquare size={16} />
                Update investigation
              </button>
            </>
          )
        }
      />
      <Failure error={result.error || action.error} retry={result.refresh} />
      {result.loading && <Loading />}
      {result.data && (
        <>
          <div className="context-strip">
            <Status value={result.data.status} />
            <Status value={result.data.severity} />
            <span>Observed {date(result.data.created_at)}</span>
            <Link to={`/transfers/${result.data.transfer_id}`}>
              Open associated transfer →
            </Link>
          </div>
          <Panel title="What was observed">
            <p>
              The controlled gateway blocked this transfer because{" "}
              {result.data.scan.decision.reason === "EXACT_PROTECTED_FILE"
                ? "the submitted bytes exactly matched a protected file"
                : "protected byte matches met the active policy threshold"}
              . The evidence below records the evaluated policy and registry
              versions.
            </p>
            <p className="help-text">
              No file bytes were released through this blocked attempt.
              RootSentinel does not control transfers outside its gateway.
              Resolving an incident never authorizes the blocked transfer.
            </p>
          </Panel>
          <Evidence scan={result.data.scan} />
          <Panel
            title="Investigation timeline"
            subtitle={`Revision ${result.data.revision} · Updates are authorized and audited.`}
          >
            <ol className="timeline">
              {result.data.history.map((h) => (
                <li key={h.id}>
                  <div className="timeline-dot" />
                  <div>
                    <div className="timeline-heading">
                      <Status value={h.status} />
                      <time>{date(h.created_at)}</time>
                    </div>
                    <p className="preserve-lines">
                      {h.note || "Status recorded without an additional note."}
                    </p>
                    {h.resolution && (
                      <p className="preserve-lines">
                        <strong>Resolution:</strong> {h.resolution}
                      </p>
                    )}
                    <small className="muted break">
                      Reviewer {h.actor_id} · revision {h.revision}
                    </small>
                  </div>
                </li>
              ))}
            </ol>
          </Panel>
          <p className="help-text">
            JSON exports contain sanitized investigation metadata and audit
            references. They are not independently certified forensic artifacts.
          </p>
          <Dialog
            open={edit}
            title="Update investigation"
            close={() => setEdit(false)}
            busy={action.busy}
          >
            <form className="form-stack" onSubmit={update}>
              <label>
                Investigation status
                <select name="status" defaultValue={result.data.status}>
                  <option>OPEN</option>
                  <option>INVESTIGATING</option>
                  <option>RESOLVED</option>
                </select>
              </label>
              <label>
                Analyst note
                <textarea
                  name="note"
                  maxLength={1000}
                  rows={4}
                  placeholder="Record relevant synthetic investigation context. Do not paste source code or secrets."
                />
              </label>
              <label>
                Resolution reason
                <textarea
                  name="resolution"
                  maxLength={500}
                  rows={2}
                  placeholder="Required when resolving an incident"
                  aria-invalid={resolutionError ? true : undefined}
                  aria-describedby={
                    resolutionError ? "resolution-error" : undefined
                  }
                  onChange={() => setResolutionError("")}
                />
              </label>
              {resolutionError && (
                <p id="resolution-error" className="field-error">
                  {resolutionError}
                </p>
              )}
              <Failure error={action.error} />
              <p className="help-text">
                The transfer verdict remains BLOCK. Conflicting updates are
                rejected; refresh before retrying.
              </p>
              <div className="dialog-actions">
                <button
                  type="button"
                  className="button secondary"
                  disabled={action.busy}
                  onClick={() => setEdit(false)}
                >
                  Cancel
                </button>
                <button className="button primary" disabled={action.busy}>
                  Save investigation
                </button>
              </div>
            </form>
          </Dialog>
        </>
      )}
    </>
  );
}
