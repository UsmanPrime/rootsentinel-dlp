import {
  ArrowDownLeft,
  ArrowUpRight,
  Boxes,
  Clock3,
  RefreshCw,
  ShieldAlert,
  UploadCloud,
} from "lucide-react";
import { Link } from "react-router-dom";
import type {
  Overview as OverviewData,
  TransferPage,
} from "../../lib/contracts";
import { useGet, useTitle } from "../../lib/hooks";
import { date, short } from "../../lib/errors";
import {
  Empty,
  Failure,
  Loading,
  PageHeader,
  Panel,
  Status,
  Table,
} from "../../components/ui";

export default function Overview() {
  useTitle("Security overview");
  const overview = useGet<OverviewData>("/overview");
  const recent = useGet<TransferPage>("/transfers?limit=6");
  const data = overview.data;
  const distribution = data
    ? [
        {
          label: "Allowed decisions",
          count: data.allowed_decisions,
          className: "allow",
        },
        {
          label: "Blocked decisions",
          count: data.blocked_decisions,
          className: "block",
        },
        {
          label: "Without a final decision",
          count: data.undecided_transfers,
          className: "other",
        },
      ]
    : [];
  const maximum = Math.max(2, ...(data?.daily.map((x) => x.total) ?? []));
  function refresh() {
    overview.refresh();
    recent.refresh();
  }
  return (
    <>
      <PageHeader
        eyebrow="SECURITY OPERATIONS"
        title="Security overview"
        description="A clear view of the bytes crossing your controlled boundary."
        actions={
          <>
            <button
              className="button secondary"
              onClick={refresh}
              disabled={overview.loading}
            >
              <RefreshCw size={15} />
              Refresh
            </button>
            <Link className="button primary" to="/transfers">
              <UploadCloud size={16} />
              New transfer
            </Link>
          </>
        }
      />
      <Failure error={overview.error} retry={refresh} />
      {overview.loading && <Loading label="Reading workspace metrics" />}
      {data && (
        <>
          <div className="observation-line">
            <span className="scope-chip">
              {data.scope === "own" ? "YOUR TRANSFERS" : "WORKSPACE VIEW"}
            </span>
            <span>Observed {date(data.observed_at)} · Refresh on demand</span>
            <span className="api-observed">
              API responded · {data.mode} mode
            </span>
          </div>
          <div className="metric-grid">
            <article className="metric">
              <div>
                <span>Observed transfers</span>
                <UploadCloud size={18} />
              </div>
              <strong>{data.total_transfers.toLocaleString()}</strong>
              <p>All retained attempts</p>
            </article>
            <article className="metric">
              <div>
                <span>Blocked decisions</span>
                <ShieldAlert size={18} />
              </div>
              <strong className="text-danger">
                {data.blocked_decisions.toLocaleString()}
              </strong>
              <p>Protected content withheld</p>
            </article>
            <article className="metric">
              <div>
                <span>Allowed decisions</span>
                <ArrowUpRight size={18} />
              </div>
              <strong className="text-success">
                {data.allowed_decisions.toLocaleString()}
              </strong>
              <p>Release still requires verification</p>
            </article>
            <article className="metric">
              <div>
                <span>
                  {data.scope === "own"
                    ? "Without a decision"
                    : "Active incidents"}
                </span>
                <Clock3 size={18} />
              </div>
              <strong>
                {(
                  data.active_incidents ?? data.undecided_transfers
                ).toLocaleString()}
              </strong>
              <p>
                {data.scope === "own"
                  ? "Incomplete or failed evaluations"
                  : "Open or investigating"}
              </p>
            </article>
          </div>
          <div className="dashboard-grid">
            <Panel
              title="Transfer activity"
              subtitle="Last 7 UTC calendar days, including today"
              actions={<span className="scope-chip">ACTUAL ATTEMPTS</span>}
            >
              <div
                className="activity-chart"
                role="img"
                aria-label={`Seven-day transfer counts: ${data.daily.map((d) => `${d.date}: ${d.total}`).join("; ")}`}
              >
                <div className="chart-scale">
                  <span>{maximum}</span>
                  <span>{Math.round(maximum / 2)}</span>
                  <span>0</span>
                </div>
                <div className="chart-bars">
                  {data.daily.map((day) => (
                    <div className="chart-column" key={day.date}>
                      <span className="bar-value">{day.total}</span>
                      <div className="bar-track">
                        <i
                          style={{
                            height: `${(day.total / maximum) * 100}%`,
                            borderTopWidth: day.total ? 2 : 0,
                          }}
                        />
                      </div>
                      <span>
                        {new Date(day.date + "T00:00:00Z").toLocaleDateString(
                          "en",
                          { month: "short", day: "numeric", timeZone: "UTC" },
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              {!data.daily.some((x) => x.total) && (
                <p className="chart-empty">No transfers in this time window.</p>
              )}
              <details className="text-alternative">
                <summary>View activity as a table</summary>
                <Table label="Daily transfer counts">
                  <thead>
                    <tr>
                      <th scope="col">UTC date</th>
                      <th scope="col">Attempts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.daily.map((d) => (
                      <tr key={d.date}>
                        <td>{d.date}</td>
                        <td>{d.total}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </details>
            </Panel>
            <Panel
              title="Policy outcomes"
              subtitle="All retained transfers · persisted decisions"
            >
              <div className="outcome-total">
                <strong>{data.total_transfers}</strong>
                <span>observed attempts</span>
              </div>
              <div className="distribution" aria-hidden="true">
                {distribution.map((d) => (
                  <span
                    className={d.className}
                    key={d.label}
                    style={{
                      width: `${data.total_transfers ? (d.count / data.total_transfers) * 100 : 0}%`,
                    }}
                  />
                ))}
              </div>
              <ul className="legend">
                {distribution.map((d) => (
                  <li key={d.label}>
                    <span>
                      <i className={d.className} />
                      {d.label}
                    </span>
                    <strong>{d.count}</strong>
                  </li>
                ))}
              </ul>
              <p className="tiny muted">
                An ALLOW decision is separate from release eligibility. Expiry
                and revision changes can invalidate release.
              </p>
            </Panel>
          </div>
          {data.scope === "workspace" && (
            <div className="context-strip">
              <div>
                <Boxes size={18} />
                <span>
                  <strong>{data.active_assets}</strong> active protected assets
                </span>
                <Link to="/assets">
                  Open registry <ArrowUpRight size={13} />
                </Link>
              </div>
              <div>
                <ShieldAlert size={18} />
                <span>
                  Active incidents: <strong>{data.severity?.HIGH ?? 0}</strong>{" "}
                  high / <strong>{data.severity?.MEDIUM ?? 0}</strong> medium
                </span>
                <Link to="/incidents">
                  Investigate <ArrowUpRight size={13} />
                </Link>
              </div>
              <div>
                <Clock3 size={18} />
                <span>
                  Audit head <strong>#{data.audit_sequence}</strong>
                </span>
                <Link to="/audit">
                  Verify integrity <ArrowUpRight size={13} />
                </Link>
              </div>
            </div>
          )}
        </>
      )}
      <Panel
        title="Recent transfer activity"
        subtitle="Latest 6 authorized records, newest first"
        actions={
          <Link className="text-link" to="/transfers">
            View gateway <ArrowRightIcon />
          </Link>
        }
      >
        <Failure error={recent.error} retry={recent.refresh} />
        {recent.loading && <Loading />}
        {recent.data &&
          (!recent.data.items.length ? (
            <Empty
              title="Your first transfer starts here"
              action={
                <Link className="button primary" to="/guide">
                  Open the guided demo
                </Link>
              }
            >
              Register synthetic material, submit a candidate, and inspect the
              resulting evidence.
            </Empty>
          ) : (
            <Table label="Recent transfer activity">
              <thead>
                <tr>
                  <th scope="col">Transfer</th>
                  <th scope="col">State</th>
                  <th scope="col">Submitted</th>
                  <th scope="col">Record</th>
                </tr>
              </thead>
              <tbody>
                {recent.data.items.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <span className="file-cell">
                        <ArrowDownLeft size={17} />
                        <strong>{t.filename}</strong>
                      </span>
                    </td>
                    <td>
                      <Status value={t.state} />
                    </td>
                    <td className="muted">{date(t.created_at)}</td>
                    <td>
                      <Link
                        to={"/transfers/" + t.id}
                        aria-label={`Open transfer ${short(t.id)}`}
                      >
                        <code>{short(t.id)}</code> ↗
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ))}
      </Panel>
      <div className="boundary-banner">
        <ShieldAlert size={18} />
        <p>
          <strong>Know the boundary.</strong> RootSentinel controls its own
          release path. Transfers through other applications remain outside its
          coverage.
        </p>
        <Link to="/guide#limitations">
          Detection limits <ArrowUpRight size={14} />
        </Link>
      </div>
    </>
  );
}
function ArrowRightIcon() {
  return <ArrowUpRight size={14} aria-hidden="true" />;
}
