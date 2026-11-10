import { useState, type FormEvent } from "react";
import { SlidersHorizontal } from "lucide-react";
import { api, jsonBody } from "../../api";
import {
  Dialog,
  Failure,
  Loading,
  Notice,
  PageHeader,
  Pager,
  Panel,
  Table,
} from "../../components/ui";
import { useAction, useGet, useTitle } from "../../lib/hooks";
import { date, short } from "../../lib/errors";
import { useSession } from "../../lib/session";
import { useToast } from "../../lib/toast";
import type { PolicyPage, PolicyView } from "../../lib/contracts";

export default function Policies() {
  useTitle("Policies");
  const { auth } = useSession();
  const action = useAction();
  const [offset, setOffset] = useState(0);
  const [edit, setEdit] = useState(false);
  const [thresholdError, setThresholdError] = useState("");
  const toast = useToast();
  const [saved, setSaved] = useState<number>();
  const active = useGet<PolicyView>("/policies/active");
  const history = useGet<PolicyPage>(
    auth!.user.role !== "EMPLOYEE"
      ? `/policies/history?limit=10&offset=${offset}`
      : null,
  );
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const values = new FormData(e.currentTarget);
    const threshold = Number(values.get("threshold"));
    if (!Number.isInteger(threshold) || threshold < 1 || threshold > 10485760) {
      setThresholdError("Enter a whole number of bytes from 1 to 10,485,760.");
      return;
    }
    setThresholdError("");
    void action
      .run(() =>
        api<PolicyView>(
          "/policies",
          jsonBody({
            expected_version: active.data!.id,
            block_enabled: values.get("enabled") === "on",
            threshold,
          }),
          auth!.csrf_token,
        ),
      )
      .then((v) => {
        if (v) {
          setSaved(v.number);
          toast(`Policy version ${v.number} is active`);
          setEdit(false);
          active.refresh();
          history.refresh();
        }
      });
  }
  return (
    <>
      <PageHeader
        eyebrow="DETERMINISTIC AUTHORIZATION"
        title="Policies"
        description="Detection supplies evidence. Versioned policy determines the outcome. Only the gateway can authorize a release."
        actions={
          auth!.user.role === "ADMIN" &&
          active.data && (
            <button className="button primary" onClick={() => setEdit(true)}>
              <SlidersHorizontal size={16} />
              Create policy version
            </button>
          )
        }
      />
      <Failure
        error={active.error || history.error}
        retry={() => {
          active.refresh();
          history.refresh();
        }}
      />
      {saved && (
        <Notice tone="success">
          Policy version {saved} is now active. Older transfer approvals must be
          reevaluated by submitting a new transfer.
        </Notice>
      )}
      {active.loading && <Loading />}
      {active.data && (
        <>
          <Panel
            title={`Active policy · v${active.data.number}`}
            subtitle={`Created ${date(active.data.created_at)}`}
          >
            <div className="policy-grid">
              <div>
                <span className="field-caption">EXACT PROTECTED FILE</span>
                <strong className="negative-text">Always BLOCK</strong>
                <p>Filename changes do not affect byte identity.</p>
              </div>
              <div>
                <span className="field-caption">BLOCK MATCHING</span>
                <strong>
                  {active.data.block_enabled ? "Enabled" : "Disabled"}
                </strong>
                <p>Fixed-size, raw-byte fingerprint evidence.</p>
              </div>
              <div>
                <span className="field-caption">MATCHED-BYTE THRESHOLD</span>
                <strong>{active.data.threshold.toLocaleString()} B</strong>
                <p>For at least one protected asset version.</p>
              </div>
            </div>
            <p className="help-text break">
              Policy ID {active.data.id} · Author{" "}
              {active.data.actor_id ?? "Migration default"}
            </p>
          </Panel>
          <Panel title="Decision precedence">
            <ol className="explanation-list">
              <li>
                <strong>Fail closed.</strong> Invalid, unauthorized or failed
                evaluations never authorize release.
              </li>
              <li>
                <strong>Exact match → BLOCK.</strong> This rule takes precedence
                and cannot be bypassed by an administrator.
              </li>
              <li>
                <strong>Qualifying blocks → BLOCK.</strong> When enabled, the
                server applies the configured per-asset matched-byte threshold.
              </li>
              <li>
                <strong>No qualifying match → ALLOW.</strong> Release still
                requires current revisions, an intact snapshot and mandatory
                audit persistence.
              </li>
            </ol>
          </Panel>
          {history.data && (
            <Panel title="Immutable policy history">
              <Table label="Policy history">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Block matching</th>
                    <th>Threshold</th>
                    <th>Created</th>
                    <th>Author</th>
                  </tr>
                </thead>
                <tbody>
                  {history.data.items.map((p) => (
                    <tr key={p.id}>
                      <td>
                        v{p.number}
                        {p.id === active.data!.id ? " · active" : ""}
                      </td>
                      <td>{p.block_enabled ? "Enabled" : "Disabled"}</td>
                      <td>{p.threshold.toLocaleString()} B</td>
                      <td>{date(p.created_at)}</td>
                      <td className="mono">
                        {p.actor_id ? short(p.actor_id) : "Default"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pager
                offset={offset}
                count={history.data.items.length}
                change={setOffset}
              />
            </Panel>
          )}
          <Dialog
            open={edit}
            title="Create a new policy version"
            close={() => setEdit(false)}
            busy={action.busy}
          >
            <form className="form-stack" onSubmit={submit}>
              <Notice>
                Confirm this change intentionally. It affects subsequent
                evaluations and invalidates pending approvals. Historical
                policies remain unchanged.
              </Notice>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  name="enabled"
                  defaultChecked={active.data.block_enabled}
                />
                Enable block matching
              </label>
              <label>
                Minimum matched outbound bytes
                <input
                  type="number"
                  name="threshold"
                  min={1}
                  max={10485760}
                  step={1}
                  defaultValue={active.data.threshold}
                  required
                  aria-invalid={thresholdError ? true : undefined}
                  aria-describedby={
                    thresholdError ? "threshold-error" : undefined
                  }
                  onChange={() => setThresholdError("")}
                />
              </label>
              {thresholdError && (
                <p id="threshold-error" className="field-error">
                  {thresholdError}
                </p>
              )}
              <p className="help-text">
                Exact protected-file matches always BLOCK. Turning off block
                matching reduces partial-copy detection enforcement.
              </p>
              <Failure error={action.error} />
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
                  Confirm new version
                </button>
              </div>
            </form>
          </Dialog>
        </>
      )}
    </>
  );
}
