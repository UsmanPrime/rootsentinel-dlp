import { useState } from 'react';
import { api, fixture, jsonBody, type Auth, type Scan } from './api';

interface Transfer {
  id: string; state: string; reason: string; file_sha256: string; file_size: number;
  expires_at: string; release_eligible: boolean; incident_id: string | null; scan: Scan | null;
}
interface Incident {
  id: string; transfer_id: string; status: string; severity: string; revision: number;
  history: { id: string; status: string; note: string; resolution: string }[];
}
interface Verification { valid: boolean; reason: string; through_sequence: number; checkpoint_sequence: number | null }

export function TransferWorkbench({ auth }: { auth: Auth }) {
  const [selection, setSelection] = useState('benign');
  const [file, setFile] = useState<File | null>(null);
  const [transfer, setTransfer] = useState<Transfer | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [events, setEvents] = useState<{ event: { id: string; sequence: number; kind: string; timestamp: string }; mac: string }[]>([]);
  const [note, setNote] = useState('');
  const [resolution, setResolution] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const investigate = auth.user.role !== 'EMPLOYEE';

  async function perform(label: string, action: () => Promise<void>) {
    setBusy(label); setError(''); setMessage('');
    try { await action(); }
    catch (err) { setError(err instanceof Error ? err.message : 'REQUEST_FAILED'); }
    finally { setBusy(''); }
  }
  async function refreshTransfer(identifier: string) { setTransfer(await api<Transfer>('/transfers/' + identifier)); }
  function save(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function download() {
    const response = await fetch(`/api/v1/transfers/${transfer!.id}/release`, {
      method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': auth.csrf_token },
    });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      await refreshTransfer(transfer!.id);
      throw new Error(body?.error?.code ?? 'RELEASE_FAILED');
    }
    const bytes = await response.arrayBuffer();
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).map(b => b.toString(16).padStart(2, '0')).join('');
    if (digest !== transfer!.file_sha256 || bytes.byteLength !== transfer!.file_size) throw new Error('BROWSER_INTEGRITY_MISMATCH');
    save(new Blob([bytes], { type: 'application/octet-stream' }), `transfer-${transfer!.id}.bin`);
    await refreshTransfer(transfer!.id);
    setMessage('Download response verified in this browser. Recipient storage is not confirmed. A retry requires a new transfer.');
  }
  return <section className="card" aria-labelledby="transfer-title">
    <h3 id="transfer-title">Controlled transfer gateway</h3>
    <p>Local mode only. Register the synthetic asset below before demonstrating a protected transfer. Downloads are single-use, expire after 15 minutes and require current registry and policy versions.</p>
    <div className="work-grid">
      <label>Transfer fixture<select aria-label="Transfer fixture" value={selection} onChange={e => { setSelection(e.target.value); setFile(null); }}>
        <option value="benign">Unprotected note</option><option value="protected">Protected synthetic file</option>
        <option value="partial">Aligned partial copy</option><option value="shifted">Shifted content (known blind spot)</option>
      </select></label>
      <label>Optional local synthetic file (10 MiB maximum)<input type="file" onChange={e => setFile(e.target.files?.[0] ?? null)} /></label>
    </div>
    <button disabled={!!busy} onClick={() => void perform('Receiving and evaluating transfer', async () => {
      setTransfer(null); setIncident(null);
      if (file && file.size > 10485760) throw new Error('INPUT_TOO_LARGE');
      const result = await api<Transfer>('/transfers?filename=candidate.bin', {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'Idempotency-Key': crypto.randomUUID() },
        body: file ?? fixture(selection),
      }, auth.csrf_token);
      setTransfer(result);
      if (result.incident_id && investigate) setIncident(await api<Incident>('/incidents/' + result.incident_id));
    })}>Submit transfer</button>
    {busy && <p role="status">{busy}…</p>}
    {error && <p role="alert">{error}. Release is not confirmed. Refresh the transfer before retrying; stale, expired or consumed transfers require a new evaluation.</p>}
    {message && <p role="status">{message}</p>}
    {transfer && <article aria-live="polite">
      <h4>Transfer state: {transfer.state}</h4><p>{transfer.reason}</p>
      <dl><dt>Transfer ID</dt><dd>{transfer.id}</dd><dt>SHA-256</dt><dd>{transfer.file_sha256}</dd>
        <dt>Bytes</dt><dd>{transfer.file_size}</dd><dt>Release deadline</dt><dd>{new Date(transfer.expires_at).toLocaleString()}</dd></dl>
      {transfer.scan && <><p>Policy verdict: {transfer.scan.decision.outcome} · registry revision {transfer.scan.detection.registry_revision}</p>
        <p className="digest">Policy version {transfer.scan.policy_id}</p>
        {transfer.scan.detection.matches.map(match => <details key={match.version_id}>
          <summary>{match.exact ? 'Exact match' : 'Block match'}: {match.matched_bytes} matching bytes</summary>
          <p className="digest">Asset {match.asset_id}, version {match.version_id}</p>
          <p>Outbound intervals: {match.intervals.slice(0, 20).map(([a, b]) => `[${a}, ${b})`).join(', ')}</p>
          <p>Coverage {match.coverage.numerator}/{match.coverage.denominator}; shared blocks do not establish unique ownership.</p>
        </details>)}</>}
      <button disabled={!!busy || !transfer.release_eligible} onClick={() => void perform('Verifying and downloading', download)}>Verified download</button>
      <button disabled={!!busy} onClick={() => void perform('Refreshing transfer', () => refreshTransfer(transfer.id))}>Refresh transfer</button>
      {transfer.incident_id && <p className="digest">Associated incident: {transfer.incident_id}</p>}
    </article>}
    {investigate && <>
      <h4>Incident investigation</h4>
      <button disabled={!!busy} onClick={() => void perform('Loading incidents', async () => {
        setIncidents((await api<{ items: Incident[] }>('/incidents?limit=25')).items);
      })}>Load incidents</button>
      <ul>{incidents.map(item => <li key={item.id}><button disabled={!!busy} onClick={() => void perform('Loading incident', async () => {
        setIncident(await api<Incident>('/incidents/' + item.id));
      })}>{item.severity} · {item.status} · {item.id}</button></li>)}</ul>
      {incident && <article>
        <h4>Incident: {incident.status}</h4><p>Severity {incident.severity}: exact matches HIGH, threshold block matches MEDIUM. Intent is not established.</p>
        <ul>{incident.history.map(h => <li key={h.id}>{h.status}: {h.note} {h.resolution}</li>)}</ul>
        <label>Investigation note<input value={note} maxLength={1000} onChange={e => setNote(e.target.value)} /></label>
        <label>Resolution reason<input value={resolution} maxLength={500} onChange={e => setResolution(e.target.value)} /></label>
        {(['INVESTIGATING', 'RESOLVED'] as const).map(status => <button key={status} disabled={!!busy || incident.status === 'RESOLVED'} onClick={() => void perform('Updating investigation', async () => {
          setIncident(await api<Incident>('/incidents/' + incident.id, { ...jsonBody({ expected_revision: incident.revision, status, note, resolution }), method: 'PATCH' }, auth.csrf_token));
        })}>{status === 'RESOLVED' ? 'Resolve incident' : 'Mark investigating'}</button>)}
        <button disabled={!!busy} onClick={() => void perform('Exporting sanitized evidence', async () => {
          const result = await api('/exports/incidents/' + incident.id);
          save(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }), 'incident-evidence.json');
        })}>Export incident JSON</button>
      </article>}
      <h4>Audit integrity</h4>
      <p>HMAC verification depends on trusted keys and independently retained checkpoints. It does not protect against a compromised host or key holder.</p>
      <button disabled={!!busy} onClick={() => void perform('Verifying audit chain', async () => {
        setVerification(await api<Verification>('/audit/verify', { method: 'POST' }, auth.csrf_token));
        setEvents((await api<{ events: typeof events }>('/audit/events?limit=25')).events);
      })}>Verify audit chain</button>
      {verification && <p role="status">Audit {verification.valid ? 'verified' : 'FAILED'} through event {verification.through_sequence}: {verification.reason}. Retained checkpoint: {verification.checkpoint_sequence ?? 'none'}.</p>}
      <ol>{events.map(({ event }) => <li key={event.id}>#{event.sequence} {event.kind} · {event.timestamp}</li>)}</ol>
    </>}
  </section>;
}
