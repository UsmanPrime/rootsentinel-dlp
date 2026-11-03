import { useEffect, useState, type FormEvent } from 'react';
import { api, fixture, jsonBody, type Asset, type Auth, type Policy, type Scan } from './api';

export function Workbench() {
  const [auth, setAuth] = useState<Auth | null>(null);
  const [checking, setChecking] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [selection, setSelection] = useState('protected');

  async function refresh(session: Auth) {
    const active = await api<Policy>('/policies/active');
    const registry = session.user.role === 'EMPLOYEE' ? [] : (await api<{ items: Asset[] }>('/assets?limit=100')).items;
    setPolicy(active); setAssets(registry);
  }
  useEffect(() => {
    let live = true;
    api<Auth>('/auth/me').then(async session => {
      if (live) { setAuth(session); await refresh(session); }
    }).catch(err => {
      if (live && err.message !== 'AUTHENTICATION_REQUIRED') setError(err.message);
    }).finally(() => { if (live) setChecking(false); });
    return () => { live = false; };
  }, []);

  async function perform(action: () => Promise<void>) {
    setBusy(true); setError(''); setMessage('');
    try { await action(); }
    catch (err) {
      const code = err instanceof Error ? err.message : 'REQUEST_FAILED';
      setError(code);
      if (code === 'AUTHENTICATION_REQUIRED') { setAuth(null); setScan(null); setAssets([]); setPolicy(null); }
    } finally { setBusy(false); }
  }
  function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    void perform(async () => {
      const session = await api<Auth>('/auth/login', jsonBody({ username: data.get('username'), password: data.get('password') }));
      form.reset(); setAuth(session); await refresh(session);
    });
  }
  function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const label = new FormData(event.currentTarget).get('label') as string;
    void perform(async () => {
      await api('/assets?label=' + encodeURIComponent(label), { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: fixture('protected') }, auth!.csrf_token);
      await refresh(auth!); setMessage('Synthetic asset registered. Only its fingerprints are retained.');
    });
  }
  return <section className="workbench" aria-labelledby="workbench-title">
    <div className="section-heading"><h2 id="workbench-title">Local detection workbench</h2><span>Phase 02 / real backend processing</span></div>
    <p>Use locally bootstrapped accounts and synthetic fixtures. A policy ALLOW is an evaluation result; no file delivery is available.</p>
    {checking && <p role="status">Checking backend session…</p>}
    {error && <div className="notice error" role="alert">Request could not complete: {error}. No release was authorized. Check that the local API is running and your session is valid.</div>}
    {message && <p className="notice" role="status">{message}</p>}
    {!checking && !auth && <form onSubmit={login} className="work-form">
      <label>Username<input name="username" autoComplete="username" required maxLength={64} /></label>
      <label>Password<input name="password" type="password" autoComplete="current-password" required maxLength={128} /></label>
      <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>}
    {auth && <>
      <div className="session-bar"><p>Signed in as <strong>{auth.user.username}</strong> · {auth.user.role}</p>
        <button disabled={busy} onClick={() => void perform(async () => {
          await api('/auth/logout', { method: 'POST' }, auth.csrf_token);
          setAuth(null); setAssets([]); setPolicy(null); setScan(null);
        })}>Sign out</button></div>
      <div className="work-grid">
        {auth.user.role !== 'EMPLOYEE' && <article className="card">
          <h3>Protected asset registry</h3>
          {assets.length === 0 ? <p>No registered assets. Register the synthetic sample to begin.</p> : <ul>{assets.map(a => <li key={a.id}>
            <strong>{a.label}</strong> · version {a.current_version} · {a.retired ? 'retired' : 'active'}
          </li>)}</ul>}
          <p className="limitation">Showing up to 100 assets. Version details and pagination are available through the REST API.</p>
          {auth.user.role === 'ADMIN' && <form onSubmit={register} className="work-form">
            <label>Asset label<input name="label" defaultValue="Synthetic source sample" pattern="[A-Za-z0-9][A-Za-z0-9 ._()\-]*" maxLength={120} required /></label>
            <p>Registers eight deterministic 1 KiB synthetic blocks.</p>
            <button disabled={busy}>Register synthetic asset</button>
          </form>}
        </article>}
        <article className="card"><h3>Active policy</h3>
          {policy && <><p>Version {policy.number} · exact matches always BLOCK.</p><p>Block matching: {policy.block_enabled ? 'enabled' : 'disabled'} · threshold {policy.threshold.toLocaleString()} bytes per asset.</p>
          <code className="digest">{policy.id}</code></>}
          <p>Policy changes require ADMIN authorization through the versioned REST API. There is no administrator bypass.</p>
        </article>
        <article className="card"><h3>Evaluate a candidate</h3>
          <label>Synthetic input<select value={selection} onChange={event => setSelection(event.target.value)}>
            <option value="protected">Exact protected file</option><option value="renamed">Renamed copy</option>
            <option value="partial">Aligned partial copy</option><option value="modified">One-byte change</option>
            <option value="shifted">One-byte prefix (known limitation)</option><option value="benign">Unprotected note</option><option value="empty">Empty file</option>
          </select></label>
          <button disabled={busy} onClick={() => void perform(async () => {
            setScan(null);
            const result = await api<Scan>('/scans?filename=' + selection + '.txt', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: fixture(selection) }, auth.csrf_token);
            setScan(result);
          })}>{busy ? 'Processing…' : 'Run scan'}</button>
        </article>
      </div>
      {scan && <article className="scan-result" aria-labelledby="result-title" aria-live="polite">
        <h3 id="result-title">Policy decision: <span className={'verdict ' + scan.decision.outcome.toLowerCase()}>{scan.decision.outcome}</span></h3>
        <p>{scan.decision.reason} · registry revision {scan.detection.registry_revision}</p>
        <p>File: {scan.filename} · {scan.detection.manifest.file_size.toLocaleString()} bytes · {scan.detection.manifest.chunk_count} chunks</p>
        <dl><dt>Scan ID</dt><dd>{scan.id}</dd><dt>SHA-256</dt><dd>{scan.detection.manifest.file_sha256}</dd><dt>Merkle root</dt><dd>{scan.detection.manifest.merkle_root}</dd><dt>Policy version ID</dt><dd>{scan.policy_id}</dd></dl>
        <h4>Matching evidence ({scan.detection.matches.length} asset versions)</h4>
        {!scan.detection.matches.length && <p>No matching blocks or exact files were found. Raw-byte matching can miss shifted, encoded or transformed protected content.</p>}
        {scan.detection.matches.slice(0, 20).map(match => <details key={match.version_id}>
          <summary>{match.exact ? 'Exact file match' : 'Block match'} · {match.matched_bytes.toLocaleString()} bytes · {match.coverage.denominator ? (100 * match.coverage.numerator / match.coverage.denominator).toFixed(1) : '0'}% coverage</summary>
          <p className="digest">Asset {match.asset_id} / version {match.version_id}</p>
          {match.blocks.slice(0, 20).map(block => <div key={block.sha256 + block.length} className="block-evidence">
            <code className="digest">{block.sha256}</code><p>{block.length} bytes; protected indices: {block.source_indices.slice(0, 20).join(', ')}; outbound indices: {block.outbound_indices.slice(0, 20).join(', ')}</p>
          </div>)}
          <p>Display capped at 20 blocks/indices. Full evidence is available from the scan API. Shared and repeated blocks do not establish unique ownership.</p>
        </details>)}
      </article>}
    </>}
  </section>;
}
