import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { Workbench } from './Workbench';

const capabilities = [
  { number: '01', title: 'Identify exact bytes', label: 'SHA-256', text: 'A file fingerprint stays the same when a file is renamed. Changing its bytes changes the fingerprint.' },
  { number: '02', title: 'Find matching blocks', label: '1 KiB chunks', text: 'Fixed-size block fingerprints provide the foundation for detecting unchanged, aligned portions of registered material.' },
  { number: '03', title: 'Verify an integrity proof', label: 'Merkle trees', text: 'An inclusion proof checks a chunk descriptor against a separately trusted root. It does not authorize a transfer.' },
];

function App() {
  return (
    <div className="layout">
      <a className="skip-link" href="#content">Skip to content</a>
      <header className="topbar">
        <a className="brand" href="#content" aria-label="RootSentinel home">
          <span className="brand-icon" aria-hidden="true">R<span>·</span></span>
          <span>RootSentinel <span className="brand-label">DLP</span></span>
        </a>
        <span className="phase"><span aria-hidden="true" /> Phase 02 · Detection</span>
      </header>
      <main id="content">
        <section className="hero" aria-labelledby="title">
          <p className="eyebrow">FILE INTEGRITY / CONTROLLED TRANSFER</p>
          <h1 id="title">Understand the evidence.<br /><span>Control the release.</span></h1>
          <p className="intro">A cryptographic foundation for protecting registered source code at a controlled outbound gateway.</p>
          <a className="text-link" href="#foundation">Explore the foundation <span aria-hidden="true">↘</span></a>
          <div className="scope-note"><strong>Local detection and policy</strong><p>The authenticated workbench processes synthetic files through the backend. File release and public deployment are not available yet.</p></div>
        </section>
        <Workbench />
        <section id="foundation" aria-labelledby="foundation-title">
          <div className="section-heading"><h2 id="foundation-title">Three distinct responsibilities</h2><span>Cryptographic profile v1</span></div>
          <div className="cards">{capabilities.map(item => (
            <article className="card" key={item.number}>
              <div className="card-top"><span className="number">{item.number}</span><span className="tag">{item.label}</span></div>
              <h3>{item.title}</h3><p>{item.text}</p>
            </article>
          ))}</div>
        </section>
        <section className="boundary" aria-labelledby="boundary-title">
          <div><p className="eyebrow">DEFINED SECURITY BOUNDARY</p><h2 id="boundary-title">One gateway. Two demonstration modes.</h2></div>
          <div className="modes"><div><h3>Public browser workflow</h3><p>Planned: real processing and controlled release of synthetic fixture inputs.</p></div><div><h3>Local staging workflow</h3><p>Planned: Linux/WSL2 admission, scanning and release into a gateway-owned destination.</p></div></div>
          <p className="limitation">Gateway enforcement does not prevent transfers through other applications, devices or network routes. Fixed chunks can miss shifted or transformed content.</p>
        </section>
      </main>
      <footer><span>RootSentinel — CS-3002 Information Security</span><a href="https://github.com/UsmanPrime/rootsentinel-dlp" rel="noreferrer" target="_blank">Project repository <span aria-hidden="true">↗</span></a></footer>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
