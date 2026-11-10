import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCheck, FlaskConical, GitBranch } from "lucide-react";
import { api, jsonBody } from "../../api";
import {
  Empty,
  Failure,
  Hash,
  Loading,
  Notice,
  PageHeader,
  Pager,
  Panel,
  Status,
  Table,
} from "../../components/ui";
import { useAction, useGet, useTitle } from "../../lib/hooks";
import { useSession } from "../../lib/session";
import type {
  AssetPage,
  IntegrityView,
  ProofView,
  ScanView,
  TreeNode,
  TreeView,
  VersionSummary,
} from "../../lib/contracts";

export function tamperProof(proof: ProofView): ProofView {
  const copy = structuredClone(proof);
  if (copy.siblings.length)
    copy.siblings[0] =
      (copy.siblings[0][0] === "0" ? "1" : "0") + copy.siblings[0].slice(1);
  else
    copy.chunk.sha256 =
      (copy.chunk.sha256[0] === "0" ? "1" : "0") + copy.chunk.sha256.slice(1);
  return copy;
}

export function TreeDiagram({
  tree,
  select,
}: {
  tree: TreeView;
  select: (n: number) => void;
}) {
  // A leaf being hovered or focused: its path to the root and the proof siblings along it are highlighted.
  const [preview, setPreview] = useState<string | null>(null);
  if (!tree.nodes.length)
    return (
      <Empty title="Empty tree">
        The empty input has a root, but no leaves and no inclusion proof.
      </Empty>
    );
  const positions = new Map<string, { x: number; y: number }>();
  const byId = new Map(tree.nodes.map((n) => [n.id, n]));
  let next = 0;
  function place(node: TreeNode, depth: number): number {
    const l = node.left && byId.get(node.left);
    const r = node.right && byId.get(node.right);
    const x = l && r ? (place(l, depth + 1) + place(r, depth + 1)) / 2 : next++;
    positions.set(node.id, { x, y: depth });
    return x;
  }
  place(tree.nodes[tree.nodes.length - 1], 0);
  const parent = new Map<string, string>();
  for (const n of tree.nodes)
    for (const child of [n.left, n.right]) if (child) parent.set(child, n.id);
  const previewPath = new Set<string>();
  const previewSiblings = new Set<string>();
  for (let id = preview; id; id = parent.get(id) ?? null) {
    previewPath.add(id);
    const up = parent.get(id);
    const node = up ? byId.get(up) : undefined;
    const other = node && (node.left === id ? node.right : node.left);
    if (other) previewSiblings.add(other);
  }
  const previewLeaf = preview ? byId.get(preview) : undefined;
  const hover = (id: string | null) => () => setPreview(id);
  const width = Math.max(600, next * 110),
    height =
      80 + Math.max(...Array.from(positions.values()).map((p) => p.y)) * 90;
  const point = (id: string) => {
    const p = positions.get(id)!;
    return { x: ((p.x + 0.5) * width) / next, y: p.y * 90 + 35 };
  };
  return (
    <div
      className="tree-scroll"
      tabIndex={0}
      role="region"
      aria-label="Merkle tree visualization. Select leaves with the chunk table below."
    >
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className={`tree-min-${Math.min(9, Math.max(6, Math.round(width / 100)))}`}
        role="img"
        aria-label={`${tree.manifest.chunk_count}-leaf Merkle tree, selected chunk ${tree.selected_index}. ${tree.mode === "proof_path" ? "Collapsed proof path." : "Full ordered tree."}`}
      >
        {tree.nodes.flatMap((n) =>
          [n.left, n.right]
            .filter((x): x is string => !!x)
            .map((child) => {
              const a = point(n.id),
                b = point(child);
              return (
                <path
                  key={`${n.id}-${child}`}
                  d={`M${a.x},${a.y + 22} V${a.y + 45} H${b.x} V${b.y - 22}`}
                  className={`tree-edge ${byId.get(child)?.selected_path ? "selected" : ""} ${previewPath.has(child) ? "previewed" : ""}`}
                />
              );
            }),
        )}
        {tree.nodes.map((n) => {
          const p = point(n.id);
          return (
            <g
              key={n.id}
              transform={`translate(${p.x},${p.y})`}
              className={`tree-node ${n.selected_path ? "selected" : n.sibling ? "sibling" : ""} ${previewPath.has(n.id) ? "previewed" : previewSiblings.has(n.id) ? "preview-sibling" : ""}`}
              onMouseEnter={n.count === 1 ? hover(n.id) : undefined}
              onMouseLeave={n.count === 1 ? hover(null) : undefined}
            >
              <rect x={-48} y={-23} width={96} height={48} rx={6} />
              <text y={-4} textAnchor="middle">
                {n.count === 1
                  ? `Chunk ${n.start}`
                  : `${n.start}…${n.start + n.count - 1}`}
              </text>
              <text y={12} textAnchor="middle" className="tree-digest">
                {n.digest.slice(0, 10)}
              </text>
            </g>
          );
        })}
      </svg>
      <p className="help-text">
        Teal: selected leaf to root. Amber: proof sibling subtree. Hover a leaf,
        or focus a chunk button, to preview its path. Ordered chunk selection is
        available below.
      </p>
      <p className="tree-preview" aria-live="polite">
        {previewLeaf
          ? `Previewing chunk ${previewLeaf.start}: ${previewPath.size} nodes to the root, ${previewSiblings.size} sibling ${previewSiblings.size === 1 ? "hash" : "hashes"} in its proof.`
          : ""}
      </p>
      <div className="leaf-shortcuts" aria-label="Leaf shortcuts">
        {tree.nodes
          .filter((n) => n.count === 1)
          .map((n) => (
            <button
              key={n.id}
              className="button secondary small"
              aria-pressed={n.start === tree.selected_index}
              onClick={() => select(n.start)}
              onFocus={hover(n.id)}
              onBlur={hover(null)}
              onMouseEnter={hover(n.id)}
              onMouseLeave={hover(null)}
            >
              Chunk {n.start}
            </button>
          ))}
      </div>
    </div>
  );
}

export default function Integrity() {
  useTitle("Integrity explorer");
  const { auth } = useSession();
  const [params, setParams] = useSearchParams();
  const asset = params.get("asset") ?? "",
    version = params.get("version") ?? "";
  const [index, setIndex] = useState(0);
  const [offset, setOffset] = useState(0);
  const [assetOffset, setAssetOffset] = useState(0);
  const [versionOffset, setVersionOffset] = useState(0);
  const [verification, setVerification] = useState<{
    valid: boolean;
    tampered: boolean;
  }>();
  const [empty, setEmpty] = useState<ScanView>();
  const action = useAction();
  const assets = useGet<AssetPage>(`/assets?limit=10&offset=${assetOffset}`);
  const versions = useGet<VersionSummary[]>(
    asset ? `/assets/${asset}/versions?limit=5&offset=${versionOffset}` : null,
  );
  const selected = version || versions.data?.[0]?.id;
  const tree = useGet<TreeView>(
    asset && selected
      ? `/assets/${asset}/versions/${selected}/tree?index=${index}&offset=${offset}&limit=16`
      : null,
  );
  function choose(n: number) {
    setIndex(n);
    setVerification(undefined);
    setEmpty(undefined);
  }
  async function verify(tampered: boolean) {
    setVerification(undefined);
    const result = await action.run(() =>
      api<IntegrityView>(
        "/integrity/verify",
        jsonBody({
          asset_id: asset,
          version_id: selected,
          proof: tampered ? tamperProof(tree.data!.proof!) : tree.data!.proof,
        }),
        auth!.csrf_token,
      ),
    );
    if (result) setVerification({ valid: result.valid, tampered });
  }
  return (
    <>
      <PageHeader
        eyebrow="CRYPTOGRAPHIC EVIDENCE"
        title="Integrity explorer"
        description="Follow one chunk to the trusted root. Verify a real proof, then change a copy and observe the difference."
      />
      <Panel
        title="Select a fingerprint version"
        subtitle="Registry metadata only. Source bytes never leave the registry."
      >
        <div className="form-grid">
          <label>
            Protected asset
            <select
              value={asset}
              onChange={(e) => {
                setParams({ asset: e.target.value });
                setIndex(0);
                setOffset(0);
                setVersionOffset(0);
                setVerification(undefined);
                setEmpty(undefined);
              }}
            >
              <option value="">Choose an asset</option>
              {asset && !assets.data?.items.some((a) => a.id === asset) && (
                <option value={asset}>
                  Selected asset · {asset.slice(0, 8)}
                </option>
              )}
              {assets.data?.items.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                  {a.retired ? " (retired)" : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            Immutable version
            <select
              value={selected ?? ""}
              disabled={!versions.data?.length}
              onChange={(e) => {
                setParams({ asset, version: e.target.value });
                setIndex(0);
                setOffset(0);
                setVerification(undefined);
              }}
            >
              <option value="">Choose a version</option>
              {version && !versions.data?.some((v) => v.id === version) && (
                <option value={version}>Selected historical version</option>
              )}
              {versions.data?.map((v) => (
                <option key={v.id} value={v.id}>
                  v{v.number} · {v.manifest.chunk_count} chunks
                </option>
              ))}
            </select>
          </label>
        </div>
        <Failure
          error={assets.error || versions.error}
          retry={() => {
            assets.refresh();
            versions.refresh();
          }}
        />
        {assets.data && (
          <Pager
            size={10}
            offset={assetOffset}
            count={assets.data.items.length}
            change={setAssetOffset}
            label="Asset list pages"
          />
        )}
        {asset && versions.data && versions.data.length >= 5 && (
          <button
            className="button secondary small"
            onClick={() => setVersionOffset(versionOffset + 5)}
          >
            Load older versions
          </button>
        )}
      </Panel>
      {!asset && (
        <Empty
          title="Choose a protected asset"
          action={
            <Link className="button secondary" to="/assets">
              Open registry
            </Link>
          }
        >
          The three-chunk synthetic sample illustrates an uneven tree. Register
          it from the asset workspace.
        </Empty>
      )}
      <Failure error={tree.error || action.error} retry={tree.refresh} />
      {tree.loading && (
        <Loading label="Computing the ordered tree projection" />
      )}
      {tree.data && (
        <>
          <Panel
            title="Ordered Merkle commitment"
            subtitle={`${tree.data.manifest.chunk_count} leaves · ${tree.data.mode === "full" ? "Complete tree" : "Bounded proof path; other subtrees collapsed"}`}
          >
            <Hash
              value={tree.data.manifest.merkle_root}
              label="Trusted registered root"
            />
            <TreeDiagram tree={tree.data} select={choose} />
          </Panel>
          <div className="two-column">
            <Panel
              title={`Chunk ${index} · inclusion proof`}
              subtitle="Verification runs on the server against the registered manifest."
            >
              <dl className="facts">
                <div>
                  <dt>Byte offset</dt>
                  <dd>{index * tree.data.manifest.chunk_size}</dd>
                </div>
                <div>
                  <dt>Chunk length</dt>
                  <dd>{tree.data.proof?.chunk.length} B</dd>
                </div>
              </dl>
              {tree.data.proof && (
                <Hash
                  value={tree.data.proof.chunk.sha256}
                  label="Chunk SHA-256"
                />
              )}
              <div className="button-row">
                <button
                  className="button primary"
                  disabled={action.busy || !tree.data.proof}
                  onClick={() => void verify(false)}
                >
                  <CheckCheck size={16} />
                  Verify inclusion
                </button>
                <button
                  className="button secondary"
                  disabled={action.busy || !tree.data.proof}
                  onClick={() => void verify(true)}
                >
                  <FlaskConical size={16} />
                  Test tampered copy
                </button>
              </div>
              {verification && (
                <Notice tone={verification.valid ? "success" : "info"}>
                  <strong>
                    {verification.tampered ? "Tampered copy" : "Original proof"}
                    : {verification.valid ? "VERIFIED" : "REJECTED"}
                  </strong>
                  <p>
                    {verification.valid
                      ? "The chunk descriptor belongs to the committed ordered tree."
                      : "The changed proof does not reconstruct the trusted root. Stored data was not changed."}
                  </p>
                </Notice>
              )}
              <details>
                <summary>
                  Proof sibling hashes ({tree.data.proof?.siblings.length ?? 0})
                </summary>
                {tree.data.proof?.siblings.map((hash, n) => (
                  <Hash
                    key={n}
                    value={hash}
                    label={`Sibling ${n + 1} · leaf toward root`}
                  />
                ))}
              </details>
            </Panel>
            <Panel title="How to read this tree">
              <ol className="explanation-list">
                <li>
                  <strong>Fingerprint the bytes.</strong> Each chunk has a
                  SHA-256 digest.
                </li>
                <li>
                  <strong>Commit to its position.</strong> The leaf hashes a
                  0x00 prefix and the specified index, length and digest
                  descriptor.
                </li>
                <li>
                  <strong>Combine child commitments.</strong> An internal node
                  hashes 0x01 followed by the left and right hashes.
                </li>
                <li>
                  <strong>Reconstruct the root.</strong> Siblings are consumed
                  bottom-up using the tree size and leaf index.
                </li>
              </ol>
              <p className="help-text">
                Uneven trees split at the largest power of two below their size.
                No odd leaf is duplicated. Domain separation prevents leaf and
                node encodings from being confused.
              </p>
              <p className="help-text">
                This proves descriptor inclusion against a trusted root. It is
                not a claim of semantic similarity or proof of unique source
                ownership.
              </p>
            </Panel>
          </div>
          <Panel
            title="Ordered chunk descriptors"
            subtitle="Accessible selection and textual alternative. At most 16 rows per page."
          >
            <Table label="Ordered chunks">
              <thead>
                <tr>
                  <th>Chunk</th>
                  <th>Offset</th>
                  <th>Length</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {tree.data.chunks.map((c) => (
                  <tr key={c.index}>
                    <td>
                      <button
                        className="button secondary small"
                        aria-pressed={index === c.index}
                        onClick={() => choose(c.index)}
                      >
                        Select chunk {c.index}
                      </button>
                    </td>
                    <td>{c.index * tree.data!.manifest.chunk_size}</td>
                    <td>{c.length} B</td>
                    <td>
                      <code className="table-hash">{c.sha256}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager
              size={16}
              offset={offset}
              count={tree.data.chunks.length}
              change={setOffset}
              label="Chunk pages"
            />
            <details>
              <summary>Tree nodes as a table</summary>
              <Table label="Tree nodes">
                <thead>
                  <tr>
                    <th>Range</th>
                    <th>Commitment</th>
                    <th>Relationship</th>
                  </tr>
                </thead>
                <tbody>
                  {tree.data.nodes.map((n) => (
                    <tr key={n.id}>
                      <td>
                        {n.start}–{n.start + n.count - 1}
                      </td>
                      <td>
                        <code className="table-hash">{n.digest}</code>
                      </td>
                      <td>
                        {n.selected_path
                          ? "Selected path"
                          : n.sibling
                            ? "Sibling subtree"
                            : "Other subtree"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </details>
          </Panel>
        </>
      )}
      {/* Rendered once the tree has settled, so the arriving tree never pushes this panel down (layout shift). */}
      {!tree.loading && (
        <Panel
          title="The empty-file boundary"
          subtitle="Empty files can be fingerprinted, but cannot be registered as protected IP."
        >
          <button
            className="button secondary"
            disabled={action.busy}
            onClick={() =>
              void action
                .run(() =>
                  api<ScanView>(
                    "/scans?filename=empty-demo.bin",
                    {
                      method: "POST",
                      headers: { "Content-Type": "application/octet-stream" },
                      body: new Uint8Array(),
                    },
                    auth!.csrf_token,
                  ),
                )
                .then((result) => {
                  if (result) setEmpty(result);
                })
            }
          >
            <GitBranch size={16} />
            Fingerprint empty input
          </button>
          {empty && (
            <>
              <Status value={empty.decision.outcome} />
              <Hash
                value={empty.detection.manifest.merkle_root}
                label="Empty Merkle root from backend"
              />
              <p>
                No leaves; no inclusion proof exists. The root is SHA-256 of the
                empty string.
              </p>
            </>
          )}
        </Panel>
      )}
    </>
  );
}
