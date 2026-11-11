import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Plus, Search, GitBranch, Archive } from "lucide-react";
import { api, fixture } from "../../api";
import {
  Dialog,
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
import { bytes, date, short } from "../../lib/errors";
import { useSession } from "../../lib/session";
import { useEnvironment } from "../../lib/environment";
import { useToast } from "../../lib/toast";
import { PROFILE_NAMES } from "../../components/Verdict";

/** The server's display-label rule (schemas.Label), checked before sending so the form can explain it. */
const ASSET_LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,119}$/;
import type {
  AssetPage,
  AssetView,
  VersionSummary,
  VersionView,
} from "../../lib/contracts";

export function Registration({
  close,
  done,
  asset,
}: {
  close: () => void;
  done: (v: VersionView) => void;
  asset?: AssetView;
}) {
  const { auth } = useSession();
  const action = useAction();
  const [source, setSource] = useState("protected");
  const [file, setFile] = useState<File>();
  const [invalid, setInvalid] = useState("");
  const [labelError, setLabelError] = useState("");
  const cap = useEnvironment().maxUploadBytes;
  const toast = useToast();
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const label = String(new FormData(e.currentTarget).get("label") ?? "");
    if (!asset && !ASSET_LABEL.test(label)) {
      setLabelError(
        "Start with a letter or digit, then use letters, digits, spaces and . _ ( ) - only (up to 120 characters).",
      );
      return;
    }
    const body = source === "local" ? file : fixture(source);
    if (!body || (body instanceof File && (!body.size || body.size > cap))) {
      setInvalid(`Choose a nonempty synthetic file up to ${bytes(cap)}.`);
      return;
    }
    const path = asset
      ? `/assets/${asset.id}/versions?expected_version=${asset.current_version}`
      : `/assets?label=${encodeURIComponent(label)}`;
    void action
      .run(() =>
        api<VersionView>(
          path,
          {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body,
          },
          auth!.csrf_token,
        ),
      )
      .then((v) => {
        if (v) {
          toast(
            asset ? `Version ${v.number} registered` : `Registered ${label}`,
          );
          done(v);
        }
      });
  }
  return (
    <Dialog
      open
      title={asset ? "Register immutable version" : "Register protected asset"}
      close={close}
      busy={action.busy}
    >
      <form className="form-stack" onSubmit={submit}>
        <p className="muted">
          The server fingerprints the received bytes. Only descriptors are
          retained in the registry. Use synthetic inputs in this demonstration.
        </p>
        {!asset && (
          <label>
            Asset label
            <input
              name="label"
              required
              maxLength={120}
              placeholder="e.g. Synthetic payment service"
              aria-invalid={labelError ? true : undefined}
              aria-describedby={labelError ? "asset-label-error" : undefined}
              onChange={() => setLabelError("")}
            />
          </label>
        )}
        {!asset && labelError && (
          <p id="asset-label-error" className="field-error">
            {labelError}
          </p>
        )}
        <label>
          Registration input
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="protected">Protected sample · 8 blocks</option>
            <option value="source">
              Source sample · 7 blocks, 4 content-defined chunks
            </option>
            <option value="odd">Uneven tree sample · 3 chunks</option>
            <option value="local">Local synthetic file</option>
          </select>
        </label>
        {source === "local" && (
          <label>
            Synthetic file
            <input
              type="file"
              required
              onChange={(e) => setFile(e.target.files?.[0])}
            />
          </label>
        )}
        {asset && (
          <Notice>
            Creates version {asset.current_version + 1}. Earlier fingerprints
            remain unchanged. Pending approvals become stale when the registry
            changes.
          </Notice>
        )}
        {invalid && <Notice tone="error">{invalid}</Notice>}
        <Failure error={action.error} />
        <div className="dialog-actions">
          <button
            type="button"
            className="button secondary"
            disabled={action.busy}
            onClick={close}
          >
            Cancel
          </button>
          <button className="button primary" disabled={action.busy}>
            {action.busy ? "Fingerprinting…" : "Register fingerprints"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export default function Assets() {
  useTitle("Protected assets");
  const { id } = useParams();
  return id ? <AssetDetail key={id} id={id} /> : <AssetList />;
}

function AssetList() {
  const { auth } = useSession();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("false");
  const [offset, setOffset] = useState(0);
  const [register, setRegister] = useState(false);
  const result = useGet<AssetPage>(
    `/assets?limit=10&offset=${offset}&q=${encodeURIComponent(q)}${filter ? `&retired=${filter}` : ""}`,
  );
  return (
    <>
      <PageHeader
        eyebrow="INTELLECTUAL PROPERTY"
        title="Protected assets"
        description="Immutable fingerprints. Traceable versions. No source code stored in the registry."
        actions={
          auth!.user.role === "ADMIN" && (
            <button
              className="button primary"
              onClick={() => setRegister(true)}
            >
              <Plus size={16} />
              Register asset
            </button>
          )
        }
      />
      <Panel
        title="Asset registry"
        subtitle="Search covers all authorized registry labels."
      >
        <div className="filter-bar">
          <form
            className="search-form"
            onSubmit={(e) => {
              e.preventDefault();
              setQ(String(new FormData(e.currentTarget).get("search") ?? ""));
              setOffset(0);
            }}
          >
            <label className="sr-only" htmlFor="asset-search">
              Search assets
            </label>
            <input
              id="asset-search"
              name="search"
              placeholder="Search asset labels"
              maxLength={120}
            />
            <button className="icon-button" aria-label="Search assets">
              <Search size={18} />
            </button>
          </form>
          <label className="inline-label">
            Protection
            <select
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
                setOffset(0);
              }}
            >
              <option value="false">Active</option>
              <option value="true">Retired</option>
              <option value="">All states</option>
            </select>
          </label>
        </div>
        <Failure error={result.error} retry={result.refresh} />
        {result.loading && <Loading />}
        {result.data &&
          (result.data.items.length ? (
            <Table label="Protected asset registry">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Status</th>
                  <th>Latest version</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                {result.data.items.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link className="row-link" to={`/assets/${a.id}`}>
                        {a.label}
                      </Link>
                      <small className="muted mono">{short(a.id)}</small>
                    </td>
                    <td>
                      <Status value={a.retired ? "RETIRED" : "ACTIVE"} />
                    </td>
                    <td>v{a.current_version}</td>
                    <td>{date(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Empty title="No assets found">
              Register a synthetic sample or adjust the search and protection
              filter.
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
      {register && (
        <Registration
          close={() => setRegister(false)}
          done={(v) => navigate(`/assets/${v.asset_id}`)}
        />
      )}
    </>
  );
}

function AssetDetail({ id }: { id: string }) {
  const { auth } = useSession();
  const action = useAction();
  const [offset, setOffset] = useState(0);
  const [register, setRegister] = useState(false);
  const [retiring, setRetiring] = useState(false);
  const toast = useToast();
  const asset = useGet<AssetView>(`/assets/${id}`);
  const versions = useGet<VersionSummary[]>(
    `/assets/${id}/versions?limit=5&offset=${offset}`,
  );
  const refresh = () => {
    asset.refresh();
    versions.refresh();
  };
  return (
    <>
      <Link className="back-link" to="/assets">
        ← Protected assets
      </Link>
      <PageHeader
        eyebrow="ASSET RECORD"
        title={asset.data?.label ?? "Asset details"}
        description="Historical versions remain available after retirement."
        actions={
          asset.data &&
          auth!.user.role === "ADMIN" &&
          !asset.data.retired && (
            <>
              <button
                className="button secondary"
                onClick={() => setRetiring(true)}
              >
                <Archive size={15} />
                Retire asset
              </button>
              <button
                className="button primary"
                onClick={() => setRegister(true)}
              >
                <Plus size={15} />
                New version
              </button>
            </>
          )
        }
      />
      <Failure error={asset.error || versions.error} retry={refresh} />
      {asset.loading && <Loading />}
      {asset.data && (
        <div className="context-strip">
          <Status value={asset.data.retired ? "RETIRED" : "ACTIVE"} />
          <span>
            Latest version <strong>v{asset.data.current_version}</strong>
          </span>
          <span>Registered {date(asset.data.created_at)}</span>
          <code className="break">{id}</code>
        </div>
      )}
      {versions.loading && <Loading label="Loading immutable versions" />}
      {versions.data?.map((v) => (
        <Panel
          key={v.id}
          title={`Version ${v.number}`}
          subtitle={`Registered ${date(v.created_at)}`}
          actions={
            <Link
              className="button secondary small"
              to={`/integrity?asset=${id}&version=${v.id}`}
            >
              <GitBranch size={15} />
              Explore integrity
            </Link>
          }
        >
          <dl className="facts">
            <div>
              <dt>File size</dt>
              <dd>{bytes(v.manifest.file_size)}</dd>
            </div>
            <div>
              <dt>Chunks</dt>
              <dd>
                {v.manifest.chunk_count} × up to {v.manifest.chunk_size} B
              </dd>
            </div>
            <div>
              <dt>Registry revision</dt>
              <dd>{v.registry_revision}</dd>
            </div>
            <div>
              <dt>Registered by</dt>
              <dd className="mono break">{v.actor_id}</dd>
            </div>
          </dl>
          <Hash value={v.manifest.file_sha256} label="Whole-file SHA-256" />
          <Hash value={v.manifest.merkle_root} label="Trusted Merkle root" />
          <p className="help-text">
            SHA-256 identifies exact bytes. The Merkle root commits to ordered
            chunk descriptors; it is an integrity commitment, not a similarity
            score.
          </p>
          <h3 className="field-caption">DETECTION PROFILES</h3>
          <ul className="profile-list" aria-label="Detection profiles">
            {(v.profiles ?? []).map((p) => (
              <li key={p.profile_id}>
                <span>
                  {PROFILE_NAMES[p.profile_id]?.name ?? p.profile_id}{" "}
                  <code className="profile-id">{p.profile_id}</code>
                </span>
                <span>
                  {p.fingerprinted ? (
                    <>
                      <strong>{p.chunk_count}</strong>{" "}
                      {PROFILE_NAMES[p.profile_id]?.unit ?? "chunks"} registered
                    </>
                  ) : (
                    <span className="muted">
                      Not fingerprinted. This version was registered before the
                      profile existed and its bytes are not stored; register a
                      new version to add it.
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
          <small className="muted break">
            Manifest profile {v.manifest.profile_id} · Version ID {v.id}
          </small>
        </Panel>
      ))}
      {versions.data && (
        <Pager
          size={5}
          offset={offset}
          count={versions.data.length}
          change={setOffset}
        />
      )}
      {register && asset.data && (
        <Registration
          asset={asset.data}
          close={() => setRegister(false)}
          done={() => {
            setRegister(false);
            refresh();
          }}
        />
      )}
      <Dialog
        open={retiring}
        title="Retire this asset?"
        close={() => setRetiring(false)}
        busy={action.busy}
      >
        <p>
          Future scans will exclude this asset. Historical decisions and
          fingerprints remain. Existing transfer approvals become stale.
        </p>
        <Failure error={action.error} />
        <div className="dialog-actions">
          <button
            className="button secondary"
            disabled={action.busy}
            onClick={() => setRetiring(false)}
          >
            Cancel
          </button>
          <button
            className="button danger"
            disabled={action.busy}
            onClick={() =>
              void action
                .run(() =>
                  api(
                    `/assets/${id}/retire`,
                    { method: "POST" },
                    auth!.csrf_token,
                  ),
                )
                .then((v) => {
                  if (v) {
                    setRetiring(false);
                    refresh();
                    toast("Asset retired. Its versions stay in the history.");
                  }
                })
            }
          >
            Confirm retirement
          </button>
        </div>
      </Dialog>
    </>
  );
}
