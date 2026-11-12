import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  BrowserRouter,
  Link,
  NavLink,
  Navigate,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  Activity,
  ArrowRight,
  BookOpen,
  Boxes,
  ChevronRight,
  CircleHelp,
  Fingerprint,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Menu,
  Shield,
  SlidersHorizontal,
  UploadCloud,
} from "lucide-react";
import { api, jsonBody } from "./api";
import { Dialog, Empty, Failure, Loading, Notice } from "./components/ui";
import { useAction, useTitle } from "./lib/hooks";
import { SessionProvider, isPrivileged, useSession } from "./lib/session";
import { ApiError } from "./api";
import { errorMessage } from "./lib/errors";
import {
  EnvironmentProvider,
  environmentLabel,
  useEnvironment,
} from "./lib/environment";
import { ToastProvider } from "./lib/toast";
import { Tour, TourInvite, markTourSeen, tourSeen } from "./components/Tour";
import type { AuthView } from "./lib/contracts";

const Overview = lazy(() => import("./features/overview/Overview"));
const Gateway = lazy(() => import("./features/transfers/Gateway"));
const Assets = lazy(() => import("./features/assets/Assets"));
const Integrity = lazy(() => import("./features/integrity/Integrity"));
const Incidents = lazy(() => import("./features/incidents/Incidents"));
const Audit = lazy(() => import("./features/audit/Audit"));
const Policies = lazy(() => import("./features/policies/Policies"));
const SandboxAudit = lazy(() => import("./features/sandbox/SandboxAudit"));
const Guide = lazy(() => import("./features/guide/Guide"));

const navigation: {
  path: string;
  name: string;
  icon: typeof Activity;
  privileged: boolean;
  visitorOnly?: boolean;
}[] = [
  { path: "/", name: "Overview", icon: LayoutDashboard, privileged: false },
  {
    path: "/transfers",
    name: "Transfer Gateway",
    icon: UploadCloud,
    privileged: false,
  },
  { path: "/assets", name: "Protected Assets", icon: Boxes, privileged: true },
  {
    path: "/integrity",
    name: "Integrity Explorer",
    icon: GitBranch,
    privileged: true,
  },
  { path: "/incidents", name: "Incidents", icon: Shield, privileged: true },
  {
    path: "/audit",
    name: "Activity & Audit",
    icon: Activity,
    privileged: true,
  },
  {
    path: "/policies",
    name: "Policies",
    icon: SlidersHorizontal,
    privileged: false,
  },
  {
    path: "/sandbox-audit",
    name: "My audit trail",
    icon: Activity,
    privileged: false,
    visitorOnly: true,
  },
  { path: "/guide", name: "Guided Demo", icon: BookOpen, privileged: false },
];

function Brand() {
  return (
    <Link to="/" className="brand">
      <span className="brand-emblem">
        <Fingerprint size={27} strokeWidth={1.6} />
      </span>
      <span>
        RootSentinel<small> Data loss prevention</small>
      </span>
    </Link>
  );
}

function Login() {
  useTitle("Sign in");
  const session = useSession();
  const action = useAction();
  const navigate = useNavigate();
  const location = useLocation();
  const environment = useEnvironment();
  const visitorAction = useAction();
  if (session.auth) return <Navigate to="/" replace />;
  function exploreAsVisitor() {
    void visitorAction
      .run(() => api<AuthView>("/auth/visitor", { method: "POST" }))
      .then((auth) => {
        if (!auth) return;
        session.setAuth(auth);
        navigate("/", { replace: true });
      });
  }
  const visitorRefused =
    visitorAction.error instanceof ApiError &&
    visitorAction.error.code.startsWith("VISITOR_");
  function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    void action
      .run(() =>
        api<AuthView>(
          "/auth/login",
          jsonBody({
            username: values.get("username"),
            password: values.get("password"),
          }),
        ),
      )
      .then((auth) => {
        if (!auth) return;
        form.reset();
        session.setAuth(auth);
        const destination = location.state?.from;
        navigate(
          typeof destination === "string" &&
            destination.startsWith("/") &&
            !destination.startsWith("//") &&
            destination !== "/login"
            ? destination
            : "/",
          { replace: true },
        );
      });
  }
  return (
    <main className="login-page">
      <section className="login-story">
        <Brand />
        <div>
          <p className="eyebrow">KNOW THE BYTES. CONTROL THE EXIT.</p>
          <h1>
            Evidence before
            <br />
            <span>every release.</span>
          </h1>
          <p>
            Inspect protected content, understand the policy decision, and
            verify exactly what leaves your gateway.
          </p>
          <div className="login-tree" aria-hidden="true">
            <i />
            <i />
            <i />
            <i />
            <i />
            <i />
            <i />
          </div>
          <p className="boundary-note">
            A controlled transfer boundary.
            <br />
            Transparent evidence. Explicit limitations.
          </p>
        </div>
        <span className="tiny muted">
          SHA-256 / MERKLE INTEGRITY / AUTHENTICATED AUDIT
        </span>
      </section>
      <section className="login-access" aria-labelledby="login-title">
        <div className="login-card">
          <span className="eyebrow">
            {environment.hosted === true
              ? "HOSTED DEMO WORKSPACE"
              : environment.hosted === false
                ? "LOCAL SECURITY WORKSPACE"
                : "SECURITY WORKSPACE"}
          </span>
          <h2 id="login-title">Welcome back</h2>
          <p className="muted">
            Sign in with your administrator-provisioned account.
          </p>
          <p className="muted">
            Use synthetic files only. Do not upload confidential or personal
            data to this demonstration.
          </p>
          {session.expired && (
            <Notice>Your session ended. Sign in again to continue.</Notice>
          )}
          {session.visitorEnded && (
            <div className="visitor-ended" role="status">
              <h3>Your visitor session has ended</h3>
              <p>
                Visitor sessions last 30 minutes at most and end after 10
                minutes without activity. Everything you did stays in the audit
                record; nothing real was touched.
              </p>
              {environment.visitorMode && (
                <button
                  className="button primary"
                  disabled={visitorAction.busy}
                  onClick={exploreAsVisitor}
                >
                  Start a new visitor session
                </button>
              )}
            </div>
          )}
          {visitorRefused && (
            <div className="visitor-ended" role="alert">
              <h3>Visitor access is unavailable right now</h3>
              <p>{errorMessage(visitorAction.error)}</p>
              <p>Signing in with an account below still works.</p>
            </div>
          )}
          <Failure
            error={
              action.error ||
              session.problem ||
              (visitorAction.error && !visitorRefused
                ? visitorAction.error
                : null)
            }
            retry={session.problem ? session.check : undefined}
          />
          <form onSubmit={signIn} className="form-stack">
            <label>
              Username
              <input
                name="username"
                autoComplete="username"
                maxLength={64}
                required
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                maxLength={128}
                required
              />
            </label>
            <button className="button primary full" disabled={action.busy}>
              {action.busy ? "Signing in…" : "Sign in"}
              <ArrowRight size={16} />
            </button>
          </form>
          {environment.visitorMode && (
            <div className="visitor-entry">
              <p className="muted">
                No account? Run the real flow in a sandbox of synthetic files.
                No password, no real data, ends after 30 minutes.
              </p>
              <button
                type="button"
                className="button secondary full"
                disabled={visitorAction.busy}
                onClick={exploreAsVisitor}
              >
                {visitorAction.busy ? "Opening sandbox…" : "Explore as visitor"}
              </button>
            </div>
          )}
          <div className="login-note">
            <Shield size={17} />
            <p>
              Session credentials stay in a secure server-managed cookie. Public
              demonstration access is not enabled.
            </p>
          </div>
          <a
            className="text-link"
            href="https://github.com/UsmanPrime/rootsentinel-dlp"
            target="_blank"
            rel="noopener noreferrer"
          >
            Project documentation ↗
          </a>
        </div>
      </section>
    </main>
  );
}

function Protected({
  children,
  privileged = false,
  visitorOnly = false,
}: {
  children: ReactNode;
  privileged?: boolean;
  visitorOnly?: boolean;
}) {
  const { auth, checking, problem, check } = useSession();
  const location = useLocation();
  if (checking)
    return (
      <main className="session-loading">
        <Loading label="Checking your session" />
      </main>
    );
  if (!auth)
    return problem ? (
      <main className="session-loading">
        <Failure error={problem} retry={check} />
        <Link to="/login">Go to sign in</Link>
      </main>
    ) : (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname + location.search }}
      />
    );
  if (
    (privileged && !isPrivileged(auth.user.role)) ||
    (visitorOnly && auth.user.role !== "VISITOR")
  )
    return (
      <Empty
        level={1}
        title="Access restricted"
        action={
          <Link className="button secondary" to="/">
            Return to overview
          </Link>
        }
      >
        Your role can submit transfers and inspect your own results. This
        workspace requires an analyst or administrator.
      </Empty>
    );
  return children;
}

function Shell() {
  const { auth, setAuth } = useSession();
  const action = useAction();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);
  const [invite, setInvite] = useState(() => !tourSeen());
  const environment = useEnvironment();
  const label = environmentLabel(environment.hosted);
  const privileged = isPrivileged(auth!.user.role);
  const visitor = auth!.visitor;
  const main = useRef<HTMLElement>(null);
  const active = navigation.find((x) =>
    x.path === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(x.path),
  );
  useEffect(() => {
    setMobileOpen(false);
    main.current?.focus();
    window.scrollTo(0, 0);
  }, [location.pathname]);
  const links = (
    <nav aria-label="Main navigation">
      {navigation
        .filter(
          (x) =>
            (!x.privileged || privileged) &&
            (!x.visitorOnly || auth!.user.role === "VISITOR"),
        )
        .map(({ path, name, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === "/"}
            onClick={() => setMobileOpen(false)}
          >
            <Icon size={18} strokeWidth={1.7} />
            <span>{name}</span>
            <ChevronRight className="nav-chevron" size={13} />
          </NavLink>
        ))}
    </nav>
  );
  return (
    <div className="app-shell" key={auth!.user.id}>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar">
        <Brand />
        <p className="nav-label">WORKSPACE</p>
        {links}
        <div className="sidebar-foot">
          <span className="local-mark" />
          <strong>Controlled gateway</strong>
          <p>{label.detail}</p>
          <Link to="/guide#limitations">
            Understand the boundary <ArrowRight size={12} />
          </Link>
        </div>
      </aside>
      <div className="main-column">
        {visitor && (
          <div className="visitor-banner" role="status">
            <strong>Visitor mode</strong>
            <span>Synthetic data only. Nothing here is real.</span>
            <span>
              Session ends {new Date(visitor.expires_at).toLocaleTimeString()}{" "}
              at the latest
            </span>
            <span>
              {visitor.submissions_remaining} of {visitor.submissions_total}{" "}
              submissions left
            </span>
          </div>
        )}
        <header className="app-topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-toggle"
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={21} />
            </button>
            <span className="muted">Workspace</span>
            <ChevronRight size={13} />
            <strong>{active?.name ?? "Record"}</strong>
          </div>
          <div className="account">
            <span
              className={`environment ${environment.hosted ? "hosted" : ""}`}
              title={
                environment.hosted === null
                  ? "Deployment type not reported yet"
                  : "Reported by the server"
              }
            >
              {label.badge}
            </span>
            <button
              className="icon-button"
              aria-label="Take the product tour"
              onClick={() => setTourOpen(true)}
            >
              <CircleHelp size={18} />
            </button>
            <div className="account-label">
              <strong>{auth!.user.username}</strong>
              <span>{auth!.user.role}</span>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  await api(
                    "/auth/logout",
                    { method: "POST" },
                    auth!.csrf_token,
                  );
                  setAuth(null);
                })
              }
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main
          ref={main}
          id="main-content"
          tabIndex={-1}
          className="page-content"
        >
          <Failure error={action.error} />
          {invite && location.pathname === "/" && (
            <TourInvite
              start={() => {
                setInvite(false);
                setTourOpen(true);
              }}
              dismiss={() => {
                markTourSeen();
                setInvite(false);
              }}
            />
          )}
          <Suspense fallback={<Loading label="Opening workspace" />}>
            <Outlet />
          </Suspense>
        </main>
        <footer className="app-footer">
          <span>RootSentinel / Evidence-driven transfer control</span>
          <span>
            Gateway scope only · Use synthetic files only; never upload
            confidential data
            {environment.commit !== "unknown" &&
              ` · Build ${environment.commit.slice(0, 7)}`}
          </span>
        </footer>
      </div>
      <Dialog
        open={mobileOpen}
        close={() => setMobileOpen(false)}
        title="Navigate workspace"
      >
        <div className="mobile-links">{links}</div>
      </Dialog>
      <Tour
        open={tourOpen}
        close={() => {
          setTourOpen(false);
          setInvite(false);
        }}
        privileged={privileged}
      />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <EnvironmentProvider>
        <ToastProvider>
          <SessionProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route
                element={
                  <Protected>
                    <Shell />
                  </Protected>
                }
              >
                <Route index element={<Overview />} />
                <Route path="transfers/:id?" element={<Gateway />} />
                <Route
                  path="assets/:id?"
                  element={
                    <Protected privileged>
                      <Assets />
                    </Protected>
                  }
                />
                <Route
                  path="integrity"
                  element={
                    <Protected privileged>
                      <Integrity />
                    </Protected>
                  }
                />
                <Route
                  path="incidents/:id?"
                  element={
                    <Protected privileged>
                      <Incidents />
                    </Protected>
                  }
                />
                <Route
                  path="audit"
                  element={
                    <Protected privileged>
                      <Audit />
                    </Protected>
                  }
                />
                <Route path="policies" element={<Policies />} />
                <Route
                  path="sandbox-audit"
                  element={
                    <Protected visitorOnly>
                      <SandboxAudit />
                    </Protected>
                  }
                />
                <Route path="guide" element={<Guide />} />
                <Route
                  path="*"
                  element={
                    <Empty
                      title="Page not found"
                      action={
                        <Link className="button primary" to="/">
                          Open overview
                        </Link>
                      }
                    >
                      Use workspace navigation to find a record.
                    </Empty>
                  }
                />
              </Route>
            </Routes>
          </SessionProvider>
        </ToastProvider>
      </EnvironmentProvider>
    </BrowserRouter>
  );
}
