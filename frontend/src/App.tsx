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
import { SessionProvider, useSession } from "./lib/session";
import type { AuthView } from "./lib/contracts";

const Overview = lazy(() => import("./features/overview/Overview"));
const Gateway = lazy(() => import("./features/transfers/Gateway"));
const Assets = lazy(() => import("./features/assets/Assets"));
const Integrity = lazy(() => import("./features/integrity/Integrity"));
const Incidents = lazy(() => import("./features/incidents/Incidents"));
const Audit = lazy(() => import("./features/audit/Audit"));
const Policies = lazy(() => import("./features/policies/Policies"));
const Guide = lazy(() => import("./features/guide/Guide"));

const navigation = [
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
  { path: "/guide", name: "Guided Demo", icon: BookOpen, privileged: false },
];

function Brand() {
  return (
    <Link to="/" className="brand" aria-label="RootSentinel overview">
      <span className="brand-emblem">
        <Fingerprint size={27} strokeWidth={1.6} />
      </span>
      <span>
        RootSentinel<small>DATA LOSS PREVENTION</small>
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
  if (session.auth) return <Navigate to="/" replace />;
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
          <span className="eyebrow">LOCAL SECURITY WORKSPACE</span>
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
          <Failure
            error={action.error || session.problem}
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
}: {
  children: ReactNode;
  privileged?: boolean;
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
  if (privileged && auth.user.role === "EMPLOYEE")
    return (
      <Empty
        title="Access restricted"
        action={
          <Link className="button secondary" to="/">
            Return to overview
          </Link>
        }
      >
        Your employee role can submit transfers and inspect your own results.
        This workspace requires an analyst or administrator.
      </Empty>
    );
  return children;
}

function Shell() {
  const { auth, setAuth } = useSession();
  const action = useAction();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
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
        .filter((x) => !x.privileged || auth!.user.role !== "EMPLOYEE")
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
          <p>Local mode · Single workspace</p>
          <Link to="/guide#limitations">
            Understand the boundary <ArrowRight size={12} />
          </Link>
        </div>
      </aside>
      <div className="main-column">
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
            <span className="environment">LOCAL</span>
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
          <Suspense fallback={<Loading label="Opening workspace" />}>
            <Outlet />
          </Suspense>
        </main>
        <footer className="app-footer">
          <span>RootSentinel / Evidence-driven transfer control</span>
          <span>Gateway scope only · Use synthetic files only; never upload confidential data</span>
        </footer>
      </div>
      <Dialog
        open={mobileOpen}
        close={() => setMobileOpen(false)}
        title="Navigate workspace"
      >
        <div className="mobile-links">{links}</div>
      </Dialog>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
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
    </BrowserRouter>
  );
}
