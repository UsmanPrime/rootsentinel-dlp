import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "../api";
import type { AuthView } from "./contracts";

type Session = {
  auth: AuthView | null;
  checking: boolean;
  expired: boolean;
  problem: unknown;
  setAuth: (auth: AuthView | null) => void;
  check: () => void;
};
const Context = createContext<Session | null>(null);
export function SessionProvider({ children }: { children: ReactNode }) {
  const [auth, update] = useState<AuthView | null>(null);
  const current = useRef(auth);
  current.current = auth;
  const [checking, setChecking] = useState(true);
  const [expired, setExpired] = useState(false);
  const [problem, setProblem] = useState<unknown>(null);
  const [revision, setRevision] = useState(0);
  const setAuth = useCallback((value: AuthView | null) => {
    update(value);
    setExpired(false);
    setProblem(null);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setChecking(true);
    // /auth/session answers 204 (not 401) without a session, so a signed-out page load logs no failed request.
    api<AuthView | undefined>("/auth/session", { signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted) update(value ?? null);
      })
      .catch((error) => {
        if (!controller.signal.aborted) {
          update(null);
          if (error.status !== 401) setProblem(error);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setChecking(false);
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => {
    function expire() {
      if (current.current) setExpired(true);
      update(null);
    }
    window.addEventListener("rootsentinel:session-expired", expire);
    return () =>
      window.removeEventListener("rootsentinel:session-expired", expire);
  }, []);
  return (
    <Context.Provider
      value={{
        auth,
        checking,
        expired,
        problem,
        setAuth,
        check: () => setRevision((x) => x + 1),
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function useSession() {
  const value = useContext(Context);
  if (!value) throw new Error("Session provider required");
  return value;
}
