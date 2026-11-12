import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

/** What the server says about itself (GET /health). The interface never guesses from the hostname. */
export type Environment = {
  /** true: an https origin fronted by a host (the hosted demo); false: local; null: not known yet. */
  hosted: boolean | null;
  commit: string;
  maxUploadBytes: number;
  /** true when the server offers sandboxed visitor sessions (the kill switch is on). */
  visitorMode: boolean;
  /** The lower upload cap a visitor session enforces. */
  visitorUploadBytes: number;
};

const DEFAULT_UPLOAD_CAP = 10485760;
const fallback: Environment = {
  hosted: null,
  commit: "unknown",
  maxUploadBytes: DEFAULT_UPLOAD_CAP,
  visitorMode: false,
  visitorUploadBytes: 65536,
};
const Context = createContext<Environment>(fallback);

export function parseHealth(body: unknown): Environment {
  const value = (body ?? {}) as Record<string, unknown>;
  const cap = value.max_upload_bytes;
  return {
    hosted: typeof value.hosted === "boolean" ? value.hosted : null,
    commit:
      typeof value.commit === "string" && /^[0-9a-f]{7,40}$/.test(value.commit)
        ? value.commit
        : "unknown",
    maxUploadBytes:
      typeof cap === "number" && Number.isInteger(cap) && cap >= 1024
        ? cap
        : DEFAULT_UPLOAD_CAP,
    visitorMode: value.visitor_mode === true,
    visitorUploadBytes:
      typeof value.visitor_upload_bytes === "number" &&
      Number.isInteger(value.visitor_upload_bytes) &&
      value.visitor_upload_bytes >= 1024
        ? value.visitor_upload_bytes
        : 65536,
  };
}

export function EnvironmentProvider({ children }: { children: ReactNode }) {
  const [environment, setEnvironment] = useState<Environment>(fallback);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/health", { signal: controller.signal, credentials: "same-origin" })
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        if (!controller.signal.aborted && body)
          setEnvironment(parseHealth(body));
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, []);
  return <Context.Provider value={environment}>{children}</Context.Provider>;
}

export function useEnvironment() {
  return useContext(Context);
}

/** The short badge text and its longer description for the shell. */
export function environmentLabel(hosted: boolean | null) {
  if (hosted === true)
    return { badge: "Hosted demo", detail: "Hosted demo · Single workspace" };
  if (hosted === false)
    return { badge: "Local", detail: "Local mode · Single workspace" };
  return { badge: "Workspace", detail: "Single workspace" };
}
