import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useSession } from "./session";

export function useGet<T>(path: string | null) {
  const { auth } = useSession();
  const [revision, setRevision] = useState(0);
  const key = `${auth?.user.id ?? ""}:${path}:${revision}`;
  const [state, setState] = useState<{
    key: string;
    data: T | null;
    error: unknown;
    loading: boolean;
  }>({ key, data: null, error: null, loading: !!path });
  useEffect(() => {
    const controller = new AbortController();
    setState({ key, data: null, error: null, loading: !!path });
    if (path)
      api<T>(path, { signal: controller.signal })
        .then((data) => {
          if (!controller.signal.aborted)
            setState({ key, data, error: null, loading: false });
        })
        .catch((error) => {
          if (!controller.signal.aborted)
            setState({ key, data: null, error, loading: false });
        });
    return () => controller.abort();
  }, [path, revision, auth?.user.id]);
  const refresh = useCallback(() => setRevision((x) => x + 1), []);
  return {
    ...(state.key === key
      ? state
      : { data: null, error: null, loading: !!path }),
    refresh,
  };
}

export function useAction() {
  const guard = useRef(false);
  const live = useRef(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    if (guard.current) return undefined;
    guard.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await action();
      return live.current ? result : undefined;
    } catch (failure) {
      if (live.current) setError(failure);
      return undefined;
    } finally {
      guard.current = false;
      if (live.current) setBusy(false);
    }
  }
  return { busy, error, run, clear: () => setError(null) };
}

export function useTitle(title: string) {
  useEffect(() => {
    document.title = `${title} | RootSentinel`;
  }, [title]);
}
