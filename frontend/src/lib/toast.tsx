import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { CheckCircle2, Info, X, XCircle } from "lucide-react";

export type ToastTone = "success" | "info" | "error";
type Toast = { id: number; message: string; tone: ToastTone };
type Push = (message: string, tone?: ToastTone) => void;

const Context = createContext<Push>(() => undefined);
const LIFETIME_MS = 6000;

/**
 * Short confirmations for completed actions. They repeat what the page already shows, so nothing is lost when one
 * disappears; errors that need a decision stay inline on the page instead.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);
  const timers = useRef(new Map<number, number>());
  const dismiss = useCallback((id: number) => {
    setToasts((items) => items.filter((item) => item.id !== id));
    const timer = timers.current.get(id);
    if (timer) window.clearTimeout(timer);
    timers.current.delete(id);
  }, []);
  const push = useCallback<Push>(
    (message, tone = "success") => {
      const id = next.current++;
      setToasts((items) => [...items.slice(-3), { id, message, tone }]);
      timers.current.set(
        id,
        window.setTimeout(() => dismiss(id), LIFETIME_MS),
      );
    },
    [dismiss],
  );
  useEffect(() => {
    const all = timers.current;
    return () => all.forEach((timer) => window.clearTimeout(timer));
  }, []);
  return (
    <Context.Provider value={push}>
      {children}
      <div className="toast-region" aria-label="Notifications" role="region">
        <div role="status" aria-live="polite">
          <ul>
            {toasts.map((toast) => {
              const Icon =
                toast.tone === "success"
                  ? CheckCircle2
                  : toast.tone === "error"
                    ? XCircle
                    : Info;
              return (
                <li key={toast.id} className={`toast ${toast.tone}`}>
                  <Icon size={17} aria-hidden="true" />
                  <span>{toast.message}</span>
                  <button
                    className="icon-button"
                    aria-label="Dismiss notification"
                    onClick={() => dismiss(toast.id)}
                  >
                    <X size={15} />
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </Context.Provider>
  );
}

export function useToast() {
  return useContext(Context);
}
