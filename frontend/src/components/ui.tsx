import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  AlertCircle,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowUpDown,
  Check,
  Copy,
  ShieldCheck,
  X,
  XCircle,
} from "lucide-react";
import { errorMessage } from "../lib/errors";
import { useToast } from "../lib/toast";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {actions && <div className="header-actions">{actions}</div>}
    </header>
  );
}
export function Panel({
  title,
  subtitle,
  children,
  actions,
  className = "",
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
export function Status({ value }: { value: string }) {
  const good = [
    "ALLOW",
    "ALLOWED",
    "STREAM_FINISHED",
    "VERIFIED",
    "ACTIVE",
    "RESOLVED",
  ].includes(value);
  const bad = ["BLOCK", "BLOCKED", "ERROR", "FAILED", "HIGH"].includes(value);
  const Icon = good ? ShieldCheck : bad ? XCircle : AlertCircle;
  return (
    <span
      className={`status ${good ? "positive" : bad ? "negative" : "caution"}`}
    >
      <Icon size={13} aria-hidden="true" />
      {value.replaceAll("_", " ")}
    </span>
  );
}
export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "error" | "success";
}) {
  return (
    <div
      className={`notice ${tone}`}
      role={tone === "error" ? "alert" : "status"}
    >
      {children}
    </div>
  );
}
export function Failure({
  error,
  retry,
}: {
  error: unknown;
  retry?: () => void;
}) {
  if (!error) return null;
  return (
    <Notice tone="error">
      <p>{errorMessage(error)}</p>
      {retry && (
        <button className="button secondary small" onClick={retry}>
          Try again
        </button>
      )}
    </Notice>
  );
}
export function Loading({
  label = "Loading records",
  rows = 0,
}: {
  label?: string;
  /** Show this many table-row placeholders instead of text lines, so lists do not jump when data arrives. */
  rows?: number;
}) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="loader" aria-hidden="true" />
      {label}
      {rows ? (
        <div className="skeleton-table" aria-hidden="true">
          {Array.from({ length: rows }, (_, i) => (
            <span key={i}>
              <i />
              <i />
              <i />
            </span>
          ))}
        </div>
      ) : (
        <div className="skeleton-lines" aria-hidden="true">
          <i />
          <i />
          <i />
        </div>
      )}
    </div>
  );
}
export function Empty({
  title,
  children,
  action,
  level = 3,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
  /** Heading level; 1 when the empty state is the whole page (for example an access refusal). */
  level?: 1 | 2 | 3;
}) {
  const Heading = ("h" + level) as "h1" | "h2" | "h3";
  return (
    <div className="empty">
      <div className="empty-mark" aria-hidden="true">
        <ShieldCheck size={24} />
      </div>
      <Heading className="empty-title">{title}</Heading>
      <p>{children}</p>
      {action}
    </div>
  );
}
export function Hash({
  value,
  label = "SHA-256",
}: {
  value: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  const toast = useToast();
  return (
    <div className="hash-field">
      <span className="field-caption">{label}</span>
      <div>
        <code>{value}</code>
        <button
          className="icon-button"
          aria-label={`Copy ${label}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setFailed(false);
              toast(` copied to the clipboard`, "info");
            } catch {
              setFailed(true);
            }
          }}
        >
          {copied ? <Check size={16} /> : <Copy size={16} />}
        </button>
      </div>
      {copied && (
        <span className="sr-only" role="status">
          {label} copied
        </span>
      )}
      {failed && (
        <span role="status">
          Clipboard unavailable. Select the hash text to copy it.
        </span>
      )}
    </div>
  );
}
export function Pager({
  offset,
  count,
  size = 10,
  change,
  label = "Pagination",
}: {
  offset: number;
  count: number;
  size?: number;
  change: (n: number) => void;
  /** Distinct names when a page has more than one pager, so each navigation landmark is unique. */
  label?: string;
}) {
  return (
    <nav className="pager" aria-label={label}>
      <span>
        {count
          ? `Showing ${offset + 1}–${offset + count}`
          : "No records on this page"}
      </span>
      <div>
        <button
          className="button secondary small"
          disabled={offset === 0}
          onClick={() => change(Math.max(0, offset - size))}
        >
          <ArrowLeft size={14} />
          Previous
        </button>
        <button
          className="button secondary small"
          disabled={count < size}
          onClick={() => change(offset + size)}
        >
          Next
          <ArrowRight size={14} />
        </button>
      </div>
    </nav>
  );
}
export function Dialog({
  open,
  title,
  children,
  close,
  busy = false,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  close: () => void;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (!open) {
      if (dialog?.open) dialog.close();
      return;
    }
    const previous = document.activeElement as HTMLElement | null;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog?.open) dialog.close();
      previous?.focus();
    };
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={id}
      onKeyDown={(e) => {
        if (e.key !== "Tab") return;
        const items = Array.from(
          e.currentTarget.querySelectorAll<HTMLElement>(
            'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]',
          ),
        ).filter((item) => item.getClientRects().length);
        if (!items.length) {
          e.preventDefault();
          return;
        }
        if (e.shiftKey && document.activeElement === items[0]) {
          e.preventDefault();
          items.at(-1)?.focus();
        } else if (!e.shiftKey && document.activeElement === items.at(-1)) {
          e.preventDefault();
          items[0].focus();
        }
      }}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) close();
      }}
    >
      <div className="dialog-heading">
        <h2 id={id}>{title}</h2>
        <button
          className="icon-button"
          disabled={busy}
          aria-label="Close dialog"
          onClick={close}
        >
          <X size={20} />
        </button>
      </div>
      {open && children}
    </dialog>
  );
}
export function Table({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="table-scroll" tabIndex={0} role="region" aria-label={label}>
      <table>{children}</table>
    </div>
  );
}

export type SortDirection = "ascending" | "descending";
/** A column header that sorts the rows on this page; aria-sort tells assistive technology the current order. */
export function SortHeader({
  label,
  column,
  sort,
  change,
}: {
  label: string;
  column: string;
  sort: { column: string; direction: SortDirection };
  change: (column: string) => void;
}) {
  const active = sort.column === column;
  const Icon = !active
    ? ArrowUpDown
    : sort.direction === "ascending"
      ? ArrowUp
      : ArrowDown;
  return (
    <th scope="col" aria-sort={active ? sort.direction : "none"}>
      <button className="sort-button" onClick={() => change(column)}>
        {label}
        <Icon size={13} aria-hidden="true" />
      </button>
    </th>
  );
}

export function nextSort(
  current: { column: string; direction: SortDirection },
  column: string,
): { column: string; direction: SortDirection } {
  if (current.column !== column) return { column, direction: "ascending" };
  return {
    column,
    direction: current.direction === "ascending" ? "descending" : "ascending",
  };
}
