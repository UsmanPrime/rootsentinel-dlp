import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ArrowRight, Compass, X } from "lucide-react";
import { Dialog } from "./ui";

const STORAGE_KEY = "rootsentinel.tour";

/** Session-scoped memory of "tour seen". sessionStorage only: nothing persists beyond the browser session. */
export function tourSeen() {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY) === "done";
  } catch {
    return false;
  }
}
export function markTourSeen() {
  try {
    window.sessionStorage.setItem(STORAGE_KEY, "done");
  } catch {
    // Storage can be unavailable (private mode); the invitation then simply shows again next time.
  }
}

type Step = {
  title: string;
  body: string;
  path: string;
  link: string;
  privileged?: boolean;
};
const STEPS: Step[] = [
  {
    title: "The overview",
    body: "Counts come straight from the server: every evaluated transfer, how many were blocked or allowed, open incidents and the audit sequence.",
    path: "/",
    link: "Stay on the overview",
  },
  {
    title: "Submit a transfer",
    body: "Drop a synthetic file or pick a sample. The gateway freezes the bytes, hashes the whole file and every 1 KiB block, and decides ALLOW or BLOCK.",
    path: "/transfers",
    link: "Open the transfer gateway",
  },
  {
    title: "Read the verdict",
    body: "Each transfer explains its decision: which protected asset matched, how many bytes and blocks, and the policy threshold it was judged by. An ALLOW is released once, after a confirmation.",
    path: "/transfers",
    link: "See your transfers",
  },
  {
    title: "Investigate incidents",
    body: "Every BLOCK opens an incident with the matching evidence. Analysts record notes, resolve it and export the evidence.",
    path: "/incidents",
    link: "Open incidents",
    privileged: true,
  },
  {
    title: "Verify the audit chain",
    body: "Decisions, releases and incident changes are HMAC-chained events. Verify the chain and retain checkpoints from the audit page.",
    path: "/audit",
    link: "Open activity and audit",
    privileged: true,
  },
  {
    title: "Try the guided demo",
    body: "The guided demo walks through registering a sample, proving inclusion, a blocked copy and an allowed release, using real operations.",
    path: "/guide",
    link: "Open the guided demo",
  },
];

export function Tour({
  open,
  close,
  privileged,
}: {
  open: boolean;
  close: () => void;
  privileged: boolean;
}) {
  const steps = STEPS.filter((step) => privileged || !step.privileged);
  const [index, setIndex] = useState(0);
  const step = steps[Math.min(index, steps.length - 1)];
  function finish() {
    markTourSeen();
    setIndex(0);
    close();
  }
  return (
    <Dialog
      open={open}
      close={finish}
      title={`Product tour · ${index + 1} of ${steps.length}`}
    >
      <div className="tour-step">
        <h3>{step.title}</h3>
        <p>{step.body}</p>
        <Link className="text-link" to={step.path} onClick={finish}>
          {step.link} <ArrowRight size={14} />
        </Link>
      </div>
      <ol className="tour-dots" aria-label="Tour progress">
        {steps.map((s, i) => (
          <li
            key={s.title}
            className={i === index ? "current" : ""}
            aria-current={i === index ? "step" : undefined}
          >
            <span className="sr-only">{s.title}</span>
          </li>
        ))}
      </ol>
      <div className="dialog-actions">
        <button className="button secondary" onClick={finish}>
          Skip tour
        </button>
        <span className="spacer" />
        <button
          className="button secondary"
          disabled={index === 0}
          onClick={() => setIndex(index - 1)}
        >
          <ArrowLeft size={15} />
          Back
        </button>
        {index < steps.length - 1 ? (
          <button
            className="button primary"
            onClick={() => setIndex(index + 1)}
          >
            Next
            <ArrowRight size={15} />
          </button>
        ) : (
          <button className="button primary" onClick={finish}>
            Finish
          </button>
        )}
      </div>
    </Dialog>
  );
}

/** A non-blocking invitation on the overview; it never covers the page or interrupts a task. */
export function TourInvite({
  start,
  dismiss,
}: {
  start: () => void;
  dismiss: () => void;
}) {
  return (
    <aside className="tour-invite" aria-label="Product tour invitation">
      <Compass size={20} aria-hidden="true" />
      <p>
        <strong>New here?</strong> A six-step tour shows where transfers,
        verdicts, incidents and the audit chain live.
      </p>
      <button className="button primary small" onClick={start}>
        Start the tour
      </button>
      <button
        className="icon-button"
        aria-label="Skip the tour invitation"
        onClick={dismiss}
      >
        <X size={16} />
      </button>
    </aside>
  );
}
