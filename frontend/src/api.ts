import type { Manifest } from "./crypto-contract";

export interface User {
  id: string;
  username: string;
  role: "ADMIN" | "ANALYST" | "EMPLOYEE";
}
export interface Auth {
  user: User;
  csrf_token: string;
}
export interface Asset {
  id: string;
  label: string;
  current_version: number;
  retired: boolean;
}
export interface Policy {
  id: string;
  number: number;
  threshold: number;
  block_enabled: boolean;
}
export interface Block {
  length: number;
  sha256: string;
  source_indices: number[];
  outbound_indices: number[];
}
export interface Match {
  asset_id: string;
  version_id: string;
  exact: boolean;
  matched_bytes: number;
  coverage: { numerator: number; denominator: number };
  intervals: [number, number][];
  blocks: Block[];
}
export interface Scan {
  id: string;
  filename: string;
  policy_id: string;
  release_authorized: false;
  detection: {
    manifest: Manifest;
    registry_revision: number;
    matches: Match[];
  };
  decision: {
    outcome: "ALLOW" | "BLOCK" | "INDETERMINATE";
    reason: string;
    qualifying_versions: string[];
  };
}

export class ApiError extends Error {
  constructor(
    public code: string,
    public status: number,
  ) {
    super(code);
  }
}

export async function request(
  path: string,
  options: RequestInit = {},
  csrf?: string,
): Promise<Response> {
  const headers = new Headers(options.headers);
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    if (response.status === 401 && path !== "/auth/login")
      window.dispatchEvent(new Event("rootsentinel:session-expired"));
    const code =
      typeof body?.error?.code === "string" &&
      /^[A-Z_]{1,64}$/.test(body.error.code)
        ? body.error.code
        : "REQUEST_FAILED";
    throw new ApiError(code, response.status);
  }
  return response;
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
  csrf?: string,
): Promise<T> {
  const response = await request(path, options, csrf);
  return response.status === 204
    ? (undefined as T)
    : (response.json() as Promise<T>);
}

export function jsonBody(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

/** Synthetic byte fixtures only; all fingerprints and decisions come from the server. */
export function fixture(name: string): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder();
  const blocks = Array.from({ length: 8 }, (_, i) => {
    const line = `# synthetic RootSentinel fixture block ${i}; no proprietary source\n`;
    return line.repeat(Math.floor(1024 / line.length) + 1).slice(0, 1024);
  });
  const protectedText = blocks.join("");
  const fixtures: Record<string, string> = {
    protected: protectedText,
    renamed: protectedText,
    partial: blocks[2] + blocks[3],
    shifted: "!" + protectedText,
    modified: "!" + protectedText.slice(1),
    benign: "# unrelated synthetic public note\n".repeat(80),
    empty: "",
    odd: "A".repeat(1024) + "B".repeat(1024) + "C",
  };
  if (!(name in fixtures)) throw new Error("UNKNOWN_FIXTURE");
  return encoder.encode(fixtures[name]);
}
