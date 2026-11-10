import { ApiError } from "../api";

/** The server's display-label rule (schemas.Label): 1 to 120 characters, letters/digits first, then a safe set. */
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._()-]*$/;

/**
 * A display label the gateway will accept for a chosen file name. It is only a label: the server never uses it as a
 * storage path. Characters outside the safe set become "_", and an unusable name falls back to candidate.bin.
 */
export function transferLabel(name: string): string {
  const cleaned = name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^A-Za-z0-9 ._()-]/g, "_")
    .replace(/^[^A-Za-z0-9]+/, "")
    .slice(0, 120)
    .trimEnd();
  return LABEL.test(cleaned) ? cleaned : "candidate.bin";
}

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export type UploadProgress = { loaded: number; total: number };

/**
 * POST raw bytes with real upload progress (fetch cannot report it). Same contract as api(): same-origin cookie,
 * CSRF header, typed ApiError on failure, and the session-expired event on 401.
 */
export function uploadWithProgress<T>(
  path: string,
  body: Blob,
  headers: Record<string, string>,
  csrf: string,
  onProgress: (progress: UploadProgress) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/v1${path}`);
    xhr.withCredentials = true;
    xhr.responseType = "text";
    for (const [name, value] of Object.entries(headers))
      xhr.setRequestHeader(name, value);
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable)
        onProgress({ loaded: event.loaded, total: event.total });
    };
    xhr.onerror = () => reject(new ApiError("NETWORK_UNAVAILABLE", 0));
    xhr.onload = () => {
      let parsed: unknown = null;
      try {
        parsed = xhr.responseText ? JSON.parse(xhr.responseText) : null;
      } catch {
        parsed = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(parsed as T);
        return;
      }
      if (xhr.status === 401)
        window.dispatchEvent(new Event("rootsentinel:session-expired"));
      const code = (parsed as { error?: { code?: unknown } } | null)?.error
        ?.code;
      reject(
        new ApiError(
          typeof code === "string" && /^[A-Z_]{1,64}$/.test(code)
            ? code
            : "REQUEST_FAILED",
          xhr.status,
        ),
      );
    };
    xhr.send(body);
  });
}
