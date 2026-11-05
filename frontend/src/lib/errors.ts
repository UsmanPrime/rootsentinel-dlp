import { ApiError } from "../api";

const messages: Record<string, string> = {
  INVALID_CREDENTIALS: "The username or password is incorrect.",
  AUTHENTICATION_REQUIRED: "Your session has ended. Sign in again to continue.",
  FORBIDDEN: "Your role does not have permission for this operation.",
  NOT_FOUND:
    "This record is unavailable or you do not have permission to view it.",
  PUBLIC_DEMO_NOT_READY:
    "Public demonstration access is not enabled. Use the configured local application.",
  INPUT_TOO_LARGE: "Choose a file no larger than 10 MiB.",
  INVALID_REQUEST: "Check the entered values and try again.",
  INCOMPLETE_UPLOAD: "The upload was interrupted. No release was authorized.",
  TRANSFER_STALE:
    "Policy or registry data changed. Submit a new transfer for evaluation.",
  TRANSFER_EXPIRED: "The release window expired. Submit a new transfer.",
  TRANSFER_NOT_ALLOWED:
    "This transfer cannot be released. Its current state is enforced by the server.",
  IDEMPOTENCY_CONFLICT:
    "This retry key belongs to different bytes. Start a new submission.",
  DUPLICATE_ASSET_LABEL:
    "An asset already uses that label. Open it to add a new version.",
  DUPLICATE_ASSET_VERSION:
    "These exact bytes are already registered for this asset.",
  ASSET_VERSION_CONFLICT:
    "The asset changed or was retired. Refresh before adding a version.",
  POLICY_VERSION_CONFLICT:
    "The policy changed while you were editing. Refresh and review the active version.",
  INCIDENT_VERSION_CONFLICT:
    "Another investigator updated this incident. Refresh before trying again.",
  EMPTY_PROTECTED_ASSET:
    "Empty files can be scanned, but cannot be registered as protected assets.",
  RESOLUTION_REQUIRED:
    "Enter a resolution reason before closing this incident.",
};
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (messages[error.code]) return messages[error.code];
    if (error.status === 401) return messages.AUTHENTICATION_REQUIRED;
    if (error.status === 403)
      return "Access was denied. Refresh your session and confirm you are using the configured local origin.";
    if (error.status === 429)
      return "The request limit was reached. Wait before trying again.";
    if (error.status === 503)
      return "The service cannot safely complete this operation. No release is confirmed. Check the backend and refresh the record.";
    return "The request could not be completed. Refresh the record and try again.";
  }
  return "Unable to reach the service. Check your connection and the local backend, then try again.";
}

export const reasonText: Record<string, string> = {
  EXACT_PROTECTED_FILE:
    "The entire file matches registered protected bytes, regardless of its name.",
  BLOCK_THRESHOLD_MET:
    "Matching bytes for a protected asset meet the active policy threshold.",
  NO_QUALIFYING_MATCH:
    "No match met the blocking policy. Transformed content can evade raw-byte matching.",
  RELEASE_WINDOW_EXPIRED: "The snapshot retention window has expired.",
  REVISIONS_CHANGED: "The policy or registry changed after this evaluation.",
  SERVER_SEND_COMPLETED:
    "The server finished sending. Recipient storage is not confirmed.",
  DELIVERY_NOT_CONFIRMED:
    "Delivery could not be confirmed. A retry requires a new transfer.",
};

export function bytes(size: number) {
  return size < 1024
    ? `${size} B`
    : size < 1048576
      ? `${(size / 1024).toFixed(1)} KiB`
      : `${(size / 1048576).toFixed(1)} MiB`;
}
export function date(value: string) {
  return (
    new Intl.DateTimeFormat("en", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "UTC",
    }).format(new Date(value)) + " UTC"
  );
}
export function short(value: string) {
  return value.slice(0, 8);
}
