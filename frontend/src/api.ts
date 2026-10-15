// Typed client for the ConsentLedger API. The session lives in an httpOnly
// cookie; state-changing requests echo the CSRF cookie in X-CSRF-Token.

export type Role = "owner" | "partner" | "auditor" | "admin";
export type Sensitivity = "low" | "medium" | "high" | "pii";
export type DataType = "text" | "integer" | "numeric" | "boolean" | "date" | "timestamp" | "json";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Organization {
  org_id: string;
  name: string;
  type: "ngo" | "government" | "funder" | "auditor";
  description: string | null;
  contact_email: string | null;
  created_at: string;
}

export interface User {
  user_id: string;
  email: string;
  full_name: string | null;
  role: Role;
  org_id: string;
  org_name: string | null;
  is_active: boolean;
  last_login: string | null;
  has_password: boolean;
  google_linked: boolean;
}

export interface Me {
  user: User;
  organization: Organization;
  permissions: string[];
  auth_method: "cookie" | "bearer";
  expires_at: string;
}

export interface Field {
  field_id: string;
  dataset_id: string;
  name: string;
  data_type: DataType;
  sensitivity: Sensitivity;
  description: string | null;
  is_encrypted: boolean;
  ordinal: number;
}

export interface Dataset {
  dataset_id: string;
  title: string;
  description: string | null;
  category: string | null;
  status: "draft" | "published" | "archived";
  version: number;
  owner_org_id: string;
  owner_org_name: string | null;
  created_at: string;
  updated_at: string;
  field_count: number;
  is_owner: boolean;
  has_access: boolean;
}

export interface GrantSummary {
  grant_id: string;
  field_id: string;
  field_name: string;
  purpose: string;
  expires_at: string;
}

export interface DatasetDetail extends Dataset {
  fields: Field[];
  my_grants: GrantSummary[];
  row_count: number | null;
}

export interface ColumnSuggestion {
  name: string;
  original_name: string;
  inferred_type: DataType;
  suggested_sensitivity: Sensitivity;
  confidence: number;
  detected: Record<string, number>;
  reasons: string[];
  masked_preview: unknown[];
  suggest_encryption: boolean;
}

export interface UploadPreview {
  row_count: number;
  columns: ColumnSuggestion[];
  ner_available: boolean;
}

export interface DataPage {
  columns: string[];
  rows: Record<string, unknown>[];
  total: number;
  page: number;
  page_size: number;
  purpose: string | null;
  visible_fields: string[];
  masked_fields: string[];
}

export interface Consent {
  grant_id: string;
  dataset_id: string;
  dataset_title: string | null;
  grantor_org_id: string;
  grantor_org_name: string | null;
  grantee_org_id: string;
  grantee_org_name: string | null;
  field_id: string;
  field_name: string | null;
  sensitivity: Sensitivity | null;
  purpose: string;
  granted_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  status: "active" | "expired" | "revoked";
}

export interface AccessRequest {
  request_id: string;
  dataset_id: string;
  dataset_title: string | null;
  owner_org_id: string | null;
  owner_org_name: string | null;
  grantee_org_id: string;
  grantee_org_name: string | null;
  requested_by_email: string | null;
  fields: { field_id: string; name: string | null; sensitivity: Sensitivity | null }[];
  purpose: string;
  requested_expires_at: string;
  status: "pending" | "approved" | "denied" | "expired";
  decided_by_email: string | null;
  decided_at: string | null;
  decision_note: string | null;
  created_at: string;
}

export interface AuditEntry {
  log_id: string;
  seq: number;
  ts: string;
  action: string;
  user_id: string | null;
  user_email: string | null;
  dataset_id: string | null;
  dataset_title: string | null;
  field_id: string | null;
  field_count: number;
  rows_affected: number;
  query_text: string | null;
  client_ip: string | null;
  row_hash: string;
  prev_hash: string;
}

export interface VerifyResult {
  valid: boolean;
  total_rows: number;
  verified_rows: number;
  first_error: { log_id: string; message: string } | null;
  checked_at: string;
}

export interface Alert {
  alert_id: string;
  user_id: string;
  user_email: string | null;
  user_org_name: string | null;
  dataset_id: string | null;
  dataset_title: string | null;
  score: number;
  reason: string;
  features: Record<string, unknown> | null;
  detector: "isolation_forest" | "rule" | "manual";
  status: "open" | "investigating" | "resolved" | "false_positive";
  created_at: string;
  resolved_at: string | null;
  active_grants: number;
}

export interface Dashboard {
  role: Role;
  datasets_visible: number;
  datasets_owned: number;
  consents_given_active: number;
  consents_received_active: number;
  requests_incoming_pending: number;
  requests_outgoing_pending: number;
  alerts_open: number;
  audit_events_24h: number;
  recent_audit: AuditEntry[];
  recent_alerts: Alert[];
}

export interface ApiErrorDetail {
  field?: string;
  message?: string;
}

export class ApiError extends Error {
  status: number;
  code: string;
  details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }

  /** Field-level validation messages keyed by field name. */
  fieldErrors(): Record<string, string> {
    if (!Array.isArray(this.details)) return {};
    const out: Record<string, string> = {};
    for (const d of this.details as ApiErrorDetail[]) {
      if (d && d.field && d.message) out[d.field] = d.message;
    }
    return out;
  }
}

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function csrfToken(): string | null {
  const m = document.cookie.match(/(?:^|;\s*)cl_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function qs(params: Query): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET") {
    const token = csrfToken();
    if (token) headers["X-CSRF-Token"] = token;
  }

  let res: Response;
  try {
    res = await fetch(`/api${path}`, { method, headers, body: payload, credentials: "include" });
  } catch {
    throw new ApiError(0, "network_error", "Can't reach the server. Check your connection and try again.");
  }

  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = data?.error ?? {};
    const apiError = new ApiError(
      res.status,
      err.code ?? "error",
      err.message ?? `Request failed (${res.status})`,
      err.details,
    );
    if (res.status === 401 && !path.startsWith("/auth/")) onUnauthorized?.();
    throw apiError;
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, params: Query = {}) => request<T>("GET", path + qs(params)),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: (path: string) => request<void>("DELETE", path),
};
