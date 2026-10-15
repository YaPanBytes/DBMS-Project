const dateFmt = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});

export const fmtDate = (s: string | null | undefined) => (s ? dateFmt.format(new Date(s)) : "—");
export const fmtDateTime = (s: string | null | undefined) => (s ? dateTimeFmt.format(new Date(s)) : "—");
export const fmtNumber = (n: number) => n.toLocaleString();

export function relativeDays(s: string): string {
  const days = Math.round((new Date(s).getTime() - Date.now()) / 86_400_000);
  if (days === 0) return "today";
  if (days > 0) return days === 1 ? "in 1 day" : `in ${days} days`;
  return days === -1 ? "1 day ago" : `${-days} days ago`;
}

/** yyyy-mm-dd for <input type="date">, n days from now */
export function dateInput(daysFromNow: number): string {
  const d = new Date(Date.now() + daysFromNow * 86_400_000);
  return d.toISOString().slice(0, 10);
}

/** End of the chosen day in the user's timezone, as ISO */
export function endOfDayIso(date: string): string {
  return new Date(`${date}T23:59:59`).toISOString();
}

export const ACTION_LABELS: Record<string, string> = {
  select: "Read data",
  insert: "Wrote data",
  update: "Updated",
  delete: "Deleted",
  grant_create: "Granted consent",
  grant_update: "Changed consent",
  grant_revoke: "Revoked consent",
  grant_expire: "Consent expired",
  request_create: "Requested access",
  request_update: "Updated request",
  request_approve: "Approved request",
  request_deny: "Denied request",
  login: "Signed in",
  logout: "Signed out",
  pii_scan: "Scanned for PII",
  anomaly_alert: "Anomaly flagged",
};

export const SENSITIVITY_LABELS = { low: "Low", medium: "Medium", high: "High", pii: "Personal data" };
export const ROLE_LABELS = { owner: "Data owner", partner: "Partner", auditor: "Auditor", admin: "Admin" };
