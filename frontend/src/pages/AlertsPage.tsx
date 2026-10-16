import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Alert, type Page } from "../api";
import { useAuth } from "../auth";
import { Empty, ErrorBox, Loading, Modal, PageHeader, Pagination, StatusBadge, useAction, useToast } from "../components/ui";
import { fmtDateTime } from "../format";
import { useAsync } from "../hooks";

const DETECTOR = { isolation_forest: "Isolation Forest", rule: "Threshold rule", manual: "Manual" };

export default function AlertsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open";
  const page = Number(params.get("page") ?? 1);
  const [revoking, setRevoking] = useState<Alert | null>(null);
  const action = useAction();
  const canTriage = hasRole("owner", "auditor"); // admins run the detector; they don't triage
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next, { replace: true });
  };
  const list = useAsync(() => api.get<Page<Alert>>("/alerts", { status: status === "all" ? "" : status, page, page_size: 15 }), [status, page]);

  const setStatus = async (a: Alert, s: Alert["status"]) => {
    if (await action.run(() => api.patch(`/alerts/${a.alert_id}`, { status: s }))) {
      toast(s === "resolved" ? "Marked resolved." : s === "false_positive" ? "Marked as a false alarm." : "Marked as under investigation.");
      list.reload();
    }
  };
  const revoke = async () => {
    if (!revoking) return;
    const res = await action.run(() => api.post<{ revoked_grants: number }>(`/alerts/${revoking.alert_id}/revoke-grants`));
    if (res) {
      toast(`Revoked ${res.revoked_grants} grants. Their next read is refused.`);
      setRevoking(null);
      list.reload();
    }
  };
  const runDetector = async () => {
    const res = await action.run(() => api.post<{ alerts_written: number; user_hours: number }>("/alerts/run-detector"));
    if (res) {
      toast(`Scored ${res.user_hours.toLocaleString()} user-hours. ${res.alerts_written} new alerts.`);
      list.reload();
    }
  };

  return (
    <>
      <PageHeader
        title="Alerts"
        intro="An Isolation Forest scores each user's hourly access pattern; a threshold rule runs alongside it as a baseline."
        actions={hasRole("auditor", "admin") && (
          <button type="button" className="btn" disabled={action.busy} onClick={runDetector}>
            {action.busy ? "Scoring…" : "Run detector now"}
          </button>
        )}
      />
      <div className="toolbar">
        <select aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False alarm</option>
          <option value="all">All</option>
        </select>
      </div>
      <ErrorBox error={list.error ?? action.error} onRetry={list.reload} />
      {list.loading && !list.data ? <Loading /> : list.data && list.data.items.length === 0 ? (
        <Empty title={status === "open" ? "No open alerts." : "No alerts with this status."}>Nothing unusual needs your attention.</Empty>
      ) : list.data && (
        <>
          <ul className="alert-cards" aria-busy={list.loading}>
            {list.data.items.map((a) => (
              <li key={a.alert_id} className="alert-card">
                <span className="score score-lg" style={{ ["--score" as string]: a.score }} aria-label={`Anomaly score ${a.score.toFixed(2)} of 1`}>
                  {a.score.toFixed(2)}
                </span>
                <div className="alert-card-body">
                  <div className="request-head">
                    <p><strong>{a.user_email}</strong> <span className="muted">({a.user_org_name})</span> on{" "}
                      {!a.dataset_id ? "a dataset" : canTriage ? <Link to={`/datasets/${a.dataset_id}`}>{a.dataset_title}</Link> : a.dataset_title}</p>
                    <StatusBadge status={a.status} />
                  </div>
                  <p className="alert-reason">{a.reason}</p>
                  <p className="muted small">
                    {DETECTOR[a.detector]}
                    {a.features?.also_flagged_by_rule ? " and the threshold rule" : ""}, hour starting{" "}
                    {a.features?.hour_bucket ? fmtDateTime(String(a.features.hour_bucket) + "Z") : fmtDateTime(a.created_at)} UTC.{" "}
                    {canTriage && (a.active_grants > 0 ? `${a.active_grants} active grants on this dataset.` : "No active grants on this dataset.")}
                  </p>
                  {(a.status === "open" || a.status === "investigating") && canTriage && (
                    <div className="request-actions">
                      {hasRole("owner") && a.active_grants > 0 && (
                        <button type="button" className="btn btn-danger btn-small" onClick={() => setRevoking(a)}>Revoke their access</button>
                      )}
                      {a.status === "open" && <button type="button" className="btn btn-quiet btn-small" onClick={() => setStatus(a, "investigating")}>Investigate</button>}
                      <button type="button" className="btn btn-quiet btn-small" onClick={() => setStatus(a, "resolved")}>Resolve</button>
                      <button type="button" className="btn btn-quiet btn-small" onClick={() => setStatus(a, "false_positive")}>False alarm</button>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={(p) => set("page", String(p))} noun="alerts" />
        </>
      )}
      <Modal title="Revoke access?" open={!!revoking} onClose={() => setRevoking(null)}>
        {revoking && (
          <>
            <p>This revokes all {revoking.active_grants} active grants that {revoking.user_org_name} holds on {revoking.dataset_title}, and resolves the alert. Their next read is refused.</p>
            <ErrorBox error={action.error} />
            <div className="form-actions">
              <button type="button" className="btn btn-quiet" onClick={() => setRevoking(null)}>Cancel</button>
              <button type="button" className="btn btn-danger" disabled={action.busy} onClick={revoke}>Revoke {revoking.active_grants} grants</button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
