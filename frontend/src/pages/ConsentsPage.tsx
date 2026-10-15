import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Consent, type Page } from "../api";
import { useAuth } from "../auth";
import {
  Empty, ErrorBox, FormField, Loading, Modal, PageHeader, Pagination, SearchBox, Segmented,
  SensitivityBadge, StatusBadge, useAction, useToast,
} from "../components/ui";
import { fmtDate, relativeDays } from "../format";
import { useAsync, useDebounced } from "../hooks";

type Status = "active" | "expired" | "revoked" | "all";
type Direction = "all" | "given" | "received";

export default function ConsentsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const status = (params.get("status") as Status) ?? "active";
  const direction = (params.get("direction") as Direction) ?? "all";
  const page = Number(params.get("page") ?? 1);
  const [q, setQ] = useState("");
  const query = useDebounced(q);
  const [revoking, setRevoking] = useState<Consent | null>(null);
  const [reason, setReason] = useState("");
  const action = useAction();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next, { replace: true });
  };
  const list = useAsync(() => api.get<Page<Consent>>("/consents", { status, direction, q: query, page, page_size: 20 }),
    [status, direction, query, page]);

  const revoke = async () => {
    if (!revoking) return;
    const res = await action.run(() => api.post<Consent>(`/consents/${revoking.grant_id}/revoke`, { reason: reason || null }));
    if (res) {
      toast(`Revoked. ${res.grantee_org_name} can no longer read ${res.field_name}.`);
      setRevoking(null);
      setReason("");
      list.reload();
    }
  };

  return (
    <>
      <PageHeader title="Consents" intro="Each grant covers one field, for one purpose, until a set date." />
      <div className="toolbar">
        <SearchBox value={q} onChange={(v) => { setQ(v); set("page", ""); }} placeholder="Search purpose, dataset or field" />
        {hasRole("owner") && (
          <Segmented label="Direction" value={direction} onChange={(v) => set("direction", v === "all" ? "" : v)}
            options={[{ value: "all", label: "All" }, { value: "given", label: "Given" }, { value: "received", label: "Received" }]} />
        )}
        <Segmented label="Status" value={status} onChange={(v) => set("status", v === "active" ? "" : v)}
          options={[{ value: "active", label: "Active" }, { value: "expired", label: "Expired" }, { value: "revoked", label: "Revoked" }, { value: "all", label: "All" }]} />
      </div>
      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data ? <Loading /> : list.data && list.data.items.length === 0 ? (
        <Empty title={`No ${status === "all" ? "" : status} consents${query ? " match your search" : ""}.`}>
          {hasRole("partner") && <Link to="/datasets">Browse datasets to request access</Link>}
        </Empty>
      ) : list.data && (
        <>
          <table className="table" aria-busy={list.loading}>
            <thead>
              <tr><th>Dataset and field</th><th>From</th><th>To</th><th>Purpose</th><th>Expires</th><th>Status</th>
                {hasRole("owner") && <th><span className="sr-only">Actions</span></th>}</tr>
            </thead>
            <tbody>
              {list.data.items.map((g) => (
                <tr key={g.grant_id}>
                  <td data-label="Dataset and field">
                    <Link to={`/datasets/${g.dataset_id}`}>{g.dataset_title}</Link>
                    <div><code className="field-name">{g.field_name}</code> <SensitivityBadge level={g.sensitivity} /></div>
                  </td>
                  <td data-label="From">{g.grantor_org_name}</td>
                  <td data-label="To">{g.grantee_org_name}</td>
                  <td data-label="Purpose">{g.purpose.replace(/_/g, " ")}</td>
                  <td data-label="Expires">{fmtDate(g.expires_at)}{g.status === "active" && <span className="muted small"> {relativeDays(g.expires_at)}</span>}</td>
                  <td data-label="Status"><StatusBadge status={g.status} />{g.revocation_reason && <div className="muted small">{g.revocation_reason}</div>}</td>
                  {hasRole("owner") && (
                    <td>{g.status === "active" && g.grantor_org_name && direction !== "received" && (
                      <button type="button" className="btn btn-danger btn-small" onClick={() => setRevoking(g)}>Revoke</button>
                    )}</td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={(p) => set("page", String(p))} noun="grants" />
        </>
      )}
      <Modal title="Revoke this grant?" open={!!revoking} onClose={() => setRevoking(null)}>
        {revoking && (
          <>
            <p>{revoking.grantee_org_name} will lose access to <code className="field-name">{revoking.field_name}</code> in {revoking.dataset_title} immediately. Their next read is refused.</p>
            <FormField label="Reason (optional)" hint="Recorded with the grant and visible to auditors.">
              {(p) => <input {...p} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} />}
            </FormField>
            <ErrorBox error={action.error} />
            <div className="form-actions">
              <button type="button" className="btn btn-quiet" onClick={() => setRevoking(null)}>Keep access</button>
              <button type="button" className="btn btn-danger" disabled={action.busy} onClick={revoke}>Revoke now</button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
