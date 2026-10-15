import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type AccessRequest, type Page } from "../api";
import { useAuth } from "../auth";
import {
  Empty, ErrorBox, FormField, Loading, Modal, PageHeader, Pagination, SearchBox, Segmented,
  SensitivityBadge, StatusBadge, useAction, useToast,
} from "../components/ui";
import { endOfDayIso, fmtDate } from "../format";
import { useAsync, useDebounced } from "../hooks";

type Direction = "all" | "incoming" | "outgoing";

export default function RequestsPage() {
  const { hasRole } = useAuth();
  const [params, setParams] = useSearchParams();
  const defaultDir: Direction = hasRole("owner") ? "incoming" : hasRole("partner") ? "outgoing" : "all";
  const direction = (params.get("direction") as Direction) ?? defaultDir;
  const status = params.get("status") ?? "";
  const page = Number(params.get("page") ?? 1);
  const [q, setQ] = useState("");
  const query = useDebounced(q);
  const [deciding, setDeciding] = useState<{ req: AccessRequest; mode: "approve" | "deny" } | null>(null);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next, { replace: true });
  };
  const list = useAsync(() => api.get<Page<AccessRequest>>("/requests", { direction, status, q: query, page, page_size: 15 }),
    [direction, status, query, page]);

  return (
    <>
      <PageHeader title="Access requests"
        intro={hasRole("partner") ? <>To ask for data, open a dataset and choose “Request access”. <Link to="/datasets">Browse datasets</Link></> : undefined} />
      <div className="toolbar">
        <SearchBox value={q} onChange={(v) => { setQ(v); set("page", ""); }} placeholder="Search purpose, dataset or organization" />
        {hasRole("owner") && (
          <Segmented label="Direction" value={direction} onChange={(v) => set("direction", v)}
            options={[{ value: "incoming", label: "For our datasets" }, { value: "outgoing", label: "Sent by us" }]} />
        )}
        <select aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Any status</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
        </select>
      </div>
      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data ? <Loading /> : list.data && list.data.items.length === 0 ? (
        <Empty title="No requests here." />
      ) : list.data && (
        <>
          <ul className="request-list" aria-busy={list.loading}>
            {list.data.items.map((r) => {
              const canDecide = hasRole("owner") && direction === "incoming" && r.status === "pending";
              return (
                <li key={r.request_id} className="request">
                  <div className="request-head">
                    <p>
                      <strong>{r.grantee_org_name}</strong> asks <strong>{r.owner_org_name}</strong> for{" "}
                      <Link to={`/datasets/${r.dataset_id}`}>{r.dataset_title}</Link>
                    </p>
                    <StatusBadge status={r.status} />
                  </div>
                  <p className="request-purpose">For {r.purpose.replace(/_/g, " ")}, until {fmtDate(r.requested_expires_at)}</p>
                  <div className="chips">
                    {r.fields.map((f) => <span key={f.field_id} className="chip"><code>{f.name}</code> <SensitivityBadge level={f.sensitivity} /></span>)}
                  </div>
                  <p className="muted small">
                    Sent {fmtDate(r.created_at)} by {r.requested_by_email ?? "a former member"}
                    {r.decided_at && `. ${r.status === "approved" ? "Approved" : "Decided"} ${fmtDate(r.decided_at)} by ${r.decided_by_email ?? "the owner"}`}
                    {r.decision_note && `: “${r.decision_note}”`}
                  </p>
                  {canDecide && (
                    <div className="request-actions">
                      <button type="button" className="btn btn-primary btn-small" onClick={() => setDeciding({ req: r, mode: "approve" })}>Review and approve</button>
                      <button type="button" className="btn btn-quiet btn-small" onClick={() => setDeciding({ req: r, mode: "deny" })}>Deny</button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={(p) => set("page", String(p))} noun="requests" />
        </>
      )}
      {deciding && <DecideModal {...deciding} onClose={() => setDeciding(null)} onDone={() => { setDeciding(null); list.reload(); }} />}
    </>
  );
}

function DecideModal({ req, mode, onClose, onDone }: { req: AccessRequest; mode: "approve" | "deny"; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [fields, setFields] = useState(new Set(req.fields.map((f) => f.field_id)));
  const [expires, setExpires] = useState(req.requested_expires_at.slice(0, 10));
  const [note, setNote] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mode === "approve") {
      if (fields.size === 0) return setFormError("Keep at least one field, or deny the request instead");
      if (new Date(endOfDayIso(expires)) <= new Date()) return setFormError("Choose an end date in the future");
    }
    setFormError(null);
    const res = await run(() => mode === "approve"
      ? api.post<AccessRequest>(`/requests/${req.request_id}/approve`, { field_ids: [...fields], expires_at: endOfDayIso(expires), note: note || null })
      : api.post<AccessRequest>(`/requests/${req.request_id}/deny`, { note: note || null }));
    if (res) {
      toast(mode === "approve" ? `Approved ${fields.size} fields for ${req.grantee_org_name}.` : `Denied ${req.grantee_org_name}'s request.`);
      onDone();
    }
  };

  return (
    <Modal title={mode === "approve" ? "Approve request" : "Deny request"} open onClose={onClose}>
      <form onSubmit={submit} noValidate>
        <p>{req.grantee_org_name} wants these fields of {req.dataset_title} for {req.purpose.replace(/_/g, " ")}.</p>
        {mode === "approve" && (
          <>
            <fieldset className="field-picker">
              <legend>Fields to share (untick to narrow)</legend>
              {req.fields.map((f) => (
                <label key={f.field_id} className="check-row">
                  <input type="checkbox" checked={fields.has(f.field_id)} onChange={() => {
                    const n = new Set(fields); if (n.has(f.field_id)) n.delete(f.field_id); else n.add(f.field_id); setFields(n);
                  }} />
                  <code className="field-name">{f.name}</code> <SensitivityBadge level={f.sensitivity} />
                </label>
              ))}
            </fieldset>
            <FormField label="Access ends on" hint="You can shorten what was requested.">
              {(p) => <input {...p} type="date" value={expires} max={req.requested_expires_at.slice(0, 10)} onChange={(e) => setExpires(e.target.value)} />}
            </FormField>
          </>
        )}
        <FormField label="Note to the requester (optional)">
          {(p) => <textarea {...p} rows={2} value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} />}
        </FormField>
        {formError && <p className="field-error">{formError}</p>}
        <ErrorBox error={error} />
        <div className="form-actions">
          <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
          <button type="submit" className={`btn ${mode === "approve" ? "btn-primary" : "btn-danger"}`} disabled={busy}>
            {mode === "approve" ? `Approve ${fields.size} fields` : "Deny request"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
