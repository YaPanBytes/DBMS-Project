import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type AuditEntry, type Page, type VerifyResult } from "../api";
import { useAuth } from "../auth";
import { Empty, ErrorBox, HashChip, Loading, PageHeader, Pagination, SearchBox, useAction } from "../components/ui";
import { ACTION_LABELS, fmtDateTime } from "../format";
import { useAsync, useDebounced } from "../hooks";

export default function AuditPage() {
  const { hasRole } = useAuth();
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const since = params.get("since") ?? "";
  const page = Number(params.get("page") ?? 1);
  const [q, setQ] = useState("");
  const query = useDebounced(q);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const check = useAction();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next, { replace: true });
  };
  const list = useAsync(() => api.get<Page<AuditEntry>>("/audit", { action, q: query, since: since ? new Date(since).toISOString() : "", page, page_size: 25 }),
    [action, query, since, page]);

  const runVerify = async () => {
    const res = await check.run(() => api.get<VerifyResult>("/audit/verify"));
    if (res) setVerify(res);
  };

  return (
    <>
      <PageHeader
        title="Audit trail"
        intro={hasRole("auditor") ? "Every read and change on the platform, append-only and hash-chained." : "Everything your organization did, and everything done to your datasets."}
        actions={!hasRole("partner") && (
          <button type="button" className="btn btn-primary" disabled={check.busy} onClick={runVerify}>
            {check.busy ? "Verifying…" : "Verify chain"}
          </button>
        )}
      />
      <ErrorBox error={check.error} />
      {verify && (
        <div className={`notice ${verify.valid ? "notice-good" : "notice-error"}`} role="status">
          {verify.valid ? (
            <p>All {verify.total_rows.toLocaleString()} entries verified at {fmtDateTime(verify.checked_at)}. Each hash matches its row and links to the one before, so nothing has been altered, removed or slipped in.</p>
          ) : (
            <p>The chain is broken at entry {verify.first_error?.log_id}: {verify.first_error?.message}. {verify.verified_rows.toLocaleString()} entries before it are intact.</p>
          )}
        </div>
      )}
      <div className="toolbar">
        <SearchBox value={q} onChange={(v) => { setQ(v); set("page", ""); }} placeholder="Search by user email or dataset" />
        <select aria-label="Action" value={action} onChange={(e) => set("action", e.target.value)}>
          <option value="">Any action</option>
          {Object.entries(ACTION_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <label className="inline-label">From <input type="date" value={since} onChange={(e) => set("since", e.target.value)} /></label>
      </div>
      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data ? <Loading /> : list.data && list.data.items.length === 0 ? (
        <Empty title="No entries match these filters." />
      ) : list.data && (
        <>
          <table className="table table-audit" aria-busy={list.loading}>
            <thead>
              <tr><th className="num">#</th><th>When</th><th>What</th><th>Who</th><th>Dataset</th><th className="num">Rows</th><th>Hash, linked to previous</th></tr>
            </thead>
            <tbody>
              {list.data.items.map((e) => (
                <tr key={e.log_id}>
                  <td data-label="#" className="num muted">{e.seq}</td>
                  <td data-label="When">{fmtDateTime(e.ts)}</td>
                  <td data-label="What">{ACTION_LABELS[e.action] ?? e.action}{e.field_count > 0 && <span className="muted small"> {e.field_count} fields</span>}</td>
                  <td data-label="Who">{e.user_email ?? <span className="muted">System</span>}</td>
                  <td data-label="Dataset">{e.dataset_title ?? <span className="muted">—</span>}</td>
                  <td data-label="Rows" className="num">{e.rows_affected.toLocaleString()}</td>
                  <td data-label="Hash" className="hash-cell"><HashChip hash={e.prev_hash} /><span className="hash-link" aria-hidden="true" /><HashChip hash={e.row_hash} linked /></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={(p) => set("page", String(p))} noun="entries" />
        </>
      )}
    </>
  );
}
