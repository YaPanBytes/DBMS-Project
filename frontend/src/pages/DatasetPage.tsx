import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  api,
  type AccessRequest,
  type AuditEntry,
  type Consent,
  type DataPage,
  type DatasetDetail,
  type DataType,
  type Field,
  type Organization,
  type Page,
  type Sensitivity,
  type UploadPreview,
} from "../api";
import { useAuth } from "../auth";
import {
  Empty,
  ErrorBox,
  FormField,
  Loading,
  Modal,
  PageHeader,
  Pagination,
  Redacted,
  SensitivityBadge,
  StatusBadge,
  useAction,
  useToast,
} from "../components/ui";
import { ACTION_LABELS, dateInput, endOfDayIso, fmtDate, fmtDateTime, relativeDays, SENSITIVITY_LABELS } from "../format";
import { useAsync } from "../hooks";

type Tab = "fields" | "data" | "sharing" | "activity";
const SENSITIVITIES: Sensitivity[] = ["low", "medium", "high", "pii"];
const DATA_TYPES: DataType[] = ["text", "integer", "numeric", "boolean", "date", "timestamp", "json"];

export default function DatasetPage() {
  const { id = "" } = useParams();
  const { me, hasRole } = useAuth();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) ?? "fields";
  const setTab = (t: Tab) => setParams(t === "fields" ? {} : { tab: t }, { replace: true });

  const ds = useAsync(() => api.get<DatasetDetail>(`/datasets/${id}`), [id]);
  const [modal, setModal] = useState<null | "upload" | "grant" | "request" | "archive">(null);
  const publish = useAction();

  if (ds.loading && !ds.data) return <Loading />;
  if (ds.error) return <ErrorBox error={ds.error} onRetry={ds.reload} />;
  if (!ds.data || !me) return null;
  const d = ds.data;
  const isOwner = d.is_owner && hasRole("owner");
  const canRequest = !d.is_owner && hasRole("partner", "owner") && d.status === "published";

  const doPublish = async () => {
    const res = await publish.run(() => api.post(`/datasets/${id}/publish`));
    if (res) {
      toast("Published. Partners can now find it and request fields.");
      ds.reload();
    }
  };

  const tabs: { value: Tab; label: string }[] = [
    { value: "fields", label: `Fields (${d.fields.length})` },
    ...(isOwner || d.my_grants.length ? [{ value: "data" as Tab, label: "Data" }] : []),
    ...(isOwner || hasRole("auditor") ? [{ value: "sharing" as Tab, label: "Sharing" }] : []),
    { value: "activity", label: "Activity" },
  ];

  return (
    <>
      <p className="crumbs">
        <Link to="/datasets">Datasets</Link>
      </p>
      <PageHeader
        title={d.title}
        intro={
          <>
            <StatusBadge status={d.status} /> {d.owner_org_name}
            {d.category && `, ${d.category.replace("_", " ")}`}
            {d.row_count !== null && `, ${d.row_count.toLocaleString()} rows`}
            {d.description && <span className="page-intro-desc">{d.description}</span>}
          </>
        }
        actions={
          <>
            {isOwner && d.status !== "archived" && (
              <button type="button" className="btn" onClick={() => setModal("upload")}>
                {d.status === "draft" ? "Upload CSV" : "Load more rows"}
              </button>
            )}
            {isOwner && d.status === "draft" && (
              <button type="button" className="btn btn-primary" disabled={publish.busy || d.fields.length === 0}
                      title={d.fields.length === 0 ? "Add fields first" : undefined} onClick={doPublish}>
                {publish.busy ? "Publishing…" : "Publish"}
              </button>
            )}
            {isOwner && d.status === "published" && (
              <button type="button" className="btn btn-primary" onClick={() => setModal("grant")}>
                Grant access
              </button>
            )}
            {canRequest && (
              <button type="button" className="btn btn-primary" onClick={() => setModal("request")}>
                Request access
              </button>
            )}
          </>
        }
      />
      <ErrorBox error={publish.error} />

      {d.my_grants.length > 0 && !isOwner && (
        <div className="notice notice-good">
          <p>
            Your organization can read {new Set(d.my_grants.map((g) => g.field_name)).size} fields for{" "}
            {[...new Set(d.my_grants.map((g) => g.purpose))].map((p) => p.replace(/_/g, " ")).join(", ")}.
          </p>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Dataset sections">
        {tabs.map((t) => (
          <button key={t.value} type="button" role="tab" aria-selected={tab === t.value}
                  className={tab === t.value ? "is-on" : ""} onClick={() => setTab(t.value)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "fields" && <FieldsTab d={d} isOwner={isOwner} onChange={ds.reload} />}
      {tab === "data" && <DataTab d={d} isOwner={isOwner} />}
      {tab === "sharing" && <SharingTab d={d} isOwner={isOwner} />}
      {tab === "activity" && <ActivityTab datasetId={d.dataset_id} />}

      {isOwner && d.status !== "archived" && (
        <p className="danger-zone">
          <button type="button" className="link-btn danger" onClick={() => setModal("archive")}>
            Archive this dataset
          </button>
        </p>
      )}

      <UploadModal open={modal === "upload"} d={d} onClose={() => setModal(null)} onDone={ds.reload} />
      <GrantModal open={modal === "grant"} d={d} onClose={() => setModal(null)} onDone={ds.reload} />
      <RequestModal open={modal === "request"} d={d} onClose={() => setModal(null)} />
      <ArchiveModal open={modal === "archive"} d={d} onClose={() => setModal(null)} onDone={ds.reload} />
    </>
  );
}

// ------------------------------------------------------------------ fields

function FieldsTab({ d, isOwner, onChange }: { d: DatasetDetail; isOwner: boolean; onChange: () => void }) {
  const toast = useToast();
  const { error, run } = useAction();
  const grantedPurposes = useMemo(() => {
    const m = new Map<string, string[]>();
    d.my_grants.forEach((g) => m.set(g.field_id, [...(m.get(g.field_id) ?? []), g.purpose]));
    return m;
  }, [d.my_grants]);
  const editable = isOwner && d.status !== "archived";

  const setSensitivity = async (f: Field, sensitivity: Sensitivity) => {
    if (await run(() => api.patch(`/datasets/${d.dataset_id}/fields/${f.field_id}`, { sensitivity }))) {
      toast(`${f.name} is now marked ${SENSITIVITY_LABELS[sensitivity].toLowerCase()}`);
      onChange();
    }
  };
  const remove = async (f: Field) => {
    if (await run(() => api.del(`/datasets/${d.dataset_id}/fields/${f.field_id}`))) {
      toast(`Removed ${f.name}`);
      onChange();
    }
  };

  if (d.fields.length === 0)
    return (
      <Empty title="No fields described yet.">
        {isOwner ? "Upload a CSV and we'll suggest each field's type and sensitivity." : null}
      </Empty>
    );

  return (
    <>
      <ErrorBox error={error} />
      <table className="table">
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Sensitivity</th>
            <th>Description</th>
            {!isOwner && <th>Your access</th>}
            {editable && d.status === "draft" && <th><span className="sr-only">Actions</span></th>}
          </tr>
        </thead>
        <tbody>
          {d.fields.map((f) => (
            <tr key={f.field_id}>
              <td data-label="Field"><code className="field-name">{f.name}</code></td>
              <td data-label="Type">{f.data_type}</td>
              <td data-label="Sensitivity">
                {editable ? (
                  <select aria-label={`Sensitivity of ${f.name}`} value={f.sensitivity}
                          onChange={(e) => setSensitivity(f, e.target.value as Sensitivity)}>
                    {SENSITIVITIES.map((s) => <option key={s} value={s}>{SENSITIVITY_LABELS[s]}</option>)}
                  </select>
                ) : (
                  <SensitivityBadge level={f.sensitivity} encrypted={f.is_encrypted} />
                )}
                {editable && f.is_encrypted && <span className="muted small"> encrypted</span>}
              </td>
              <td data-label="Description">{f.description ?? <span className="muted">—</span>}</td>
              {!isOwner && (
                <td data-label="Your access">
                  {grantedPurposes.get(f.field_id)?.map((p) => p.replace(/_/g, " ")).join(", ") ?? <span className="muted">Not granted</span>}
                </td>
              )}
              {editable && d.status === "draft" && (
                <td><button type="button" className="link-btn danger" onClick={() => remove(f)}>Remove</button></td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

// ------------------------------------------------------------------ data viewer

function Cell({ value }: { value: unknown }) {
  if (value === "[REDACTED]") return <Redacted kind="redacted" />;
  if (value === "[MASKED]") return <Redacted kind="masked" />;
  if (value === null || value === undefined) return <span className="muted">—</span>;
  return <>{String(value)}</>;
}

function DataTab({ d, isOwner }: { d: DatasetDetail; isOwner: boolean }) {
  const purposes = [...new Set(d.my_grants.map((g) => g.purpose))];
  const [purpose, setPurpose] = useState(purposes[0] ?? "");
  const [page, setPage] = useState(1);
  const data = useAsync(
    () =>
      d.status === "published" || isOwner
        ? api.get<DataPage>(`/datasets/${d.dataset_id}/data`, { purpose: isOwner ? undefined : purpose, page, page_size: 25 })
        : Promise.resolve(null),
    [d.dataset_id, purpose, page],
  );

  if (d.status === "draft") return <Empty title="Publish the dataset to load and view rows." />;

  return (
    <>
      <div className="toolbar">
        {!isOwner && (
          <label className="inline-label">
            Purpose
            <select value={purpose} onChange={(e) => { setPurpose(e.target.value); setPage(1); }}>
              {purposes.map((p) => <option key={p} value={p}>{p.replace(/_/g, " ")}</option>)}
            </select>
          </label>
        )}
        <p className="muted small">
          {isOwner
            ? "You see every field. Each page you open is recorded in the audit trail."
            : "Only fields granted for this purpose are shown. Each page you open is recorded in the audit trail."}
        </p>
      </div>
      <ErrorBox error={data.error} onRetry={data.reload} />
      {data.loading && !data.data ? (
        <Loading label="Checking consent and loading rows" />
      ) : data.data && data.data.rows.length === 0 ? (
        <Empty title="No rows loaded yet.">{isOwner && "Use “Load more rows” to upload a CSV."}</Empty>
      ) : (
        data.data && (
          <>
            {!isOwner && data.data.masked_fields.length > 0 && (
              <p className="legend">
                <Redacted kind="redacted" /> personal data you have no consent for
                <Redacted kind="masked" /> other fields you have no consent for
              </p>
            )}
            <div className="table-scroll" tabIndex={0} aria-label="Dataset rows">
              <table className="table table-data" aria-busy={data.loading}>
                <thead>
                  <tr>
                    {data.data.columns.map((c) => (
                      <th key={c} className={data.data!.masked_fields.includes(c) ? "is-masked" : ""}>{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.data.rows.map((r) => (
                    <tr key={String(r.row_id)}>
                      {data.data!.columns.map((c) => <td key={c}><Cell value={r[c]} /></td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={data.data.page} pages={Math.max(1, Math.ceil(data.data.total / data.data.page_size))}
                        total={data.data.total} onPage={setPage} noun="rows" />
          </>
        )
      )}
    </>
  );
}

// ------------------------------------------------------------------ sharing & activity

function SharingTab({ d, isOwner }: { d: DatasetDetail; isOwner: boolean }) {
  const toast = useToast();
  const grants = useAsync(() => api.get<Page<Consent>>("/consents", { dataset_id: d.dataset_id, status: "active", page_size: 100 }), [d.dataset_id]);
  const requests = useAsync(() => api.get<Page<AccessRequest>>("/requests", { dataset_id: d.dataset_id, status: "pending" }), [d.dataset_id]);
  const { error, run } = useAction();

  const byGrantee = useMemo(() => {
    const m = new Map<string, Consent[]>();
    (grants.data?.items ?? []).forEach((g) => {
      const k = `${g.grantee_org_name}|${g.purpose}`;
      m.set(k, [...(m.get(k) ?? []), g]);
    });
    return [...m.entries()];
  }, [grants.data]);

  const revokeAll = async (list: Consent[]) => {
    const ok = await run(() =>
      api.post<{ revoked: number }>("/consents/revoke", {
        grant_ids: list.map((g) => g.grant_id),
        reason: "Revoked from dataset page",
      }),
    );
    if (ok) {
      toast(`Revoked ${list.length} field grants. ${list[0].grantee_org_name}'s next read is already blocked.`);
      grants.reload();
    }
  };

  return (
    <>
      <ErrorBox error={error ?? grants.error} />
      <h2 className="section-title">Who can read this dataset</h2>
      {grants.loading && !grants.data ? <Loading /> : byGrantee.length === 0 ? (
        <Empty title="Nobody has access yet." />
      ) : (
        <ul className="grant-groups">
          {byGrantee.map(([key, list]) => (
            <li key={key}>
              <div>
                <p><strong>{list[0].grantee_org_name}</strong> for {list[0].purpose.replace(/_/g, " ")}</p>
                <p className="muted small">
                  {list.map((g) => g.field_name).join(", ")}. Expires {fmtDate(list[0].expires_at)} ({relativeDays(list[0].expires_at)}).
                </p>
              </div>
              {isOwner && (
                <button type="button" className="btn btn-danger btn-small" onClick={() => revokeAll(list)}>
                  Revoke all {list.length}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <h2 className="section-title">Pending requests</h2>
      {requests.data && requests.data.items.length === 0 ? (
        <Empty title="No pending requests." />
      ) : (
        <ul className="plain-list">
          {requests.data?.items.map((r) => (
            <li key={r.request_id}>
              <strong>{r.grantee_org_name}</strong> asks for {r.fields.length} fields for {r.purpose.replace(/_/g, " ")}.{" "}
              <Link to={`/requests?direction=incoming&status=pending`}>Review</Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function ActivityTab({ datasetId }: { datasetId: string }) {
  const [page, setPage] = useState(1);
  const log = useAsync(() => api.get<Page<AuditEntry>>("/audit", { dataset_id: datasetId, page, page_size: 20 }), [datasetId, page]);
  if (log.loading && !log.data) return <Loading />;
  if (log.error) return <ErrorBox error={log.error} onRetry={log.reload} />;
  if (!log.data || log.data.items.length === 0) return <Empty title="No recorded activity you can see." />;
  return (
    <>
      <table className="table">
        <thead><tr><th>When</th><th>What</th><th>Who</th><th className="num">Rows</th></tr></thead>
        <tbody>
          {log.data.items.map((e) => (
            <tr key={e.log_id}>
              <td data-label="When">{fmtDateTime(e.ts)}</td>
              <td data-label="What">{ACTION_LABELS[e.action] ?? e.action}</td>
              <td data-label="Who">{e.user_email ?? "System"}</td>
              <td data-label="Rows" className="num">{e.rows_affected.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination page={log.data.page} pages={log.data.pages} total={log.data.total} onPage={setPage} noun="events" />
    </>
  );
}

// ------------------------------------------------------------------ upload & PII review

interface ColumnChoice {
  include: boolean;
  name: string;
  data_type: DataType;
  sensitivity: Sensitivity;
  is_encrypted: boolean;
}

function UploadModal({ open, d, onClose, onDone }: { open: boolean; d: DatasetDetail; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<UploadPreview | null>(null);
  const [choices, setChoices] = useState<ColumnChoice[]>([]);
  const { busy, error, run, setError } = useAction();
  const describing = d.fields.length === 0;

  useEffect(() => {
    if (!open) {
      setFile(null);
      setPreview(null);
      setError(null);
    }
  }, [open, setError]);

  const scan = async (f: File) => {
    setFile(f);
    const form = new FormData();
    form.append("file", f);
    const p = await run(() => api.post<UploadPreview>(`/datasets/${d.dataset_id}/upload/preview`, form));
    if (p) {
      setPreview(p);
      setChoices(p.columns.map((c) => ({ include: true, name: c.name, data_type: c.inferred_type,
        sensitivity: c.suggested_sensitivity, is_encrypted: c.suggest_encryption })));
    }
  };

  const loadRows = async () => {
    const form = new FormData();
    form.append("file", file!);
    return api.post<{ rows_loaded: number; total_rows: number }>(`/datasets/${d.dataset_id}/rows`, form);
  };

  const confirm = async (andPublish: boolean) => {
    const res = await run(async () => {
      if (describing) {
        await api.post(`/datasets/${d.dataset_id}/fields/bulk`, {
          fields: choices.filter((c) => c.include).map((c) => ({ name: c.name, data_type: c.data_type, sensitivity: c.sensitivity, is_encrypted: c.is_encrypted })),
        });
      }
      if (andPublish) {
        if (d.status === "draft") await api.post(`/datasets/${d.dataset_id}/publish`);
        return loadRows();
      }
      return null;
    });
    if (res !== undefined) {
      toast(res ? `Loaded ${res.rows_loaded.toLocaleString()} rows (${res.total_rows.toLocaleString()} in total).` : "Fields saved as a draft.");
      onClose();
      onDone();
    }
  };

  const update = (i: number, patch: Partial<ColumnChoice>) => setChoices((cs) => cs.map((c, j) => (i === j ? { ...c, ...patch } : c)));

  return (
    <Modal title={describing ? "Describe fields from a CSV" : "Load rows from a CSV"} open={open} onClose={onClose} wide>
      {!preview ? (
        <>
          <p>
            {describing
              ? "Choose a CSV with a header row. We'll scan a sample for personal data and suggest each field's type and sensitivity for you to confirm. Nothing is shared yet."
              : "Columns are matched to the dataset's fields by name. Personal-data fields marked encrypted are encrypted as they're stored."}
          </p>
          <label className="file-drop">
            <input type="file" accept=".csv,text/csv" disabled={busy} onChange={(e) => e.target.files?.[0] && scan(e.target.files[0])} />
            <span>{busy ? "Scanning for personal data…" : file ? file.name : "Choose a CSV file (up to 5 MB)"}</span>
          </label>
          <ErrorBox error={error} />
        </>
      ) : (
        <>
          <p>
            {preview.row_count.toLocaleString()} rows, {preview.columns.length} columns.{" "}
            {preview.ner_available ? "Names and places were checked with a language model as well as patterns." : "Checked with pattern rules (the language model isn't installed)."}
          </p>
          {describing ? (
            <div className="table-scroll">
              <table className="table table-review">
                <thead>
                  <tr><th>Keep</th><th>Field</th><th>Type</th><th>Sensitivity</th><th>Encrypt</th><th>Why</th><th>Preview</th></tr>
                </thead>
                <tbody>
                  {preview.columns.map((c, i) => (
                    <tr key={c.name} className={choices[i]?.include ? "" : "is-excluded"}>
                      <td><input type="checkbox" aria-label={`Keep ${c.name}`} checked={choices[i]?.include} onChange={(e) => update(i, { include: e.target.checked })} /></td>
                      <td><code className="field-name">{c.name}</code>{c.original_name !== c.name && <span className="muted small"> from “{c.original_name}”</span>}</td>
                      <td>
                        <select aria-label={`Type of ${c.name}`} value={choices[i]?.data_type} onChange={(e) => update(i, { data_type: e.target.value as DataType })}>
                          {DATA_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                        </select>
                      </td>
                      <td>
                        <select aria-label={`Sensitivity of ${c.name}`} value={choices[i]?.sensitivity} className={`sens-select sens-${choices[i]?.sensitivity}`}
                                onChange={(e) => update(i, { sensitivity: e.target.value as Sensitivity })}>
                          {SENSITIVITIES.map((s) => <option key={s} value={s}>{SENSITIVITY_LABELS[s]}</option>)}
                        </select>
                        <span className="muted small"> {Math.round(c.confidence * 100)}% sure</span>
                      </td>
                      <td><input type="checkbox" aria-label={`Encrypt ${c.name}`} checked={choices[i]?.is_encrypted} onChange={(e) => update(i, { is_encrypted: e.target.checked })} /></td>
                      <td className="small">{c.reasons.join("; ")}</td>
                      <td className="small preview-cell">{c.masked_preview.slice(0, 3).map((v, k) => <div key={k}>{String(v)}</div>)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>Ready to load {preview.row_count.toLocaleString()} rows.</p>
          )}
          <ErrorBox error={error} />
          <div className="form-actions">
            <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
            {describing && d.status === "draft" && (
              <button type="button" className="btn" disabled={busy} onClick={() => confirm(false)}>Save fields as draft</button>
            )}
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => confirm(true)}>
              {busy ? "Working…" : d.status === "draft" ? "Save fields, publish and load rows" : "Load rows"}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------------ grant / request / archive

function FieldPicker({ fields, selected, onChange }: { fields: Field[]; selected: Set<string>; onChange: (s: Set<string>) => void }) {
  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next);
  };
  return (
    <fieldset className="field-picker">
      <legend>Fields</legend>
      <div className="field-picker-actions">
        <button type="button" className="link-btn" onClick={() => onChange(new Set(fields.map((f) => f.field_id)))}>Select all</button>
        <button type="button" className="link-btn" onClick={() => onChange(new Set())}>Clear</button>
      </div>
      {fields.map((f) => (
        <label key={f.field_id} className="check-row">
          <input type="checkbox" checked={selected.has(f.field_id)} onChange={() => toggle(f.field_id)} />
          <code className="field-name">{f.name}</code>
          <SensitivityBadge level={f.sensitivity} encrypted={f.is_encrypted} />
        </label>
      ))}
    </fieldset>
  );
}

function validatePurposeAndDate(purpose: string, expires: string, fields: Set<string>) {
  const e: Record<string, string> = {};
  if (fields.size === 0) e.fields = "Choose at least one field";
  if (purpose.trim().length < 3) e.purpose = "Describe the purpose in a few words";
  if (!expires || new Date(endOfDayIso(expires)) <= new Date()) e.expires = "Choose a date in the future";
  return e;
}

function GrantModal({ open, d, onClose, onDone }: { open: boolean; d: DatasetDetail; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const orgs = useAsync(() => (open ? api.get<Page<Organization>>("/organizations", { page_size: 100 }) : Promise.resolve(null)), [open]);
  const [grantee, setGrantee] = useState("");
  const [fields, setFields] = useState<Set<string>>(new Set());
  const [purpose, setPurpose] = useState("");
  const [expires, setExpires] = useState(dateInput(90));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const next = validatePurposeAndDate(purpose, expires, fields);
    if (!grantee) next.grantee = "Choose the organization to share with";
    setErrors(next);
    if (Object.keys(next).length) return;
    const res = await run(() => api.post<Consent[]>("/consents", {
      dataset_id: d.dataset_id, grantee_org_id: grantee, field_ids: [...fields], purpose: purpose.trim().replace(/\s+/g, "_").toLowerCase(), expires_at: endOfDayIso(expires),
    }));
    if (res) {
      toast(`Granted ${res.length} fields to ${res[0].grantee_org_name}.`);
      onClose();
      onDone();
    }
  };

  return (
    <Modal title="Grant access" open={open} onClose={onClose}>
      <form onSubmit={submit} noValidate>
        <FormField label="Share with" error={errors.grantee}>
          {(p) => (
            <select {...p} value={grantee} onChange={(e) => setGrantee(e.target.value)}>
              <option value="">Choose an organization</option>
              {(orgs.data?.items ?? []).filter((o) => o.org_id !== d.owner_org_id).map((o) => <option key={o.org_id} value={o.org_id}>{o.name}</option>)}
            </select>
          )}
        </FormField>
        <FieldPicker fields={d.fields} selected={fields} onChange={setFields} />
        {errors.fields && <p className="field-error">{errors.fields}</p>}
        <FormField label="Purpose" error={errors.purpose} hint="The partner must state this purpose every time they read the data.">
          {(p) => <input {...p} value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="impact evaluation" />}
        </FormField>
        <FormField label="Access ends on" error={errors.expires}>
          {(p) => <input {...p} type="date" min={dateInput(1)} value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </FormField>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Granting…" : `Grant ${fields.size || ""} fields`}</button>
        </div>
      </form>
    </Modal>
  );
}

function RequestModal({ open, d, onClose }: { open: boolean; d: DatasetDetail; onClose: () => void }) {
  const toast = useToast();
  const [fields, setFields] = useState<Set<string>>(new Set());
  const [purpose, setPurpose] = useState("");
  const [expires, setExpires] = useState(dateInput(60));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const next = validatePurposeAndDate(purpose, expires, fields);
    setErrors(next);
    if (Object.keys(next).length) return;
    const res = await run(() => api.post<AccessRequest>("/requests", {
      dataset_id: d.dataset_id, field_ids: [...fields], purpose: purpose.trim().replace(/\s+/g, "_").toLowerCase(), expires_at: endOfDayIso(expires),
    }));
    if (res) {
      toast(`Request sent to ${res.owner_org_name}.`);
      onClose();
    }
  };

  return (
    <Modal title="Request access" open={open} onClose={onClose}>
      <form onSubmit={submit} noValidate>
        <p className="muted">{d.owner_org_name} decides which fields to share and for how long.</p>
        <FieldPicker fields={d.fields} selected={fields} onChange={setFields} />
        {errors.fields && <p className="field-error">{errors.fields}</p>}
        <FormField label="Purpose" error={errors.purpose} hint="Be specific: owners approve purposes, not people.">
          {(p) => <input {...p} value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="malnutrition surveillance" />}
        </FormField>
        <FormField label="Needed until" error={errors.expires}>
          {(p) => <input {...p} type="date" min={dateInput(1)} value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </FormField>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Sending…" : "Send request"}</button>
        </div>
      </form>
    </Modal>
  );
}

function ArchiveModal({ open, d, onClose, onDone }: { open: boolean; d: DatasetDetail; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const { busy, error, run } = useAction();
  const archive = async () => {
    if (await run(() => api.patch(`/datasets/${d.dataset_id}`, { status: "archived" }))) {
      toast("Dataset archived.");
      onClose();
      onDone();
    }
  };
  return (
    <Modal title="Archive this dataset?" open={open} onClose={onClose}>
      <p>Archived datasets leave the catalogue and can't be changed. Its audit history is kept. Existing grants stay until you revoke them or they expire.</p>
      <ErrorBox error={error} />
      <div className="form-actions">
        <button type="button" className="btn btn-quiet" onClick={onClose}>Keep it</button>
        <button type="button" className="btn btn-danger" disabled={busy} onClick={archive}>Archive dataset</button>
      </div>
    </Modal>
  );
}
