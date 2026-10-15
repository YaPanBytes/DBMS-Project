import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Dataset, type Page } from "../api";
import { useAuth } from "../auth";
import {
  Empty,
  ErrorBox,
  FormField,
  Loading,
  Modal,
  PageHeader,
  Pagination,
  SearchBox,
  Segmented,
  StatusBadge,
  useAction,
  useToast,
} from "../components/ui";
import { fmtDate } from "../format";
import { useAsync, useDebounced } from "../hooks";

type Scope = "all" | "mine" | "shared";

export default function DatasetsPage() {
  const { hasRole } = useAuth();
  const [params, setParams] = useSearchParams();
  const scope = (params.get("scope") as Scope) ?? "all";
  const status = params.get("status") ?? "";
  const category = params.get("category") ?? "";
  const page = Number(params.get("page") ?? 1);
  const [q, setQ] = useState(params.get("q") ?? "");
  const query = useDebounced(q);
  const [creating, setCreating] = useState(false);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next, { replace: true });
  };

  const categories = useAsync(() => api.get<string[]>("/datasets/categories"), []);
  const list = useAsync(
    () => api.get<Page<Dataset>>("/datasets", { scope, status, category, q: query, page, page_size: 15 }),
    [scope, status, category, query, page],
  );

  const scopes: { value: Scope; label: string }[] = hasRole("owner")
    ? [
        { value: "all", label: "All" },
        { value: "mine", label: "Ours" },
        { value: "shared", label: "Shared with us" },
      ]
    : hasRole("partner")
      ? [
          { value: "all", label: "Catalogue" },
          { value: "shared", label: "Shared with us" },
        ]
      : [{ value: "all", label: "All" }];

  return (
    <>
      <PageHeader
        title="Datasets"
        intro={hasRole("partner") ? "Browse published datasets and request the fields you need." : undefined}
        actions={
          hasRole("owner") && (
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              Register a dataset
            </button>
          )
        }
      />

      <div className="toolbar">
        <SearchBox value={q} onChange={(v) => { setQ(v); set("page", ""); }} placeholder="Search datasets" />
        {scopes.length > 1 && <Segmented label="Show" value={scope} options={scopes} onChange={(v) => set("scope", v === "all" ? "" : v)} />}
        <select aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Any status</option>
          <option value="published">Published</option>
          <option value="draft">Draft</option>
          <option value="archived">Archived</option>
        </select>
        <select aria-label="Category" value={category} onChange={(e) => set("category", e.target.value)}>
          <option value="">Any category</option>
          {(categories.data ?? []).map((c) => (
            <option key={c} value={c}>
              {c.replace("_", " ")}
            </option>
          ))}
        </select>
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data ? (
        <Loading />
      ) : list.data && list.data.items.length === 0 ? (
        <Empty title={query || status || category ? "No datasets match these filters." : "No datasets yet."}>
          {hasRole("owner") && !query && "Register your first dataset to start sharing it field by field."}
        </Empty>
      ) : (
        list.data && (
          <>
            <table className="table" aria-busy={list.loading}>
              <thead>
                <tr>
                  <th>Dataset</th>
                  <th>Owner</th>
                  <th>Status</th>
                  <th className="num">Fields</th>
                  <th>Your access</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((d) => (
                  <tr key={d.dataset_id}>
                    <td data-label="Dataset">
                      <Link to={`/datasets/${d.dataset_id}`} className="row-title">
                        {d.title}
                      </Link>
                      {d.category && <span className="muted small"> {d.category.replace("_", " ")}</span>}
                    </td>
                    <td data-label="Owner">{d.owner_org_name}</td>
                    <td data-label="Status"><StatusBadge status={d.status} /></td>
                    <td data-label="Fields" className="num">{d.field_count}</td>
                    <td data-label="Your access">
                      {d.is_owner ? "Owner" : d.has_access ? <span className="good-text">Granted</span> : <span className="muted">None</span>}
                    </td>
                    <td data-label="Updated">{fmtDate(d.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total}
                        onPage={(p) => set("page", String(p))} noun="datasets" />
          </>
        )
      )}

      <CreateDatasetModal open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function CreateDatasetModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    if (title.trim().length < 3) next.title = "Give the dataset a title of at least 3 characters";
    setErrors(next);
    if (Object.keys(next).length) return;
    const ds = await run(() =>
      api.post<Dataset>("/datasets", { title: title.trim(), description: description || null, category: category || null }),
    );
    if (ds) {
      toast("Dataset registered. Next, upload a CSV to describe its fields.");
      onClose();
      navigate(`/datasets/${ds.dataset_id}`);
    }
  };

  return (
    <Modal title="Register a dataset" open={open} onClose={onClose}>
      <form onSubmit={submit} noValidate>
        <FormField label="Title" error={errors.title}>
          {(p) => <input {...p} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} />}
        </FormField>
        <FormField label="Description" hint="What the records are and how they were collected.">
          {(p) => <textarea {...p} rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />}
        </FormField>
        <FormField label="Category" hint="For example health, education or social_welfare.">
          {(p) => <input {...p} value={category} onChange={(e) => setCategory(e.target.value)} maxLength={100} />}
        </FormField>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Registering…" : "Register dataset"}</button>
        </div>
      </form>
    </Modal>
  );
}
