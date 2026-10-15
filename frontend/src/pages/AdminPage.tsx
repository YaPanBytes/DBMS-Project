import { useState, type FormEvent } from "react";
import { api, ApiError, type Organization, type Page, type Role, type User } from "../api";
import { useAuth } from "../auth";
import { Empty, ErrorBox, FormField, Loading, Modal, PageHeader, Pagination, SearchBox, Segmented, useAction, useToast } from "../components/ui";
import { fmtDate, ROLE_LABELS } from "../format";
import { useAsync, useDebounced } from "../hooks";

const ROLES: Role[] = ["owner", "partner", "auditor", "admin"];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function AdminPage() {
  const [tab, setTab] = useState<"users" | "orgs">("users");
  return (
    <>
      <PageHeader title="Users & organizations" intro="Accounts are created here. People sign in with Google using the email you register." />
      <Segmented label="Section" value={tab} onChange={setTab} options={[{ value: "users", label: "Users" }, { value: "orgs", label: "Organizations" }]} />
      <div className="spacer" />
      {tab === "users" ? <UsersSection /> : <OrgsSection />}
    </>
  );
}

function UsersSection() {
  const { me } = useAuth();
  const toast = useToast();
  const [q, setQ] = useState("");
  const query = useDebounced(q);
  const [role, setRole] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const users = useAsync(() => api.get<Page<User>>("/users", { q: query, role, page, page_size: 20 }), [query, role, page]);
  const action = useAction();

  const update = async (u: User, patch: Partial<Pick<User, "role" | "is_active">>) => {
    if (await action.run(() => api.patch(`/users/${u.user_id}`, patch))) {
      toast(patch.is_active === false ? `Deactivated ${u.email}` : patch.is_active ? `Reactivated ${u.email}` : `Updated ${u.email}`);
      users.reload();
    }
  };

  return (
    <>
      <div className="toolbar">
        <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search name or email" />
        <select aria-label="Role" value={role} onChange={(e) => { setRole(e.target.value); setPage(1); }}>
          <option value="">Any role</option>
          {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
        </select>
        <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>Add user</button>
      </div>
      <ErrorBox error={users.error ?? action.error} onRetry={users.reload} />
      {users.loading && !users.data ? <Loading /> : users.data && users.data.items.length === 0 ? <Empty title="No users match." /> : users.data && (
        <>
          <table className="table">
            <thead><tr><th>User</th><th>Organization</th><th>Role</th><th>Sign-in</th><th>Last sign-in</th><th>Status</th></tr></thead>
            <tbody>
              {users.data.items.map((u) => (
                <tr key={u.user_id} className={u.is_active ? "" : "is-excluded"}>
                  <td data-label="User">{u.full_name ?? "—"}<div className="muted small">{u.email}</div></td>
                  <td data-label="Organization">{u.org_name}</td>
                  <td data-label="Role">
                    <select aria-label={`Role of ${u.email}`} value={u.role} disabled={u.user_id === me?.user.user_id}
                            onChange={(e) => update(u, { role: e.target.value as Role })}>
                      {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
                    </select>
                  </td>
                  <td data-label="Sign-in" className="small">{[u.google_linked && "Google", u.has_password && "Password"].filter(Boolean).join(", ") || "Google (not yet linked)"}</td>
                  <td data-label="Last sign-in">{fmtDate(u.last_login)}</td>
                  <td data-label="Status">
                    {u.user_id !== me?.user.user_id && (
                      <button type="button" className="link-btn" onClick={() => update(u, { is_active: !u.is_active })}>
                        {u.is_active ? "Deactivate" : "Reactivate"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={users.data.page} pages={users.data.pages} total={users.data.total} onPage={setPage} noun="users" />
        </>
      )}
      {creating && <CreateUserModal onClose={() => setCreating(false)} onDone={() => { setCreating(false); users.reload(); }} />}
    </>
  );
}

function CreateUserModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const orgs = useAsync(() => api.get<Page<Organization>>("/organizations", { page_size: 100 }), []);
  const [form, setForm] = useState({ email: "", full_name: "", org_id: "", role: "partner" as Role, password: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    if (!EMAIL_RE.test(form.email.trim())) next.email = "Enter a valid email address";
    if (!form.org_id) next.org_id = "Choose an organization";
    if (form.password && form.password.length < 8) next.password = "Use at least 8 characters, or leave empty for Google-only sign-in";
    setErrors(next);
    if (Object.keys(next).length) return;
    const res = await run(() => api.post<User>("/users", { ...form, email: form.email.trim(), full_name: form.full_name || null, password: form.password || null }));
    if (res) {
      toast(`Added ${res.email}. They can sign in now.`);
      onDone();
    }
  };
  const fieldErrors = error instanceof ApiError ? error.fieldErrors() : {};

  return (
    <Modal title="Add user" open onClose={onClose}>
      <form onSubmit={submit} noValidate>
        <FormField label="Email" error={errors.email ?? fieldErrors.email} hint="Their Google account email, if they'll sign in with Google.">
          {(p) => <input {...p} type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />}
        </FormField>
        <FormField label="Full name">{(p) => <input {...p} value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />}</FormField>
        <FormField label="Organization" error={errors.org_id}>
          {(p) => (
            <select {...p} value={form.org_id} onChange={(e) => setForm({ ...form, org_id: e.target.value })}>
              <option value="">Choose an organization</option>
              {(orgs.data?.items ?? []).map((o) => <option key={o.org_id} value={o.org_id}>{o.name}</option>)}
            </select>
          )}
        </FormField>
        <FormField label="Role">
          {(p) => (
            <select {...p} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
            </select>
          )}
        </FormField>
        <FormField label="Password (optional)" error={errors.password ?? fieldErrors.password} hint="Leave empty for Google-only accounts.">
          {(p) => <input {...p} type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />}
        </FormField>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button type="button" className="btn btn-quiet" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>Add user</button>
        </div>
      </form>
    </Modal>
  );
}

function OrgsSection() {
  const toast = useToast();
  const [q, setQ] = useState("");
  const query = useDebounced(q);
  const [page, setPage] = useState(1);
  const orgs = useAsync(() => api.get<Page<Organization>>("/organizations", { q: query, page, page_size: 20 }), [query, page]);
  const [form, setForm] = useState({ name: "", type: "ngo", contact_email: "" });
  const [nameError, setNameError] = useState<string>();
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (form.name.trim().length < 2) return setNameError("Enter the organization's name");
    setNameError(undefined);
    const res = await run(() => api.post<Organization>("/organizations", { ...form, name: form.name.trim(), contact_email: form.contact_email || null }));
    if (res) {
      toast(`Added ${res.name}.`);
      setForm({ name: "", type: "ngo", contact_email: "" });
      orgs.reload();
    }
  };

  return (
    <div className="two-col two-col-wide-left">
      <section>
        <div className="toolbar"><SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search organizations" /></div>
        <ErrorBox error={orgs.error} onRetry={orgs.reload} />
        {orgs.loading && !orgs.data ? <Loading /> : orgs.data && (
          <>
            <table className="table">
              <thead><tr><th>Organization</th><th>Type</th><th>Contact</th></tr></thead>
              <tbody>{orgs.data.items.map((o) => (
                <tr key={o.org_id}><td data-label="Organization">{o.name}</td><td data-label="Type">{o.type}</td><td data-label="Contact">{o.contact_email ?? "—"}</td></tr>
              ))}</tbody>
            </table>
            <Pagination page={orgs.data.page} pages={orgs.data.pages} total={orgs.data.total} onPage={setPage} noun="organizations" />
          </>
        )}
      </section>
      <section className="panel">
        <h2>Add an organization</h2>
        <form onSubmit={submit} noValidate>
          <FormField label="Name" error={nameError}>{(p) => <input {...p} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />}</FormField>
          <FormField label="Type">
            {(p) => (
              <select {...p} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                <option value="ngo">NGO</option><option value="government">Government agency</option><option value="funder">Funder</option><option value="auditor">Auditor</option>
              </select>
            )}
          </FormField>
          <FormField label="Contact email (optional)">{(p) => <input {...p} type="email" value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} />}</FormField>
          <ErrorBox error={error} />
          <button type="submit" className="btn btn-primary" disabled={busy}>Add organization</button>
        </form>
      </section>
    </div>
  );
}
