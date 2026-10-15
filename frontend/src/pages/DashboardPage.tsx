import { Link } from "react-router-dom";
import { api, type Dashboard } from "../api";
import { useAuth } from "../auth";
import { Empty, ErrorBox, HashChip, Loading, PageHeader } from "../components/ui";
import { ACTION_LABELS, fmtDateTime } from "../format";
import { useAsync } from "../hooks";

function Figure({ value, label, to }: { value: number; label: string; to?: string }) {
  const body = (
    <>
      <span className="figure-value">{value.toLocaleString()}</span>
      <span className="figure-label">{label}</span>
    </>
  );
  return to ? (
    <Link className="figure" to={to}>
      {body}
    </Link>
  ) : (
    <div className="figure">{body}</div>
  );
}

export default function DashboardPage() {
  const { me } = useAuth();
  const { data, error, loading, reload } = useAsync(() => api.get<Dashboard>("/dashboard"), []);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data || !me) return null;
  const role = data.role;
  const first = (me.user.full_name ?? me.user.email).split(" ")[0];

  return (
    <>
      <PageHeader
        title={`Hello, ${first}`}
        intro={
          role === "owner"
            ? `Here's who can see ${me.organization.name}'s data right now, and what needs a decision.`
            : role === "partner"
              ? "Here's what you've been given access to and the requests you're waiting on."
              : role === "auditor"
                ? "Every access is recorded in a tamper-evident chain. Here's the latest."
                : "Manage organizations and accounts, and keep an eye on alerts."
        }
      />

      <section className="figures" aria-label="Summary">
        {role === "owner" && (
          <>
            <Figure value={data.datasets_owned} label="datasets you own" to="/datasets?scope=mine" />
            <Figure value={data.consents_given_active} label="active field grants you've given" to="/consents?direction=given" />
            <Figure value={data.requests_incoming_pending} label="requests waiting for you" to="/requests?direction=incoming&status=pending" />
            <Figure value={data.alerts_open} label="open alerts" to="/alerts" />
          </>
        )}
        {role === "partner" && (
          <>
            <Figure value={data.consents_received_active} label="fields you can read" to="/consents?direction=received" />
            <Figure value={data.requests_outgoing_pending} label="requests awaiting a decision" to="/requests?direction=outgoing&status=pending" />
            <Figure value={data.datasets_visible} label="datasets in the catalogue" to="/datasets" />
          </>
        )}
        {(role === "auditor" || role === "admin") && (
          <>
            <Figure value={data.audit_events_24h} label="audit events in the last 24 hours" to="/audit" />
            <Figure value={data.alerts_open} label="open alerts" to="/alerts" />
            {role === "auditor" && <Figure value={data.datasets_visible} label="datasets registered" to="/datasets" />}
          </>
        )}
      </section>

      <div className="two-col">
        {role !== "partner" && (
          <section className="panel">
            <div className="panel-head">
              <h2>Unusual access</h2>
              <Link to="/alerts">All alerts</Link>
            </div>
            {data.recent_alerts.length === 0 ? (
              <Empty title="No open alerts.">The detector hasn't flagged anything that needs review.</Empty>
            ) : (
              <ul className="alert-list">
                {data.recent_alerts.map((a) => (
                  <li key={a.alert_id}>
                    <span className="score" style={{ ["--score" as string]: a.score }} aria-label={`score ${a.score.toFixed(2)}`}>
                      {a.score.toFixed(2)}
                    </span>
                    <div>
                      <p className="alert-who">
                        {a.user_email} <span className="muted">on {a.dataset_title ?? "a dataset"}</span>
                      </p>
                      <p className="alert-reason">{a.reason}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        <section className="panel">
          <div className="panel-head">
            <h2>Recent activity</h2>
            <Link to="/audit">Audit trail</Link>
          </div>
          {data.recent_audit.length === 0 ? (
            <Empty title="Nothing recorded yet." />
          ) : (
            <ol className="chain">
              {data.recent_audit.map((e) => (
                <li key={e.log_id}>
                  <div className="chain-main">
                    <p>
                      <strong>{ACTION_LABELS[e.action] ?? e.action}</strong>
                      {e.dataset_title && <> on {e.dataset_title}</>}
                    </p>
                    <p className="muted small">
                      {e.user_email ?? "System"}, {fmtDateTime(e.ts)}
                      {e.action === "select" && `, ${e.rows_affected.toLocaleString()} ${e.rows_affected === 1 ? "row" : "rows"}`}
                    </p>
                  </div>
                  <HashChip hash={e.row_hash} linked />
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </>
  );
}
