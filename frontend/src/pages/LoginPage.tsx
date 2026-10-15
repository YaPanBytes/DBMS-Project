import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, FormField, useAction } from "../components/ui";
import { useAsync } from "../hooks";

const GOOGLE_ERRORS: Record<string, string> = {
  google_cancelled: "Google sign-in was cancelled. Try again when you're ready.",
  google_failed: "Google couldn't confirm your account. Try again, or use your email and password.",
  not_registered: "That Google account isn't registered here. Ask your administrator to add your email.",
};

const DEMO_ACCOUNTS = [
  { email: "owner@hope.org", who: "Data owner at Hope Foundation" },
  { email: "funder@globalfund.org", who: "Partner at Global Fund" },
  { email: "auditor@transparency.org", who: "Auditor at Transparency Watch" },
  { email: "admin@consentledger.org", who: "Platform admin" },
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function LoginPage() {
  const { me, login } = useAuth();
  const location = useLocation();
  const [params] = useSearchParams();
  const config = useAsync(
    () => api.get<{ google_enabled: boolean; password_login_enabled: boolean }>("/auth/config"),
    [],
  );
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState<{ email?: string; password?: string }>({});
  const { busy, error, run } = useAction();

  if (me) {
    const from = (location.state as { from?: string } | null)?.from ?? "/";
    return <Navigate to={from} replace />;
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const next: typeof errors = {};
    if (!EMAIL_RE.test(email.trim())) next.email = "Enter an email address like name@example.org";
    if (!password) next.password = "Enter your password";
    setErrors(next);
    if (Object.keys(next).length) return;
    await run(() => login(email.trim(), password));
  };

  const googleError = GOOGLE_ERRORS[params.get("error") ?? ""];
  const passwordEnabled = config.data?.password_login_enabled ?? true;

  return (
    <div className="login">
      <section className="login-story" aria-hidden="true">
        <p className="login-mark">ConsentLedger</p>
        <div className="login-doc">
          <p>
            Beneficiary <span className="redaction redaction-redacted" /> in district Nagpur,
            household of 5, monthly income ₹2,387. Contact{" "}
            <span className="redaction redaction-redacted" /> before the next visit. Address{" "}
            <span className="redaction redaction-masked" />.
          </p>
        </div>
        <p className="login-tag">
          Share program data field by field, for a stated purpose, until a date you choose. Revoke it and
          the next query is already refused.
        </p>
      </section>

      <section className="login-panel">
        <h1>Sign in</h1>
        {googleError && <div className="notice notice-error" role="alert"><p>{googleError}</p></div>}

        {config.data?.google_enabled && (
          <>
            <a className="btn btn-google" href="/api/auth/google/login">
              <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
                <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/>
                <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>
                <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/>
                <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/>
              </svg>
              Sign in with Google
            </a>
            {passwordEnabled && <p className="divider-text">or use your email</p>}
          </>
        )}

        {passwordEnabled && (
          <form onSubmit={submit} noValidate>
            <FormField label="Email" error={errors.email}>
              {(p) => (
                <input {...p} type="email" autoComplete="username" value={email}
                       onChange={(e) => setEmail(e.target.value)} />
              )}
            </FormField>
            <FormField label="Password" error={errors.password}>
              {(p) => (
                <input {...p} type="password" autoComplete="current-password" value={password}
                       onChange={(e) => setPassword(e.target.value)} />
              )}
            </FormField>
            <ErrorBox error={error} />
            <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}

        {passwordEnabled && (
          <details className="demo-accounts">
            <summary>Demo accounts (password demo123)</summary>
            <ul>
              {DEMO_ACCOUNTS.map((a) => (
                <li key={a.email}>
                  <button type="button" className="link-btn" onClick={() => { setEmail(a.email); setPassword("demo123"); }}>
                    {a.email}
                  </button>
                  <span className="muted"> {a.who}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>
    </div>
  );
}
