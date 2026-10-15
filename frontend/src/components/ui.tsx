import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ApiError, type Sensitivity } from "../api";
import { SENSITIVITY_LABELS } from "../format";

// ------------------------------------------------------------------ layout bits

export function PageHeader({ title, intro, actions }: { title: string; intro?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {intro && <p className="page-intro">{intro}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: ApiError | Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="notice notice-error" role="alert">
      <p>{error.message}</p>
      {onRetry && (
        <button type="button" className="btn btn-quiet" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

const singular = (noun: string) => (noun.endsWith("ies") ? `${noun.slice(0, -3)}y` : noun.replace(/s$/, ""));

export function Pagination({
  page,
  pages,
  total,
  onPage,
  noun = "items",
}: {
  page: number;
  pages: number;
  total: number;
  onPage: (p: number) => void;
  noun?: string;
}) {
  if (total === 0) return null;
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="muted">
        {total.toLocaleString()} {total === 1 ? singular(noun) : noun}
        {pages > 1 && `, page ${page} of ${pages}`}
      </span>
      {pages > 1 && (
        <span className="pagination-buttons">
          <button type="button" className="btn btn-quiet" disabled={page <= 1} onClick={() => onPage(page - 1)}>
            Previous
          </button>
          <button
            type="button"
            className="btn btn-quiet"
            disabled={page >= pages}
            onClick={() => onPage(page + 1)}
          >
            Next
          </button>
        </span>
      )}
    </nav>
  );
}

// ------------------------------------------------------------------ badges

const STATUS_TONE: Record<string, string> = {
  active: "good",
  published: "good",
  approved: "good",
  resolved: "good",
  pending: "warn",
  open: "danger",
  investigating: "warn",
  draft: "neutral",
  expired: "neutral",
  archived: "neutral",
  revoked: "danger",
  denied: "danger",
  false_positive: "neutral",
};

export function StatusBadge({ status }: { status: string }) {
  const label = status.replace("_", " ");
  return <span className={`badge badge-${STATUS_TONE[status] ?? "neutral"}`}>{label}</span>;
}

export function SensitivityBadge({ level, encrypted }: { level: Sensitivity | null; encrypted?: boolean }) {
  if (!level) return null;
  return (
    <span className={`sens sens-${level}`} title={encrypted ? "Encrypted at rest" : undefined}>
      {SENSITIVITY_LABELS[level]}
      {encrypted && <span className="sens-lock" aria-label="encrypted"> ⦿</span>}
    </span>
  );
}

/** A masked value drawn as a redaction bar (width hints at nothing real). */
export function Redacted({ kind }: { kind: "redacted" | "masked" }) {
  return (
    <span className={`redaction redaction-${kind}`} title={kind === "redacted" ? "Personal data: not consented" : "Not consented"}>
      <span className="sr-only">{kind === "redacted" ? "Redacted" : "Masked"}</span>
    </span>
  );
}

export function HashChip({ hash, linked }: { hash: string; linked?: boolean }) {
  return (
    <code className={`hash${linked ? " hash-linked" : ""}`} title={hash}>
      {hash.slice(0, 10)}
    </code>
  );
}

// ------------------------------------------------------------------ forms

export function FormField({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string;
  children: (props: { id: string; "aria-invalid": boolean; "aria-describedby"?: string }) => ReactNode;
}) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : "", error ? `${id}-err` : ""].filter(Boolean).join(" ");
  return (
    <div className={`form-field${error ? " has-error" : ""}`}>
      <label htmlFor={id}>{label}</label>
      {children({ id, "aria-invalid": !!error, "aria-describedby": describedBy || undefined })}
      {hint && !error && (
        <p className="hint" id={`${id}-hint`}>
          {hint}
        </p>
      )}
      {error && (
        <p className="field-error" id={`${id}-err`}>
          {error}
        </p>
      )}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          className={value === o.value ? "is-on" : ""}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input
      type="search"
      className="search"
      value={value}
      placeholder={placeholder}
      aria-label={placeholder}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

// ------------------------------------------------------------------ modal

export function Modal({
  title,
  open,
  onClose,
  children,
  wide,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={`modal${wide ? " modal-wide" : ""}`}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      aria-labelledby="modal-title"
    >
      {open && (
        <div className="modal-body">
          <div className="modal-head">
            <h2 id="modal-title">{title}</h2>
            <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
              ×
            </button>
          </div>
          {children}
        </div>
      )}
    </dialog>
  );
}

// ------------------------------------------------------------------ toasts

interface Toast {
  id: number;
  text: string;
  tone: "good" | "danger";
}
const ToastContext = createContext<(text: string, tone?: "good" | "danger") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: "good" | "danger" = "good") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

/** Run an async action with a busy flag and an error message. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "error", String(e)));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}
