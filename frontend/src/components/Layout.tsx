import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import type { Role } from "../api";
import { useAuth } from "../auth";
import { ROLE_LABELS } from "../format";

export const NAV: { to: string; label: string; roles: Role[] }[] = [
  { to: "/", label: "Overview", roles: ["owner", "partner", "auditor", "admin"] },
  { to: "/datasets", label: "Datasets", roles: ["owner", "partner", "auditor"] },
  { to: "/consents", label: "Consents", roles: ["owner", "partner", "auditor"] },
  { to: "/requests", label: "Access requests", roles: ["owner", "partner", "auditor"] },
  { to: "/alerts", label: "Alerts", roles: ["owner", "auditor", "admin"] },
  { to: "/audit", label: "Audit trail", roles: ["owner", "partner", "auditor", "admin"] },
  { to: "/admin", label: "Users & organizations", roles: ["admin"] },
];

export default function Layout() {
  const { me, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setMenuOpen(false), [location.pathname]);
  if (!me) return null;
  const role = me.user.role;

  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className={`sidebar${menuOpen ? " is-open" : ""}`}>
        <div className="brand-row">
          <NavLink to="/" className="brand">
            <span className="brand-mark" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
            ConsentLedger
          </NavLink>
          <button
            type="button"
            className="menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="main-nav"
            onClick={() => setMenuOpen((o) => !o)}
          >
            {menuOpen ? "Close" : "Menu"}
          </button>
        </div>
        <nav id="main-nav" className="nav" aria-label="Main">
          {NAV.filter((n) => n.roles.includes(role)).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="whoami">
          <p className="whoami-name">{me.user.full_name ?? me.user.email}</p>
          <p className="whoami-meta">
            {ROLE_LABELS[role]}, {me.organization.name}
          </p>
          <button type="button" className="btn btn-quiet btn-small" onClick={() => logout()}>
            Sign out
          </button>
        </div>
      </aside>
      <main id="main" className="main" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}
