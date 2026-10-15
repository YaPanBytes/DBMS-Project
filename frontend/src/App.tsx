import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import type { Role } from "./api";
import { useAuth } from "./auth";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import AdminPage from "./pages/AdminPage";
import AlertsPage from "./pages/AlertsPage";
import AuditPage from "./pages/AuditPage";
import ConsentsPage from "./pages/ConsentsPage";
import DashboardPage from "./pages/DashboardPage";
import DatasetPage from "./pages/DatasetPage";
import DatasetsPage from "./pages/DatasetsPage";
import LoginPage from "./pages/LoginPage";
import NotFoundPage from "./pages/NotFoundPage";
import RequestsPage from "./pages/RequestsPage";

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Loading label="Checking your session" />;
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

/** Route guard: only the listed roles may open the page. */
function RequireRole({ roles, children }: { roles: Role[]; children: ReactNode }) {
  const { hasRole } = useAuth();
  if (!hasRole(...roles)) {
    return (
      <div className="notice notice-error" role="alert">
        <p>Your role doesn't have access to this page.</p>
      </div>
    );
  }
  return <>{children}</>;
}

const DATA_ROLES: Role[] = ["owner", "partner", "auditor"];

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="datasets" element={<RequireRole roles={DATA_ROLES}><DatasetsPage /></RequireRole>} />
        <Route path="datasets/:id" element={<RequireRole roles={DATA_ROLES}><DatasetPage /></RequireRole>} />
        <Route path="consents" element={<RequireRole roles={DATA_ROLES}><ConsentsPage /></RequireRole>} />
        <Route path="requests" element={<RequireRole roles={DATA_ROLES}><RequestsPage /></RequireRole>} />
        <Route path="alerts" element={<RequireRole roles={["owner", "auditor", "admin"]}><AlertsPage /></RequireRole>} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="admin" element={<RequireRole roles={["admin"]}><AdminPage /></RequireRole>} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
