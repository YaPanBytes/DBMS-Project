"""API tests: authentication, role-based access and consent enforcement,
exercised over HTTP against the seeded test database."""

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from backend.app import google_oauth
from backend.app.config import get_settings
from backend.app.main import create_app

PASSWORD = "demo123"


@pytest.fixture(scope="module")
def app(seeded):
    return create_app()


def client(app) -> TestClient:
    return TestClient(app)


def login(app, email: str) -> TestClient:
    c = client(app)
    r = c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = c.cookies.get("cl_csrf")
    return c


def future(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def dataset_id(c: TestClient, title: str) -> str:
    items = c.get("/api/datasets", params={"q": title}).json()["items"]
    return next(d["dataset_id"] for d in items if d["title"] == title)


# ============================================================================
# AUTH
# ============================================================================


class TestAuth:
    def test_login_sets_httponly_cookie(self, app):
        c = client(app)
        r = c.post("/api/auth/login", json={"email": "owner@hope.org", "password": PASSWORD})
        assert r.status_code == 200
        assert r.json()["user"]["role"] == "owner"
        cookie_header = " ".join(r.headers.get_list("set-cookie"))
        assert "cl_session=" in cookie_header and "HttpOnly" in cookie_header
        assert "access_token" not in r.json()  # the JWT never reaches page JavaScript

    @pytest.mark.parametrize(
        "email,password", [("owner@hope.org", "wrong"), ("nobody@x.org", "demo123")]
    )
    def test_bad_credentials_same_message(self, app, email, password):
        r = client(app).post("/api/auth/login", json={"email": email, "password": password})
        assert r.status_code == 401
        assert r.json()["error"] == {
            "code": "invalid_credentials",
            "message": "Incorrect email or password",
        }

    def test_me_requires_auth(self, app):
        r = client(app).get("/api/auth/me")
        assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    def test_bearer_token_flow(self, app):
        c = client(app)
        r = c.post(
            "/api/auth/token", data={"username": "auditor@transparency.org", "password": PASSWORD}
        )
        token = r.json()["access_token"]
        me = client(app).get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["auth_method"] == "bearer"
        assert "audit:read_all" in me.json()["permissions"]

    def test_logout_revokes_token_server_side(self, app):
        r = client(app).post(
            "/api/auth/token", data={"username": "owner@hope.org", "password": PASSWORD}
        )
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        c = client(app)
        assert c.post("/api/auth/logout", headers=h).status_code == 204
        assert c.get("/api/auth/me", headers=h).status_code == 401  # same token is now dead

    def test_csrf_required_for_cookie_writes(self, app):
        c = login(app, "owner@hope.org")
        del c.headers["X-CSRF-Token"]
        r = c.post("/api/datasets", json={"title": "No CSRF"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"

    def test_tampered_and_expired_tokens_rejected(self, app):
        s = get_settings()
        good = (
            client(app)
            .post("/api/auth/token", data={"username": "owner@hope.org", "password": PASSWORD})
            .json()["access_token"]
        )
        claims = jwt.decode(good, s.jwt_secret, algorithms=["HS256"])
        forged = jwt.encode({**claims, "role": "admin"}, "not-the-secret", algorithm="HS256")
        expired = jwt.encode(
            {**claims, "exp": int(time.time()) - 10}, s.jwt_secret, algorithm="HS256"
        )
        for token in (forged, expired, "garbage"):
            assert (
                client(app)
                .get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
                .status_code
                == 401
            )

    def test_role_comes_from_database_not_token(self, app):
        """Even a validly signed token claiming 'admin' gets the user's real role."""
        s = get_settings()
        good = (
            client(app)
            .post(
                "/api/auth/token", data={"username": "funder@globalfund.org", "password": PASSWORD}
            )
            .json()["access_token"]
        )
        claims = jwt.decode(good, s.jwt_secret, algorithms=["HS256"])
        lie = jwt.encode(
            {**claims, "role": "admin", "jti": str(uuid4())}, s.jwt_secret, algorithm="HS256"
        )
        r = client(app).post(
            "/api/organizations",
            json={"name": "Hack", "type": "ngo"},
            headers={"Authorization": f"Bearer {lie}"},
        )
        assert r.status_code == 403

    def test_google_sign_in(self, app, monkeypatch):
        s = get_settings()
        monkeypatch.setattr(s, "google_client_id", "test-client.apps.googleusercontent.com")
        claims = {
            "sub": "google-123",
            "email": "auditor@transparency.org",
            "email_verified": True,
            "name": "Robert Kim",
            "iss": "https://accounts.google.com",
        }
        monkeypatch.setattr(google_oauth, "verify_id_token", lambda token, nonce=None: claims)
        c = client(app)
        r = c.post("/api/auth/google", json={"credential": "x" * 40})
        assert r.status_code == 200 and r.json()["user"]["google_linked"] is True
        # unknown Google accounts are refused (accounts are created by admins)
        monkeypatch.setattr(
            google_oauth,
            "verify_id_token",
            lambda token, nonce=None: {**claims, "sub": "other", "email": "stranger@gmail.com"},
        )
        r = client(app).post("/api/auth/google", json={"credential": "x" * 40})
        assert r.status_code == 403 and r.json()["error"]["code"] == "not_registered"

    def test_google_redirect_flow_checks_state(self, app, monkeypatch):
        s = get_settings()
        monkeypatch.setattr(s, "google_client_id", "test-client")
        c = client(app)
        r = c.get("/api/auth/google/login", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"].startswith(google_oauth.AUTH_ENDPOINT)
        assert "state=" in r.headers["location"]
        r = c.get(
            "/api/auth/google/callback",
            params={"code": "abc", "state": "forged"},
            follow_redirects=False,
        )
        assert r.status_code == 302 and "error=google_cancelled" in r.headers["location"]

    def test_auth_config(self, app):
        assert client(app).get("/api/auth/config").json()["password_login_enabled"] is True


# ============================================================================
# RBAC
# ============================================================================


class TestRBAC:
    @pytest.mark.parametrize(
        "email", ["funder@globalfund.org", "auditor@transparency.org", "admin@consentledger.org"]
    )
    def test_only_owners_create_datasets(self, app, email):
        r = login(app, email).post("/api/datasets", json={"title": "Not allowed"})
        assert r.status_code == 403 and "owner" in r.json()["error"]["message"]

    def test_only_admins_manage_accounts(self, app):
        org = {"name": f"New Org {uuid4().hex[:6]}", "type": "ngo"}
        assert login(app, "owner@hope.org").post("/api/organizations", json=org).status_code == 403
        assert (
            login(app, "admin@consentledger.org").post("/api/organizations", json=org).status_code
            == 201
        )

    def test_non_admin_sees_only_own_org_users(self, app):
        users = login(app, "funder@globalfund.org").get("/api/users").json()["items"]
        assert {u["org_name"] for u in users} == {"Global Fund"}

    def test_auditor_cannot_read_dataset_contents(self, app):
        c = login(app, "auditor@transparency.org")
        ds = dataset_id(c, "Poverty Relief Beneficiaries 2024")
        assert c.get(f"/api/datasets/{ds}/data").status_code == 403

    def test_partner_cannot_verify_chain_but_auditor_can(self, app):
        assert login(app, "funder@globalfund.org").get("/api/audit/verify").status_code == 403
        r = login(app, "auditor@transparency.org").get("/api/audit/verify")
        assert r.status_code == 200 and r.json()["valid"] is True

    def test_detector_run_requires_auditor_or_admin(self, app):
        assert login(app, "owner@hope.org").post("/api/alerts/run-detector").status_code == 403
        r = login(app, "auditor@transparency.org").post("/api/alerts/run-detector")
        assert r.status_code == 200 and r.json()["user_hours"] > 0


# ============================================================================
# CONSENT ENFORCEMENT
# ============================================================================


class TestConsentEnforcement:
    def test_partner_reads_only_consented_fields(self, app):
        c = login(app, "funder@globalfund.org")
        ds = dataset_id(c, "Poverty Relief Beneficiaries 2024")
        assert c.get(f"/api/datasets/{ds}/data").status_code == 403  # purpose required
        r = c.get(
            f"/api/datasets/{ds}/data", params={"purpose": "impact_evaluation", "page_size": 5}
        )
        body = r.json()
        assert r.status_code == 200 and len(body["rows"]) == 5
        row = body["rows"][0]
        assert row["full_name"] == "[REDACTED]" and row["address"] == "[MASKED]"
        assert row["district"] not in ("[MASKED]", "[REDACTED]")
        assert "full_name" in body["masked_fields"] and "district" in body["visible_fields"]
        assert c.get(f"/api/datasets/{ds}/data", params={"purpose": "marketing"}).status_code == 403

    def test_owner_sees_decrypted_pii(self, app):
        c = login(app, "owner@hope.org")
        ds = dataset_id(c, "Poverty Relief Beneficiaries 2024")
        row = c.get(f"/api/datasets/{ds}/data", params={"page_size": 1}).json()["rows"][0]
        assert row["full_name"] not in ("[REDACTED]", "[ENCRYPTED]") and "@" in row["email"]

    def test_full_flow_request_approve_read_revoke(self, app):
        partner, owner = login(app, "partner@disaster.gov"), login(app, "owner@hope.org")
        ds = dataset_id(owner, "Nutrition Program Outcomes")
        fields = {
            f["name"]: f["field_id"] for f in owner.get(f"/api/datasets/{ds}").json()["fields"]
        }

        r = partner.post(
            "/api/requests",
            json={
                "dataset_id": ds,
                "purpose": "flood response",
                "field_ids": [fields["child_id"], fields["weight_kg"]],
                "expires_at": future(20),
            },
        )
        assert r.status_code == 201, r.text
        req = r.json()
        # the partner cannot approve its own request
        assert (
            partner.post(f"/api/requests/{req['request_id']}/approve", json={}).status_code == 403
        )

        r = owner.post(
            f"/api/requests/{req['request_id']}/approve",
            json={"field_ids": [fields["weight_kg"]], "note": "weights only"},
        )
        assert r.status_code == 200 and r.json()["status"] == "approved"

        data = partner.get(f"/api/datasets/{ds}/data", params={"purpose": "flood response"}).json()
        assert data["visible_fields"] == ["weight_kg"]
        assert data["rows"][0]["child_id"] == "[REDACTED]"

        grants = owner.get("/api/consents", params={"dataset_id": ds, "q": "flood"}).json()["items"]
        assert len(grants) == 1
        assert (
            owner.post(
                f"/api/consents/{grants[0]['grant_id']}/revoke", json={"reason": "t"}
            ).status_code
            == 200
        )
        r = partner.get(f"/api/datasets/{ds}/data", params={"purpose": "flood response"})
        assert r.status_code == 403  # revoked: the very next read is refused

        actions = [
            a["action"]
            for a in owner.get("/api/audit", params={"dataset_id": ds, "page_size": 10}).json()[
                "items"
            ]
        ]
        assert {
            "request_create",
            "request_approve",
            "grant_create",
            "select",
            "grant_revoke",
        } <= set(actions)

    def test_owner_cannot_grant_on_others_dataset(self, app):
        c = login(app, "owner@educare.org")
        hope = login(app, "owner@hope.org")
        ds = dataset_id(hope, "Nutrition Program Outcomes")
        field = hope.get(f"/api/datasets/{ds}").json()["fields"][0]["field_id"]
        orgs = c.get("/api/organizations", params={"q": "Global"}).json()["items"]
        r = c.post(
            "/api/consents",
            json={
                "dataset_id": ds,
                "grantee_org_id": orgs[0]["org_id"],
                "field_ids": [field],
                "purpose": "sneaky",
                "expires_at": future(),
            },
        )
        assert r.status_code == 404

    def test_upload_scan_publish_load(self, app):
        c = login(app, "owner@educare.org")
        ds = c.post("/api/datasets", json={"title": "Upload test", "category": "education"}).json()
        csv = b"Student Name,Email,Grade\nAsha Rao,asha@example.org,5\nVikram Shah,vik@example.org,6\n"
        r = c.post(
            f"/api/datasets/{ds['dataset_id']}/upload/preview",
            files={"file": ("s.csv", csv, "text/csv")},
        )
        cols = {col["name"]: col for col in r.json()["columns"]}
        assert (
            cols["email"]["suggested_sensitivity"] == "pii"
            and cols["grade"]["inferred_type"] == "integer"
        )
        fields = [
            {
                "name": n,
                "data_type": col["inferred_type"],
                "sensitivity": col["suggested_sensitivity"],
                "is_encrypted": col["suggest_encryption"],
            }
            for n, col in cols.items()
        ]
        assert (
            c.post(
                f"/api/datasets/{ds['dataset_id']}/fields/bulk", json={"fields": fields}
            ).status_code
            == 201
        )
        assert c.post(f"/api/datasets/{ds['dataset_id']}/publish").json()["status"] == "published"
        r = c.post(
            f"/api/datasets/{ds['dataset_id']}/rows", files={"file": ("s.csv", csv, "text/csv")}
        )
        assert r.json() == {"rows_loaded": 2, "total_rows": 2}
        rows = c.get(f"/api/datasets/{ds['dataset_id']}/data").json()["rows"]
        assert rows[0]["email"] == "asha@example.org"  # decrypted for the owner


class TestHardening:
    def test_repeated_failed_logins_are_throttled(self, app):
        from backend.app import ratelimit

        ratelimit.reset()
        limit = get_settings().login_max_failures
        c = client(app)
        bad = {"email": "admin@consentledger.org", "password": "wrong"}
        for _ in range(limit):
            assert c.post("/api/auth/login", json=bad).status_code == 401
        r = c.post("/api/auth/login", json=bad)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
        # throttled even with the right password, and on the token endpoint
        good = {"email": "admin@consentledger.org", "password": PASSWORD}
        assert c.post("/api/auth/login", json=good).status_code == 429
        r = c.post(
            "/api/auth/token", data={"username": "admin@consentledger.org", "password": PASSWORD}
        )
        assert r.status_code == 429
        # other accounts are unaffected
        assert (
            c.post("/api/auth/login", json={**good, "email": "owner@hope.org"}).status_code == 200
        )
        ratelimit.reset()
        assert c.post("/api/auth/login", json=good).status_code == 200

    def test_google_network_failure_is_a_clean_error(self, app, monkeypatch):
        from google.auth import exceptions as google_exceptions
        from google.oauth2 import id_token

        def boom(*a, **k):
            raise google_exceptions.TransportError("no network")

        monkeypatch.setattr(id_token, "verify_oauth2_token", boom)
        with pytest.raises(google_oauth.GoogleAuthError, match="reach Google"):
            google_oauth.verify_id_token("x")

    def test_create_request_returns_the_new_request(self, app):
        partner, owner = login(app, "partner@educare.org"), login(app, "owner@hope.org")
        ds = dataset_id(owner, "Nutrition Program Outcomes")
        field = owner.get(f"/api/datasets/{ds}").json()["fields"][0]["field_id"]
        bodies = [
            {"dataset_id": ds, "purpose": p, "field_ids": [field], "expires_at": future(9)}
            for p in ("first purpose", "second purpose")
        ]
        made = [partner.post("/api/requests", json=b).json() for b in bodies]
        assert [m["purpose"] for m in made] == ["first purpose", "second purpose"]
        assert made[0]["request_id"] != made[1]["request_id"]

    def test_verify_reports_totals(self, app):
        r = login(app, "auditor@transparency.org").get("/api/audit/verify").json()
        assert r["valid"] and r["total_rows"] == r["verified_rows"] > 0
        assert r["first_error"] is None

    def test_alerts_admin_can_view_but_not_triage(self, app):
        auditor, admin = login(app, "auditor@transparency.org"), login(
            app, "admin@consentledger.org"
        )
        auditor.post("/api/alerts/run-detector")
        items = admin.get("/api/alerts").json()["items"]
        assert items, "admins see alerts"
        r = admin.patch(f"/api/alerts/{items[0]['alert_id']}", json={"status": "resolved"})
        assert r.status_code == 403

    def test_no_grants_on_draft_datasets(self, app):
        c = login(app, "owner@educare.org")
        ds = c.post("/api/datasets", json={"title": "Draft only"}).json()["dataset_id"]
        f = c.post(f"/api/datasets/{ds}/fields", json={"name": "x", "data_type": "text"}).json()
        org = c.get("/api/organizations", params={"q": "Global"}).json()["items"][0]["org_id"]
        r = c.post(
            "/api/consents",
            json={
                "dataset_id": ds,
                "grantee_org_id": org,
                "field_ids": [f["field_id"]],
                "purpose": "research",
                "expires_at": future(),
            },
        )
        assert r.status_code == 400 and "Publish" in r.json()["error"]["message"]

    def test_field_added_after_publish_can_be_loaded_and_shared(self, app):
        c = login(app, "owner@educare.org")
        ds = c.post("/api/datasets", json={"title": "Grows later"}).json()["dataset_id"]
        c.post(f"/api/datasets/{ds}/fields", json={"name": "a", "data_type": "text"})
        c.post(f"/api/datasets/{ds}/publish")
        r = c.post(
            f"/api/datasets/{ds}/fields",
            json={"name": "b", "data_type": "integer", "sensitivity": "high"},
        )
        assert r.status_code == 201
        csv = b"a,b\nx,1\ny,2\n"
        r = c.post(f"/api/datasets/{ds}/rows", files={"file": ("d.csv", csv, "text/csv")})
        assert r.status_code == 200 and r.json()["rows_loaded"] == 2
        rows = c.get(f"/api/datasets/{ds}/data").json()["rows"]
        assert [(x["a"], x["b"]) for x in rows] == [("x", "1"), ("y", "2")]

    def test_bulk_revoke(self, app):
        owner, funder = login(app, "owner@hope.org"), login(app, "funder@globalfund.org")
        ds = dataset_id(owner, "Nutrition Program Outcomes")
        fields = [f["field_id"] for f in owner.get(f"/api/datasets/{ds}").json()["fields"][:2]]
        org = funder.get("/api/auth/me").json()["organization"]["org_id"]
        made = owner.post(
            "/api/consents",
            json={
                "dataset_id": ds,
                "grantee_org_id": org,
                "field_ids": fields,
                "purpose": "bulk test",
                "expires_at": future(),
            },
        ).json()
        assert [g["field_id"] for g in made] == fields
        ids = [g["grant_id"] for g in made]
        assert (
            funder.get(f"/api/datasets/{ds}/data", params={"purpose": "bulk test"}).status_code
            == 200
        )
        r = owner.post("/api/consents/revoke", json={"grant_ids": ids, "reason": "done"})
        assert r.status_code == 200 and r.json() == {"revoked": 2}
        assert (
            funder.get(f"/api/datasets/{ds}/data", params={"purpose": "bulk test"}).status_code
            == 403
        )
        # repeat is a no-op; someone else's ids are 404
        assert owner.post("/api/consents/revoke", json={"grant_ids": ids}).json() == {"revoked": 0}
        other = login(app, "owner@educare.org")
        assert other.post("/api/consents/revoke", json={"grant_ids": ids}).status_code == 404

    def test_oversized_upload_rejected(self, app):
        from backend.app.csv_utils import MAX_UPLOAD_BYTES

        c = login(app, "owner@educare.org")
        ds = c.post("/api/datasets", json={"title": "Too big"}).json()["dataset_id"]
        big = b"a\n" + b"x\n" * (MAX_UPLOAD_BYTES // 2 + 10)
        r = c.post(f"/api/datasets/{ds}/upload/preview", files={"file": ("b.csv", big, "text/csv")})
        assert r.status_code == 413


# ============================================================================
# VALIDATION, ERRORS, PAGINATION
# ============================================================================


class TestApiConventions:
    def test_validation_errors_are_clean(self, app):
        c = login(app, "owner@hope.org")
        r = c.post(
            "/api/consents",
            json={
                "dataset_id": "nope",
                "field_ids": [],
                "purpose": "x",
                "expires_at": "2000-01-01T00:00:00Z",
            },
        )
        body = r.json()
        assert r.status_code == 422 and body["error"]["code"] == "validation_error"
        fields = {d["field"] for d in body["error"]["details"]}
        assert {"dataset_id", "field_ids", "purpose", "expires_at", "grantee_org_id"} <= fields

    def test_pagination_and_filters(self, app):
        c = login(app, "auditor@transparency.org")
        p1 = c.get("/api/audit", params={"page_size": 5, "page": 1}).json()
        p2 = c.get("/api/audit", params={"page_size": 5, "page": 2}).json()
        assert len(p1["items"]) == 5 and p1["pages"] > 1
        assert {i["log_id"] for i in p1["items"]}.isdisjoint({i["log_id"] for i in p2["items"]})
        assert c.get("/api/audit", params={"page_size": 500}).status_code == 422
        reads = c.get("/api/audit", params={"action": "select", "page_size": 20}).json()["items"]
        assert reads and all(i["action"] == "select" for i in reads)
        found = c.get("/api/datasets", params={"q": "vaccination"}).json()["items"]
        assert [d["title"] for d in found] == ["Vaccination Coverage Survey"]

    def test_root_answers_without_auth(self, app):
        r = client(app).get("/")
        assert r.status_code == 200
        assert r.json() == {"service": "consentledger-api", "status": "ok", "docs": "/docs"}
        assert client(app).head("/").status_code == 200  # platform health probes

    def test_unknown_dataset_is_404(self, app):
        r = login(app, "owner@hope.org").get(f"/api/datasets/{uuid4()}")
        assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"

    def test_openapi_published(self, app):
        spec = client(app).get("/openapi.json").json()
        tags = {t for p in spec["paths"].values() for op in p.values() for t in op.get("tags", [])}
        assert {
            "auth",
            "organizations",
            "datasets",
            "consent",
            "requests",
            "audit",
            "alerts",
        } <= tags
