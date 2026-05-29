from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main as app_main
from main import PhishingDetectionApp
from src.billing.entitlements import locked_analyzer_result
from src.config import PipelineConfig
from src.feedback.email_lookup import EmailLookupIndex
from src.models import AnalyzerResult, PipelineResult, Verdict
from src.reporting.dashboard import PhishingDashboard
from src.saas.auth import SaaSSessionManager, USER_CSRF_COOKIE_NAME
from src.saas.database import SaaSStore
from src.security.web_security import TokenVerifier


def _build_saas_app(tmp_path, *, signup_enabled: bool):
    app_wrapper = PhishingDetectionApp.__new__(PhishingDetectionApp)
    app_wrapper.config = PipelineConfig(
        analyst_api_token="analyst-secret",
        saas_db_path=str(tmp_path / "saas.db"),
        saas_session_secret="saas-secret-for-tests",
        saas_public_signup_enabled=signup_enabled,
    )
    app_wrapper.pipeline = MagicMock()
    app_wrapper.pipeline.analyze.side_effect = _fake_analyze
    app_wrapper.report_gen = MagicMock()
    app_wrapper.ioc_exporter = MagicMock()
    app_wrapper.sigma_exporter = MagicMock()
    app_wrapper.dashboard = PhishingDashboard(
        template_dir="./templates",
        route_prefix="/admin/dashboard",
    )
    app_wrapper.token_verifier = TokenVerifier("analyst-secret")
    app_wrapper.saas_session_manager = SaaSSessionManager("saas-secret-for-tests")
    app_wrapper._saas_store = None
    app_wrapper._monitor = None
    app_wrapper._upload_results = []
    app_wrapper.email_index = EmailLookupIndex(jsonl_path=str(tmp_path / "results.jsonl"))
    return app_wrapper.create_fastapi_app()


async def _fake_analyze(email, feature_gate=None):
    url_reputation_decision = feature_gate("url_reputation")
    return PipelineResult(
        email_id=email.email_id,
        verdict=Verdict.SUSPICIOUS,
        overall_score=0.42,
        overall_confidence=0.8,
        analyzer_results={
            "payment_fraud": AnalyzerResult(
                analyzer_name="payment_fraud",
                risk_score=0.52,
                confidence=0.9,
                details={"decision": "VERIFY"},
            ),
            "url_reputation": locked_analyzer_result(
                "url_reputation",
                url_reputation_decision,
            ),
        },
        extracted_urls=[],
        iocs={"headers": {}},
        reasoning="test reasoning",
        timestamp=datetime.now(timezone.utc),
    )


def _signup(client: TestClient, *, origin: str = "https://testserver"):
    return client.post(
        "/api/saas/auth/signup",
        headers=_same_origin_headers(origin),
        json={
            "email": "owner@example.com",
            "password": "correct horse battery",
            "org_name": "Example Finance",
        },
    )


def _same_origin_headers(origin: str = "https://testserver") -> dict[str, str]:
    return {"origin": origin}


def _upload(client: TestClient, *, origin: str = "https://testserver"):
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    return client.post(
        "/api/saas/analyze/upload",
        headers={
            "x-csrf-token": csrf,
            "origin": origin,
        },
        files={
            "file": (
                "sample.eml",
                b"From: vendor@example.com\r\nSubject: Invoice update\r\n\r\nPlease verify payment details.",
                "message/rfc822",
            )
        },
    )


def _post_json_with_csrf(
    client: TestClient,
    path: str,
    payload: dict,
    *,
    origin: str = "https://testserver",
):
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    headers = _same_origin_headers(origin)
    headers["x-csrf-token"] = csrf
    return client.post(
        path,
        headers=headers,
        json=payload,
    )


def _allow_mailbox_auth(monkeypatch, *, authenticated: bool = True):
    import src.ingestion.imap_provider as imap_provider_module

    class FakeIMAPProvider:
        config_seen = None
        disconnected = False

        def __init__(self, config):
            self.config = config
            FakeIMAPProvider.config_seen = config

        def authenticate(self):
            return authenticated

        def disconnect(self):
            FakeIMAPProvider.disconnected = True

    monkeypatch.setattr(imap_provider_module, "IMAPProvider", FakeIMAPProvider)
    return FakeIMAPProvider


def _delete_with_csrf(
    client: TestClient,
    path: str,
    *,
    origin: str = "https://testserver",
):
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    headers = _same_origin_headers(origin)
    headers["x-csrf-token"] = csrf
    return client.delete(path, headers=headers)


def _patch_json_with_csrf(
    client: TestClient,
    path: str,
    payload: dict,
    *,
    origin: str = "https://testserver",
):
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    headers = _same_origin_headers(origin)
    headers["x-csrf-token"] = csrf
    return client.patch(path, headers=headers, json=payload)


def _stripe_signature(payload: bytes, secret: str, timestamp: int) -> str:
    signed = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


class FakeStripeBillingClient:
    created_customers = []
    checkout_sessions = []
    portal_sessions = []

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def create_customer(self, *, email: str, name: str, metadata: dict):
        self.created_customers.append({"email": email, "name": name, "metadata": metadata})
        return {"id": "cus_test"}

    def create_checkout_session(self, **kwargs):
        self.checkout_sessions.append(kwargs)
        return {"id": "cs_test", "url": "https://checkout.stripe.com/c/cs_test"}

    def create_portal_session(self, **kwargs):
        self.portal_sessions.append(kwargs)
        return {"id": "bps_test", "url": "https://billing.stripe.com/p/session/test"}


class InvalidStripeBillingClient(FakeStripeBillingClient):
    def create_customer(self, **kwargs):
        raise app_main.StripeAPIError(
            "Invalid API Key provided: sk_live_redacted",
            status_code=401,
        )


class FakePasswordResetMailer:
    enabled = True
    fail = False
    sent = []

    def __init__(self, config):
        self.config = config

    def send_password_reset(self, email):
        if self.fail:
            raise app_main.EmailDeliveryError("delivery failed")
        self.sent.append(email)


def test_saas_signup_disabled_by_default(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=False),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = _signup(client)

    assert response.status_code == 403


def test_saas_auth_cookie_setters_require_same_origin(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    missing_origin_signup = client.post(
        "/api/saas/auth/signup",
        json={
            "email": "missing-origin@example.com",
            "password": "correct horse battery",
            "org_name": "Missing Origin",
        },
    )
    cross_origin_signup = client.post(
        "/api/saas/auth/signup",
        headers={"origin": "https://evil.example"},
        json={
            "email": "cross-origin@example.com",
            "password": "correct horse battery",
            "org_name": "Cross Origin",
        },
    )

    assert missing_origin_signup.status_code == 403
    assert cross_origin_signup.status_code == 403
    assert _signup(client).status_code == 200

    cross_origin_login = client.post(
        "/api/saas/auth/login",
        headers={"origin": "https://evil.example"},
        json={"email": "owner@example.com", "password": "correct horse battery"},
    )
    cross_origin_reset_request = client.post(
        "/api/saas/auth/password-reset/request",
        headers={"origin": "https://evil.example"},
        json={"email": "owner@example.com"},
    )
    cross_origin_reset_confirm = client.post(
        "/api/saas/auth/password-reset/confirm",
        headers={"origin": "https://evil.example"},
        json={"token": "not-real", "password": "new secure password"},
    )

    assert cross_origin_login.status_code == 403
    assert cross_origin_reset_request.status_code == 403
    assert cross_origin_reset_confirm.status_code == 403


def test_saas_signup_session_plans_upload_and_history(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    session = client.get("/api/saas/session")
    plans = client.get("/api/saas/plans")
    upload = _upload(client)
    history = client.get("/api/saas/scans")

    assert signup.status_code == 200
    assert session.json()["authenticated"] is True
    assert plans.json()["account"]["plan_slug"] == "free"
    assert upload.status_code == 200
    assert upload.json()["upload_filename"] == "sample.eml"
    assert upload.json()["account"]["monthly_scan_used"] == 1
    assert upload.json()["feature_locks"][0]["details"]["required_plan_name"] == "Starter"
    assert upload.json()["analyzer_results"]["payment_fraud"]["status"] == "success"
    assert upload.json()["analyzer_results"]["payment_fraud"]["display_name"] == "Business email compromise signals"
    assert upload.json()["analyzer_results"]["payment_fraud"]["risk_contribution"] == 0.468
    assert upload.json()["analyzer_results"]["url_reputation"]["status"] == "feature_locked"
    assert upload.json()["analyzer_results"]["url_reputation"]["plan_required"] == "starter"
    assert upload.json()["analyzer_results"]["url_reputation"]["cost_tier"] == "paid_low"
    assert upload.json()["analyzer_results"]["url_reputation"]["duration_ms"] == 0.0
    assert upload.json()["analyzer_results"]["url_reputation"]["evidence"]
    assert upload.json()["product_verdicts"]["phishanalyze"]["verdict"] == "SUSPICIOUS"
    assert upload.json()["product_verdicts"]["payshield"]["display_decision"] == "VERIFY"
    assert upload.json()["payment_protection"]["display_label"] == "Verify out of band"
    assert upload.json()["evidence_summary"]["source"] == "structured_analyzer_evidence"
    assert upload.json()["evidence_summary"]["llm_status"] == "feature_locked"
    assert history.json()["results"][0]["payment_decision"] == "VERIFY"


def test_saas_team_member_role_management_is_owner_scoped(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    listing = client.get("/api/saas/team/members")
    add = _post_json_with_csrf(
        client,
        "/api/saas/team/members",
        {
            "email": "analyst@example.com",
            "password": "correct horse analyst",
            "role": "analyst",
        },
    )
    analyst_id = add.json()["member"]["user_id"]
    update = _patch_json_with_csrf(
        client,
        f"/api/saas/team/members/{analyst_id}",
        {"role": "viewer"},
    )
    delete = _delete_with_csrf(client, f"/api/saas/team/members/{analyst_id}")
    owner_id = listing.json()["members"][0]["user_id"]
    delete_last_owner = _delete_with_csrf(client, f"/api/saas/team/members/{owner_id}")

    assert listing.status_code == 200
    assert listing.json()["permissions"]["can_manage_team"] is True
    assert listing.json()["members"][0]["role"] == "owner"
    assert add.status_code == 200
    assert add.json()["member"]["email"] == "analyst@example.com"
    assert add.json()["member"]["role"] == "analyst"
    assert update.status_code == 200
    assert update.json()["member"]["role"] == "viewer"
    assert delete.status_code == 200
    assert delete.json()["deleted"] is True
    assert delete_last_owner.status_code == 400


def test_mailbox_scan_now_is_feature_gated_before_lookup(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes/mail_missing/scan-now",
        {"max_results": 1},
    )

    assert response.status_code == 402
    assert response.json()["locked"]["feature_slug"] == "mailbox_monitoring"


def test_mailbox_scan_now_fetches_unread_and_stores_result(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")

    from src.ingestion.email_provider import FetchedEmail
    import src.ingestion.imap_provider as imap_provider_module

    class FakeIMAPProvider:
        config_seen = None
        disconnected = False

        def __init__(self, config):
            self.config = config
            FakeIMAPProvider.config_seen = config

        def authenticate(self):
            return True

        def fetch_new_emails(self, max_results=20):
            assert max_results == 2
            return [
                FetchedEmail(
                    provider_id="uid-1",
                    account_id="owner@example.com",
                    raw_bytes=(
                        b"From: vendor@example.com\r\n"
                        b"Subject: Invoice INV-100\r\n\r\n"
                        b"Private mailbox body should not be returned. Payment due AUD $120.00."
                    ),
                    provider_type="imap",
                    metadata={},
                )
            ]

        def disconnect(self):
            FakeIMAPProvider.disconnected = True

    monkeypatch.setattr(imap_provider_module, "IMAPProvider", FakeIMAPProvider)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="pro")
    connect = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "zoho",
            "email": "owner@example.com",
            "app_password": "secret app password",
        },
    )
    mailbox_id = connect.json()["mailbox"]["id"]
    response = _post_json_with_csrf(
        client,
        f"/api/saas/mailboxes/{mailbox_id}/scan-now",
        {"max_results": 2},
    )
    history = client.get("/api/saas/scans")
    serialized = json.dumps(response.json())

    assert response.status_code == 200
    assert response.json()["fetched"] == 1
    assert response.json()["analyzed"] == 1
    assert response.json()["skipped_non_payment"] == 0
    assert response.json()["results"][0]["subject"] == "Invoice INV-100"
    assert response.json()["mailbox"]["credential_saved"] is True
    assert history.json()["results"][0]["email_id"]
    assert FakeIMAPProvider.config_seen.host == "imap.zoho.com"
    assert FakeIMAPProvider.config_seen.port == 993
    assert FakeIMAPProvider.config_seen.user == "owner@example.com"
    assert FakeIMAPProvider.disconnected is True
    assert "Private mailbox body" not in serialized
    assert "secret app password" not in serialized
    assert "encrypted_token_ref" not in serialized


def test_mailbox_scan_now_skips_clear_non_payment_mail(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")

    from src.ingestion.email_provider import FetchedEmail
    import src.ingestion.imap_provider as imap_provider_module

    class FakeIMAPProvider:
        def __init__(self, config):
            self.config = config

        def authenticate(self):
            return True

        def fetch_new_emails(self, max_results=20):
            assert max_results == 2
            return [
                FetchedEmail(
                    provider_id="uid-meeting",
                    account_id="owner@example.com",
                    raw_bytes=(
                        b"From: teammate@example.com\r\n"
                        b"Subject: Team planning reminder\r\n\r\n"
                        b"Bring your roadmap notes to tomorrow's meeting."
                    ),
                    provider_type="imap",
                    metadata={},
                ),
                FetchedEmail(
                    provider_id="uid-invoice",
                    account_id="owner@example.com",
                    raw_bytes=(
                        b"From: vendor@example.com\r\n"
                        b"Subject: Invoice INV-200\r\n\r\n"
                        b"Amount due AUD $240.00. Please process through normal approval."
                    ),
                    provider_type="imap",
                    metadata={},
                ),
            ]

        def disconnect(self):
            pass

    monkeypatch.setattr(imap_provider_module, "IMAPProvider", FakeIMAPProvider)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="pro")
    connect = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "imap",
            "email": "owner@example.com",
            "host": "imap.example.com",
            "app_password": "secret app password",
        },
    )
    mailbox_id = connect.json()["mailbox"]["id"]

    response = _post_json_with_csrf(
        client,
        f"/api/saas/mailboxes/{mailbox_id}/scan-now",
        {"max_results": 2},
    )
    payload = response.json()
    history = client.get("/api/saas/scans")
    serialized = json.dumps(payload)

    assert response.status_code == 200
    assert payload["fetched"] == 2
    assert payload["analyzed"] == 1
    assert payload["skipped_non_payment"] == 1
    assert payload["skipped_results"][0]["payment_relevance"]["label"] == "non_payment"
    assert "ml_sidecar" not in payload["skipped_results"][0]["payment_relevance"]
    assert payload["results"][0]["subject"] == "Invoice INV-200"
    assert len(history.json()["results"]) == 1
    assert "Bring your roadmap notes" not in serialized
    assert "secret app password" not in serialized
    assert "encrypted_token_ref" not in serialized


def test_saas_scan_history_delete_is_org_scoped_and_keeps_usage(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    assert _upload(client).status_code == 200
    first_history = client.get("/api/saas/scans")
    result_id = first_history.json()["results"][0]["id"]

    missing_csrf = client.delete(f"/api/saas/scans/{result_id}")
    delete = _delete_with_csrf(client, f"/api/saas/scans/{result_id}")
    second_delete = _delete_with_csrf(client, f"/api/saas/scans/{result_id}")
    history = client.get("/api/saas/scans")
    session = client.get("/api/saas/session")

    assert missing_csrf.status_code == 403
    assert delete.status_code == 200
    assert delete.json()["deleted"] is True
    assert second_delete.status_code == 404
    assert history.json()["results"] == []
    assert session.json()["account"]["monthly_scan_used"] == 1


def test_saas_mailbox_connection_is_plan_gated_and_csrf_protected(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    listing = client.get("/api/saas/mailboxes")
    missing_csrf = client.post(
        "/api/saas/mailboxes",
        json={
            "provider": "gmail",
            "email": "owner@example.com",
            "app_password": "app-specific-password",
        },
    )
    locked = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "gmail",
            "email": "owner@example.com",
            "app_password": "app-specific-password",
        },
    )
    invalid_port = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "imap",
            "email": "owner@example.com",
            "host": "imap.example.com",
            "port": "not-a-port",
            "app_password": "app-specific-password",
        },
    )
    missing_proton_port = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "proton",
            "email": "owner@example.com",
            "host": "bridge-host.example",
            "app_password": "app-specific-password",
        },
    )
    invalid_provider = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "unknownmail",
            "email": "owner@example.com",
            "app_password": "app-specific-password",
        },
    )

    assert listing.status_code == 200
    assert listing.json()["mailboxes"] == []
    assert listing.json()["quota"] == {"used": 0, "limit": 0, "remaining": 0}
    assert listing.json()["entitlement"]["required_plan_name"] == "Pro"
    assert missing_csrf.status_code == 403
    assert invalid_port.status_code == 400
    assert invalid_port.json()["detail"] == "IMAP port is invalid"
    assert missing_proton_port.status_code == 400
    assert missing_proton_port.json()["detail"] == "IMAP port is required for Proton Mail Bridge"
    assert invalid_provider.status_code == 400
    assert "Yahoo" in invalid_provider.json()["detail"]
    assert locked.status_code == 402
    assert locked.json()["locked"]["feature_slug"] == "mailbox_monitoring"
    assert "app-specific-password" not in json.dumps(locked.json())


def test_saas_mailbox_connection_encrypts_and_lists_masked_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")
    fake_provider = _allow_mailbox_auth(monkeypatch)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="pro")
    connect = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "imap",
            "email": "owner@example.com",
            "host": "imap.example.com",
            "app_password": "secret app password",
        },
    )
    listing = client.get("/api/saas/mailboxes")
    stored = store.list_mail_accounts(context["org_id"])[0]
    delete = _delete_with_csrf(client, f"/api/saas/mailboxes/{stored.id}")
    after_delete = client.get("/api/saas/mailboxes")

    assert connect.status_code == 200
    assert connect.json()["mailbox"]["external_account_id"] == "owner@example.com"
    assert connect.json()["mailbox"]["credential_saved"] is True
    assert connect.json()["mailbox"]["status"] == "active"
    assert fake_provider.config_seen.host == "imap.example.com"
    assert fake_provider.config_seen.user == "owner@example.com"
    assert fake_provider.disconnected is True
    assert listing.json()["quota"] == {"used": 1, "limit": 3, "remaining": 2}
    assert listing.json()["mailboxes"][0]["credential_saved"] is True
    assert listing.json()["mailboxes"][0]["status"] == "active"
    assert "encrypted_token_ref" not in json.dumps(listing.json())
    assert "secret app password" not in json.dumps(listing.json())
    assert stored.encrypted_token_ref.startswith("enc:v2:")
    assert "secret app password" not in stored.encrypted_token_ref
    assert delete.status_code == 200
    assert delete.json()["deleted"] is True
    assert after_delete.json()["mailboxes"] == []


def test_saas_mailbox_connection_rejects_bad_credentials_without_storing(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")
    _allow_mailbox_auth(monkeypatch, authenticated=False)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="pro")
    connect = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "imap",
            "email": "owner@example.com",
            "host": "imap.example.com",
            "app_password": "wrong app password",
        },
    )
    listing = client.get("/api/saas/mailboxes")

    assert connect.status_code == 502
    assert connect.json()["detail"].startswith("Mailbox authentication failed")
    assert listing.json()["mailboxes"] == []
    assert "wrong app password" not in json.dumps(connect.json())


def test_saas_mailbox_listing_marks_full_quota_locked(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "test-mailbox-encryption-key-for-unit-tests")
    _allow_mailbox_auth(monkeypatch)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="pro")

    for index in range(3):
        response = _post_json_with_csrf(
            client,
            "/api/saas/mailboxes",
            {
                "provider": "imap",
                "email": f"owner{index}@example.com",
                "host": "imap.example.com",
                "app_password": "secret app password",
            },
        )
        assert response.status_code == 200

    listing = client.get("/api/saas/mailboxes")
    extra = _post_json_with_csrf(
        client,
        "/api/saas/mailboxes",
        {
            "provider": "imap",
            "email": "extra@example.com",
            "host": "imap.example.com",
            "app_password": "secret app password",
        },
    )

    assert listing.status_code == 200
    assert listing.json()["quota"] == {"used": 3, "limit": 3, "remaining": 0}
    assert listing.json()["entitlement"]["available"] is False
    assert listing.json()["entitlement"]["limit_kind"] == "quota"
    assert listing.json()["entitlement"]["required_plan_name"] == "Business"
    assert extra.status_code == 402
    assert extra.json()["locked"]["required_plan_name"] == "Business"


def test_saas_upload_rejects_oversized_email_before_parsing(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_EMAIL_UPLOAD_BYTES", "12")
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    response = client.post(
        "/api/saas/analyze/upload",
        headers={
            "x-csrf-token": csrf,
            "origin": "https://testserver",
        },
        files={
            "file": (
                "sample.eml",
                b"From: vendor@example.com\r\nSubject: Invoice update\r\n\r\nBody",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 413
    assert "byte limit" in response.json()["detail"]


def test_saas_logout_clears_user_session_with_csrf(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    assert client.get("/api/saas/session").json()["authenticated"] is True

    missing_csrf = client.post("/api/saas/auth/logout")
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    logout = client.post(
        "/api/saas/auth/logout",
        headers={
            "x-csrf-token": csrf,
            "referer": "https://testserver/app",
        },
        json={},
    )
    session = client.get("/api/saas/session")

    assert missing_csrf.status_code == 403
    assert logout.status_code == 200
    assert session.json()["authenticated"] is False


def test_saas_manual_scan_quota_returns_locked_response(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    statuses = [_upload(client).status_code for _ in range(6)]

    assert statuses[:5] == [200, 200, 200, 200, 200]
    assert statuses[5] == 402


def test_saas_password_reset_disabled_smtp_returns_generic_ok(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = client.post(
        "/api/saas/auth/password-reset/request",
        headers=_same_origin_headers(),
        json={"email": "owner@example.com"},
    )

    assert response.status_code == 200
    assert response.json()["email_delivery_configured"] is False


def test_saas_password_reset_rejects_invalid_json(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    malformed = client.post(
        "/api/saas/auth/password-reset/request",
        content="{bad json",
        headers={**_same_origin_headers(), "content-type": "application/json"},
    )
    wrong_shape = client.post(
        "/api/saas/auth/password-reset/request",
        headers=_same_origin_headers(),
        json=["not", "an", "object"],
    )

    assert malformed.status_code == 400
    assert malformed.json()["detail"] == "Invalid JSON body"
    assert wrong_shape.status_code == 400
    assert wrong_shape.json()["detail"] == "JSON object body required"


def test_saas_password_reset_request_is_rate_limited(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    statuses = [
        client.post(
            "/api/saas/auth/password-reset/request",
            headers=_same_origin_headers(),
            json={"email": "owner@example.com"},
        ).status_code
        for _ in range(6)
    ]

    assert statuses[:5] == [200, 200, 200, 200, 200]
    assert statuses[5] == 429


def test_saas_login_is_rate_limited_after_failed_attempts(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    statuses = [
        client.post(
            "/api/saas/auth/login",
            headers=_same_origin_headers(),
            json={"email": "owner@example.com", "password": "wrong password"},
        ).status_code
        for _ in range(11)
    ]

    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


def test_saas_password_reset_request_and_confirm(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "SMTPPasswordResetMailer", FakePasswordResetMailer)
    monkeypatch.setenv("PHISHANALYZE_PUBLIC_URL", "https://phishanalyze.example.test")
    FakePasswordResetMailer.enabled = True
    FakePasswordResetMailer.fail = False
    FakePasswordResetMailer.sent = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    request = client.post(
        "/api/saas/auth/password-reset/request",
        headers=_same_origin_headers(),
        json={"email": "owner@example.com"},
    )
    token = parse_qs(urlparse(FakePasswordResetMailer.sent[0].reset_url).query)["reset_token"][0]
    confirm = client.post(
        "/api/saas/auth/password-reset/confirm",
        headers=_same_origin_headers(),
        json={"token": token, "password": "new secure password"},
    )
    old_login = client.post(
        "/api/saas/auth/login",
        headers=_same_origin_headers(),
        json={"email": "owner@example.com", "password": "correct horse battery"},
    )
    new_login = client.post(
        "/api/saas/auth/login",
        headers=_same_origin_headers(),
        json={"email": "owner@example.com", "password": "new secure password"},
    )
    replay = client.post(
        "/api/saas/auth/password-reset/confirm",
        headers=_same_origin_headers(),
        json={"token": token, "password": "another secure password"},
    )

    assert request.status_code == 200
    assert request.json()["email_delivery_configured"] is True
    assert FakePasswordResetMailer.sent[0].reset_url.startswith(
        "https://phishanalyze.example.test/analyze?"
    )
    assert FakePasswordResetMailer.sent[0].to_email == "owner@example.com"
    assert confirm.status_code == 200
    assert confirm.json()["account"]["email"] == "owner@example.com"
    assert old_login.status_code == 401
    assert new_login.status_code == 200
    assert replay.status_code == 400


def test_saas_password_reset_unknown_email_does_not_send_or_leak(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "SMTPPasswordResetMailer", FakePasswordResetMailer)
    FakePasswordResetMailer.enabled = True
    FakePasswordResetMailer.fail = False
    FakePasswordResetMailer.sent = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/api/saas/auth/password-reset/request",
        headers=_same_origin_headers(),
        json={"email": "missing@example.com"},
    )

    assert response.status_code == 200
    assert response.json()["email_delivery_configured"] is True
    assert "If this email belongs" in response.json()["message"]
    assert FakePasswordResetMailer.sent == []


def test_saas_password_reset_delivery_failure_returns_503(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "SMTPPasswordResetMailer", FakePasswordResetMailer)
    FakePasswordResetMailer.enabled = True
    FakePasswordResetMailer.fail = True
    FakePasswordResetMailer.sent = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = client.post(
        "/api/saas/auth/password-reset/request",
        headers=_same_origin_headers(),
        json={"email": "owner@example.com"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Password reset email could not be sent"


def test_saas_checkout_reports_missing_stripe_config(tmp_path, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_STARTER", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_STARTER_YEARLY", raising=False)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = _post_json_with_csrf(client, "/api/saas/billing/checkout", {"plan": "starter"})

    assert response.status_code == 503
    assert response.json()["missing_env"] == ["STRIPE_SECRET_KEY", "STRIPE_PRICE_STARTER"]


def test_saas_yearly_checkout_reports_missing_yearly_price(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.delenv("STRIPE_PRICE_STARTER_YEARLY", raising=False)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "starter", "billing_interval": "yearly"},
    )

    assert response.status_code == 503
    assert response.json()["missing_env"] == ["STRIPE_PRICE_STARTER_YEARLY"]


def test_saas_checkout_invalid_stripe_key_returns_safe_billing_error(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setattr(app_main, "StripeBillingClient", InvalidStripeBillingClient)
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    response = _post_json_with_csrf(client, "/api/saas/billing/checkout", {"plan": "starter"})

    assert response.status_code == 503
    payload = response.json()
    assert payload["billing_available"] is False
    assert payload["stripe_status_code"] == 401
    assert "valid Stripe secret key" in payload["reason"]
    assert "sk_live" not in json.dumps(payload)


def test_saas_checkout_rejects_current_or_lower_plan(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    context = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.set_subscription(org_id=context["org_id"], plan_slug="business")

    lower_plan = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "pro"},
    )
    current_plan = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "business"},
    )

    assert lower_plan.status_code == 409
    assert lower_plan.json()["billing_available"] is False
    assert lower_plan.json()["reason"] == "Pro is already included in your Business plan."
    assert current_plan.status_code == 409
    assert current_plan.json()["reason"] == "Business is already included in your Business plan."


def test_saas_checkout_and_portal_create_stripe_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setenv("STRIPE_PRICE_STARTER_YEARLY", "price_starter_yearly")
    monkeypatch.setenv("PHISHANALYZE_PUBLIC_URL", "https://phishanalyze.example.test")
    monkeypatch.setenv("PAYSHIELD_PUBLIC_URL", "https://payshield.example.test")
    monkeypatch.setattr(app_main, "StripeBillingClient", FakeStripeBillingClient)
    FakeStripeBillingClient.created_customers = []
    FakeStripeBillingClient.checkout_sessions = []
    FakeStripeBillingClient.portal_sessions = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://payshield.example.test",
        follow_redirects=False,
    )

    assert _signup(client, origin="https://payshield.example.test").status_code == 200
    checkout = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "starter"},
        origin="https://payshield.example.test",
    )
    portal = _post_json_with_csrf(
        client,
        "/api/saas/billing/portal",
        {},
        origin="https://payshield.example.test",
    )
    session = client.get("/api/saas/session")

    assert checkout.status_code == 200
    assert checkout.json()["checkout_url"] == "https://checkout.stripe.com/c/cs_test"
    assert FakeStripeBillingClient.created_customers[0]["metadata"]["org_id"].startswith("org_")
    assert FakeStripeBillingClient.checkout_sessions[0]["price_id"] == "price_starter"
    assert FakeStripeBillingClient.checkout_sessions[0]["billing_interval"] == "monthly"
    assert FakeStripeBillingClient.checkout_sessions[0]["adaptive_pricing_enabled"] is True
    assert FakeStripeBillingClient.checkout_sessions[0]["success_url"].startswith(
        "https://payshield.example.test/app?billing=success"
    )
    assert FakeStripeBillingClient.portal_sessions[0]["return_url"] == (
        "https://payshield.example.test/app?billing=portal"
    )
    assert portal.status_code == 200
    assert portal.json()["portal_url"] == "https://billing.stripe.com/p/session/test"
    assert session.json()["account"]["stripe_customer_id"] == "cus_test"


def test_saas_checkout_from_phishanalyze_returns_to_phishanalyze(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setenv("PHISHANALYZE_PUBLIC_URL", "https://phishanalyze.example.test")
    monkeypatch.setenv("PAYSHIELD_PUBLIC_URL", "https://payshield.example.test")
    monkeypatch.setattr(app_main, "StripeBillingClient", FakeStripeBillingClient)
    FakeStripeBillingClient.created_customers = []
    FakeStripeBillingClient.checkout_sessions = []
    FakeStripeBillingClient.portal_sessions = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://phishanalyze.example.test",
        follow_redirects=False,
    )

    assert _signup(client, origin="https://phishanalyze.example.test").status_code == 200
    checkout = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "starter"},
        origin="https://phishanalyze.example.test",
    )
    portal = _post_json_with_csrf(
        client,
        "/api/saas/billing/portal",
        {},
        origin="https://phishanalyze.example.test",
    )

    assert checkout.status_code == 200
    assert FakeStripeBillingClient.checkout_sessions[0]["success_url"].startswith(
        "https://phishanalyze.example.test/dashboard?billing=success"
    )
    assert FakeStripeBillingClient.checkout_sessions[0]["cancel_url"] == (
        "https://phishanalyze.example.test/dashboard?billing=cancelled"
    )
    assert portal.status_code == 200
    assert FakeStripeBillingClient.portal_sessions[0]["return_url"] == (
        "https://phishanalyze.example.test/dashboard?billing=portal"
    )


def test_saas_yearly_checkout_uses_yearly_price(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setenv("STRIPE_PRICE_STARTER_YEARLY", "price_starter_yearly")
    monkeypatch.setattr(app_main, "StripeBillingClient", FakeStripeBillingClient)
    FakeStripeBillingClient.created_customers = []
    FakeStripeBillingClient.checkout_sessions = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    checkout = _post_json_with_csrf(
        client,
        "/api/saas/billing/checkout",
        {"plan": "starter", "billing_interval": "yearly"},
    )

    assert checkout.status_code == 200
    assert checkout.json()["billing_interval"] == "yearly"
    assert FakeStripeBillingClient.checkout_sessions[0]["price_id"] == "price_starter_yearly"
    assert FakeStripeBillingClient.checkout_sessions[0]["billing_interval"] == "yearly"


def test_stripe_webhook_updates_subscription_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "stripe_secret_for_tests")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "stripe_webhook_secret_for_tests")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro")
    monkeypatch.setenv("STRIPE_PRICE_PRO_YEARLY", "price_pro_yearly")
    monkeypatch.setattr(app_main, "StripeBillingClient", FakeStripeBillingClient)
    FakeStripeBillingClient.created_customers = []
    FakeStripeBillingClient.checkout_sessions = []
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    assert _post_json_with_csrf(client, "/api/saas/billing/checkout", {"plan": "starter"}).status_code == 200
    event = {
        "id": "evt_test",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_test",
                "customer": "cus_test",
                "status": "active",
                "current_period_end": 1_800_000_000,
                "items": {"data": [{"price": {"id": "price_pro_yearly"}}]},
            }
        },
    }
    payload = json.dumps(event, separators=(",", ":")).encode("utf-8")
    webhook = client.post(
        "/api/stripe/webhook",
        content=payload,
        headers={
            "stripe-signature": _stripe_signature(payload, "stripe_webhook_secret_for_tests", int(time.time())),
            "content-type": "application/json",
        },
    )
    session = client.get("/api/saas/session")

    assert webhook.status_code == 200
    assert webhook.json()["processed"] is True
    assert session.json()["account"]["plan_slug"] == "pro"
    assert session.json()["account"]["billing_interval"] == "yearly"
    assert session.json()["account"]["current_period_end"].startswith("2027-01-15")
    assert session.json()["account"]["stripe_subscription_id"] == "sub_test"


def test_saas_store_mail_account_metadata_is_org_scoped(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    owner = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )
    other = store.create_user_with_org(
        email="other@example.com",
        password="correct horse battery",
        org_name="Other Finance",
    )

    account = store.register_mail_account(
        org_id=owner.org_id,
        user_id=owner.user_id,
        provider="gmail",
        external_account_id="owner@example.com",
        encrypted_token_ref="vault://mail/owner",
        status="pending",
    )
    store.set_mail_account_status(
        org_id=owner.org_id,
        mail_account_id=account.id,
        status="active",
        actor_user_id=owner.user_id,
    )

    owner_accounts = store.list_mail_accounts(owner.org_id)
    other_accounts = store.list_mail_accounts(other.org_id)
    deleted_other = store.delete_mail_account(
        org_id=other.org_id,
        user_id=other.user_id,
        mail_account_id=account.id,
    )
    deleted_owner = store.delete_mail_account(
        org_id=owner.org_id,
        user_id=owner.user_id,
        mail_account_id=account.id,
    )

    assert len(owner_accounts) == 1
    assert owner_accounts[0].id == account.id
    assert owner_accounts[0].status == "active"
    assert other_accounts == []
    assert deleted_other is False
    assert deleted_owner is True
    assert store.list_mail_accounts(owner.org_id) == []


def test_saas_security_policy_defaults_to_passkey_monitor_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("PHISHANALYZE_PASSKEY_ENFORCEMENT", raising=False)
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    assert signup.status_code == 200

    response = client.get("/api/saas/security/policy")

    assert response.status_code == 200
    policy = response.json()["policy"]
    assert policy["enforcement"] == "monitor"
    assert policy["passkey_registered"] is False
    assert policy["legacy_admin_access"]["phishing_resistant"] is False


def test_passkey_enforce_blocks_privileged_mutation_when_step_up_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHANALYZE_PASSKEY_ENFORCEMENT", "enforce")
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    account = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.add_webauthn_credential(
        org_id=account["org_id"],
        user_id=account["user_id"],
        credential_id="credential-test",
        public_key_b64="public-key-test",
        sign_count=0,
    )

    response = _post_json_with_csrf(client, "/api/saas/team/members", {
        "email": "analyst@example.com",
        "password": "correct horse battery",
        "role": "analyst",
    })

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["passkey_required"] is True
    assert detail["action"] == "team.member.create"


def test_passkey_enforce_allows_privileged_mutation_after_step_up(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHANALYZE_PASSKEY_ENFORCEMENT", "enforce")
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    account = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.add_webauthn_credential(
        org_id=account["org_id"],
        user_id=account["user_id"],
        credential_id="credential-test",
        public_key_b64="public-key-test",
        sign_count=0,
    )
    store.record_passkey_step_up(org_id=account["org_id"], user_id=account["user_id"])

    response = _post_json_with_csrf(client, "/api/saas/team/members", {
        "email": "analyst@example.com",
        "password": "correct horse battery",
        "role": "analyst",
    })

    assert response.status_code == 200
    assert response.json()["member"]["email"] == "analyst@example.com"


def test_passkey_enforce_blocks_every_registered_privileged_mutation(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHANALYZE_PASSKEY_ENFORCEMENT", "enforce")
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    account = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    store.add_webauthn_credential(
        org_id=account["org_id"],
        user_id=account["user_id"],
        credential_id="credential-test",
        public_key_b64="public-key-test",
        sign_count=0,
    )
    member = store.add_org_member(
        org_id=account["org_id"],
        actor_user_id=account["user_id"],
        email="analyst@example.com",
        password="correct horse analyst",
        role="analyst",
    )
    mailbox = store.register_mail_account(
        org_id=account["org_id"],
        user_id=account["user_id"],
        provider="gmail",
        external_account_id="owner@example.com",
        encrypted_token_ref="enc:v2:redacted",
        status="active",
    )
    scan_id = store.create_scan_job(
        org_id=account["org_id"],
        user_id=account["user_id"],
        source="manual_upload",
    )
    store.record_scan_result(
        org_id=account["org_id"],
        user_id=account["user_id"],
        scan_job_id=scan_id,
        email_id="email-1",
        verdict="SUSPICIOUS",
        payment_decision="VERIFY",
        result={"email_id": "email-1"},
    )
    result_id = store.list_scan_results(account["org_id"])[0]["id"]
    case = store.create_incident_case(
        org_id=account["org_id"],
        actor_user_id=account["user_id"],
        scan_result_id=result_id,
    )

    policy = client.get("/api/saas/security/policy").json()["policy"]
    matrix = {item["action"]: item for item in policy["privileged_actions"]}
    assert set(matrix) == app_main.PRIVILEGED_STEP_UP_ACTIONS
    assert all(item["requires_step_up"] for item in matrix.values())

    checks = [
        (
            "post",
            "/api/saas/team/members",
            {"email": "new@example.com", "password": "correct horse battery", "role": "analyst"},
            "team.member.create",
        ),
        ("patch", f"/api/saas/team/members/{member.user_id}", {"role": "viewer"}, "team.member.update"),
        ("delete", f"/api/saas/team/members/{member.user_id}", {}, "team.member.delete"),
        ("post", "/api/saas/mailboxes", {}, "mailbox.connect"),
        ("delete", f"/api/saas/mailboxes/{mailbox.id}", {}, "mailbox.delete"),
        ("post", f"/api/saas/mailboxes/{mailbox.id}/scan-now", {"max_results": 1}, "mailbox.scan_now"),
        ("post", "/api/saas/billing/checkout", {"plan": "starter"}, "billing.checkout"),
        ("post", "/api/saas/billing/portal", {}, "billing.portal"),
        ("post", "/api/saas/security/passkeys/register/options", {}, "passkey.register"),
        ("delete", "/api/saas/security/passkeys/credential-test", {}, "passkey.delete"),
        ("delete", f"/api/saas/scans/{result_id}", {}, "scan.delete"),
        ("post", "/api/saas/cases", {"scan_result_id": result_id}, "case.create"),
        ("post", f"/api/saas/cases/{case['id']}/remediation-plan", {}, "case.remediation_plan"),
        ("patch", f"/api/saas/cases/{case['id']}", {"status": "triaged"}, "case.update"),
        (
            "post",
            "/api/saas/simulations/results",
            {"results": [{"recipient_ref": "finance-1", "outcome": "reported"}]},
            "simulation.ingest",
        ),
    ]
    for method, path, body, action in checks:
        if method == "post":
            response = _post_json_with_csrf(client, path, body)
        elif method == "patch":
            response = _patch_json_with_csrf(client, path, body)
        else:
            response = _delete_with_csrf(client, path)
        assert response.status_code == 403, path
        detail = response.json()["detail"]
        assert detail["passkey_required"] is True
        assert detail["action"] == action


def test_saas_case_api_links_scan_and_transitions_status(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    assert _signup(client).status_code == 200
    assert _upload(client).status_code == 200
    result_id = client.get("/api/saas/scans").json()["results"][0]["id"]

    created = _post_json_with_csrf(
        client,
        "/api/saas/cases",
        {
            "scan_result_id": result_id,
            "severity": "high",
            "note": "Manual pilot case",
        },
    )
    case_id = created.json()["case"]["id"]
    updated = _patch_json_with_csrf(
        client,
        f"/api/saas/cases/{case_id}",
        {
            "status": "triaged",
            "escalate": True,
            "escalation_reason": "Finance owner review",
        },
    )
    detail = client.get(f"/api/saas/cases/{case_id}")

    assert created.status_code == 200
    assert created.json()["case"]["scan_result_id"] == result_id
    assert updated.status_code == 200
    assert updated.json()["case"]["status"] == "triaged"
    assert updated.json()["case"]["escalation_reason"] == "Finance owner review"
    assert detail.json()["case"]["events"][0]["event_type"] == "created"
    assert detail.json()["case"]["events"][-1]["event_type"] == "escalated"


def test_saas_case_remediation_plan_is_audit_only_and_redacted(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    assert _signup(client).status_code == 200
    assert _upload(client).status_code == 200
    result_id = client.get("/api/saas/scans").json()["results"][0]["id"]
    case_id = _post_json_with_csrf(client, "/api/saas/cases", {"scan_result_id": result_id}).json()["case"]["id"]

    response = _post_json_with_csrf(client, f"/api/saas/cases/{case_id}/remediation-plan", {})
    detail = client.get(f"/api/saas/cases/{case_id}")
    serialized = json.dumps(response.json())

    assert response.status_code == 200
    plan = response.json()["plan"]
    assert plan["schema_version"] == "incident-remediation-plan.v1"
    assert plan["mode"] == "audit_only"
    assert "preserve-scan-evidence" in {action["id"] for action in plan["actions"]}
    assert "hold-payment-review" in {action["id"] for action in plan["actions"]}
    assert plan["non_goals"] == [
        "no_auto_delete",
        "no_auto_quarantine",
        "no_payment_authorization",
        "no_raw_message_body_returned",
    ]
    assert "raw_headers" not in serialized
    assert "body_html" not in serialized
    assert detail.json()["case"]["events"][-1]["event_type"] == "remediation_plan.generated"


def test_saas_simulation_results_ingest_updates_dashboard_summary(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    assert _signup(client).status_code == 200

    ingest = _post_json_with_csrf(
        client,
        "/api/saas/simulations/results",
        {
            "campaign_id": "may-pilot",
            "results": [
                {"recipient_ref": "alice@example.com", "outcome": "reported"},
                {"recipient_ref": "finance-seat-2", "outcome": "clicked"},
                {"recipient_ref": "finance-seat-3", "outcome": "submitted_credentials"},
            ],
        },
    )
    summary = client.get("/api/saas/simulations/summary")
    serialized = json.dumps(ingest.json())

    assert ingest.status_code == 200
    assert ingest.json()["ingested"] == 3
    assert summary.json()["summary"]["total"] == 3
    assert summary.json()["summary"]["reported"] == 1
    assert summary.json()["summary"]["clicked"] == 2
    assert summary.json()["summary"]["submitted_credentials"] == 1
    assert "alice@example.com" not in serialized


def test_saas_channel_scan_normalizes_sms_and_does_not_echo_raw_text(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    assert signup.status_code == 200

    response = _post_json_with_csrf(client, "/api/saas/analyze/channel", {
        "channel": "sms",
        "sender": "+61400111222",
        "text": "Secret callback code 123456 at https://example.test/pay",
        "timestamp": "2026-05-08T01:02:03+00:00",
    })

    assert response.status_code == 200
    payload = response.json()
    assert payload["channel"]["channel"] == "sms"
    assert payload["source"] == "manual_channel_scan"
    assert "Secret callback code" not in json.dumps(payload)


def test_saas_channel_scan_requires_csrf(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    assert signup.status_code == 200

    response = client.post("/api/saas/analyze/channel", json={
        "channel": "chat",
        "text": "Click https://example.test",
    })

    assert response.status_code in {400, 403}


def test_saas_channel_scan_obeys_manual_scan_quota(tmp_path):
    client = TestClient(_build_saas_app(tmp_path, signup_enabled=True), base_url="https://testserver")
    signup = _signup(client)
    account = signup.json()["account"]
    store = SaaSStore(tmp_path / "saas.db")
    for index in range(account["monthly_scan_quota"]):
        store.record_usage_event(
            org_id=account["org_id"],
            user_id=account["user_id"],
            feature_slug="manual_scan",
            idempotency_key=f"seed-{index}",
        )

    response = _post_json_with_csrf(client, "/api/saas/analyze/channel", {
        "channel": "voice_transcript",
        "transcript": "Call back the billing desk now.",
        "timestamp": "2026-05-08T01:02:03+00:00",
    })

    assert response.status_code == 402
