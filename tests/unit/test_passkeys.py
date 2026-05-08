from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from src.saas.database import SaaSStore
from src.saas.passkeys import verify_registration


def test_webauthn_challenge_is_single_use_and_tamper_resistant(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )
    store.create_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge="challenge-one",
    )

    assert store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge="tampered",
    ) is False
    assert store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge="challenge-one",
    ) is True
    assert store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge="challenge-one",
    ) is False


def test_webauthn_stale_challenge_is_rejected(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )
    store.create_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="register",
        challenge="old-challenge",
    )
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with store._connect() as conn:
        conn.execute(
            "UPDATE webauthn_challenges SET expires_at = ? WHERE challenge = ?",
            (expired, "old-challenge"),
        )
        conn.commit()

    assert store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="register",
        challenge="old-challenge",
    ) is False


def test_passkey_step_up_ttl_is_recorded(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )

    expires_at = store.record_passkey_step_up(
        org_id=context.org_id,
        user_id=context.user_id,
        ttl_seconds=120,
    )

    assert store.has_fresh_passkey_step_up(org_id=context.org_id, user_id=context.user_id) is True
    assert store.get_passkey_step_up(org_id=context.org_id, user_id=context.user_id)["expires_at"] == expires_at


def test_tampered_registration_credential_is_rejected(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_registration(
            store,
            context,
            request=type("Request", (), {
                "headers": {"host": "testserver"},
                "url": type("URL", (), {"scheme": "https", "netloc": "testserver", "hostname": "testserver"})(),
            })(),
            payload={"challenge": "bad", "credential": {"id": "bad", "type": "public-key", "response": {}}},
        )

    assert exc_info.value.status_code == 400
