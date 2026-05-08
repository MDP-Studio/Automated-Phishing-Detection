"""Passkey/WebAuthn helpers for staged phishing-resistant step-up."""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from src.saas.database import SaaSStore


@dataclass(frozen=True)
class PasskeyRuntimeConfig:
    rp_id: str
    rp_name: str
    origin: str
    challenge_ttl_seconds: int
    step_up_ttl_seconds: int


def webauthn_available() -> bool:
    try:
        import webauthn  # noqa: F401
        return True
    except ImportError:
        return False


def passkey_config_from_request(request: Request) -> PasskeyRuntimeConfig:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    host = host.split(",", 1)[0].strip()
    hostname = host.split(":", 1)[0] if host else request.url.hostname or "localhost"
    scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",", 1)[0]
    origin = os.getenv("PASSKEY_ORIGIN", "").strip().rstrip("/") or f"{scheme}://{host}"
    rp_id = os.getenv("PASSKEY_RP_ID", "").strip() or hostname
    rp_name = os.getenv("PASSKEY_RP_NAME", "").strip() or "PhishAnalyze"
    return PasskeyRuntimeConfig(
        rp_id=rp_id,
        rp_name=rp_name,
        origin=origin,
        challenge_ttl_seconds=_env_int("PASSKEY_CHALLENGE_TTL_SECONDS", 300),
        step_up_ttl_seconds=_env_int("PASSKEY_STEP_UP_TTL_SECONDS", 600),
    )


def registration_options(store: SaaSStore, context, request: Request) -> dict[str, Any]:
    webauthn, structs, options_to_json, bytes_to_base64url, _ = _webauthn_imports()
    cfg = passkey_config_from_request(request)
    challenge = secrets.token_bytes(32)
    challenge_b64 = bytes_to_base64url(challenge)
    credentials = store.list_webauthn_credentials(org_id=context.org_id, user_id=context.user_id)
    options = webauthn.generate_registration_options(
        rp_id=cfg.rp_id,
        rp_name=cfg.rp_name,
        user_name=context.email,
        user_id=context.user_id.encode("utf-8"),
        user_display_name=context.email,
        challenge=challenge,
        timeout=cfg.challenge_ttl_seconds * 1000,
        authenticator_selection=structs.AuthenticatorSelectionCriteria(
            resident_key=structs.ResidentKeyRequirement.PREFERRED,
            user_verification=structs.UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            structs.PublicKeyCredentialDescriptor(id=_base64url_to_bytes(cred.credential_id))
            for cred in credentials
        ],
    )
    store.create_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="register",
        challenge=challenge_b64,
        ttl_seconds=cfg.challenge_ttl_seconds,
    )
    return {
        "options": json.loads(options_to_json(options)),
        "challenge": challenge_b64,
        "rp_id": cfg.rp_id,
        "origin": cfg.origin,
    }


def verify_registration(store: SaaSStore, context, request: Request, payload: dict[str, Any]) -> dict:
    webauthn, _, _, bytes_to_base64url, base64url_to_bytes = _webauthn_imports()
    cfg = passkey_config_from_request(request)
    credential = payload.get("credential") or payload.get("response")
    challenge = str(payload.get("challenge") or "").strip()
    if not isinstance(credential, dict) or not challenge:
        raise HTTPException(status_code=400, detail="Credential and challenge are required")
    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=cfg.rp_id,
            expected_origin=cfg.origin,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Passkey registration verification failed") from exc
    if not store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="register",
        challenge=challenge,
    ):
        raise HTTPException(status_code=400, detail="Passkey challenge expired or was already used")
    transports = _extract_transports(credential)
    record = store.add_webauthn_credential(
        org_id=context.org_id,
        user_id=context.user_id,
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key_b64=bytes_to_base64url(verified.credential_public_key),
        sign_count=int(verified.sign_count),
        transports=transports,
        aaguid=str(getattr(verified, "aaguid", "") or ""),
    )
    expires_at = store.record_passkey_step_up(
        org_id=context.org_id,
        user_id=context.user_id,
        ttl_seconds=cfg.step_up_ttl_seconds,
    )
    return {"credential": record.to_public_dict(), "step_up_expires_at": expires_at}


def authentication_options(store: SaaSStore, context, request: Request) -> dict[str, Any]:
    webauthn, structs, options_to_json, bytes_to_base64url, _ = _webauthn_imports()
    cfg = passkey_config_from_request(request)
    credentials = store.list_webauthn_credentials(org_id=context.org_id, user_id=context.user_id)
    if not credentials:
        raise HTTPException(status_code=409, detail="No passkey is registered for this user")
    challenge = secrets.token_bytes(32)
    challenge_b64 = bytes_to_base64url(challenge)
    options = webauthn.generate_authentication_options(
        rp_id=cfg.rp_id,
        challenge=challenge,
        timeout=cfg.challenge_ttl_seconds * 1000,
        allow_credentials=[
            structs.PublicKeyCredentialDescriptor(id=_base64url_to_bytes(cred.credential_id))
            for cred in credentials
        ],
        user_verification=structs.UserVerificationRequirement.REQUIRED,
    )
    store.create_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge=challenge_b64,
        ttl_seconds=cfg.challenge_ttl_seconds,
    )
    return {
        "options": json.loads(options_to_json(options)),
        "challenge": challenge_b64,
        "rp_id": cfg.rp_id,
        "origin": cfg.origin,
    }


def verify_authentication(store: SaaSStore, context, request: Request, payload: dict[str, Any]) -> dict:
    webauthn, _, _, _, base64url_to_bytes = _webauthn_imports()
    cfg = passkey_config_from_request(request)
    credential = payload.get("credential") or payload.get("response")
    challenge = str(payload.get("challenge") or "").strip()
    if not isinstance(credential, dict) or not challenge:
        raise HTTPException(status_code=400, detail="Credential and challenge are required")
    credential_id = str(credential.get("id") or credential.get("rawId") or "").strip()
    if not credential_id:
        raise HTTPException(status_code=400, detail="Credential ID is required")
    record = store.get_webauthn_credential(
        org_id=context.org_id,
        user_id=context.user_id,
        credential_id=credential_id,
    )
    if record is None:
        raise HTTPException(status_code=403, detail="Passkey credential is not registered for this user")
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=cfg.rp_id,
            expected_origin=cfg.origin,
            credential_public_key=base64url_to_bytes(record.public_key_b64),
            credential_current_sign_count=record.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Passkey authentication verification failed") from exc
    if not store.consume_webauthn_challenge(
        org_id=context.org_id,
        user_id=context.user_id,
        purpose="authenticate",
        challenge=challenge,
    ):
        raise HTTPException(status_code=400, detail="Passkey challenge expired or was already used")
    store.update_webauthn_credential_usage(
        org_id=context.org_id,
        user_id=context.user_id,
        credential_id=record.credential_id,
        sign_count=int(verified.new_sign_count),
    )
    expires_at = store.record_passkey_step_up(
        org_id=context.org_id,
        user_id=context.user_id,
        ttl_seconds=cfg.step_up_ttl_seconds,
    )
    return {"verified": True, "step_up_expires_at": expires_at}


def _webauthn_imports():
    try:
        import webauthn
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
        from webauthn.helpers import structs
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="WebAuthn support is not installed on this deployment",
        ) from exc
    return webauthn, structs, options_to_json, bytes_to_base64url, base64url_to_bytes


def _base64url_to_bytes(value: str) -> bytes:
    _, _, _, _, base64url_to_bytes = _webauthn_imports()
    return base64url_to_bytes(value)


def _extract_transports(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response") if isinstance(credential, dict) else {}
    transports = response.get("transports") if isinstance(response, dict) else []
    if not isinstance(transports, list):
        return []
    return [str(item) for item in transports if str(item)]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
