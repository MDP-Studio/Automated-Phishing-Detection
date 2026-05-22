"""SQLite-backed SaaS account, tenant, subscription, and usage store."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from src.billing.entitlements import EntitlementDecision, feature_entitlement
from src.billing.plans import get_plan
from src.support.mailbox_guides import CONNECTABLE_MAILBOX_PROVIDERS, MAILBOX_PROVIDER_ERROR

ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}
WORKSPACE_ROLES = {"owner", "admin", "analyst", "viewer"}
BILLING_INTERVALS = {"monthly", "yearly"}
CASE_STATUSES = {"open", "triaged", "investigating", "contained", "closed"}
CASE_SEVERITIES = {"low", "medium", "high", "critical"}
CASE_STATUS_TRANSITIONS = {
    "open": {"triaged", "investigating", "closed"},
    "triaged": {"investigating", "contained", "closed"},
    "investigating": {"contained", "closed"},
    "contained": {"closed", "investigating"},
    "closed": {"investigating"},
}
SIMULATION_OUTCOMES = {
    "reported",
    "opened",
    "clicked",
    "submitted_credentials",
    "ignored",
}

logger = logging.getLogger(__name__)


def normalize_billing_interval(value: str | None) -> str:
    """Return the canonical billing interval used by account APIs."""
    interval = (value or "monthly").strip().lower()
    if interval == "annual":
        interval = "yearly"
    return interval if interval in BILLING_INTERVALS else "monthly"


class DuplicateEmailError(ValueError):
    """Raised when a signup tries to reuse an existing email address."""


class InvalidCredentialsError(ValueError):
    """Raised when email/password authentication fails."""


class PasswordResetTokenError(ValueError):
    """Raised when a password reset token is invalid, used, or expired."""


@dataclass(frozen=True)
class AccountContext:
    user_id: str
    email: str
    org_id: str
    org_name: str
    role: str
    plan_slug: str
    plan_name: str
    subscription_status: str
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    billing_interval: str
    current_period_end: str | None
    monthly_scan_quota: int
    monthly_scan_used: int
    monthly_scan_remaining: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MailAccountRecord:
    id: str
    org_id: str
    user_id: str
    provider: str
    external_account_id: str | None
    encrypted_token_ref: str | None
    status: str
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_public_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "external_account_id": self.external_account_id,
            "status": self.status,
            "created_at": self.created_at,
            "credential_saved": bool(self.encrypted_token_ref),
        }


@dataclass(frozen=True)
class TeamMemberRecord:
    user_id: str
    email: str
    role: str
    created_at: str

    def to_public_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class WebAuthnCredentialRecord:
    id: str
    org_id: str
    user_id: str
    credential_id: str
    public_key_b64: str
    sign_count: int
    transports: list[str]
    aaguid: str
    created_at: str
    last_used_at: str | None

    def to_public_dict(self) -> dict:
        return {
            "id": self.id,
            "credential_id": self.credential_id,
            "transports": self.transports,
            "aaguid": self.aaguid,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
        }


@dataclass(frozen=True)
class IncidentCaseRecord:
    id: str
    org_id: str
    scan_result_id: str
    scan_job_id: str | None
    email_id: str
    title: str
    status: str
    severity: str
    owner_user_id: str | None
    owner_email: str | None
    escalated_at: str | None
    escalation_reason: str | None
    created_at: str
    updated_at: str
    closed_at: str | None
    event_count: int = 0

    def to_public_dict(self) -> dict:
        return asdict(self)


class SaaSStore:
    """Small production-shaped account store for local SQLite deployments."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)
            self._ensure_schema(conn)
            conn.execute("PRAGMA user_version = 1")
            conn.commit()

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Apply additive migrations for existing SQLite deployments."""
        subscription_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(subscriptions)").fetchall()
        }
        if "billing_interval" not in subscription_columns:
            conn.execute(
                "ALTER TABLE subscriptions "
                "ADD COLUMN billing_interval TEXT NOT NULL DEFAULT 'monthly'"
            )

    def create_user_with_org(
        self,
        *,
        email: str,
        password: str,
        org_name: str | None = None,
        plan_slug: str = "free",
    ) -> AccountContext:
        normalized_email = normalize_email(email)
        validate_password(password)
        plan = get_plan(plan_slug)
        now = utc_now_iso()
        user_id = new_id("usr")
        org_id = new_id("org")
        organization_name = (org_name or normalized_email.split("@", 1)[0] or "Workspace").strip()
        password_hash = hash_password(password)

        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, normalized_email, password_hash, now),
                )
                conn.execute(
                    """
                    INSERT INTO organizations (id, name, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (org_id, organization_name, now),
                )
                conn.execute(
                    """
                    INSERT INTO memberships (user_id, org_id, role, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, org_id, "owner", now),
                )
                conn.execute(
                    """
                    INSERT INTO subscriptions (
                        org_id, plan_slug, status, billing_interval, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (org_id, plan.slug, "active", "monthly", now),
                )
                self._write_audit(
                    conn,
                    org_id=org_id,
                    actor_user_id=user_id,
                    action="user.signup",
                    target_type="user",
                    target_id=user_id,
                    metadata={"plan_slug": plan.slug},
                    now=now,
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if "users.email" in str(exc):
                raise DuplicateEmailError("email already exists") from exc
            raise

        context = self.get_account_context(user_id)
        if context is None:
            raise RuntimeError("created account could not be loaded")
        return context

    def authenticate(self, email: str, password: str) -> AccountContext:
        normalized_email = normalize_email(email)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, password_hash, disabled_at FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if row is None or row["disabled_at"]:
                raise InvalidCredentialsError("invalid email or password")
            if not verify_password(password, row["password_hash"]):
                raise InvalidCredentialsError("invalid email or password")
            context = self.get_account_context(row["id"])
            if context is None:
                raise InvalidCredentialsError("account has no active organization")
            self._write_audit(
                conn,
                org_id=context.org_id,
                actor_user_id=context.user_id,
                action="user.login",
                target_type="user",
                target_id=context.user_id,
                metadata={},
                now=utc_now_iso(),
            )
            conn.commit()
            return context

    def create_password_reset_token(
        self,
        email: str,
        *,
        ttl_minutes: int = 30,
    ) -> str | None:
        normalized_email = normalize_email(email)
        token = secrets.token_urlsafe(32)
        token_hash = hash_reset_token(token)
        now = utc_now_iso()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()

        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, disabled_at FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if row is None or row["disabled_at"]:
                return None
            conn.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = ?
                WHERE user_id = ? AND used_at IS NULL
                """,
                (now, row["id"]),
            )
            conn.execute(
                """
                INSERT INTO password_reset_tokens (
                    id, user_id, token_hash, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (new_id("prt"), row["id"], token_hash, now, expires_at),
            )
            conn.commit()
        return token

    def reset_password_with_token(self, token: str, new_password: str) -> AccountContext:
        validate_password(new_password)
        token_hash = hash_reset_token(token)
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at, u.disabled_at
                FROM password_reset_tokens prt
                JOIN users u ON u.id = prt.user_id
                WHERE prt.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None or row["used_at"] or row["disabled_at"]:
                raise PasswordResetTokenError("invalid or expired reset token")
            try:
                expires_at = datetime.fromisoformat(row["expires_at"])
            except ValueError as exc:
                raise PasswordResetTokenError("invalid or expired reset token") from exc
            if expires_at < now_dt:
                conn.execute(
                    "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                conn.commit()
                raise PasswordResetTokenError("invalid or expired reset token")

            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new_password), row["user_id"]),
            )
            conn.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = ?
                WHERE user_id = ? AND used_at IS NULL
                """,
                (now, row["user_id"]),
            )
            org_row = conn.execute(
                """
                SELECT org_id FROM memberships
                WHERE user_id = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (row["user_id"],),
            ).fetchone()
            if org_row is not None:
                self._write_audit(
                    conn,
                    org_id=org_row["org_id"],
                    actor_user_id=row["user_id"],
                    action="user.password_reset",
                    target_type="user",
                    target_id=row["user_id"],
                    metadata={},
                    now=now,
                )
            conn.commit()

        context = self.get_account_context(row["user_id"])
        if context is None:
            raise PasswordResetTokenError("invalid or expired reset token")
        return context

    def get_account_context(self, user_id: str) -> AccountContext | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    u.id AS user_id,
                    u.email,
                    o.id AS org_id,
                    o.name AS org_name,
                    o.stripe_customer_id,
                    m.role,
                    COALESCE(s.plan_slug, 'free') AS plan_slug,
                    COALESCE(s.status, 'active') AS subscription_status,
                    s.stripe_subscription_id,
                    COALESCE(s.billing_interval, 'monthly') AS billing_interval,
                    s.current_period_end
                FROM users u
                JOIN memberships m ON m.user_id = u.id
                JOIN organizations o ON o.id = m.org_id
                LEFT JOIN subscriptions s ON s.org_id = o.id
                WHERE u.id = ? AND u.disabled_at IS NULL
                ORDER BY m.created_at ASC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            if row is None:
                return None

            plan_slug = row["plan_slug"] or "free"
            if row["subscription_status"] not in ACTIVE_SUBSCRIPTION_STATUSES and plan_slug != "free":
                plan_slug = "free"
            plan = get_plan(plan_slug)
            used = self.monthly_usage_count(
                row["org_id"],
                "manual_scan",
                conn=conn,
            )
            return AccountContext(
                user_id=row["user_id"],
                email=row["email"],
                org_id=row["org_id"],
                org_name=row["org_name"],
                role=row["role"],
                plan_slug=plan.slug,
                plan_name=plan.name,
                subscription_status=row["subscription_status"],
                stripe_customer_id=row["stripe_customer_id"],
                stripe_subscription_id=row["stripe_subscription_id"],
                billing_interval=normalize_billing_interval(row["billing_interval"]),
                current_period_end=row["current_period_end"],
                monthly_scan_quota=plan.scan_quota,
                monthly_scan_used=used,
                monthly_scan_remaining=max(plan.scan_quota - used, 0),
            )

    def set_subscription(
        self,
        *,
        org_id: str,
        plan_slug: str,
        status: str = "active",
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        billing_interval: str = "monthly",
        current_period_end: str | None = None,
    ) -> None:
        plan = get_plan(plan_slug)
        billing_interval = normalize_billing_interval(billing_interval)
        now = utc_now_iso()
        with self._connect() as conn:
            if stripe_customer_id:
                conn.execute(
                    "UPDATE organizations SET stripe_customer_id = ? WHERE id = ?",
                    (stripe_customer_id, org_id),
                )
            conn.execute(
                """
                INSERT INTO subscriptions (
                    org_id, stripe_subscription_id, plan_slug, status,
                    billing_interval, current_period_end, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    stripe_subscription_id = excluded.stripe_subscription_id,
                    plan_slug = excluded.plan_slug,
                    status = excluded.status,
                    billing_interval = excluded.billing_interval,
                    current_period_end = excluded.current_period_end,
                    updated_at = excluded.updated_at
                """,
                (
                    org_id,
                    stripe_subscription_id,
                    plan.slug,
                    status,
                    billing_interval,
                    current_period_end,
                    now,
                ),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=None,
                action="subscription.updated",
                target_type="subscription",
                target_id=org_id,
                metadata={
                    "plan_slug": plan.slug,
                    "status": status,
                    "billing_interval": billing_interval,
                    "current_period_end": current_period_end,
                },
                now=now,
            )
            conn.commit()

    def set_org_stripe_customer(self, *, org_id: str, stripe_customer_id: str) -> None:
        """Persist the Stripe customer that owns an organization's billing."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE organizations SET stripe_customer_id = ? WHERE id = ?",
                (stripe_customer_id, org_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=None,
                action="stripe.customer.linked",
                target_type="stripe_customer",
                target_id=stripe_customer_id,
                metadata={},
                now=utc_now_iso(),
            )
            conn.commit()

    def list_org_members(self, org_id: str) -> list[TeamMemberRecord]:
        """Return active workspace members without password or session data."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT u.id AS user_id, u.email, m.role, m.created_at
                FROM memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.org_id = ? AND u.disabled_at IS NULL
                ORDER BY
                    CASE m.role
                        WHEN 'owner' THEN 0
                        WHEN 'admin' THEN 1
                        WHEN 'analyst' THEN 2
                        ELSE 3
                    END,
                    u.email ASC
                """,
                (org_id,),
            ).fetchall()
            return [
                TeamMemberRecord(
                    user_id=row["user_id"],
                    email=row["email"],
                    role=row["role"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def add_org_member(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        email: str,
        password: str,
        role: str = "analyst",
    ) -> TeamMemberRecord:
        """Create or attach a user to an organization with a scoped role."""
        normalized_email = normalize_email(email)
        validate_password(password)
        role = _validate_workspace_role(role)
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, disabled_at FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if row is None:
                user_id = new_id("usr")
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, normalized_email, hash_password(password), now),
                )
            elif row["disabled_at"]:
                raise ValueError("user account is disabled")
            else:
                user_id = row["id"]
            existing = conn.execute(
                "SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?",
                (org_id, user_id),
            ).fetchone()
            if existing is not None:
                raise ValueError("user is already a member of this workspace")
            conn.execute(
                """
                INSERT INTO memberships (user_id, org_id, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, org_id, role, now),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="team.member_added",
                target_type="user",
                target_id=user_id,
                metadata={"role": role},
                now=now,
            )
            conn.commit()
            return TeamMemberRecord(
                user_id=user_id,
                email=normalized_email,
                role=role,
                created_at=now,
            )

    def update_org_member_role(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        target_user_id: str,
        role: str,
    ) -> TeamMemberRecord:
        """Update a member role while preserving at least one owner."""
        role = _validate_workspace_role(role)
        now = utc_now_iso()
        with self._connect() as conn:
            current = conn.execute(
                """
                SELECT u.email, m.role, m.created_at
                FROM memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.org_id = ? AND m.user_id = ? AND u.disabled_at IS NULL
                """,
                (org_id, target_user_id),
            ).fetchone()
            if current is None:
                raise ValueError("member not found")
            if current["role"] == "owner" and role != "owner":
                owner_count = self._owner_count(conn, org_id)
                if owner_count <= 1:
                    raise ValueError("workspace must keep at least one owner")
            conn.execute(
                """
                UPDATE memberships
                SET role = ?
                WHERE org_id = ? AND user_id = ?
                """,
                (role, org_id, target_user_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="team.role_updated",
                target_type="user",
                target_id=target_user_id,
                metadata={"role": role},
                now=now,
            )
            conn.commit()
            return TeamMemberRecord(
                user_id=target_user_id,
                email=current["email"],
                role=role,
                created_at=current["created_at"],
            )

    def remove_org_member(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        target_user_id: str,
    ) -> bool:
        """Remove a workspace membership without deleting the user account."""
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
                (org_id, target_user_id),
            ).fetchone()
            if row is None:
                return False
            if row["role"] == "owner" and self._owner_count(conn, org_id) <= 1:
                raise ValueError("workspace must keep at least one owner")
            conn.execute(
                "DELETE FROM memberships WHERE org_id = ? AND user_id = ?",
                (org_id, target_user_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="team.member_removed",
                target_type="user",
                target_id=target_user_id,
                metadata={"role": row["role"]},
                now=now,
            )
            conn.commit()
            return True

    def get_org_id_for_stripe_customer(self, stripe_customer_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM organizations WHERE stripe_customer_id = ?",
                (stripe_customer_id,),
            ).fetchone()
            return row["id"] if row else None

    def get_org_id_for_stripe_subscription(self, stripe_subscription_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT org_id FROM subscriptions WHERE stripe_subscription_id = ?",
                (stripe_subscription_id,),
            ).fetchone()
            return row["org_id"] if row else None

    def check_entitlement(
        self,
        *,
        org_id: str,
        user_id: str | None,
        feature_slug: str,
        enforce_scan_quota: bool = False,
        audit_lock: bool = True,
    ) -> EntitlementDecision:
        with self._connect() as conn:
            plan_slug = self._org_plan_slug(org_id, conn)
            used = self.monthly_usage_count(org_id, "manual_scan", conn=conn)
            decision = feature_entitlement(
                plan_slug,
                feature_slug,
                monthly_scan_used=used,
                enforce_scan_quota=enforce_scan_quota,
            )
            if audit_lock and not decision.available:
                now = utc_now_iso()
                conn.execute(
                    """
                    INSERT INTO feature_locks (
                        id, org_id, user_id, feature_slug, required_plan, reason, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id("lock"),
                        org_id,
                        user_id,
                        decision.feature_slug,
                        decision.required_plan,
                        decision.reason,
                        now,
                    ),
                )
                self._write_audit(
                    conn,
                    org_id=org_id,
                    actor_user_id=user_id,
                    action="feature.locked",
                    target_type="feature",
                    target_id=decision.feature_slug,
                    metadata=decision.to_dict(),
                    now=now,
                )
                conn.commit()
            return decision

    def record_usage_event(
        self,
        *,
        org_id: str,
        user_id: str | None,
        feature_slug: str,
        quantity: int = 1,
        idempotency_key: str | None = None,
    ) -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO usage_events (
                    id, org_id, user_id, feature_slug, quantity, occurred_at, idempotency_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("use"),
                    org_id,
                    user_id,
                    feature_slug,
                    quantity,
                    now,
                    idempotency_key,
                ),
            )
            conn.commit()

    def create_scan_job(
        self,
        *,
        org_id: str,
        user_id: str,
        source: str,
        mail_account_id: str | None = None,
    ) -> str:
        scan_job_id = new_id("scan")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs (
                    id, org_id, user_id, mail_account_id, status, source, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_job_id, org_id, user_id, mail_account_id, "running", source, utc_now_iso()),
            )
            conn.commit()
        return scan_job_id

    def register_mail_account(
        self,
        *,
        org_id: str,
        user_id: str,
        provider: str,
        external_account_id: str | None,
        encrypted_token_ref: str | None,
        status: str = "pending",
    ) -> MailAccountRecord:
        provider = (provider or "").strip().lower()
        if provider not in CONNECTABLE_MAILBOX_PROVIDERS:
            raise ValueError(MAILBOX_PROVIDER_ERROR)
        if status not in {"pending", "active", "error", "disabled"}:
            raise ValueError("status must be pending, active, error, or disabled")

        now = utc_now_iso()
        mail_account_id = new_id("mail")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO mail_accounts (
                    id, org_id, user_id, provider, external_account_id,
                    encrypted_token_ref, status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mail_account_id,
                    org_id,
                    user_id,
                    provider,
                    external_account_id,
                    encrypted_token_ref,
                    status,
                    now,
                ),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="mail_account.registered",
                target_type="mail_account",
                target_id=mail_account_id,
                metadata={"provider": provider, "status": status},
                now=now,
            )
            conn.commit()
        return MailAccountRecord(
            id=mail_account_id,
            org_id=org_id,
            user_id=user_id,
            provider=provider,
            external_account_id=external_account_id,
            encrypted_token_ref=encrypted_token_ref,
            status=status,
            created_at=now,
        )

    def list_mail_accounts(self, org_id: str) -> list[MailAccountRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, org_id, user_id, provider, external_account_id,
                       encrypted_token_ref, status, created_at
                FROM mail_accounts
                WHERE org_id = ?
                ORDER BY created_at DESC
                """,
                (org_id,),
            ).fetchall()
            return [
                MailAccountRecord(
                    id=row["id"],
                    org_id=row["org_id"],
                    user_id=row["user_id"],
                    provider=row["provider"],
                    external_account_id=row["external_account_id"],
                    encrypted_token_ref=row["encrypted_token_ref"],
                    status=row["status"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def get_mail_account(self, *, org_id: str, mail_account_id: str) -> MailAccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, org_id, user_id, provider, external_account_id,
                       encrypted_token_ref, status, created_at
                FROM mail_accounts
                WHERE org_id = ? AND id = ?
                """,
                (org_id, mail_account_id),
            ).fetchone()
            if row is None:
                return None
            return MailAccountRecord(
                id=row["id"],
                org_id=row["org_id"],
                user_id=row["user_id"],
                provider=row["provider"],
                external_account_id=row["external_account_id"],
                encrypted_token_ref=row["encrypted_token_ref"],
                status=row["status"],
                created_at=row["created_at"],
            )

    def set_mail_account_status(
        self,
        *,
        org_id: str,
        mail_account_id: str,
        status: str,
        actor_user_id: str | None = None,
    ) -> None:
        if status not in {"pending", "active", "error", "disabled"}:
            raise ValueError("status must be pending, active, error, or disabled")
        now = utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE mail_accounts
                SET status = ?
                WHERE id = ? AND org_id = ?
                """,
                (status, mail_account_id, org_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("mail account not found for organization")
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="mail_account.status_updated",
                target_type="mail_account",
                target_id=mail_account_id,
                metadata={"status": status},
                now=now,
            )
            conn.commit()

    def delete_mail_account(
        self,
        *,
        org_id: str,
        user_id: str,
        mail_account_id: str,
    ) -> bool:
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, provider, external_account_id
                FROM mail_accounts
                WHERE id = ? AND org_id = ?
                """,
                (mail_account_id, org_id),
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                "DELETE FROM mail_accounts WHERE id = ? AND org_id = ?",
                (mail_account_id, org_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="mail_account.deleted",
                target_type="mail_account",
                target_id=mail_account_id,
                metadata={
                    "provider": row["provider"],
                    "external_account_id": row["external_account_id"],
                },
                now=now,
            )
            conn.commit()
            return True

    def complete_scan_job(self, scan_job_id: str, status: str = "completed") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status = ?, completed_at = ? WHERE id = ?",
                (status, utc_now_iso(), scan_job_id),
            )
            conn.commit()

    def record_scan_result(
        self,
        *,
        org_id: str,
        user_id: str,
        scan_job_id: str,
        email_id: str,
        verdict: str,
        payment_decision: str | None,
        result: dict,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_results (
                    id, org_id, user_id, scan_job_id, email_id, verdict,
                    payment_decision, result_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("res"),
                    org_id,
                    user_id,
                    scan_job_id,
                    email_id,
                    verdict,
                    payment_decision,
                    json.dumps(result, default=str),
                    utc_now_iso(),
                ),
            )
            conn.commit()

    def list_scan_results(self, org_id: str, *, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, email_id, verdict, payment_decision, result_json, created_at
                FROM scan_results
                WHERE org_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "email_id": row["email_id"],
                    "verdict": row["verdict"],
                    "payment_decision": row["payment_decision"],
                    "created_at": row["created_at"],
                    "result": json.loads(row["result_json"]),
                }
                for row in rows
            ]

    def delete_scan_result(self, *, org_id: str, user_id: str, result_id: str) -> bool:
        """Delete one stored scan result scoped to an organization.

        Usage rows are intentionally kept so deleting history cannot reset quota.
        """
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, scan_job_id, email_id
                FROM scan_results
                WHERE id = ? AND org_id = ?
                """,
                (result_id, org_id),
            ).fetchone()
            if row is None:
                return False

            conn.execute(
                "DELETE FROM scan_results WHERE id = ? AND org_id = ?",
                (result_id, org_id),
            )
            conn.execute(
                """
                DELETE FROM scan_jobs
                WHERE id = ? AND org_id = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM scan_results WHERE scan_job_id = scan_jobs.id
                  )
                """,
                (row["scan_job_id"], org_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="scan_result.deleted",
                target_type="scan_result",
                target_id=result_id,
                metadata={"email_id": row["email_id"]},
                now=now,
            )
            conn.commit()
            return True

    def create_incident_case(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        scan_result_id: str,
        owner_user_id: str | None = None,
        severity: str = "medium",
        title: str | None = None,
        note: str | None = None,
    ) -> dict:
        """Open a lightweight incident case tied to an existing scan result."""
        severity = _validate_case_severity(severity)
        now = utc_now_iso()
        case_id = new_id("case")
        with self._connect() as conn:
            scan = conn.execute(
                """
                SELECT id, scan_job_id, email_id, verdict, payment_decision, result_json
                FROM scan_results
                WHERE id = ? AND org_id = ?
                """,
                (scan_result_id, org_id),
            ).fetchone()
            if scan is None:
                raise ValueError("scan result not found")

            owner_user_id = owner_user_id or actor_user_id
            if owner_user_id and not self._user_is_org_member(conn, org_id, owner_user_id):
                raise ValueError("case owner must be a workspace member")

            subject = _scan_result_subject(scan["result_json"])
            case_title = _clean_short_text(title or subject or f"Incident for {scan['email_id']}", 160)
            conn.execute(
                """
                INSERT INTO incident_cases (
                    id, org_id, scan_result_id, scan_job_id, email_id, title, status,
                    severity, owner_user_id, escalated_at, escalation_reason,
                    created_at, updated_at, closed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL)
                """,
                (
                    case_id,
                    org_id,
                    scan["id"],
                    scan["scan_job_id"],
                    scan["email_id"],
                    case_title,
                    "open",
                    severity,
                    owner_user_id,
                    now,
                    now,
                ),
            )
            self._write_case_event(
                conn,
                case_id=case_id,
                org_id=org_id,
                actor_user_id=actor_user_id,
                event_type="created",
                from_status=None,
                to_status="open",
                note=note,
                evidence={
                    "scan_result_id": scan["id"],
                    "scan_job_id": scan["scan_job_id"],
                    "email_id": scan["email_id"],
                    "verdict": scan["verdict"],
                    "payment_decision": scan["payment_decision"],
                    "subject": subject,
                },
                now=now,
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="incident_case.created",
                target_type="incident_case",
                target_id=case_id,
                metadata={
                    "scan_result_id": scan["id"],
                    "status": "open",
                    "severity": severity,
                },
                now=now,
            )
            conn.commit()
        case = self.get_incident_case(org_id=org_id, case_id=case_id)
        if case is None:
            raise RuntimeError("created incident case could not be loaded")
        return case

    def list_incident_cases(self, org_id: str, *, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit or 50), 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*, u.email AS owner_email,
                       COUNT(e.id) AS event_count
                FROM incident_cases c
                LEFT JOIN users u ON u.id = c.owner_user_id
                LEFT JOIN incident_case_events e ON e.case_id = c.id
                WHERE c.org_id = ?
                GROUP BY c.id
                ORDER BY c.updated_at DESC, c.created_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
            return [self._incident_case_record_from_row(row).to_public_dict() for row in rows]

    def get_incident_case(self, *, org_id: str, case_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT c.*, u.email AS owner_email,
                       (
                           SELECT COUNT(*)
                           FROM incident_case_events e
                           WHERE e.case_id = c.id
                       ) AS event_count
                FROM incident_cases c
                LEFT JOIN users u ON u.id = c.owner_user_id
                WHERE c.id = ? AND c.org_id = ?
                """,
                (case_id, org_id),
            ).fetchone()
            if row is None:
                return None
            events = conn.execute(
                """
                SELECT id, event_type, from_status, to_status, note,
                       evidence_json, created_at
                FROM incident_case_events
                WHERE case_id = ? AND org_id = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (case_id, org_id),
            ).fetchall()
            payload = self._incident_case_record_from_row(row).to_public_dict()
            payload["events"] = [
                {
                    "id": event["id"],
                    "event_type": event["event_type"],
                    "from_status": event["from_status"],
                    "to_status": event["to_status"],
                    "note": event["note"],
                    "evidence": _safe_json_dict(event["evidence_json"]),
                    "created_at": event["created_at"],
                }
                for event in events
            ]
            return payload

    def update_incident_case(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        case_id: str,
        status: str | None = None,
        owner_user_id: str | None = None,
        severity: str | None = None,
        escalate: bool = False,
        escalation_reason: str | None = None,
        note: str | None = None,
    ) -> dict:
        """Apply a small incident workflow update and append immutable events."""
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM incident_cases
                WHERE id = ? AND org_id = ?
                """,
                (case_id, org_id),
            ).fetchone()
            if row is None:
                raise ValueError("incident case not found")

            updates: dict[str, object] = {"updated_at": now}
            current_status = row["status"]
            if status is not None:
                next_status = _validate_case_status(status)
                if next_status != current_status:
                    allowed = CASE_STATUS_TRANSITIONS.get(current_status, set())
                    if next_status not in allowed:
                        raise ValueError(
                            f"case status cannot move from {current_status} to {next_status}"
                        )
                    updates["status"] = next_status
                    updates["closed_at"] = now if next_status == "closed" else None
                    self._write_case_event(
                        conn,
                        case_id=case_id,
                        org_id=org_id,
                        actor_user_id=actor_user_id,
                        event_type="status_changed",
                        from_status=current_status,
                        to_status=next_status,
                        note=note,
                        evidence={},
                        now=now,
                    )

            if owner_user_id is not None and owner_user_id != row["owner_user_id"]:
                if not self._user_is_org_member(conn, org_id, owner_user_id):
                    raise ValueError("case owner must be a workspace member")
                updates["owner_user_id"] = owner_user_id
                self._write_case_event(
                    conn,
                    case_id=case_id,
                    org_id=org_id,
                    actor_user_id=actor_user_id,
                    event_type="owner_changed",
                    from_status=None,
                    to_status=None,
                    note=note,
                    evidence={
                        "from_owner_user_id": row["owner_user_id"],
                        "to_owner_user_id": owner_user_id,
                    },
                    now=now,
                )

            if severity is not None:
                next_severity = _validate_case_severity(severity)
                if next_severity != row["severity"]:
                    updates["severity"] = next_severity
                    self._write_case_event(
                        conn,
                        case_id=case_id,
                        org_id=org_id,
                        actor_user_id=actor_user_id,
                        event_type="severity_changed",
                        from_status=None,
                        to_status=None,
                        note=note,
                        evidence={
                            "from_severity": row["severity"],
                            "to_severity": next_severity,
                        },
                        now=now,
                    )

            clean_note = _clean_note(note)
            if escalate:
                reason = _clean_short_text(escalation_reason or note or "Escalated for review", 240)
                updates["escalated_at"] = row["escalated_at"] or now
                updates["escalation_reason"] = reason
                self._write_case_event(
                    conn,
                    case_id=case_id,
                    org_id=org_id,
                    actor_user_id=actor_user_id,
                    event_type="escalated",
                    from_status=row["status"],
                    to_status=updates.get("status", row["status"]),
                    note=clean_note,
                    evidence={"reason": reason},
                    now=now,
                )
            elif clean_note and not any(
                key in updates for key in {"status", "owner_user_id", "severity"}
            ):
                self._write_case_event(
                    conn,
                    case_id=case_id,
                    org_id=org_id,
                    actor_user_id=actor_user_id,
                    event_type="note",
                    from_status=None,
                    to_status=None,
                    note=clean_note,
                    evidence={},
                    now=now,
                )

            assignments = ", ".join(f"{name} = ?" for name in updates)
            values = list(updates.values()) + [case_id, org_id]
            conn.execute(
                f"UPDATE incident_cases SET {assignments} WHERE id = ? AND org_id = ?",
                values,
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="incident_case.updated",
                target_type="incident_case",
                target_id=case_id,
                metadata={
                    "status": updates.get("status", row["status"]),
                    "severity": updates.get("severity", row["severity"]),
                    "escalated": bool(updates.get("escalated_at") or row["escalated_at"]),
                },
                now=now,
            )
            conn.commit()
        case = self.get_incident_case(org_id=org_id, case_id=case_id)
        if case is None:
            raise RuntimeError("updated incident case could not be loaded")
        return case

    def record_simulation_results(
        self,
        *,
        org_id: str,
        actor_user_id: str,
        results: list[dict],
        campaign_id: str | None = None,
    ) -> list[dict]:
        """Ingest compact awareness simulation outcomes without storing message bodies."""
        if not results:
            raise ValueError("at least one simulation result is required")
        if len(results) > 250:
            raise ValueError("ingest at most 250 simulation results per request")
        now = utc_now_iso()
        saved: list[dict] = []
        with self._connect() as conn:
            for item in results:
                if not isinstance(item, dict):
                    raise ValueError("simulation results must be JSON objects")
                normalized = _normalize_simulation_result(item, org_id=org_id)
                result_id = new_id("sim")
                row_campaign_id = _clean_short_text(
                    str(item.get("campaign_id") or campaign_id or "default"), 80
                )
                conn.execute(
                    """
                    INSERT INTO simulation_results (
                        id, org_id, actor_user_id, campaign_id, recipient_ref,
                        scenario, outcome, reported, clicked,
                        submitted_credentials, opened, detected_by_user,
                        occurred_at, metadata_json, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result_id,
                        org_id,
                        actor_user_id,
                        row_campaign_id,
                        normalized["recipient_ref"],
                        normalized["scenario"],
                        normalized["outcome"],
                        int(normalized["reported"]),
                        int(normalized["clicked"]),
                        int(normalized["submitted_credentials"]),
                        int(normalized["opened"]),
                        int(normalized["detected_by_user"]),
                        normalized["occurred_at"],
                        json.dumps(normalized["metadata"], default=str),
                        now,
                    ),
                )
                saved.append(
                    {
                        "id": result_id,
                        "campaign_id": row_campaign_id,
                        "recipient_ref": normalized["recipient_ref"],
                        "scenario": normalized["scenario"],
                        "outcome": normalized["outcome"],
                        "occurred_at": normalized["occurred_at"],
                    }
                )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="simulation_results.ingested",
                target_type="simulation_campaign",
                target_id=campaign_id or "default",
                metadata={"count": len(saved)},
                now=now,
            )
            conn.commit()
        return saved

    def simulation_summary(self, org_id: str, *, days: int = 90) -> dict:
        days = max(1, min(int(days or 90), 365))
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(reported), 0) AS reported,
                    COALESCE(SUM(clicked), 0) AS clicked,
                    COALESCE(SUM(submitted_credentials), 0) AS submitted_credentials,
                    COALESCE(SUM(opened), 0) AS opened,
                    COALESCE(SUM(detected_by_user), 0) AS detected_by_user,
                    MAX(occurred_at) AS last_result_at
                FROM simulation_results
                WHERE org_id = ? AND occurred_at >= ?
                """,
                (org_id, since),
            ).fetchone()
            by_outcome = [
                {"name": item["outcome"], "count": int(item["count"] or 0)}
                for item in conn.execute(
                    """
                    SELECT outcome, COUNT(*) AS count
                    FROM simulation_results
                    WHERE org_id = ? AND occurred_at >= ?
                    GROUP BY outcome
                    ORDER BY count DESC, outcome ASC
                    """,
                    (org_id, since),
                ).fetchall()
            ]

        total = int(row["total"] or 0)
        reported = int(row["reported"] or 0)
        clicked = int(row["clicked"] or 0)
        submitted = int(row["submitted_credentials"] or 0)
        opened = int(row["opened"] or 0)
        detected = int(row["detected_by_user"] or 0)
        if total:
            report_rate = reported / total
            click_rate = clicked / total
            credential_rate = submitted / total
            risk_score = round(
                min(
                    100,
                    max(
                        0,
                        (click_rate * 45)
                        + (credential_rate * 45)
                        + ((1 - report_rate) * 10),
                    ),
                )
            )
        else:
            report_rate = click_rate = credential_rate = 0.0
            risk_score = None
        return {
            "window_days": days,
            "status": "pilot_ready" if total >= 10 else "needs_pilot",
            "target_sample_size": 10,
            "total": total,
            "reported": reported,
            "clicked": clicked,
            "submitted_credentials": submitted,
            "opened": opened,
            "detected_by_user": detected,
            "report_rate": round(report_rate, 4),
            "click_rate": round(click_rate, 4),
            "credential_submission_rate": round(credential_rate, 4),
            "risk_score": risk_score,
            "risk_level": _simulation_risk_level(risk_score),
            "last_result_at": row["last_result_at"],
            "by_outcome": by_outcome,
        }

    def admin_overview(self, *, audit_limit: int = 20) -> dict:
        """Return privacy-preserving aggregate SaaS state for owner/admin views.

        This intentionally avoids raw emails, result JSON, mailbox credentials,
        Stripe identifiers, external mailbox IDs, and audit metadata. Admins get
        counts and redacted org references for operations without reading
        customer mail content.
        """
        audit_limit = max(1, min(int(audit_limit or 20), 100))
        with self._connect() as conn:
            total_users = int(
                conn.execute(
                    "SELECT COUNT(*) AS count FROM users WHERE disabled_at IS NULL"
                ).fetchone()["count"]
                or 0
            )
            total_orgs = int(
                conn.execute("SELECT COUNT(*) AS count FROM organizations").fetchone()["count"]
                or 0
            )
            total_scans = int(
                conn.execute("SELECT COUNT(*) AS count FROM scan_results").fetchone()["count"]
                or 0
            )
            total_mailboxes = int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM mail_accounts
                    WHERE status != 'disabled'
                    """
                ).fetchone()["count"]
                or 0
            )
            total_cases = int(
                conn.execute("SELECT COUNT(*) AS count FROM incident_cases").fetchone()["count"]
                or 0
            )
            total_simulations = int(
                conn.execute("SELECT COUNT(*) AS count FROM simulation_results").fetchone()["count"]
                or 0
            )

            def grouped(query: str, params: tuple = ()) -> list[dict]:
                return [
                    {"name": row["name"], "count": int(row["count"] or 0)}
                    for row in conn.execute(query, params).fetchall()
                ]

            plans = grouped(
                """
                SELECT COALESCE(plan_slug, 'free') AS name, COUNT(*) AS count
                FROM subscriptions
                GROUP BY COALESCE(plan_slug, 'free')
                ORDER BY count DESC, name ASC
                """
            )
            subscription_status = grouped(
                """
                SELECT COALESCE(status, 'unknown') AS name, COUNT(*) AS count
                FROM subscriptions
                GROUP BY COALESCE(status, 'unknown')
                ORDER BY count DESC, name ASC
                """
            )
            verdicts = grouped(
                """
                SELECT verdict AS name, COUNT(*) AS count
                FROM scan_results
                GROUP BY verdict
                ORDER BY count DESC, name ASC
                """
            )
            payment_decisions = grouped(
                """
                SELECT COALESCE(payment_decision, 'not_payment_specific') AS name, COUNT(*) AS count
                FROM scan_results
                GROUP BY COALESCE(payment_decision, 'not_payment_specific')
                ORDER BY count DESC, name ASC
                """
            )
            mailboxes_by_status = grouped(
                """
                SELECT status AS name, COUNT(*) AS count
                FROM mail_accounts
                GROUP BY status
                ORDER BY count DESC, name ASC
                """
            )
            mailboxes_by_provider = grouped(
                """
                SELECT provider AS name, COUNT(*) AS count
                FROM mail_accounts
                GROUP BY provider
                ORDER BY count DESC, name ASC
                """
            )
            usage_this_month = grouped(
                """
                SELECT feature_slug AS name, COALESCE(SUM(quantity), 0) AS count
                FROM usage_events
                WHERE occurred_at >= ?
                GROUP BY feature_slug
                ORDER BY count DESC, name ASC
                """,
                (month_start_iso(),),
            )
            feature_locks = grouped(
                """
                SELECT feature_slug AS name, COUNT(*) AS count
                FROM feature_locks
                GROUP BY feature_slug
                ORDER BY count DESC, name ASC
                LIMIT 12
                """
            )
            cases_by_status = grouped(
                """
                SELECT status AS name, COUNT(*) AS count
                FROM incident_cases
                GROUP BY status
                ORDER BY count DESC, name ASC
                """
            )
            simulation_outcomes = grouped(
                """
                SELECT outcome AS name, COUNT(*) AS count
                FROM simulation_results
                GROUP BY outcome
                ORDER BY count DESC, name ASC
                """
            )
            analyzer_stats = self._aggregate_analyzer_stats(conn)
            ops_status = _safe_ops_status()
            payment_assurance = _safe_payment_assurance_status()

            audit_rows = conn.execute(
                """
                SELECT org_id, action, target_type, created_at
                FROM audit_logs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (audit_limit,),
            ).fetchall()
            recent_audit = [
                {
                    "org_ref": hashlib.sha256(row["org_id"].encode("utf-8")).hexdigest()[:12],
                    "action": row["action"],
                    "target_type": row["target_type"],
                    "created_at": row["created_at"],
                }
                for row in audit_rows
            ]

        return {
            "totals": {
                "users": total_users,
                "organizations": total_orgs,
                "scans": total_scans,
                "mailboxes": total_mailboxes,
                "incident_cases": total_cases,
                "simulation_results": total_simulations,
            },
            "plans": plans,
            "subscription_status": subscription_status,
            "verdicts": verdicts,
            "payment_decisions": payment_decisions,
            "mailboxes_by_status": mailboxes_by_status,
            "mailboxes_by_provider": mailboxes_by_provider,
            "usage_this_month": usage_this_month,
            "feature_locks": feature_locks,
            "cases_by_status": cases_by_status,
            "simulation_outcomes": simulation_outcomes,
            "analyzers": analyzer_stats,
            "cti_transport": ops_status,
            "payment_assurance": payment_assurance,
            "recent_audit": recent_audit,
            "privacy": {
                "raw_email_bodies": False,
                "raw_result_json": False,
                "mailbox_credentials": False,
                "external_mailbox_ids": False,
                "stripe_ids": False,
                "secrets": False,
            },
        }

    def _aggregate_analyzer_stats(self, conn: sqlite3.Connection) -> dict:
        """Aggregate normalized analyzer result metadata without raw payloads."""
        status_counts: Counter[str] = Counter()
        cost_tier_counts: Counter[str] = Counter()
        failure_counts: Counter[str] = Counter()
        locked_counts: Counter[str] = Counter()
        not_configured_counts: Counter[str] = Counter()
        cached_counts: Counter[str] = Counter()
        product_verdict_counts: Counter[str] = Counter()
        payment_display_counts: Counter[str] = Counter()

        rows = conn.execute("SELECT result_json FROM scan_results").fetchall()
        for row in rows:
            try:
                payload = json.loads(row["result_json"] or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                logger.debug("Skipping malformed analyzer stats JSON: %s", exc)
                continue

            product_verdicts = payload.get("product_verdicts") or {}
            phish = product_verdicts.get("phishanalyze") or {}
            payshield = product_verdicts.get("payshield") or {}
            if phish.get("verdict"):
                product_verdict_counts[str(phish["verdict"])] += 1
            elif payload.get("verdict"):
                product_verdict_counts[str(payload["verdict"])] += 1
            if payshield.get("display_decision"):
                payment_display_counts[str(payshield["display_decision"])] += 1
            else:
                payment_details = payload.get("payment_protection") or {}
                if payment_details.get("display_decision"):
                    payment_display_counts[str(payment_details["display_decision"])] += 1
                elif payment_details.get("decision"):
                    payment_display_counts[str(payment_details["decision"])] += 1

            analyzer_results = payload.get("analyzer_results") or {}
            if not isinstance(analyzer_results, dict):
                continue
            for analyzer_id, analyzer in analyzer_results.items():
                if not isinstance(analyzer, dict):
                    continue
                safe_id = str(analyzer.get("analyzer_id") or analyzer_id)
                status = str(analyzer.get("status") or "unknown").lower()
                cost_tier = str(analyzer.get("cost_tier") or "unknown").lower()
                status_counts[status] += 1
                cost_tier_counts[cost_tier] += 1
                if status in {"failed", "timeout"}:
                    failure_counts[safe_id] += 1
                elif status == "feature_locked":
                    locked_counts[safe_id] += 1
                elif status == "not_configured":
                    not_configured_counts[safe_id] += 1
                elif status == "cached" or analyzer.get("cached") is True:
                    cached_counts[safe_id] += 1

        return {
            "statuses": _counter_rows(status_counts),
            "cost_tiers": _counter_rows(cost_tier_counts),
            "failures": _counter_rows(failure_counts),
            "locked": _counter_rows(locked_counts),
            "not_configured": _counter_rows(not_configured_counts),
            "cached": _counter_rows(cached_counts),
            "product_verdicts": _counter_rows(product_verdict_counts),
            "payment_display_decisions": _counter_rows(payment_display_counts),
        }

    def create_webauthn_challenge(
        self,
        *,
        org_id: str,
        user_id: str,
        purpose: str,
        challenge: str,
        ttl_seconds: int = 300,
    ) -> str:
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        expires_at = (now_dt + timedelta(seconds=max(30, ttl_seconds))).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO webauthn_challenges (
                    id, org_id, user_id, purpose, challenge, created_at, expires_at, used_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (new_id("wch"), org_id, user_id, purpose, challenge, now, expires_at),
            )
            conn.commit()
        return challenge

    def consume_webauthn_challenge(
        self,
        *,
        org_id: str,
        user_id: str,
        purpose: str,
        challenge: str,
    ) -> bool:
        now = utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE webauthn_challenges
                SET used_at = ?
                WHERE org_id = ?
                  AND user_id = ?
                  AND purpose = ?
                  AND challenge = ?
                  AND used_at IS NULL
                  AND expires_at >= ?
                """,
                (now, org_id, user_id, purpose, challenge, now),
            )
            conn.commit()
            return cursor.rowcount == 1

    def add_webauthn_credential(
        self,
        *,
        org_id: str,
        user_id: str,
        credential_id: str,
        public_key_b64: str,
        sign_count: int,
        transports: list[str] | None = None,
        aaguid: str = "",
    ) -> WebAuthnCredentialRecord:
        now = utc_now_iso()
        record_id = new_id("pkc")
        transports = transports or []
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO webauthn_credentials (
                    id, org_id, user_id, credential_id, public_key_b64,
                    sign_count, transports_json, aaguid, created_at, last_used_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    record_id,
                    org_id,
                    user_id,
                    credential_id,
                    public_key_b64,
                    int(sign_count),
                    json.dumps(transports),
                    aaguid,
                    now,
                ),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="passkey.registered",
                target_type="webauthn_credential",
                target_id=credential_id,
                metadata={"transports": transports, "aaguid": aaguid},
                now=now,
            )
            conn.commit()
        return WebAuthnCredentialRecord(
            id=record_id,
            org_id=org_id,
            user_id=user_id,
            credential_id=credential_id,
            public_key_b64=public_key_b64,
            sign_count=int(sign_count),
            transports=transports,
            aaguid=aaguid,
            created_at=now,
            last_used_at=None,
        )

    def list_webauthn_credentials(self, *, org_id: str, user_id: str) -> list[WebAuthnCredentialRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, org_id, user_id, credential_id, public_key_b64, sign_count,
                       transports_json, aaguid, created_at, last_used_at
                FROM webauthn_credentials
                WHERE org_id = ? AND user_id = ?
                ORDER BY created_at DESC
                """,
                (org_id, user_id),
            ).fetchall()
            return [self._webauthn_record_from_row(row) for row in rows]

    def get_webauthn_credential(
        self,
        *,
        org_id: str,
        user_id: str,
        credential_id: str,
    ) -> WebAuthnCredentialRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, org_id, user_id, credential_id, public_key_b64, sign_count,
                       transports_json, aaguid, created_at, last_used_at
                FROM webauthn_credentials
                WHERE org_id = ? AND user_id = ? AND credential_id = ?
                """,
                (org_id, user_id, credential_id),
            ).fetchone()
            return self._webauthn_record_from_row(row) if row else None

    def count_webauthn_credentials(self, *, org_id: str, user_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM webauthn_credentials
                WHERE org_id = ? AND user_id = ?
                """,
                (org_id, user_id),
            ).fetchone()
            return int(row["count"] or 0)

    def update_webauthn_credential_usage(
        self,
        *,
        org_id: str,
        user_id: str,
        credential_id: str,
        sign_count: int,
    ) -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?, last_used_at = ?
                WHERE org_id = ? AND user_id = ? AND credential_id = ?
                """,
                (int(sign_count), now, org_id, user_id, credential_id),
            )
            conn.commit()

    def delete_webauthn_credential(
        self,
        *,
        org_id: str,
        user_id: str,
        credential_id: str,
    ) -> bool:
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT credential_id
                FROM webauthn_credentials
                WHERE org_id = ? AND user_id = ? AND credential_id = ?
                """,
                (org_id, user_id, credential_id),
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                """
                DELETE FROM webauthn_credentials
                WHERE org_id = ? AND user_id = ? AND credential_id = ?
                """,
                (org_id, user_id, credential_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="passkey.deleted",
                target_type="webauthn_credential",
                target_id=credential_id,
                metadata={},
                now=now,
            )
            conn.commit()
            return True

    def record_passkey_step_up(
        self,
        *,
        org_id: str,
        user_id: str,
        ttl_seconds: int = 600,
    ) -> str:
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        expires_at = (now_dt + timedelta(seconds=max(60, ttl_seconds))).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO passkey_stepups (org_id, user_id, verified_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(org_id, user_id) DO UPDATE SET
                    verified_at = excluded.verified_at,
                    expires_at = excluded.expires_at
                """,
                (org_id, user_id, now, expires_at),
            )
            conn.commit()
        return expires_at

    def get_passkey_step_up(self, *, org_id: str, user_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT verified_at, expires_at
                FROM passkey_stepups
                WHERE org_id = ? AND user_id = ?
                """,
                (org_id, user_id),
            ).fetchone()
            if row is None:
                return None
            return {"verified_at": row["verified_at"], "expires_at": row["expires_at"]}

    def has_fresh_passkey_step_up(self, *, org_id: str, user_id: str) -> bool:
        row = self.get_passkey_step_up(org_id=org_id, user_id=user_id)
        if row is None:
            return False
        return str(row.get("expires_at") or "") >= utc_now_iso()

    def feature_lock_count(self, org_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM feature_locks WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            return int(row["count"] or 0)

    def monthly_usage_count(
        self,
        org_id: str,
        feature_slug: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        close_conn = conn is None
        if conn is None:
            conn = self._open()
        try:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(quantity), 0) AS used
                FROM usage_events
                WHERE org_id = ? AND feature_slug = ? AND occurred_at >= ?
                """,
                (org_id, feature_slug, month_start_iso()),
            ).fetchone()
            return int(row["used"] or 0)
        finally:
            if close_conn:
                conn.close()

    def _org_plan_slug(self, org_id: str, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT plan_slug, status FROM subscriptions WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if row is None:
            return "free"
        if row["status"] not in ACTIVE_SUBSCRIPTION_STATUSES and row["plan_slug"] != "free":
            return "free"
        return row["plan_slug"] or "free"

    @staticmethod
    def _webauthn_record_from_row(row: sqlite3.Row) -> WebAuthnCredentialRecord:
        try:
            transports = json.loads(row["transports_json"] or "[]")
        except json.JSONDecodeError as exc:
            logger.debug("Ignoring malformed WebAuthn transport JSON: %s", exc)
            transports = []
        if not isinstance(transports, list):
            transports = []
        return WebAuthnCredentialRecord(
            id=row["id"],
            org_id=row["org_id"],
            user_id=row["user_id"],
            credential_id=row["credential_id"],
            public_key_b64=row["public_key_b64"],
            sign_count=int(row["sign_count"] or 0),
            transports=[str(item) for item in transports],
            aaguid=row["aaguid"] or "",
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )

    @staticmethod
    def _incident_case_record_from_row(row: sqlite3.Row) -> IncidentCaseRecord:
        return IncidentCaseRecord(
            id=row["id"],
            org_id=row["org_id"],
            scan_result_id=row["scan_result_id"],
            scan_job_id=row["scan_job_id"],
            email_id=row["email_id"],
            title=row["title"],
            status=row["status"],
            severity=row["severity"],
            owner_user_id=row["owner_user_id"],
            owner_email=row["owner_email"],
            escalated_at=row["escalated_at"],
            escalation_reason=row["escalation_reason"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            closed_at=row["closed_at"],
            event_count=int(row["event_count"] or 0),
        )

    @staticmethod
    def _owner_count(conn: sqlite3.Connection, org_id: str) -> int:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM memberships m
            JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND m.role = 'owner' AND u.disabled_at IS NULL
            """,
            (org_id,),
        ).fetchone()
        return int(row["count"] or 0)

    @staticmethod
    def _user_is_org_member(conn: sqlite3.Connection, org_id: str, user_id: str) -> bool:
        row = conn.execute(
            """
            SELECT 1
            FROM memberships m
            JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND m.user_id = ? AND u.disabled_at IS NULL
            """,
            (org_id, user_id),
        ).fetchone()
        return row is not None

    def _write_case_event(
        self,
        conn: sqlite3.Connection,
        *,
        case_id: str,
        org_id: str,
        actor_user_id: str | None,
        event_type: str,
        from_status: str | None,
        to_status: str | None,
        note: str | None,
        evidence: dict,
        now: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO incident_case_events (
                id, case_id, org_id, actor_user_id, event_type,
                from_status, to_status, note, evidence_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("evt"),
                case_id,
                org_id,
                actor_user_id,
                event_type,
                from_status,
                to_status,
                _clean_note(note),
                json.dumps(evidence or {}, default=str),
                now,
            ),
        )

    def _write_audit(
        self,
        conn: sqlite3.Connection,
        *,
        org_id: str,
        actor_user_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None,
        metadata: dict,
        now: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_logs (
                id, org_id, actor_user_id, action, target_type, target_id,
                metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("audit"),
                org_id,
                actor_user_id,
                action,
                target_type,
                target_id,
                json.dumps(metadata, default=str),
                now,
            ),
        )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._open()
        try:
            yield conn
        finally:
            conn.close()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_password(password: str) -> None:
    if len(password or "") < 10:
        raise ValueError("password must be at least 10 characters")


def _validate_workspace_role(role: str) -> str:
    role = str(role or "").strip().lower()
    if role not in WORKSPACE_ROLES:
        raise ValueError("role must be owner, admin, analyst, or viewer")
    return role


def hash_password(password: str, *, iterations: int = 210_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, raw_iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(raw_iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError) as exc:
        logger.debug("Password hash verification received an invalid encoded value: %s", exc)
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def month_start_iso() -> str:
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat()


def _counter_rows(counter: Counter[str]) -> list[dict]:
    return [
        {"name": name, "count": int(count)}
        for name, count in sorted(
            counter.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]


def _safe_ops_status() -> dict:
    try:
        from src.reporting.ops_status import cti_transport_overview

        return cti_transport_overview()
    except Exception as exc:
        logger.debug("CTI transport overview unavailable: %s", exc)
        return {
            "taxii": {"status": "unavailable", "enabled": False, "configured": False},
            "sigma_conversion": {"status": "unavailable"},
        }


def _safe_payment_assurance_status() -> dict:
    try:
        from src.reporting.ops_status import payment_assurance_overview

        return payment_assurance_overview()
    except Exception as exc:
        logger.debug("Payment assurance overview unavailable: %s", exc)
        return {"status": "unavailable", "ready": False}


def _validate_case_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value not in CASE_STATUSES:
        raise ValueError("case status must be open, triaged, investigating, contained, or closed")
    return value


def _validate_case_severity(severity: str) -> str:
    value = str(severity or "medium").strip().lower()
    if value not in CASE_SEVERITIES:
        raise ValueError("case severity must be low, medium, high, or critical")
    return value


def _clean_short_text(value: str | None, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit].strip()


def _clean_note(value: str | None) -> str | None:
    text = _clean_short_text(value, 1000)
    return text or None


def _safe_json_dict(raw: str | None) -> dict:
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        logger.debug("Ignoring malformed JSON object payload: %s", exc)
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _scan_result_subject(raw_result_json: str | None) -> str | None:
    result = _safe_json_dict(raw_result_json)
    headers = ((result.get("iocs") or {}).get("headers") or {})
    subject = headers.get("subject") if isinstance(headers, dict) else None
    return _clean_short_text(subject, 160) or None


def _normalize_simulation_result(item: dict, *, org_id: str) -> dict:
    outcome = str(item.get("outcome") or "").strip().lower()
    if not outcome:
        outcome = "reported" if item.get("reported") else "ignored"
    if outcome not in SIMULATION_OUTCOMES:
        raise ValueError(
            "simulation outcome must be reported, opened, clicked, "
            "submitted_credentials, or ignored"
        )
    reported = bool(item.get("reported")) or outcome == "reported"
    submitted = bool(item.get("submitted_credentials")) or outcome == "submitted_credentials"
    clicked = bool(item.get("clicked")) or submitted or outcome == "clicked"
    opened = bool(item.get("opened")) or clicked or outcome == "opened"
    detected = bool(item.get("detected_by_user")) or reported
    occurred_at = _clean_short_text(item.get("occurred_at") or utc_now_iso(), 80)
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return {
        "recipient_ref": _simulation_recipient_ref(item.get("recipient_ref"), org_id=org_id),
        "scenario": _clean_short_text(item.get("scenario") or "phishing_simulation", 120),
        "outcome": outcome,
        "reported": reported,
        "clicked": clicked,
        "submitted_credentials": submitted,
        "opened": opened,
        "detected_by_user": detected,
        "occurred_at": occurred_at,
        "metadata": _redacted_simulation_metadata(metadata),
    }


def _simulation_recipient_ref(value: object, *, org_id: str) -> str:
    text = _clean_short_text(str(value or "unknown"), 160)
    if "@" in text:
        digest = hashlib.sha256(f"{org_id}:{text.lower()}".encode("utf-8")).hexdigest()[:16]
        return f"recipient_hash:{digest}"
    return text or "unknown"


def _redacted_simulation_metadata(metadata: dict) -> dict:
    allowed = {}
    for key, value in metadata.items():
        key_text = _clean_short_text(key, 40).lower()
        if key_text in {"raw_email", "body", "html", "password", "token", "secret"}:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            allowed[key_text] = _clean_short_text(str(value), 200) if isinstance(value, str) else value
    return allowed


def _simulation_risk_level(score: int | None) -> str:
    if score is None:
        return "not_enough_data"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
ON password_reset_tokens(user_id);

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stripe_customer_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, org_id)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT,
    plan_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    billing_interval TEXT NOT NULL DEFAULT 'monthly',
    current_period_end TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mail_accounts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_account_id TEXT,
    encrypted_token_ref TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mail_account_id TEXT REFERENCES mail_accounts(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    email_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    payment_decision TEXT,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_cases (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_result_id TEXT NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    scan_job_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    email_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    escalated_at TEXT,
    escalation_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    UNIQUE(org_id, scan_result_id)
);

CREATE TABLE IF NOT EXISTS incident_case_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES incident_cases(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    note TEXT,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_events (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    feature_slug TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    occurred_at TEXT NOT NULL,
    idempotency_key TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS feature_locks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    feature_slug TEXT NOT NULL,
    required_plan TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key_b64 TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports_json TEXT NOT NULL DEFAULT '[]',
    aaguid TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS passkey_stepups (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS simulation_results (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    campaign_id TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    scenario TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reported INTEGER NOT NULL DEFAULT 0,
    clicked INTEGER NOT NULL DEFAULT 0,
    submitted_credentials INTEGER NOT NULL DEFAULT 0,
    opened INTEGER NOT NULL DEFAULT 0,
    detected_by_user INTEGER NOT NULL DEFAULT 0,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usage_org_feature_time
    ON usage_events(org_id, feature_slug, occurred_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_org_time
    ON scan_results(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_incident_cases_org_status
    ON incident_cases(org_id, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_incident_case_events_case
    ON incident_case_events(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_feature_locks_org_time
    ON feature_locks(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time
    ON audit_logs(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
    ON webauthn_credentials(org_id, user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user
    ON webauthn_challenges(org_id, user_id, purpose, expires_at);
CREATE INDEX IF NOT EXISTS idx_simulation_results_org_time
    ON simulation_results(org_id, occurred_at);
"""
