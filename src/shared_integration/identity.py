"""Persistent tenant, user, membership, API-key, and BFF-session repository."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from shared_integration.db_models import (
    ApiKeyRow,
    AuditEventRow,
    Base,
    IdentityClientRow,
    MembershipRow,
    TenantRow,
    UserRow,
    UserSessionRow,
)
from shared_integration.sql_jobs import create_database_engine

ROLES: Final = frozenset({"viewer", "analyst", "admin"})
TENANT_STATUSES: Final = frozenset({"active", "suspended", "disabled"})
MEMBERSHIP_STATUSES: Final = frozenset({"active", "suspended"})
IDENTITY_CLIENT_SCOPES: Final = ("auth:exchange",)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$|^[a-z0-9]$")
_KEY_PREFIX = re.compile(r"^igw_[0-9a-f]{24}$")
_IDENTITY_CLIENT_PREFIX = re.compile(r"^igb_[0-9a-f]{24}$")
_USER_SESSION_TOKEN = re.compile(r"^igs_[A-Za-z0-9_-]{40,64}$")
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_DEFAULT_SESSION_TTL_SECONDS = 5 * 60
_MAX_SESSION_TTL_SECONDS = 15 * 60


@dataclass(frozen=True)
class TenantRecord:
    id: str
    slug: str
    name: str
    status: str
    retention_days: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class UserRecord:
    id: str
    issuer: str
    subject: str
    email: str | None
    display_name: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class MembershipRecord:
    tenant_id: str
    user_id: str
    role: str
    status: str
    created_at: datetime


@dataclass(frozen=True)
class ApiKeyPrincipal:
    tenant_id: str
    role: str
    scopes: tuple[str, ...]
    api_key_id: str


@dataclass(frozen=True)
class IssuedApiKey:
    id: str
    tenant_id: str
    role: str
    scopes: tuple[str, ...]
    expires_at: datetime | None
    token: str


@dataclass(frozen=True)
class IdentityClientRecord:
    id: str
    name: str
    key_prefix: str
    allowed_issuers: tuple[str, ...]
    active: bool
    rotated_from_id: str | None
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True)
class IssuedIdentityClient:
    record: IdentityClientRecord
    token: str


@dataclass(frozen=True)
class IdentityClientPrincipal:
    identity_client_id: str
    name: str
    allowed_issuers: tuple[str, ...]
    scopes: tuple[str, ...] = IDENTITY_CLIENT_SCOPES


@dataclass(frozen=True)
class IssuedUserSession:
    id: str
    tenant_id: str
    user_id: str
    identity_client_id: str
    expires_at: datetime
    token: str


@dataclass(frozen=True)
class UserSessionPrincipal:
    tenant_id: str
    user_id: str
    role: str
    session_id: str
    identity_client_id: str


class SQLAlchemyIdentityRepository:
    """Manage persistent identity state and verify non-reversible API keys."""

    def __init__(
        self,
        database_url: str,
        *,
        create_schema: bool = False,
        engine: Engine | None = None,
    ) -> None:
        self.engine = engine or create_database_engine(database_url)
        self._owns_engine = engine is None
        if create_schema:
            Base.metadata.create_all(self.engine)
        self._sessions = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=Session,
        )

    def create_tenant(
        self,
        *,
        tenant_id: str,
        slug: str,
        name: str,
        retention_days: int = 90,
        actor: str = "system",
    ) -> TenantRecord:
        _validate_identifier(tenant_id, "tenant_id")
        if not _SLUG.fullmatch(slug):
            raise ValueError("slug must use lowercase letters, digits, and internal hyphens")
        clean_name = name.strip()
        if not clean_name or len(clean_name) > 255:
            raise ValueError("name must contain 1 to 255 characters")
        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")

        now = _utcnow()
        with self._sessions.begin() as session:
            row = TenantRow(
                id=tenant_id,
                slug=slug,
                name=clean_name,
                status="active",
                retention_days=retention_days,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            _audit(
                session,
                tenant_id,
                actor,
                "tenant.created",
                "tenant",
                tenant_id,
                {"slug": slug, "retention_days": retention_days},
                now,
            )
        return _tenant_record(row)

    def set_tenant_status(
        self,
        tenant_id: str,
        status: str,
        *,
        actor: str = "system",
    ) -> TenantRecord:
        if status not in TENANT_STATUSES:
            raise ValueError(f"status must be one of {sorted(TENANT_STATUSES)}")
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.get(TenantRow, tenant_id)
            if row is None:
                raise KeyError(f"tenant not found: {tenant_id}")
            previous = row.status
            row.status = status
            row.updated_at = now
            _audit(
                session,
                tenant_id,
                actor,
                "tenant.status_changed",
                "tenant",
                tenant_id,
                {"from": previous, "to": status},
                now,
            )
        return _tenant_record(row)

    def upsert_user(
        self,
        *,
        issuer: str,
        subject: str,
        email: str | None = None,
        display_name: str | None = None,
    ) -> UserRecord:
        clean_issuer = issuer.strip()
        clean_subject = subject.strip()
        if not clean_issuer or len(clean_issuer) > 512:
            raise ValueError("issuer must contain 1 to 512 characters")
        if not clean_subject or len(clean_subject) > 255:
            raise ValueError("subject must contain 1 to 255 characters")
        if email is not None and len(email) > 320:
            raise ValueError("email must contain at most 320 characters")
        if display_name is not None and len(display_name) > 255:
            raise ValueError("display_name must contain at most 255 characters")

        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(UserRow).where(
                    UserRow.issuer == clean_issuer,
                    UserRow.subject == clean_subject,
                )
            )
            if row is None:
                row = UserRow(
                    id=f"usr_{uuid.uuid4().hex}",
                    issuer=clean_issuer,
                    subject=clean_subject,
                    email=email,
                    display_name=display_name,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.email = email
                row.display_name = display_name
                row.updated_at = now
            session.flush()
        return _user_record(row)

    def set_membership(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role: str,
        actor: str = "system",
    ) -> MembershipRecord:
        _validate_role(role)
        now = _utcnow()
        with self._sessions.begin() as session:
            if session.get(TenantRow, tenant_id) is None:
                raise KeyError(f"tenant not found: {tenant_id}")
            if session.get(UserRow, user_id) is None:
                raise KeyError(f"user not found: {user_id}")
            row = session.get(MembershipRow, (tenant_id, user_id))
            if row is None:
                row = MembershipRow(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    role=role,
                    status="active",
                    created_at=now,
                )
                session.add(row)
            else:
                row.role = role
            _audit(
                session,
                tenant_id,
                actor,
                "membership.set",
                "membership",
                user_id,
                {"role": role},
                now,
            )
            session.flush()
        return _membership_record(row)

    def set_membership_status(
        self,
        *,
        tenant_id: str,
        user_id: str,
        status: str,
        actor: str = "system",
    ) -> MembershipRecord:
        if status not in MEMBERSHIP_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(MEMBERSHIP_STATUSES)}"
            )
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.get(MembershipRow, (tenant_id, user_id))
            if row is None:
                raise KeyError(
                    f"membership not found: tenant={tenant_id}, user={user_id}"
                )
            previous = row.status
            row.status = status
            _audit(
                session,
                tenant_id,
                actor,
                "membership.status_changed",
                "membership",
                user_id,
                {"from": previous, "to": status},
                now,
            )
        return _membership_record(row)

    def get_membership(self, tenant_id: str, user_id: str) -> MembershipRecord | None:
        with self._sessions() as session:
            row = session.get(MembershipRow, (tenant_id, user_id))
            return _membership_record(row) if row is not None else None

    def issue_api_key(
        self,
        *,
        tenant_id: str,
        role: str,
        scopes: tuple[str, ...] | list[str] = (),
        expires_at: datetime | None = None,
        actor: str = "system",
    ) -> IssuedApiKey:
        _validate_role(role)
        normalized_scopes = _normalize_scopes(scopes)
        normalized_expiry = _normalize_expiry(expires_at)
        now = _utcnow()
        if normalized_expiry is not None and normalized_expiry <= now:
            raise ValueError("expires_at must be in the future")

        prefix = f"igw_{secrets.token_hex(12)}"
        secret = secrets.token_urlsafe(32)
        token = f"{prefix}.{secret}"
        row = ApiKeyRow(
            id=f"key_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            key_prefix=prefix,
            secret_hash=_hash_secret(secret),
            role=role,
            scopes=list(normalized_scopes),
            expires_at=normalized_expiry,
            created_at=now,
        )
        with self._sessions.begin() as session:
            tenant = session.get(TenantRow, tenant_id)
            if tenant is None:
                raise KeyError(f"tenant not found: {tenant_id}")
            if tenant.status != "active":
                raise ValueError("API keys can only be issued for active tenants")
            session.add(row)
            session.flush()
            _audit(
                session,
                tenant_id,
                actor,
                "api_key.issued",
                "api_key",
                row.id,
                {"prefix": prefix, "role": role, "scopes": list(normalized_scopes)},
                now,
            )
        return IssuedApiKey(
            id=row.id,
            tenant_id=tenant_id,
            role=role,
            scopes=normalized_scopes,
            expires_at=normalized_expiry,
            token=token,
        )

    def authenticate_api_key(self, token: str) -> ApiKeyPrincipal | None:
        prefix, secret = _parse_api_key(token)
        if prefix is None or secret is None:
            return None
        with self._sessions() as session:
            row = session.scalar(select(ApiKeyRow).where(ApiKeyRow.key_prefix == prefix))
            if row is None or not _verify_secret(secret, row.secret_hash):
                return None
            tenant = session.get(TenantRow, row.tenant_id)
            now = _utcnow()
            if tenant is None or tenant.status != "active" or row.revoked_at is not None:
                return None
            expires_at = _as_utc(row.expires_at)
            if expires_at is not None and expires_at <= now:
                return None
            if row.role not in ROLES:
                return None
            return ApiKeyPrincipal(
                tenant_id=row.tenant_id,
                role=row.role,
                scopes=tuple(row.scopes or ()),
                api_key_id=row.id,
            )

    def revoke_api_key(
        self,
        tenant_id: str,
        api_key_id: str,
        *,
        actor: str = "system",
    ) -> bool:
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(ApiKeyRow).where(
                    ApiKeyRow.tenant_id == tenant_id,
                    ApiKeyRow.id == api_key_id,
                )
            )
            if row is None:
                return False
            if row.revoked_at is None:
                row.revoked_at = now
                _audit(
                    session,
                    tenant_id,
                    actor,
                    "api_key.revoked",
                    "api_key",
                    api_key_id,
                    {"prefix": row.key_prefix},
                    now,
                )
            return True

    def issue_identity_client(
        self,
        *,
        name: str,
        allowed_issuers: tuple[str, ...] | list[str],
    ) -> IssuedIdentityClient:
        clean_name = _normalize_client_name(name)
        normalized_issuers = _normalize_issuers(allowed_issuers)
        now = _utcnow()
        row, token = _new_identity_client(
            name=clean_name,
            allowed_issuers=normalized_issuers,
            rotated_from_id=None,
            now=now,
        )
        with self._sessions.begin() as session:
            session.add(row)
            session.flush()
        return IssuedIdentityClient(record=_identity_client_record(row), token=token)

    def list_identity_clients(self) -> tuple[IdentityClientRecord, ...]:
        with self._sessions() as session:
            rows = session.scalars(
                select(IdentityClientRow).order_by(
                    IdentityClientRow.created_at,
                    IdentityClientRow.id,
                )
            ).all()
            return tuple(_identity_client_record(row) for row in rows)

    def rotate_identity_client(self, identity_client_id: str) -> IssuedIdentityClient:
        now = _utcnow()
        with self._sessions.begin() as session:
            previous = session.get(IdentityClientRow, identity_client_id)
            if previous is None:
                raise KeyError(f"identity client not found: {identity_client_id}")
            if not previous.active or previous.revoked_at is not None:
                raise ValueError("revoked identity clients cannot be rotated")
            row, token = _new_identity_client(
                name=previous.name,
                allowed_issuers=tuple(previous.allowed_issuers or ()),
                rotated_from_id=previous.id,
                now=now,
            )
            session.add(row)
            session.flush()
        return IssuedIdentityClient(record=_identity_client_record(row), token=token)

    def authenticate_identity_client(
        self,
        token: str,
        *,
        issuer: str,
    ) -> IdentityClientPrincipal | None:
        prefix, secret = _parse_identity_client_key(token)
        clean_issuer = issuer.strip() if isinstance(issuer, str) else ""
        if prefix is None or secret is None or not clean_issuer:
            return None
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(IdentityClientRow).where(
                    IdentityClientRow.key_prefix == prefix
                )
            )
            if row is None or not _verify_secret(secret, row.secret_hash):
                return None
            if (
                not row.active
                or row.revoked_at is not None
                or clean_issuer not in tuple(row.allowed_issuers or ())
            ):
                return None
            row.last_used_at = now
            row.updated_at = now
            return IdentityClientPrincipal(
                identity_client_id=row.id,
                name=row.name,
                allowed_issuers=tuple(row.allowed_issuers or ()),
            )

    def revoke_identity_client(self, identity_client_id: str) -> bool:
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.get(IdentityClientRow, identity_client_id)
            if row is None:
                return False
            if row.revoked_at is None:
                row.active = False
                row.revoked_at = now
                row.updated_at = now
            return True

    def issue_user_session(
        self,
        *,
        identity_client_id: str,
        tenant_id: str,
        user_id: str,
        ttl_seconds: int = _DEFAULT_SESSION_TTL_SECONDS,
        actor: str = "identity-exchange",
    ) -> IssuedUserSession:
        ttl = _normalize_session_ttl(ttl_seconds)
        now = _utcnow()
        expires_at = now + ttl
        token = f"igs_{secrets.token_urlsafe(32)}"
        row = UserSessionRow(
            id=f"ses_{uuid.uuid4().hex}",
            token_hash=_hash_session_token(token),
            user_id=user_id,
            tenant_id=tenant_id,
            identity_client_id=identity_client_id,
            created_at=now,
            expires_at=expires_at,
        )
        with self._sessions.begin() as session:
            client = session.get(IdentityClientRow, identity_client_id)
            if (
                client is None
                or not client.active
                or client.revoked_at is not None
            ):
                raise ValueError("identity client must be active")
            tenant = session.get(TenantRow, tenant_id)
            if tenant is None:
                raise KeyError(f"tenant not found: {tenant_id}")
            if tenant.status != "active":
                raise ValueError("user sessions can only be issued for active tenants")
            if session.get(UserRow, user_id) is None:
                raise KeyError(f"user not found: {user_id}")
            membership = session.get(MembershipRow, (tenant_id, user_id))
            if membership is None or membership.status != "active":
                raise ValueError("an active membership is required")
            if membership.role not in ROLES:
                raise ValueError("membership role is invalid")
            session.add(row)
            session.flush()
            _audit(
                session,
                tenant_id,
                actor,
                "user_session.issued",
                "user_session",
                row.id,
                {
                    "user_id": user_id,
                    "identity_client_id": identity_client_id,
                    "expires_at": expires_at.isoformat(),
                },
                now,
            )
        return IssuedUserSession(
            id=row.id,
            tenant_id=tenant_id,
            user_id=user_id,
            identity_client_id=identity_client_id,
            expires_at=expires_at,
            token=token,
        )

    def authenticate_user_session(self, token: str) -> UserSessionPrincipal | None:
        if not isinstance(token, str) or not _USER_SESSION_TOKEN.fullmatch(token):
            return None
        token_hash = _hash_session_token(token)
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(UserSessionRow).where(
                    UserSessionRow.token_hash == token_hash
                )
            )
            if row is None or not hmac.compare_digest(row.token_hash, token_hash):
                return None
            expires_at = _as_utc(row.expires_at)
            if (
                row.revoked_at is not None
                or expires_at is None
                or expires_at <= now
            ):
                return None
            client = session.get(IdentityClientRow, row.identity_client_id)
            tenant = session.get(TenantRow, row.tenant_id)
            membership = session.get(MembershipRow, (row.tenant_id, row.user_id))
            if (
                client is None
                or not client.active
                or client.revoked_at is not None
                or tenant is None
                or tenant.status != "active"
                or membership is None
                or membership.status != "active"
                or membership.role not in ROLES
            ):
                return None
            row.last_seen_at = now
            return UserSessionPrincipal(
                tenant_id=row.tenant_id,
                user_id=row.user_id,
                role=membership.role,
                session_id=row.id,
                identity_client_id=row.identity_client_id,
            )

    def revoke_user_session(
        self,
        tenant_id: str,
        session_id: str,
        *,
        actor: str = "system",
    ) -> bool:
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(UserSessionRow).where(
                    UserSessionRow.tenant_id == tenant_id,
                    UserSessionRow.id == session_id,
                )
            )
            if row is None:
                return False
            if row.revoked_at is None:
                row.revoked_at = now
                _audit(
                    session,
                    tenant_id,
                    actor,
                    "user_session.revoked",
                    "user_session",
                    session_id,
                    {"user_id": row.user_id},
                    now,
                )
            return True

    def cleanup_expired_user_sessions(
        self,
        *,
        before: datetime | None = None,
    ) -> int:
        cutoff = _normalize_expiry(before) if before is not None else _utcnow()
        if cutoff is None:  # pragma: no cover - guarded by the expression above
            raise AssertionError("session cleanup cutoff cannot be None")
        with self._sessions.begin() as session:
            result = session.execute(
                delete(UserSessionRow).where(UserSessionRow.expires_at <= cutoff)
            )
            return int(result.rowcount or 0)

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()


def _hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    salt_text = _b64encode(salt)
    digest_text = _b64encode(digest)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt_text}${digest_text}"


def _verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        n_value, r_value, p_value = int(n), int(r), int(p)
        if (n_value, r_value, p_value) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return False
        digest = hashlib.scrypt(
            secret.encode("utf-8"),
            salt=_b64decode(salt),
            n=n_value,
            r=r_value,
            p=p_value,
            dklen=32,
        )
        return hmac.compare_digest(digest, _b64decode(expected))
    except (TypeError, ValueError):
        return False


def _parse_api_key(token: str) -> tuple[str | None, str | None]:
    if not isinstance(token, str) or len(token) > 128:
        return None, None
    prefix, separator, secret = token.partition(".")
    if separator != "." or not _KEY_PREFIX.fullmatch(prefix):
        return None, None
    if not 32 <= len(secret) <= 64:
        return None, None
    return prefix, secret


def _parse_identity_client_key(token: str) -> tuple[str | None, str | None]:
    if not isinstance(token, str) or len(token) > 128:
        return None, None
    prefix, separator, secret = token.partition(".")
    if separator != "." or not _IDENTITY_CLIENT_PREFIX.fullmatch(prefix):
        return None, None
    if not 32 <= len(secret) <= 64:
        return None, None
    return prefix, secret


def _normalize_client_name(name: str) -> str:
    clean_name = name.strip() if isinstance(name, str) else ""
    if not clean_name or len(clean_name) > 255:
        raise ValueError("name must contain 1 to 255 characters")
    return clean_name


def _normalize_issuers(
    issuers: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    result: list[str] = []
    for issuer in issuers:
        clean_issuer = issuer.strip() if isinstance(issuer, str) else ""
        if not clean_issuer or len(clean_issuer) > 512:
            raise ValueError("each issuer must contain 1 to 512 characters")
        if clean_issuer not in result:
            result.append(clean_issuer)
    if not result:
        raise ValueError("at least one issuer is required")
    if len(result) > 16:
        raise ValueError("an identity client can allow at most 16 issuers")
    return tuple(result)


def _new_identity_client(
    *,
    name: str,
    allowed_issuers: tuple[str, ...],
    rotated_from_id: str | None,
    now: datetime,
) -> tuple[IdentityClientRow, str]:
    prefix = f"igb_{secrets.token_hex(12)}"
    secret = secrets.token_urlsafe(32)
    row = IdentityClientRow(
        id=f"idc_{uuid.uuid4().hex}",
        name=name,
        key_prefix=prefix,
        secret_hash=_hash_secret(secret),
        allowed_issuers=list(allowed_issuers),
        active=True,
        rotated_from_id=rotated_from_id,
        created_at=now,
        updated_at=now,
    )
    return row, f"{prefix}.{secret}"


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_session_ttl(ttl_seconds: int) -> timedelta:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError("ttl_seconds must be an integer")
    if not 1 <= ttl_seconds <= _MAX_SESSION_TTL_SECONDS:
        raise ValueError(
            f"ttl_seconds must be between 1 and {_MAX_SESSION_TTL_SECONDS}"
        )
    return timedelta(seconds=ttl_seconds)


def _normalize_scopes(scopes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    result: list[str] = []
    for scope in scopes:
        if not isinstance(scope, str) or not scope or len(scope) > 128:
            raise ValueError("each scope must contain 1 to 128 characters")
        if scope not in result:
            result.append(scope)
    if len(result) > 64:
        raise ValueError("an API key can contain at most 64 scopes")
    return tuple(result)


def _normalize_expiry(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("expires_at must include a timezone")
    return value.astimezone(UTC)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _validate_identifier(value: str, field: str) -> None:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"{field} must contain 1 to 128 letters, digits, '.', '_', ':', or '-'"
        )


def _validate_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {sorted(ROLES)}")


def _tenant_record(row: TenantRow) -> TenantRecord:
    return TenantRecord(
        id=row.id,
        slug=row.slug,
        name=row.name,
        status=row.status,
        retention_days=row.retention_days,
        created_at=_as_utc(row.created_at) or row.created_at,
        updated_at=_as_utc(row.updated_at) or row.updated_at,
    )


def _user_record(row: UserRow) -> UserRecord:
    return UserRecord(
        id=row.id,
        issuer=row.issuer,
        subject=row.subject,
        email=row.email,
        display_name=row.display_name,
        created_at=_as_utc(row.created_at) or row.created_at,
        updated_at=_as_utc(row.updated_at) or row.updated_at,
    )


def _membership_record(row: MembershipRow) -> MembershipRecord:
    return MembershipRecord(
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        role=row.role,
        status=row.status,
        created_at=_as_utc(row.created_at) or row.created_at,
    )


def _identity_client_record(row: IdentityClientRow) -> IdentityClientRecord:
    return IdentityClientRecord(
        id=row.id,
        name=row.name,
        key_prefix=row.key_prefix,
        allowed_issuers=tuple(row.allowed_issuers or ()),
        active=row.active,
        rotated_from_id=row.rotated_from_id,
        created_at=_as_utc(row.created_at) or row.created_at,
        updated_at=_as_utc(row.updated_at) or row.updated_at,
        last_used_at=_as_utc(row.last_used_at),
        revoked_at=_as_utc(row.revoked_at),
    )


def _audit(
    session: Session,
    tenant_id: str,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict[str, object],
    now: datetime,
) -> None:
    session.add(
        AuditEventRow(
            id=f"audit_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome="success",
            details=details,
            created_at=now,
        )
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "ApiKeyPrincipal",
    "IDENTITY_CLIENT_SCOPES",
    "IdentityClientPrincipal",
    "IdentityClientRecord",
    "IssuedApiKey",
    "IssuedIdentityClient",
    "IssuedUserSession",
    "MEMBERSHIP_STATUSES",
    "MembershipRecord",
    "ROLES",
    "SQLAlchemyIdentityRepository",
    "TENANT_STATUSES",
    "TenantRecord",
    "UserSessionPrincipal",
    "UserRecord",
]
