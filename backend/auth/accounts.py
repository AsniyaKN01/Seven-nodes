from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Protocol, Tuple

# Ensure .env is loaded (though app.py should have loaded it first)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent.parent / ".env")
except ImportError:
    pass

from auth.schemas import (
    AuthResponse,
    UserAccount,
    UserAccountCreate,
    UserAccountPublic,
    UserSession,
    UserSessionCreate,
)

from auth.crypto import hash_sha256, hash_with_salt, verify_hash_with_salt

# optional DynamoDB-backed implementations (import lazily to avoid boto3 dependency when not used)


def _use_dynamodb() -> bool:
    return os.environ.get("USE_DYNAMODB", "").lower() in ("1", "true", "yes")


class AccountServiceDependency(Protocol):
    """Methods this auth service needs from account storage."""

    def create_account(self, payload: UserAccountCreate) -> Optional[UserAccount]:
        """Default implementation backed by DynamoDB AccountsManager.

        Concrete implementations (like InMemoryAccountsManager) are free to
        override this; this method simply provides a ready-to-use DynamoDB
        integration when a concrete manager is not injected.
        """
        from auth.accounts_manager import AccountsManager

        manager = AccountsManager()
        return manager.create_account(payload)

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        """Validate credentials using the DynamoDB-backed AccountsManager by default."""
        from auth.accounts_manager import AccountsManager

        manager = AccountsManager()
        return manager.verify_credentials(email, password)

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        """Return an account by ID using the DynamoDB-backed AccountsManager by default."""
        from auth.accounts_manager import AccountsManager

        manager = AccountsManager()
        return manager.get_account(user_id)

    def to_public(self, account: UserAccount) -> UserAccountPublic:
        """Convert a full account model into a public-safe version by default."""
        from auth.accounts_manager import AccountsManager

        return AccountsManager.to_public(account)


class SessionServiceDependency(Protocol):
    """Methods this auth service needs from session storage."""

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> tuple[Optional[UserSession], Optional[str]]:
        """Default implementation backed by DynamoDB SessionsManager.

        Concrete implementations (like InMemorySessionsManager) are free to
        override this; this method simply provides a ready-to-use DynamoDB
        integration when a concrete manager is not injected.
        """
        from auth.sessions_manager import SessionsManager

        manager = SessionsManager()
        return manager.create_session(payload, ip_address=ip_address)

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        """Validate a bearer token using the DynamoDB-backed SessionsManager by default."""
        from auth.sessions_manager import SessionsManager

        manager = SessionsManager()
        return manager.validate_session_token(auth_token)

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a single session by its token hash using DynamoDB-backed SessionsManager."""
        from auth.sessions_manager import SessionsManager

        manager = SessionsManager()
        return manager.revoke_session(session_id)

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        """Revoke all sessions belonging to a user using DynamoDB-backed SessionsManager."""
        from auth.sessions_manager import SessionsManager

        manager = SessionsManager()
        return manager.revoke_all_user_sessions(user_id)


class DynamoSessionService(SessionServiceDependency):
    """Session service backed by the DynamoDB SessionsManager.

    This is a thin adapter that satisfies the SessionServiceDependency protocol
    while delegating all operations to the existing DynamoDB implementation.
    """

    def __init__(self) -> None:
        # Imported lazily so that boto3/DynamoDB are only required when this
        # concrete implementation is actually used.
        from auth.sessions_manager import SessionsManager

        self._delegate = SessionsManager()

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> Tuple[Optional[UserSession], Optional[str]]:
        return self._delegate.create_session(payload, ip_address=ip_address)

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        return self._delegate.validate_session_token(auth_token)

    def revoke_session(self, session_id: str) -> bool:
        return self._delegate.revoke_session(session_id)

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        return self._delegate.revoke_all_user_sessions(user_id)


class InMemoryAccountsManager(AccountServiceDependency):
    """Simple in-process accounts store, used when USE_DYNAMODB is disabled.

    This is intended for local development and tests only. All data is kept in
    memory and lost when the process exits.
    """

    def __init__(self) -> None:
        self._accounts_by_id: dict[str, UserAccount] = {}
        self._accounts_by_email: dict[str, UserAccount] = {}

    @staticmethod
    def to_public(account: UserAccount) -> UserAccountPublic:
        return UserAccountPublic(
            user_id=account.user_id,
            first_name=account.first_name,
            last_name=account.last_name,
            email=account.email,
            organisation_type=account.organisation_type,
            account_tier=account.account_tier,
            created_at=account.created_at,
        )

    def create_account(self, payload: UserAccountCreate) -> Optional[UserAccount]:
        if payload.email in self._accounts_by_email:
            return None

        now = datetime.now(timezone.utc).isoformat()
        account = UserAccount(
            user_id=str(uuid.uuid4()),
            first_name=payload.first_name,
            last_name=payload.last_name,
            email=payload.email,
            password_hash=hash_with_salt(payload.password),
            organisation_type=payload.organisation_type,
            account_tier=payload.account_tier,
            created_at=now,
            is_active=True,
        )
        self._accounts_by_id[account.user_id] = account
        self._accounts_by_email[account.email] = account
        return account

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        account = self._accounts_by_email.get(email)
        if account is None or not account.is_active:
            return None
        if not verify_hash_with_salt(password, account.password_hash):
            return None
        return account

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        return self._accounts_by_id.get(user_id)


class InMemorySessionsManager(SessionServiceDependency):
    """In-process sessions store for local development when USE_DYNAMODB is disabled."""

    def __init__(
        self,
        session_ttl_hours: int = int(os.getenv("AUTH_SESSION_TTL_HOURS", "24")),
        remember_me_ttl_days: int = int(os.getenv("AUTH_REMEMBER_ME_TTL_DAYS", "30")),
    ) -> None:
        self._sessions: dict[str, UserSession] = {}
        self._session_ttl_hours = session_ttl_hours
        self._remember_me_ttl_days = remember_me_ttl_days

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> Tuple[Optional[UserSession], Optional[str]]:
        import secrets

        raw_token = secrets.token_urlsafe(32)
        created_at_dt = datetime.now(timezone.utc)
        if payload.remember_me:
            expires_at_dt = created_at_dt + timedelta(days=self._remember_me_ttl_days)
        else:
            expires_at_dt = created_at_dt + timedelta(hours=self._session_ttl_hours)

        session = UserSession(
            token_hash=hash_sha256(raw_token),
            user_id=payload.user_id,
            created_at=created_at_dt.isoformat(),
            expires_at=int(expires_at_dt.timestamp()),
            remember_me=payload.remember_me,
            ip_address=ip_address,
        )
        self._sessions[session.token_hash] = session
        return session, raw_token

    def _get_session_by_hash(self, token_hash: str) -> Optional[UserSession]:
        session = self._sessions.get(token_hash)
        if session is None:
            return None
        # simple expiry check mirroring Dynamo-backed behaviour
        if session.expires_at <= int(datetime.now(timezone.utc).timestamp()):
            return None
        return session

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        token_hash = hash_sha256(auth_token)
        return self._get_session_by_hash(token_hash)

    def revoke_session(self, token_hash: str) -> bool:
        return self._sessions.pop(token_hash, None) is not None

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        to_delete = [k for k, v in self._sessions.items() if v.user_id == user_id]
        for k in to_delete:
            self._sessions.pop(k, None)
        return True


class AuthenticationService:
    """Simple auth workflow scaffold using account and session managers."""

    def __init__(
        self,
        accounts_manager: Optional[AccountServiceDependency] = None,
        sessions_manager: Optional[SessionServiceDependency] = None,
    ) -> None:
        # if the caller didn't provide a concrete storage implementation we
        # choose one based on environment configuration.  This keeps the
        # rest of the codebase ignorant about the backend.
        if accounts_manager is None or sessions_manager is None:
            if _use_dynamodb():
                # import here to avoid requiring boto3 for simple in-memory tests
                from auth.dynamo import DynamoAccountsManager, DynamoSessionsManager

                accounts_manager = accounts_manager or DynamoAccountsManager()
                sessions_manager = sessions_manager or DynamoSessionsManager()
            else:
                accounts_manager = accounts_manager or InMemoryAccountsManager()
                sessions_manager = sessions_manager or InMemorySessionsManager()

        self.accounts = accounts_manager
        self.sessions = sessions_manager

    def register(
        self,
        payload: UserAccountCreate,
        *,
        remember_me: bool = False,
        ip_address: Optional[str] = None,
    ) -> Optional[AuthResponse]:
        """Create account and first session, returning auth response."""
        account = self.accounts.create_account(payload)
        if account is None:
            return None

        session_payload = UserSessionCreate(user_id=account.user_id, remember_me=remember_me)
        session, raw_token = self.sessions.create_session(
            session_payload, ip_address=ip_address
        )
        if session is None or raw_token is None:
            return None

        user_public = self.accounts.to_public(account)
        return AuthResponse(user=user_public, auth_token=raw_token)

    def login(
        self,
        email: str,
        password: str,
        *,
        remember_me: bool = False,
        ip_address: Optional[str] = None,
    ) -> Optional[AuthResponse]:
        """Validate credentials and create session."""
        account = self.accounts.verify_credentials(email, password)
        if account is None:
            return None

        session_payload = UserSessionCreate(user_id=account.user_id, remember_me=remember_me)
        session, raw_token = self.sessions.create_session(
            session_payload, ip_address=ip_address
        )
        if session is None or raw_token is None:
            return None

        user_public = self.accounts.to_public(account)
        return AuthResponse(user=user_public, auth_token=raw_token)

    def authenticate(self, auth_token: str) -> Optional[UserAccount]:
        """Return authenticated user for a valid token."""
        session = self.sessions.validate_session_token(auth_token)
        if session is None:
            return None
        return self.accounts.get_account(session.user_id)

    def logout(self, auth_token: str) -> bool:
        """Revoke current session token."""
        token_hash = hash_sha256(auth_token)
        return self.sessions.revoke_session(token_hash)

    def logout_all(self, auth_token: str) -> bool:
        """Revoke all sessions for token owner."""
        session = self.sessions.validate_session_token(auth_token)
        if session is None:
            return False
        return self.sessions.revoke_all_user_sessions(session.user_id)
