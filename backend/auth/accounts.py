from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Protocol

# Ensure .env is loaded (though app.py should have loaded it first)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent.parent / ".env")
except ImportError:
    pass

from auth.schemas import AuthResponse, UserAccount, UserAccountCreate, UserAccountPublic, UserSession, UserSessionCreate

# default in-memory managers
from auth.accounts_manager import AccountsManager
from auth.sessions_manager import SessionsManager, hash_token

# optional DynamoDB-backed implementations (import lazily to avoid boto3 dependency when not used)


def _use_dynamodb() -> bool:
    return os.environ.get("USE_DYNAMODB", "").lower() in ("1", "true", "yes")


class AccountServiceDependency(Protocol):
    """Methods this auth service needs from account storage."""

    def create_account(self, payload: UserAccountCreate) -> Optional[UserAccount]:
        ...

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        ...

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        ...

    def to_public(self, account: UserAccount) -> UserAccountPublic:
        ...


class SessionServiceDependency(Protocol):
    """Methods this auth service needs from session storage."""

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> tuple[Optional[UserSession], Optional[str]]:
        ...

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        ...

    def revoke_session(self, session_id: str) -> bool:
        ...

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        ...


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
                accounts_manager = accounts_manager or AccountsManager()
                sessions_manager = sessions_manager or SessionsManager()

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
        token_hash = hash_token(auth_token)
        return self.sessions.revoke_session(token_hash)

    def logout_all(self, auth_token: str) -> bool:
        """Revoke all sessions for token owner."""
        session = self.sessions.validate_session_token(auth_token)
        if session is None:
            return False
        return self.sessions.revoke_all_user_sessions(session.user_id)
