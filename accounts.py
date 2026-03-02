from __future__ import annotations

from typing import Optional, Protocol

from auth.schemas import (
    AuthResponse,
    UserAccount,
    UserAccountCreate,
    UserAccountPublic,
    UserSession,
    UserSessionCreate,
)


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
        if accounts_manager is None or sessions_manager is None:
            from auth.accounts_manager import AccountsManager
            from auth.sessions_manager import SessionsManager

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
        raise NotImplementedError("Implement register")

    def login(
        self,
        email: str,
        password: str,
        *,
        remember_me: bool = False,
        ip_address: Optional[str] = None,
    ) -> Optional[AuthResponse]:
        """Validate credentials and create session."""
        raise NotImplementedError("Implement login")

    def authenticate(self, auth_token: str) -> Optional[UserAccount]:
        """Return authenticated user for a valid token."""
        raise NotImplementedError("Implement authenticate")

    def logout(self, auth_token: str) -> bool:
        """Revoke current session token."""
        raise NotImplementedError("Implement logout")

    def logout_all(self, auth_token: str) -> bool:
        """Revoke all sessions for token owner."""
        raise NotImplementedError("Implement logout_all")
