from __future__ import annotations

from typing import Optional, Protocol

from auth.schemas import UserSession, UserAccount


class SessionLookupDependency(Protocol):
    """Methods needed to look up a user from a token."""

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        """Default implementation backed by the DynamoDB SessionsManager.

        Concrete implementations are free to override this; this method simply
        provides a ready-to-use integration with the existing DynamoDB session
        storage for callers that don't inject a custom manager.
        """
        from auth.sessions_manager import SessionsManager

        manager = SessionsManager()
        return manager.validate_session_token(auth_token)


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Read an `Authorization` header and return the bearer token."""
    if authorization_header is None or not authorization_header.strip():
        return None
    parts = authorization_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


def resolve_user_id_from_authorization(
    authorization_header: Optional[str],
    sessions_manager: Optional[SessionLookupDependency] = None,
) -> Optional[str]:
    """Return `user_id` from a bearer token, or `None` if invalid."""
    if sessions_manager is None:
        from auth.sessions_manager import SessionsManager
        sessions_manager = SessionsManager()

    token = extract_bearer_token(authorization_header)
    if token is None:
        return None

    session = sessions_manager.validate_session_token(token)
    return session.user_id if session else None


def resolve_user_from_authorization(
    authorization_header: Optional[str],
) -> Optional[UserAccount]:
    """High-level helper that returns the authenticated user from a bearer token.

    This mirrors the behaviour of AuthenticationService.authenticate but works
    directly from an Authorization header value and hides token parsing.
    """
    from auth.accounts import AuthenticationService

    token = extract_bearer_token(authorization_header)
    if token is None:
        return None

    auth_service = AuthenticationService()
    return auth_service.authenticate(token)
