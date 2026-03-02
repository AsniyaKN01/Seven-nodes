from __future__ import annotations

from typing import Optional, Protocol


class SessionLookupDependency(Protocol):
    """Methods needed to look up a user from a token."""

    def validate_session_token(self, auth_token: str):
        ...


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Read an `Authorization` header and return the bearer token."""
    raise NotImplementedError("Implement extract_bearer_token")


def resolve_user_id_from_authorization(
    authorization_header: Optional[str],
    sessions_manager: Optional[SessionLookupDependency] = None,
) -> Optional[str]:
    """Return `user_id` from a bearer token, or `None` if invalid."""
    if sessions_manager is None:
        from auth.sessions_manager import SessionsManager

        sessions_manager = SessionsManager()

    raise NotImplementedError("Implement resolve_user_id_from_authorization")
