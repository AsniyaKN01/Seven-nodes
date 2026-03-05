from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv

# Load from /auth/.env specifically — don't pull from global environment
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

from auth.crypto import hash_sha256
from auth.schemas import UserSession, UserSessionCreate

DEFAULT_SESSIONS_TABLE = os.getenv("AUTH_SESSIONS_TABLE", "UserSessions")
DEFAULT_TOKEN_INDEX = os.getenv("AUTH_SESSIONS_TOKEN_INDEX", "auth-token-hash-index")  # defined but not used — token_hash is the PK, direct lookup applies
DEFAULT_USER_INDEX = os.getenv("AUTH_SESSIONS_USER_INDEX", "user-id-index")
SESSION_TTL_HOURS = int(os.getenv("AUTH_SESSION_TTL_HOURS", "24"))
REMEMBER_ME_TTL_DAYS = int(os.getenv("AUTH_REMEMBER_ME_TTL_DAYS", "30"))


class SessionsManager:
    """Handles all DynamoDB reads and writes for the UserSessions table.
    No business logic lives here — that belongs in accounts.py.

    token_hash is the partition key — raw tokens are never stored, only their SHA-256 hash.
    expires_at is a Unix timestamp that DynamoDB TTL reads to auto-delete expired rows.
    """

    def __init__(
        self,
        sessions_table: str = DEFAULT_SESSIONS_TABLE,
        token_index_name: str = DEFAULT_TOKEN_INDEX,
        user_index_name: str = DEFAULT_USER_INDEX,
    ) -> None:
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(sessions_table)
        self.user_index_name = user_index_name

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> Tuple[Optional[UserSession], Optional[str]]:
        """Write a new session to DynamoDB.

        Returns (session, raw_token). The raw token is only exposed here —
        the DB record holds the hash. Returns (None, None) on failure.
        """
        raw_token = secrets.token_urlsafe(32)
        created_at = datetime.now(timezone.utc)

        if payload.remember_me:
            expires_at = created_at + timedelta(days=REMEMBER_ME_TTL_DAYS)
        else:
            #expires_at = created_at + timedelta(hours=SESSION_TTL_HOURS)
            expires_at = created_at + timedelta(seconds=60)

        session = UserSession(
            token_hash=_hash_token(raw_token),
            user_id=payload.user_id,
            created_at=created_at.isoformat(),
            expires_at=int(expires_at.timestamp()),
            remember_me=payload.remember_me,
            ip_address=ip_address,
        )

        try:
            self.table.put_item(Item=_session_to_item(session))
        except Exception:
            return None, None

        return session, raw_token

    def get_session(self, token_hash: str) -> Optional[UserSession]:
        """Direct PK lookup by token_hash."""
        response = self.table.get_item(Key={"token_hash": token_hash})
        item = response.get("Item")
        return _item_to_session(item) if item else None

    def get_session_by_token(self, auth_token: str) -> Optional[UserSession]:
        """Hash the raw bearer token and do a direct PK lookup — no GSI needed."""
        return self.get_session(_hash_token(auth_token))

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        """Returns the session if the token resolves and hasn't expired.

        DynamoDB TTL handles deletion eventually but isn't instant,
        so we always check expiry here explicitly.
        """
        session = self.get_session_by_token(auth_token)
        if session is None:
            return None
        if session.expires_at <= int(datetime.now(timezone.utc).timestamp()):
            return None
        return session

    def revoke_session(self, token_hash: str) -> bool:
        """Delete one session by token_hash — single device logout."""
        try:
            self.table.delete_item(Key={"token_hash": token_hash})
            return True
        except Exception:
            return False

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        """Find all sessions for a user via user-id-index GSI and delete them — logout everywhere."""
        try:
            response = self.table.query(
                IndexName=self.user_index_name,
                KeyConditionExpression=Key("user_id").eq(user_id),
            )
            for item in response.get("Items", []):
                self.table.delete_item(Key={"token_hash": item["token_hash"]})
            return True
        except Exception:
            return False


# --- DynamoDB serialisation helpers ---

def _hash_token(raw_token: str) -> str:
    """SHA-256 the raw token — this is what gets stored and looked up as the PK."""
    return hash_sha256(raw_token)


def _session_to_item(session: UserSession) -> dict:
    """ip_address omitted when None to keep items clean."""
    item: dict = {
        "token_hash": session.token_hash,
        "user_id": session.user_id,
        "created_at": session.created_at,
        "expires_at": session.expires_at,  # Number type — required for DynamoDB TTL
        "remember_me": session.remember_me,
    }
    if session.ip_address is not None:
        item["ip_address"] = session.ip_address
    return item


def _item_to_session(item: dict) -> UserSession:
    return UserSession(
        token_hash=item["token_hash"],
        user_id=item["user_id"],
        created_at=item["created_at"],
        expires_at=int(item["expires_at"]),
        remember_me=item.get("remember_me", False),
        ip_address=item.get("ip_address"),
    )