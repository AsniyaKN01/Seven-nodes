from __future__ import annotations

import hashlib
import secrets
import time
from typing import Optional

from auth.schemas import UserSession, UserSessionCreate

SESSION_EXPIRY_NORMAL = 24 * 60 * 60
SESSION_EXPIRY_REMEMBER_ME = 30 * 24 * 60 * 60


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


class SessionsManager:

    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}
        self._user_sessions: dict[str, set[str]] = {}

    def create_session(
        self,
        payload: UserSessionCreate,
        *,
        ip_address: Optional[str] = None,
    ) -> tuple[Optional[UserSession], Optional[str]]:
        raw_token = _generate_token()
        token_hash = hash_token(raw_token)

        expiry_seconds = (
            SESSION_EXPIRY_REMEMBER_ME if payload.remember_me else SESSION_EXPIRY_NORMAL
        )
        now = int(time.time())
        expires_at = now + expiry_seconds
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        session = UserSession(
            token_hash=token_hash,
            user_id=payload.user_id,
            created_at=created_at,
            expires_at=expires_at,
            remember_me=payload.remember_me,
            ip_address=ip_address,
        )

        self._sessions[token_hash] = session
        if payload.user_id not in self._user_sessions:
            self._user_sessions[payload.user_id] = set()
        self._user_sessions[payload.user_id].add(token_hash)

        return session, raw_token

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        token_hash = hash_token(auth_token)
        session = self._sessions.get(token_hash)
        if session is None:
            return None
        if session.expires_at < int(time.time()):
            self._remove_session(token_hash)
            return None
        return session

    def revoke_session(self, session_id: str) -> bool:
        if session_id in self._sessions:
            self._remove_session(session_id)
            return True
        return False

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        token_hashes = self._user_sessions.get(user_id)
        if not token_hashes:
            return False
        for th in list(token_hashes):
            self._remove_session(th)
        return True

    def _remove_session(self, token_hash: str) -> None:
        session = self._sessions.pop(token_hash, None)
        if session:
            user_set = self._user_sessions.get(session.user_id)
            if user_set:
                user_set.discard(token_hash)
                if not user_set:
                    del self._user_sessions[session.user_id]
