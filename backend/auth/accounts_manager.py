from __future__ import annotations

import hashlib
import time
import uuid
from typing import Optional

from auth.schemas import UserAccount, UserAccountCreate, UserAccountPublic


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _verify_password(password: str, password_hash: str) -> bool:
    return _hash_password(password) == password_hash


def _normalise_email(email: str) -> str:
    return email.strip().lower()


def _is_valid_email(email: str) -> bool:
    e = (email or "").strip()
    return bool(e and "@" in e and "." in e.split("@")[-1] and len(e) <= 254)


def _is_valid_password(password: str) -> bool:
    return bool(password and len(password) >= 8)


def _is_valid_names(first_name: str, last_name: str) -> bool:
    return bool((first_name or "").strip() and (last_name or "").strip())


class AccountsManager:

    def __init__(self) -> None:
        self._accounts: dict[str, UserAccount] = {}
        self._email_index: dict[str, str] = {}

    def create_account(self, payload: UserAccountCreate) -> Optional[UserAccount]:
        if not (_is_valid_email(payload.email) and _is_valid_password(payload.password)
                and _is_valid_names(payload.first_name, payload.last_name)):
            return None

        email = _normalise_email(payload.email)
        if email in self._email_index:
            return None

        user_id = str(uuid.uuid4())
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        password_hash = _hash_password(payload.password)

        account = UserAccount(
            user_id=user_id,
            first_name=payload.first_name.strip(),
            last_name=payload.last_name.strip(),
            email=email,
            password_hash=password_hash,
            organisation_type=payload.organisation_type,
            account_tier=payload.account_tier,
            created_at=created_at,
            is_active=True,
        )

        self._accounts[user_id] = account
        self._email_index[email] = user_id
        return account

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        email = _normalise_email(email)
        user_id = self._email_index.get(email)
        if user_id is None:
            return None
        account = self._accounts.get(user_id)
        if account is None or not account.is_active:
            return None
        if not _verify_password(password, account.password_hash):
            return None
        return account

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        return self._accounts.get(user_id)

    def to_public(self, account: UserAccount) -> UserAccountPublic:
        return UserAccountPublic(
            user_id=account.user_id,
            first_name=account.first_name,
            last_name=account.last_name,
            email=account.email,
            organisation_type=account.organisation_type,
            account_tier=account.account_tier,
            created_at=account.created_at,
        )
