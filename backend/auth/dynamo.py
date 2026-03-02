from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from typing import Optional

import boto3
from boto3.dynamodb.conditions import Key

from auth.schemas import (
    UserAccount,
    UserAccountCreate,
    UserAccountPublic,
    UserSession,
    UserSessionCreate,
    OrganisationType,
    AccountTier,
)

# session helpers (originally in sessions_manager)
SESSION_EXPIRY_NORMAL = 24 * 60 * 60
SESSION_EXPIRY_REMEMBER_ME = 30 * 24 * 60 * 60

def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(32)

# re‑use some of the helper functions from accounts_manager.py

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


class DynamoAccountsManager:
    """DynamoDB-backed account storage. Tables and indexes must be created externally.

    Environment variables:
      * DYNAMODB_ACCOUNTS_TABLE (default "Accounts")
      * AWS_REGION / AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY as usual for boto3
    """

    def __init__(self) -> None:
        table_name = os.environ.get("DYNAMODB_ACCOUNTS_TABLE", "Accounts")
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(table_name)

    def create_account(self, payload: UserAccountCreate) -> Optional[UserAccount]:
        if not (_is_valid_email(payload.email)
                and _is_valid_password(payload.password)
                and _is_valid_names(payload.first_name, payload.last_name)):
            return None

        email = _normalise_email(payload.email)

        # check uniqueness via email-index (GSI on "email")
        resp = self.table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
            Limit=1,
        )
        if resp.get("Count", 0) > 0:
            return None

        user_id = str(uuid.uuid4())
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        password_hash = _hash_password(payload.password)

        item = {
            "user_id": user_id,
            "first_name": payload.first_name.strip(),
            "last_name": payload.last_name.strip(),
            "email": email,
            "password_hash": password_hash,
            "organisation_type": payload.organisation_type.value,
            "account_tier": payload.account_tier.value,
            "created_at": created_at,
            "is_active": True,
        }

        self.table.put_item(Item=item)

        return UserAccount(
            user_id=user_id,
            first_name=item["first_name"],
            last_name=item["last_name"],
            email=email,
            password_hash=password_hash,
            organisation_type=payload.organisation_type,
            account_tier=payload.account_tier,
            created_at=created_at,
            is_active=True,
        )

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        email = _normalise_email(email)
        resp = self.table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
            Limit=1,
        )
        items = resp.get("Items", [])
        if not items:
            return None
        item = items[0]
        if not item.get("is_active", True):
            return None
        if not _verify_password(password, item.get("password_hash", "")):
            return None
        # map back to UserAccount
        return UserAccount(
            user_id=item["user_id"],
            first_name=item["first_name"],
            last_name=item["last_name"],
            email=item["email"],
            password_hash=item["password_hash"],
            organisation_type=OrganisationType(item["organisation_type"]),
            account_tier=AccountTier(item["account_tier"]),
            created_at=item["created_at"],
            is_active=item.get("is_active", True),
        )

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        resp = self.table.get_item(Key={"user_id": user_id})
        item = resp.get("Item")
        if item is None:
            return None
        return UserAccount(
            user_id=item["user_id"],
            first_name=item["first_name"],
            last_name=item["last_name"],
            email=item["email"],
            password_hash=item["password_hash"],
            organisation_type=OrganisationType(item["organisation_type"]),
            account_tier=AccountTier(item["account_tier"]),
            created_at=item["created_at"],
            is_active=item.get("is_active", True),
        )

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


class DynamoSessionsManager:
    """DynamoDB-backed session storage.

    Requires a user_id-index GSI on the sessions table for logout_all functionality.
    """

    def __init__(self) -> None:
        table_name = os.environ.get("DYNAMODB_SESSIONS_TABLE", "Sessions")
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(table_name)

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

        item: dict[str, any] = {
            "token_hash": token_hash,
            "user_id": payload.user_id,
            "created_at": created_at,
            "expires_at": expires_at,
            "remember_me": payload.remember_me,
        }
        if ip_address:
            item["ip_address"] = ip_address

        self.table.put_item(Item=item)
        return UserSession(**item), raw_token

    def validate_session_token(self, auth_token: str) -> Optional[UserSession]:
        token_hash = hash_token(auth_token)
        resp = self.table.get_item(Key={"token_hash": token_hash})
        item = resp.get("Item")
        if item is None:
            return None
        if item["expires_at"] < int(time.time()):
            self.revoke_session(token_hash)
            return None
        return UserSession(**item)

    def revoke_session(self, session_id: str) -> bool:
        # session_id is token_hash
        self.table.delete_item(Key={"token_hash": session_id})
        return True

    def revoke_all_user_sessions(self, user_id: str) -> bool:
        resp = self.table.query(
            IndexName="user_id-index",
            KeyConditionExpression=Key("user_id").eq(user_id),
        )
        items = resp.get("Items", [])
        if not items:
            return False
        for item in items:
            self.table.delete_item(Key={"token_hash": item["token_hash"]})
        return True


# (all helpers are defined locally; no further imports required)
