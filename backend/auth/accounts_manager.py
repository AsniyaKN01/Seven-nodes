from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import boto3
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv

# Load from /auth/.env specifically — don't pull from global environment
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

from auth.schemas import (
    AccountTier,
    OrganisationType,
    UserAccount,
    UserAccountCreate,
    UserAccountPublic,
)
from auth.crypto import hash_with_salt, verify_hash_with_salt

DEFAULT_ACCOUNTS_TABLE = os.getenv("AUTH_ACCOUNTS_TABLE", "UserAccounts")
DEFAULT_EMAIL_INDEX = os.getenv("AUTH_ACCOUNTS_EMAIL_INDEX", "email-index")


class AccountsManager:
    """Handles all DynamoDB reads and writes for the UserAccounts table.
    No business logic lives here — that belongs in accounts.py.
    """

    def __init__(
        self,
        accounts_table: str = DEFAULT_ACCOUNTS_TABLE,
        email_index_name: str = DEFAULT_EMAIL_INDEX,
    ) -> None:
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(accounts_table)
        self.email_index_name = email_index_name

    @staticmethod
    def to_public(account: UserAccount) -> UserAccountPublic:
        """Strip password_hash and is_active before anything goes to the frontend."""
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
        """Write a new account to DynamoDB. Returns None if the email is taken."""
        if self.get_account_by_email(payload.email) is not None:
            return None

        account = UserAccount(
            user_id=str(uuid.uuid4()),
            first_name=payload.first_name,
            last_name=payload.last_name,
            email=payload.email,
            password_hash=hash_with_salt(payload.password),
            organisation_type=payload.organisation_type,
            account_tier=payload.account_tier,
            created_at=datetime.now(timezone.utc).isoformat(),
            is_active=True,
        )

        self.table.put_item(Item=_account_to_item(account))
        return account

    def get_account(self, user_id: str) -> Optional[UserAccount]:
        """Direct PK lookup by user_id."""
        response = self.table.get_item(Key={"user_id": user_id})
        item = response.get("Item")
        return _item_to_account(item) if item else None

    def get_account_by_email(self, email: str) -> Optional[UserAccount]:
        """Email lookup via email-index GSI — used by login and duplicate check."""
        response = self.table.query(
            IndexName=self.email_index_name,
            KeyConditionExpression=Key("email").eq(email),
        )
        items = response.get("Items", [])
        return _item_to_account(items[0]) if items else None

    def verify_credentials(self, email: str, password: str) -> Optional[UserAccount]:
        """Returns account if email exists, account is active, and password matches.
        Deliberately returns None for any failure — no detail on which check failed.
        """
        account = self.get_account_by_email(email)
        if account is None or not account.is_active:
            return None
        if not verify_hash_with_salt(password, account.password_hash):
            return None
        return account

    def set_account_active(self, user_id: str, is_active: bool) -> bool:
        """Flip is_active on an account — used for suspension or reactivation."""
        try:
            self.table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET is_active = :val",
                ExpressionAttributeValues={":val": is_active},
            )
            return True
        except Exception:
            return False


# --- DynamoDB serialisation helpers ---

def _account_to_item(account: UserAccount) -> dict:
    """Enums stored as their string values so DynamoDB holds plain strings."""
    return {
        "user_id": account.user_id,
        "first_name": account.first_name,
        "last_name": account.last_name,
        "email": account.email,
        "password_hash": account.password_hash,
        "organisation_type": account.organisation_type.value,
        "account_tier": account.account_tier.value,
        "created_at": account.created_at,
        "is_active": account.is_active,
    }


def _item_to_account(item: dict) -> UserAccount:
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