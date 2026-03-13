"""
DynamoDB-backed storage adapters for the authentication service.

The core auth workflow in ``auth.accounts.AuthenticationService`` is storage-agnostic
and only depends on small protocol-style interfaces. This module simply exposes
the concrete DynamoDB implementations under the names that
``AuthenticationService`` expects when ``USE_DYNAMODB`` is enabled.

Currently the DynamoDB implementations live in:

    - ``auth.accounts_manager.AccountsManager``
    - ``auth.sessions_manager.SessionsManager``

We re-export them here as ``DynamoAccountsManager`` and ``DynamoSessionsManager``
so this file can evolve independently (for example, if you later introduce
separate in-memory managers or additional storage backends).
"""

from auth.accounts_manager import AccountsManager as DynamoAccountsManager
from auth.sessions_manager import SessionsManager as DynamoSessionsManager

__all__ = ["DynamoAccountsManager", "DynamoSessionsManager"]

