from dataclasses import dataclass
from typing import Optional
from enum import Enum

class AccountTier(str, Enum):
    FREE = "FREE"
    PRO = "PRO"

class OrganisationType(str, Enum):
    PHARMACEUTICAL_COMPANY = "Pharmaceutical Company"
    BIOTECH_STARTUP = "Biotech Startup"
    ACADEMIC_RESEARCH_INSTITUTION = "Academic / Research Institution"
    HOSPITAL_CLINICAL_CENTRE = "Hospital / Clinical Centre"
    CRO_CONTRACT_RESEARCH = "CRO / Contract Research"
    OTHER = "Other"

@dataclass
class UserAccountCreate:
    first_name: str
    last_name: str
    email: str
    password: str
    organisation_type: OrganisationType
    account_tier: AccountTier = AccountTier.FREE

@dataclass
class UserAccount:
    user_id: str
    first_name: str
    last_name: str
    email: str
    password_hash: str
    organisation_type: OrganisationType
    account_tier: AccountTier
    created_at: str
    is_active: bool = True

@dataclass
class UserAccountPublic:
    user_id: str
    first_name: str
    last_name: str
    email: str
    organisation_type: OrganisationType
    account_tier: AccountTier
    created_at: str

@dataclass
class UserSessionCreate:
    user_id: str
    remember_me: bool = False

@dataclass
class UserSession:
    token_hash: str
    user_id: str
    created_at: str
    expires_at: int
    remember_me: bool
    ip_address: Optional[str] = None

@dataclass
class AuthResponse:
    user: UserAccountPublic
    auth_token: str
