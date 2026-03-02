from typing import Any
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auth.accounts import AuthenticationService

# Load environment variables from .env file (if it exists)
load_dotenv(Path(__file__).parent.parent / ".env")
from auth.schemas import AuthResponse, UserAccountCreate, OrganisationType, AccountTier

app = FastAPI()
auth_service = AuthenticationService()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ORGANISATION_VALUES = [e.value for e in OrganisationType]


class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    organisation_type: str
    account_tier: str = "FREE"
    remember_me: bool = False


class LoginRequest(BaseModel):
    email: str
    password: str
    remember_me: bool = False


def auth_response_to_dict(resp: AuthResponse) -> dict[str, Any]:
    return {
        "user": {
            "user_id": resp.user.user_id,
            "first_name": resp.user.first_name,
            "last_name": resp.user.last_name,
            "email": resp.user.email,
            "organisation_type": resp.user.organisation_type.value,
            "account_tier": resp.user.account_tier.value,
            "created_at": resp.user.created_at,
        },
        "auth_token": resp.auth_token,
    }


@app.post("/api/register")
def register(data: RegisterRequest) -> dict[str, Any]:
    if data.organisation_type not in ORGANISATION_VALUES:
        raise HTTPException(400, f"organisation_type must be one of: {ORGANISATION_VALUES}")
    try:
        org_enum = OrganisationType(data.organisation_type)
    except ValueError:
        raise HTTPException(400, f"Invalid organisation_type: {data.organisation_type}")
    tier_enum = AccountTier.PRO if data.account_tier == "PRO" else AccountTier.FREE

    payload = UserAccountCreate(
        first_name=data.first_name,
        last_name=data.last_name,
        email=data.email,
        password=data.password,
        organisation_type=org_enum,
        account_tier=tier_enum,
    )
    resp = auth_service.register(payload, remember_me=data.remember_me)
    if resp is None:
        raise HTTPException(400, "Registration failed (email may already be in use)")
    return auth_response_to_dict(resp)


@app.post("/api/login")
def login(data: LoginRequest) -> dict[str, Any]:
    resp = auth_service.login(data.email, data.password, remember_me=data.remember_me)
    if resp is None:
        raise HTTPException(401, "Invalid email or password")
    return auth_response_to_dict(resp)


@app.post("/api/logout")
def logout(request: Request) -> dict[str, bool]:
    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[7:].strip()
    ok = auth_service.logout(token)
    return {"success": ok}
