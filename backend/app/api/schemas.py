"""Request/response shapes for the authentication boundary.

These are deliberately narrow projections: no password material, no policy
internals, no repository objects. Anything not listed here does not leave the
process.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class ClearanceResponse(BaseModel):
    level: str | None
    verified: bool
    expires_at: str | None = None


class AgencyResponse(BaseModel):
    agency_id: str
    name: str


class SessionResponse(BaseModel):
    session_id: str
    expires_at: str


class LoginResponse(BaseModel):
    token: str
    session: SessionResponse
    user_id: str
    display_name: str | None
    clearance: ClearanceResponse


class MeResponse(BaseModel):
    user_id: str
    username: str
    display_name: str | None
    roles: list[str]
    clearance: ClearanceResponse
    authorized_agencies: list[AgencyResponse]
    active_agency_id: str | None
    session: SessionResponse


class ContextSwitchRequest(BaseModel):
    agency_id: str = Field(min_length=1, max_length=64)
    department: str | None = Field(default=None, max_length=64)
    unit: str | None = Field(default=None, max_length=64)


class ContextResponse(BaseModel):
    agency_id: str
    agency_name: str
    role: str
    clearance_level: str
    department: str | None = None
    unit: str | None = None
