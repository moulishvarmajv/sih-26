"""Deterministic API error codes.

Responses carry a stable code and nothing else — no exception text, no stack
trace, and nothing that distinguishes "no such user" from "wrong password".
"""
from __future__ import annotations

from enum import Enum

from fastapi import HTTPException, status


class ApiError(str, Enum):
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    AGENCY_ACCESS_DENIED = "AGENCY_ACCESS_DENIED"
    CLEARANCE_INVALID = "CLEARANCE_INVALID"
    NO_ACTIVE_CONTEXT = "NO_ACTIVE_CONTEXT"
    # Unknown and unauthorized resources return the same code on purpose, so a
    # caller cannot enumerate cases or evidence they have no access to.
    CASE_ACCESS_DENIED = "CASE_ACCESS_DENIED"
    EVIDENCE_ACCESS_DENIED = "EVIDENCE_ACCESS_DENIED"
    ANALYSIS_NOT_AVAILABLE = "ANALYSIS_NOT_AVAILABLE"


def http_error(error: ApiError, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": error.value})


def unauthorized(error: ApiError) -> HTTPException:
    return http_error(error, status.HTTP_401_UNAUTHORIZED)


def forbidden(error: ApiError) -> HTTPException:
    return http_error(error, status.HTTP_403_FORBIDDEN)
