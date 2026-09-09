"""Deterministic API error codes.

Responses carry a stable code and nothing else — no exception text, no stack
trace, and nothing that distinguishes "no such user" from "wrong password".
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from fastapi import HTTPException, status

from app.api.schemas import ErrorResponse


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
    GRAPH_ACCESS_DENIED = "GRAPH_ACCESS_DENIED"
    GRAPH_UNAVAILABLE = "GRAPH_UNAVAILABLE"
    RESOLUTION_ACCESS_DENIED = "RESOLUTION_ACCESS_DENIED"
    RESOLUTION_NOT_OPEN = "RESOLUTION_NOT_OPEN"
    ANALYTICS_ACCESS_DENIED = "ANALYTICS_ACCESS_DENIED"
    # An entity that is absent and one the reader may not see answer alike, so
    # neither can be distinguished by probing.
    ANALYTICS_ENTITY_NOT_FOUND = "ANALYTICS_ENTITY_NOT_FOUND"
    DEBT_ACCESS_DENIED = "DEBT_ACCESS_DENIED"
    # Only reachable once a caller is already authorized to acknowledge in this
    # case, so it discloses nothing a read of the item list would not.
    DEBT_ITEM_NOT_FOUND = "DEBT_ITEM_NOT_FOUND"


def http_error(error: ApiError, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": error.value})


def unauthorized(error: ApiError) -> HTTPException:
    return http_error(error, status.HTTP_401_UNAUTHORIZED)


def forbidden(error: ApiError) -> HTTPException:
    return http_error(error, status.HTTP_403_FORBIDDEN)


def _documented(*codes: int) -> dict[int | str, dict[str, Any]]:
    """Declare the error body in OpenAPI, so a client is not guessing its shape."""
    return {code: {"model": ErrorResponse} for code in codes}


#: Every route behind the session boundary can answer with these.
AUTHENTICATED_ERRORS = _documented(
    status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN
)

#: Reading an analysis that has never been computed.
ANALYSIS_ERRORS = _documented(status.HTTP_404_NOT_FOUND)

#: The graph backend being unreachable is a 503, not a failure of the request.
GRAPH_ERRORS = _documented(status.HTTP_503_SERVICE_UNAVAILABLE)

#: Deciding a resolution that is no longer awaiting review.
RESOLUTION_REVIEW_ERRORS = _documented(status.HTTP_409_CONFLICT)

#: Login answers 401 for every failure mode, so none of them can be told apart.
LOGIN_ERRORS = _documented(status.HTTP_401_UNAUTHORIZED)

#: Analytics answers 404 for an entity that is absent *or* out of scope.
ANALYTICS_ERRORS = _documented(status.HTTP_404_NOT_FOUND)

#: Acknowledging a debt item that this calculation does not produce.
DEBT_ERRORS = _documented(status.HTTP_404_NOT_FOUND)
