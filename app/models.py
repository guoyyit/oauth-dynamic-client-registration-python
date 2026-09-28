"""Pydantic schemas for request bodies.

The service keeps an open-but-known metadata model (RFC 7591 style): known
fields are validated for type and value; unknown fields are rejected with a
precise error code.  Responses are plain dictionaries assembled by the
service layer so that secret material is never accidentally serialized.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

ALLOWED_GRANT_TYPES = frozenset(
    {"authorization_code", "client_credentials", "refresh_token", "implicit"}
)
ALLOWED_TOKEN_AUTH_METHODS = frozenset(
    {"client_secret_basic", "client_secret_post", "none"}
)
ALLOWED_RESPONSE_TYPES = frozenset({"code", "token"})

ALLOWED_FIELDS = frozenset(
    {
        "redirect_uris",
        "grant_types",
        "response_types",
        "token_endpoint_auth_method",
        "scope",
        "client_name",
        "client_uri",
        "logo_uri",
        "contacts",
        "tos_uri",
        "policy_uri",
    }
)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    software_statement: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1)
    software_statement: str = Field(min_length=1)
    expected_version: int = Field(ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretRotateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    software_statement: str = Field(min_length=1)
    retain_old_secret: bool = True
    grace_period_seconds: int | None = Field(default=None, ge=0)


class SecretRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    software_statement: str = Field(min_length=1)
    secret_id: str | None = None


class StateTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    software_statement: str = Field(min_length=1)
    target_state: str = Field(min_length=1)
    expected_version: int | None = Field(default=None, ge=1)


class RecoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    software_statement: str = Field(min_length=1)
    expected_version: int | None = Field(default=None, ge=1)
