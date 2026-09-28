"""Validation of registration/update metadata against protocol rules.

Every failure raises :class:`~dcr.errors.DCR` with a specific, distinguishable
error code so callers know exactly which field was rejected. Validation is
pure: it performs no persistence, therefore invalid requests can have no
side effects.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .config import (
    ALLOWED_GRANT_TYPES,
    ALLOWED_TOKEN_AUTH_METHODS,
    DEFAULT_GRANT_TYPES,
    DEFAULT_RESPONSE_TYPES,
    REDIRECT_REQUIRED_GRANTS,
    Settings,
)
from .errors import DCR, ErrorCode
from .models import SoftwareStatement


def _is_https_or_localhost(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return True
    # http://localhost / 127.0.0.1 / ::1 allowed for local development only.
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    # Native/public client loopback redirection (RFC 8252).
    if parsed.scheme in {"http", "https"} and parsed.hostname and parsed.hostname.endswith(".localhost"):
        return True
    return False


def _validate_redirect_uris(redirect_uris: object, grant_types: list[str]) -> list[str]:
    if not isinstance(redirect_uris, list) or not redirect_uris:
        if any(g in REDIRECT_REQUIRED_GRANTS for g in grant_types):
            raise DCR(
                ErrorCode.INVALID_REDIRECT_URIS,
                "redirect_uris is required for authorization_code/implicit grants",
            )
        return []
    normalized: list[str] = []
    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri:
            raise DCR(ErrorCode.INVALID_REDIRECT_URIS, "every redirect_uri must be a non-empty string")
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            raise DCR(ErrorCode.INVALID_REDIRECT_URIS, f"redirect_uri is not an absolute URI: {uri!r}")
        if parsed.fragment:
            raise DCR(ErrorCode.INVALID_REDIRECT_URIS, f"redirect_uri must not contain a fragment: {uri!r}")
        if not _is_https_or_localhost(uri):
            raise DCR(
                ErrorCode.INVALID_REDIRECT_URIS,
                f"redirect_uri must use https (or loopback http): {uri!r}",
            )
        normalized.append(uri)
    if len(set(normalized)) != len(normalized):
        raise DCR(ErrorCode.INVALID_REDIRECT_URIS, "redirect_uris must not contain duplicates")
    return normalized


def _validate_grant_types(grant_types: object) -> list[str]:
    if grant_types is None:
            return list(DEFAULT_GRANT_TYPES)
    if not isinstance(grant_types, list) or not grant_types:
        raise DCR(ErrorCode.INVALID_GRANT_TYPES, "grant_types must be a non-empty array")
    for grant in grant_types:
        if not isinstance(grant, str) or grant not in ALLOWED_GRANT_TYPES:
            raise DCR(ErrorCode.INVALID_GRANT_TYPES, f"unsupported grant_type: {grant!r}")
    if len(set(grant_types)) != len(grant_types):
        raise DCR(ErrorCode.INVALID_GRANT_TYPES, "grant_types must not contain duplicates")
    return grant_types


def _validate_response_types(response_types: object, grant_types: list[str]) -> list[str]:
    if response_types is None:
        if "implicit" in grant_types:
            return ["token"]
        if "authorization_code" in grant_types:
            return list(DEFAULT_RESPONSE_TYPES)
        return []
    if not isinstance(response_types, list):
        raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "response_types must be an array")
    allowed = {"code", "token", "id_token"}
    for rt in response_types:
        if not isinstance(rt, str) or rt not in allowed:
            raise DCR(ErrorCode.INVALID_CLIENT_METADATA, f"unsupported response_type: {rt!r}")
    if "code" in response_types and "authorization_code" not in grant_types:
        raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "response_type 'code' requires grant_type authorization_code")
    if "token" in response_types and "implicit" not in grant_types:
        raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "response_type 'token' requires grant_type implicit")
    return response_types


def _validate_token_auth(method: object, grant_types: list[str]) -> str:
    if method is None:
        method = "client_secret_basic"
    if not isinstance(method, str) or method not in ALLOWED_TOKEN_AUTH_METHODS:
        raise DCR(
            ErrorCode.INVALID_TOKEN_ENDPOINT_AUTH,
            f"unsupported token_endpoint_auth_method: {method!r}",
        )
    if method == "none" and "client_credentials" in grant_types:
        raise DCR(
            ErrorCode.INVALID_TOKEN_ENDPOINT_AUTH,
            "token_endpoint_auth_method 'none' cannot be combined with client_credentials",
        )
    if method != "none" and not any(
        g in grant_types for g in ("authorization_code", "refresh_token", "client_credentials")
    ):
        raise DCR(
            ErrorCode.INVALID_TOKEN_ENDPOINT_AUTH,
            f"token_endpoint_auth_method {method!r} requires a confidential grant type",
        )
    return method


def _validate_scope(scope: object, settings: Settings) -> str:
    if scope is None:
        return ""
    if not isinstance(scope, str):
        raise DCR(ErrorCode.INVALID_SCOPE, "scope must be a space-delimited string")
    scopes = scope.split()
    unknown = [sc for sc in scopes if sc not in settings.allowed_scopes]
    if unknown:
        raise DCR(ErrorCode.INVALID_SCOPE, f"scope values not allowed: {', '.join(unknown)}")
    return " ".join(dict.fromkeys(scopes))


def validate_metadata(metadata: dict, settings: Settings) -> dict:
    """Validate and normalize client metadata; raise DCR with a specific code."""
    if not isinstance(metadata, dict):
        raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "metadata must be a JSON object")

    grant_types = _validate_grant_types(metadata.get("grant_types"))
    redirect_uris = _validate_redirect_uris(metadata.get("redirect_uris"), grant_types)
    response_types = _validate_response_types(metadata.get("response_types"), grant_types)
    token_auth = _validate_token_auth(metadata.get("token_endpoint_auth_method"), grant_types)
    scope = _validate_scope(metadata.get("scope"), settings)

    client_name = metadata.get("client_name", "")
    if client_name is not None and not isinstance(client_name, str):
        raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "client_name must be a string")

    client_uri = metadata.get("client_uri")
    if client_uri is not None:
        if not isinstance(client_uri, str) or not urlparse(client_uri).scheme:
            raise DCR(ErrorCode.INVALID_CLIENT_METADATA, "client_uri must be an absolute URI")

    return {
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_auth,
        "scope": scope,
        "client_name": client_name or "",
    }


def assert_statement_owns_client(statement: SoftwareStatement, software_id: str, issuer: str) -> None:
    """Ensure the statement proves ownership of the client being updated."""
    if statement.iss != issuer:
        raise DCR(
            ErrorCode.SOFTWARE_STATEMENT_MISMATCH,
            "software statement issuer does not match the registered client's issuer",
            status_code=403,
        )
    if statement.software_id != software_id:
        raise DCR(
            ErrorCode.SOFTWARE_STATEMENT_MISMATCH,
            "software statement does not own this client (software_id mismatch)",
            status_code=403,
        )
