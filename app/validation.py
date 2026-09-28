"""Validation of software-statement claims and client metadata.

Metadata is an RFC 7591-style open object, but this local service only
accepts a known set of fields so that mistakes surface with precise error
codes instead of being silently persisted.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.errors import (
    ERR_INVALID_GRANT_TYPE,
    ERR_INVALID_METADATA,
    ERR_INVALID_REDIRECT_URI,
    ERR_INVALID_REQUEST,
    ERR_INVALID_SOFTWARE_STATEMENT,
    ERR_INVALID_TOKEN_ENDPOINT_AUTH,
    RegistrationError,
)
from app.models import (
    ALLOWED_FIELDS,
    ALLOWED_GRANT_TYPES,
    ALLOWED_RESPONSE_TYPES,
    ALLOWED_TOKEN_AUTH_METHODS,
)

# RFC 6749 scope-token: printable ASCII minus space, double-quote and backslash.
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")

# Claims that a software statement must carry.
REQUIRED_STATEMENT_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "software_id")


def _ensure_str(value: object, field: str, code: str = ERR_INVALID_METADATA) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistrationError(code, f"field {field!r} must be a non-empty string", 400)
    return value


def _ensure_list_of_str(
    value: object, field: str, code: str
) -> list[str]:
    if not isinstance(value, list) or not value:
        raise RegistrationError(code, f"field {field!r} must be a non-empty array", 400)
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise RegistrationError(
                code, f"field {field!r} must contain only non-empty strings", 400
            )
        cleaned.append(item)
    return cleaned


def _is_valid_https_or_localhost_uri(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme == "http":
        host = parsed.hostname or ""
        return host in {"localhost", "127.0.0.1", "::1"}
    return False


def validate_redirect_uri(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegistrationError(
            ERR_INVALID_REDIRECT_URI, "redirect_uris entries must be strings", 400
        )
    # Native app loopback or custom-scheme URIs (e.g. com.example.app:/oauth)
    parsed = urlparse(value)
    if parsed.scheme == "https":
        if not parsed.netloc:
            raise RegistrationError(
                ERR_INVALID_REDIRECT_URI, f"invalid https redirect URI: {value!r}", 400
            )
    elif parsed.scheme == "http":
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise RegistrationError(
                ERR_INVALID_REDIRECT_URI,
                "http redirect URIs are only allowed on loopback hosts",
                400,
            )
    elif re.fullmatch(r"[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+", parsed.scheme or ""):
        # RFC 8252 reverse-DNS private-use scheme (e.g. com.example.app:/oauth).
        if not value.split(":", 1)[1]:
            raise RegistrationError(
                ERR_INVALID_REDIRECT_URI, f"invalid custom-scheme redirect URI: {value!r}", 400
            )
    else:
        raise RegistrationError(
            ERR_INVALID_REDIRECT_URI, f"invalid redirect URI: {value!r}", 400
        )
    if "#" in value:
        raise RegistrationError(
            ERR_INVALID_REDIRECT_URI, "redirect URIs must not contain fragments", 400
        )
    return value


def _validate_scope(value: object) -> str:
    scope = _ensure_str(value, "scope")
    for token in scope.split():
        if not _SCOPE_TOKEN.fullmatch(token):
            raise RegistrationError(
                ERR_INVALID_METADATA, f"invalid scope token: {token!r}", 400
            )
    return scope


def validate_metadata(metadata: dict, *, partial: bool = False) -> dict:
    """Validate a client metadata object and return a normalized copy.

    With ``partial=True`` only the provided keys are checked (updates);
    with full validation (registration) grant types default per RFC 7591
    and required cross-field invariants are enforced.
    """
    if not isinstance(metadata, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "metadata must be an object", 400)

    unknown = set(metadata) - ALLOWED_FIELDS
    if unknown:
        raise RegistrationError(
            ERR_INVALID_METADATA,
            f"unsupported metadata field(s): {', '.join(sorted(unknown))}",
            400,
        )

    normalized: dict = {}

    if "redirect_uris" in metadata:
        uris = _ensure_list_of_str(metadata["redirect_uris"], "redirect_uris", ERR_INVALID_REDIRECT_URI)
        normalized["redirect_uris"] = [validate_redirect_uri(u) for u in uris]
    elif not partial:
        normalized["redirect_uris"] = []

    if "grant_types" in metadata:
        grant_types = _ensure_list_of_str(metadata["grant_types"], "grant_types", ERR_INVALID_GRANT_TYPE)
        bad = [g for g in grant_types if g not in ALLOWED_GRANT_TYPES]
        if bad:
            raise RegistrationError(
                ERR_INVALID_GRANT_TYPE, f"unsupported grant type(s): {', '.join(bad)}", 400
            )
        normalized["grant_types"] = grant_types
    elif not partial:
        normalized["grant_types"] = ["authorization_code"]

    if "response_types" in metadata:
        response_types = _ensure_list_of_str(
            metadata["response_types"], "response_types", ERR_INVALID_METADATA
        )
        bad = [r for r in response_types if r not in ALLOWED_RESPONSE_TYPES]
        if bad:
            raise RegistrationError(
                ERR_INVALID_METADATA, f"unsupported response type(s): {', '.join(bad)}", 400
            )
        normalized["response_types"] = response_types
    elif not partial:
        normalized["response_types"] = ["code"]

    if "token_endpoint_auth_method" in metadata:
        method = metadata["token_endpoint_auth_method"]
        if method not in ALLOWED_TOKEN_AUTH_METHODS or not isinstance(method, str):
            raise RegistrationError(
                ERR_INVALID_TOKEN_ENDPOINT_AUTH,
                f"unsupported token_endpoint_auth_method: {method!r}",
                400,
            )
        normalized["token_endpoint_auth_method"] = method
    elif not partial:
        normalized["token_endpoint_auth_method"] = "client_secret_basic"

    if "scope" in metadata:
        normalized["scope"] = _validate_scope(metadata["scope"])

    for name in ("client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri"):
        if name in metadata and metadata[name] is not None:
            text = _ensure_str(metadata[name], name)
            if name.endswith("_uri") and name != "client_name":
                if not _is_valid_https_or_localhost_uri(text):
                    raise RegistrationError(
                        ERR_INVALID_METADATA, f"field {name!r} must be an https URI", 400
                    )
            normalized[name] = text

    if "contacts" in metadata and metadata["contacts"] is not None:
        normalized["contacts"] = _ensure_list_of_str(metadata["contacts"], "contacts", ERR_INVALID_METADATA)

    _check_cross_field_invariants(normalized, partial)
    return normalized


def _check_cross_field_invariants(meta: dict, partial: bool) -> None:
    grant_types = meta.get("grant_types", ["authorization_code"] if not partial else None)
    response_types = meta.get("response_types")
    auth_method = meta.get("token_endpoint_auth_method")
    redirect_uris = meta.get("redirect_uris")

    if auth_method == "none":
        if grant_types and "client_credentials" in grant_types:
            raise RegistrationError(
                ERR_INVALID_TOKEN_ENDPOINT_AUTH,
                "public clients (token_endpoint_auth_method='none') cannot use client_credentials",
                400,
            )

    needs_redirect = False
    if grant_types and {"authorization_code", "implicit"} & set(grant_types):
        needs_redirect = True
    if response_types and ({"code", "token"} & set(response_types)):
        needs_redirect = True
    # On partial updates only flag when redirect URIs were explicitly empty
    # together with a browser-based grant/response type in the same request.
    if needs_redirect and redirect_uris is not None and len(redirect_uris) == 0:
        raise RegistrationError(
            ERR_INVALID_REDIRECT_URI,
            "browser-based grants require at least one redirect URI",
            400,
        )

    if response_types and "token" in response_types and grant_types:
        if "implicit" not in grant_types:
            raise RegistrationError(
                ERR_INVALID_GRANT_TYPE,
                "response_type 'token' requires the 'implicit' grant type",
                400,
            )


def validate_statement_claims(claims: dict) -> dict:
    """Enforce local business requirements on verified statement claims."""
    for name in REQUIRED_STATEMENT_CLAIMS:
        if name not in claims:
            raise RegistrationError(
                ERR_INVALID_SOFTWARE_STATEMENT,
                f"software statement is missing required claim: {name!r}",
                400,
            )
    for name in ("sub", "software_id"):
        _ensure_str(claims[name], name, ERR_INVALID_SOFTWARE_STATEMENT)
    for name in ("iat", "exp"):
        value = claims[name]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise RegistrationError(
                ERR_INVALID_SOFTWARE_STATEMENT,
                f"software statement claim {name!r} must be numeric",
                400,
            )
    embedded = claims.get("metadata", {})
    if embedded is None:
        embedded = {}
    if not isinstance(embedded, dict):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement 'metadata' claim must be an object",
            400,
        )
    if embedded:
        # Validate value-level constraints here; cross-field invariants are
        # enforced on the fully merged metadata at registration time.
        validate_metadata(embedded, partial=True)
    return claims


def merge_metadata(statement_meta: dict, request_meta: dict) -> dict:
    """Merge statement-embedded metadata with request metadata (request wins)."""
    merged = dict(statement_meta)
    merged.update(request_meta)
    return validate_metadata(merged)


def validate_registration_request(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "request body must be a JSON object", 400)
    token = payload.get("software_statement")
    if not isinstance(token, str) or not token:
        raise RegistrationError(
            ERR_INVALID_REQUEST, "'software_statement' is required", 400
        )
    request_meta = payload.get("metadata", {})
    if request_meta is None:
        request_meta = {}
    if not isinstance(request_meta, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "'metadata' must be an object", 400)
    return {"software_statement": token, "metadata": request_meta}


def validate_update_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "request body must be a JSON object", 400)
    token = payload.get("software_statement")
    if not isinstance(token, str) or not token:
        raise RegistrationError(
            ERR_INVALID_REQUEST, "'software_statement' is required", 400
        )
    expected_version = payload.get("expected_version")
    if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 1:
        raise RegistrationError(
            ERR_INVALID_REQUEST, "'expected_version' must be a positive integer", 400
        )
    metadata = payload.get("metadata", {})
    if metadata is None:
        metadata = {}
    validate_metadata(metadata, partial=True)
    return {
        "software_statement": token,
        "expected_version": expected_version,
        "metadata": metadata,
    }
