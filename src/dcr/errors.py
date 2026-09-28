"""Distinguishable error codes and the HTTP exception type.

Every validation / business failure raises :class:`DCR` carrying a stable
machine readable ``code`` so callers can tell failure reasons apart.
"""

from __future__ import annotations


class ErrorCode:
    INVALID_SOFTWARE_STATEMENT = "invalid_software_statement"
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED_SOFTWARE_STATEMENT = "malformed_software_statement"
    SOFTWARE_STATEMENT_EXPIRED = "software_statement_expired"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    INVALID_REDIRECT_URIS = "invalid_redirect_uris"
    INVALID_GRANT_TYPES = "invalid_grant_types"
    INVALID_TOKEN_ENDPOINT_AUTH = "invalid_token_endpoint_auth_method"
    INVALID_SCOPE = "invalid_scope"
    INVALID_CLIENT_METADATA = "invalid_client_metadata"
    INVALID_CLIENT = "invalid_client"
    INVALID_REQUEST = "invalid_request"
    CLIENT_NOT_FOUND = "client_not_found"
    DUPLICATE_CLIENT = "duplicate_client"
    SOFTWARE_STATEMENT_MISMATCH = "software_statement_mismatch"
    VERSION_CONFLICT = "version_conflict"
    INVALID_STATE_TRANSITION = "invalid_state_transition"
    CLIENT_REVOKED = "client_revoked"
    SECRET_ROTATION_REJECTED = "secret_rotation_rejected"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"


class DCR(Exception):
    """Business error mapped to a structured HTTP response."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def to_dict(self) -> dict:
        return {"error": self.code, "error_description": self.message}
