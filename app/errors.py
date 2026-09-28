"""Distinguishable error codes returned by the registration API."""

from __future__ import annotations


ERR_INVALID_REQUEST = "invalid_request"
ERR_INVALID_SOFTWARE_STATEMENT = "invalid_software_statement"
ERR_INVALID_REDIRECT_URI = "invalid_redirect_uri"
ERR_INVALID_GRANT_TYPE = "invalid_grant_type"
ERR_INVALID_TOKEN_ENDPOINT_AUTH = "invalid_token_endpoint_auth_method"
ERR_INVALID_METADATA = "invalid_client_metadata"
ERR_UNKNOWN_ISSUER = "unknown_issuer"
ERR_SIGNATURE_INVALID = "invalid_signature"
ERR_EXPIRED_STATEMENT = "expired_software_statement"
ERR_DUPLICATE_CLIENT = "duplicate_client"
ERR_CLIENT_NOT_FOUND = "client_not_found"
ERR_VERSION_CONFLICT = "version_conflict"
ERR_INVALID_STATE_TRANSITION = "invalid_state_transition"
ERR_OWNERSHIP_MISMATCH = "ownership_mismatch"
ERR_CLIENT_REVOKED = "client_revoked"
ERR_NO_ACTIVE_SECRET = "no_active_secret"
ERR_UNSUPPORTED_SIGNATURE_ALG = "unsupported_signature_algorithm"


class RegistrationError(Exception):
    """Error carrying a stable error code, HTTP status and message."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
