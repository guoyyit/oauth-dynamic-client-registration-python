"""Software statement signing/verification and client secret hashing.

Software statements are compact JWT-like tokens signed with HMAC-SHA256
(``alg=HS256``) using secrets shared locally with trusted issuers.  No
external identity source is contacted.  Client secrets returned to the
caller once are stored only as salted SHA-256 hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from app.errors import (
    ERR_EXPIRED_STATEMENT,
    ERR_INVALID_SOFTWARE_STATEMENT,
    ERR_SIGNATURE_INVALID,
    ERR_UNKNOWN_ISSUER,
    ERR_UNSUPPORTED_SIGNATURE_ALG,
    RegistrationError,
)

ALGORITHM = "HS256"
_HASH_SCHEME = "sha256"


def generate_client_id() -> str:
    """Return a high-entropy random client identifier."""
    return "cid_" + secrets.token_urlsafe(18)


def generate_client_secret(byte_length: int = 32) -> str:
    """Return a new high-entropy client secret (shown to caller once)."""
    return secrets.token_urlsafe(byte_length)


def hash_secret(secret: str) -> str:
    """Hash a client secret for at-rest storage."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"{_HASH_SCHEME}${digest}"


def verify_secret(secret: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented secret against a stored hash."""
    try:
        scheme, digest = stored_hash.split("$", 1)
    except ValueError:
        return False
    if scheme != _HASH_SCHEME:
        return False
    candidate = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, digest)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(signing_input: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()


def encode_software_statement(payload: dict, secret: str) -> str:
    """Sign a claims payload and return a compact HS256 software statement."""
    header = {"alg": ALGORITHM, "typ": "software-statement"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature_b64 = _b64url_encode(_sign(signing_input, secret))
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _decode_json_segment(segment: str, *, header: bool) -> dict:
    try:
        raw = _b64url_decode(segment)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement contains a malformed segment",
            400,
        ) from None
    if not isinstance(value, dict):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement header/payload must be a JSON object",
            400,
        )
    return value


def verify_software_statement(
    token: str,
    issuer_secrets: dict[str, str],
    expected_audience: str,
    *,
    now: int | None = None,
) -> dict:
    """Verify signature, issuer, expiry and audience; return verified claims.

    Raises :class:`RegistrationError` with a distinguishable code on any
    failure.  Verification is local and does not hit the network.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement must be a compact signed token",
            400,
        )
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = _decode_json_segment(header_b64, header=True)

    alg = header.get("alg")
    if alg != ALGORITHM:
        raise RegistrationError(
            ERR_UNSUPPORTED_SIGNATURE_ALG,
            f"unsupported software statement algorithm: {alg!r}",
            400,
        )

    claims = _decode_json_segment(payload_b64, header=False)

    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement is missing the 'iss' claim",
            400,
        )
    trusted_secret = issuer_secrets.get(issuer)
    if trusted_secret is None:
        raise RegistrationError(
            ERR_UNKNOWN_ISSUER,
            f"software statement issuer is not trusted: {issuer!r}",
            401,
        )

    try:
        provided_signature = _b64url_decode(signature_b64)
    except ValueError:
        raise RegistrationError(
            ERR_SIGNATURE_INVALID, "software statement signature is malformed", 400
        ) from None
    expected_signature = _sign(f"{header_b64}.{payload_b64}".encode("ascii"), trusted_secret)
    if not hmac.compare_digest(provided_signature, expected_signature):
        raise RegistrationError(
            ERR_SIGNATURE_INVALID, "software statement signature does not verify", 401
        )

    current_time = int(time.time()) if now is None else now

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement is missing a numeric 'exp' claim",
            400,
        )
    if current_time >= int(exp):
        raise RegistrationError(
            ERR_EXPIRED_STATEMENT,
            "software statement has expired",
            401,
        )

    nbf = claims.get("nbf")
    if nbf is not None and (not isinstance(nbf, (int, float)) or isinstance(nbf, bool)):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement 'nbf' claim must be numeric",
            400,
        )
    if isinstance(nbf, (int, float)) and current_time < int(nbf):
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement is not valid yet",
            401,
        )

    audience = claims.get("aud")
    if audience != expected_audience:
        raise RegistrationError(
            ERR_INVALID_SOFTWARE_STATEMENT,
            "software statement audience does not match this service",
            401,
        )

    return claims
