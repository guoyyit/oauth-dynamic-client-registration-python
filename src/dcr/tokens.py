"""Software statement issuing and local signature verification.

Software statements are JWS Compact Serialization (RFC 7515) tokens::

    BASE64URL(header) . BASE64URL(payload) . BASE64URL(HMAC-SHA256)

The JOSE header carries ``alg`` (``HS256`` only), ``kid`` and ``typ``.
Only the locally configured symmetric key is trusted -- verification never
contacts an external identity source.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from .config import DEFAULT_ISSUER, Settings
from .errors import DCR, ErrorCode
from .models import SoftwareStatement

ALGORITHM = "HS256"
TOKEN_TYPE = "client-software-statement+jwt"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    try:
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)
    except (ValueError, TypeError) as exc:
        raise DCR(ErrorCode.MALFORMED_SOFTWARE_STATEMENT, "malformed base64url segment") from exc


def _sign(signing_input: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()


def issue_software_statement(
    claims: dict,
    *,
    secret: str = "",
    kid: str = "",
    ttl_seconds: int = 600,
) -> str:
    """Mint a signed software statement (used by trusted issuer tooling/tests).

    ``claims`` must include ``software_id`` (and normally ``metadata``);
    ``iat``/``exp``/``jti`` are filled when absent.
    """
    if not secret:
        raise ValueError("secret is required")
    now = int(time.time())
    payload = dict(claims)
    payload.setdefault("iss", DEFAULT_ISSUER)
    payload.setdefault("sub", payload.get("software_id", ""))
    payload.setdefault("iat", now)
    payload.setdefault("exp", now + ttl_seconds)
    payload.setdefault("jti", secrets.token_urlsafe(12))

    header = {"alg": ALGORITHM, "kid": kid or "local-key-1", "typ": TOKEN_TYPE}
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header_seg}.{payload_seg}".encode()
    signature_seg = _b64url_encode(_sign(signing_input, secret))
    return f"{header_seg}.{payload_seg}.{signature_seg}"


def _decode_json(segment: str) -> dict:
    try:
        value = json.loads(_b64url_decode(segment))
    except json.JSONDecodeError as exc:
        raise DCR(ErrorCode.MALFORMED_SOFTWARE_STATEMENT, "segment is not valid JSON") from exc
    if not isinstance(value, dict):
        raise DCR(ErrorCode.MALFORMED_SOFTWARE_STATEMENT, "token segment must be a JSON object")
    return value


def verify_software_statement(token: str, settings: Settings, *, now: int | None = None) -> SoftwareStatement:
    """Verify signature, expiry and issuer; raise DCR on any failure."""
    if not isinstance(token, str) or token.count(".") != 2:
        raise DCR(ErrorCode.MALFORMED_SOFTWARE_STATEMENT, "software_statement must be a compact JWS")
    header_seg, payload_seg, signature_seg = token.split(".")

    # Only HS256 is accepted. The algorithm is pinned (not taken from the
    # token at verification time), so algorithm-confusion attacks are moot;
    # still reject explicitly before touching the signature so callers get a
    # precise reason.
    header = _decode_json(header_seg)
    if header.get("alg") != ALGORITHM:
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, f"unsupported alg: {header.get('alg')!r}")

    expected = _sign(f"{header_seg}.{payload_seg}".encode(), settings.signing_secret)
    try:
        provided = _b64url_decode(signature_seg)
    except DCR:
        raise
    if not hmac.compare_digest(expected, provided):
        raise DCR(ErrorCode.INVALID_SIGNATURE, "software statement signature verification failed")

    if header.get("typ") not in (None, TOKEN_TYPE):
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, f"unsupported typ: {header.get('typ')!r}")

    claims = _decode_json(payload_seg)

    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "claim 'iss' is required")
    if issuer != settings.trusted_issuer:
        raise DCR(ErrorCode.UNTRUSTED_ISSUER, f"issuer {issuer!r} is not trusted")

    current = int(time.time()) if now is None else now
    exp = claims.get("exp")
    iat = claims.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "claims 'iat' and 'exp' must be integers")
    if exp < current:
        raise DCR(ErrorCode.SOFTWARE_STATEMENT_EXPIRED, "software statement has expired")
    if exp <= iat:
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "'exp' must be after 'iat'")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "claim 'jti' is required")

    software_id = claims.get("software_id")
    if not isinstance(software_id, str) or not software_id:
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "claim 'software_id' is required")

    metadata = claims.get("metadata", {})
    if not isinstance(metadata, dict):
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "'metadata' claim must be a JSON object")

    client_id = claims.get("client_id")
    if client_id is not None and (not isinstance(client_id, str) or not client_id):
        raise DCR(ErrorCode.INVALID_SOFTWARE_STATEMENT, "'client_id' claim must be a non-empty string")

    return SoftwareStatement(
        iss=issuer,
        sub=str(claims.get("sub", software_id)),
        software_id=software_id,
        client_id=client_id,
        metadata=metadata,
        issued_at=iat,
        expires_at=exp,
        jti=jti,
        kid=str(header.get("kid", "")),
        raw=token,
    )
