"""Software statement verification and secret hashing tests."""

from __future__ import annotations

import time

import pytest

from app.crypto import (
    encode_software_statement,
    generate_client_id,
    generate_client_secret,
    hash_secret,
    verify_secret,
    verify_software_statement,
)
from app.errors import RegistrationError

ISSUERS = {"issuer-a": "secret-a"}
AUDIENCE = "test-dcr"


def _claims(**overrides) -> dict:
    now = int(time.time())
    base = {
        "iss": "issuer-a",
        "sub": "vendor-1",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "software_id": "sw-1",
    }
    base.update(overrides)
    return base


def test_statement_round_trip() -> None:
    token = encode_software_statement(_claims(), "secret-a")
    claims = verify_software_statement(token, ISSUERS, AUDIENCE)
    assert claims["software_id"] == "sw-1"


def test_forged_signature_rejected() -> None:
    token = encode_software_statement(_claims(), "secret-a")
    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(forged, ISSUERS, AUDIENCE)
    assert exc.value.code == "invalid_signature"


def test_signed_with_wrong_key_rejected() -> None:
    token = encode_software_statement(_claims(), "attacker-key")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE)
    assert exc.value.code == "invalid_signature"


def test_tampered_payload_rejected() -> None:
    token = encode_software_statement(_claims(), "secret-a")
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}x.{signature}"
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(tampered, ISSUERS, AUDIENCE)
    assert exc.value.code == "invalid_software_statement"


def test_expired_statement_rejected() -> None:
    token = encode_software_statement(_claims(exp=100), "secret-a")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE, now=200)
    assert exc.value.code == "expired_software_statement"


def test_unknown_issuer_rejected() -> None:
    token = encode_software_statement(_claims(iss="issuer-evil"), "secret-a")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE)
    assert exc.value.code == "unknown_issuer"


def test_audience_mismatch_rejected() -> None:
    token = encode_software_statement(_claims(aud="other-service"), "secret-a")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE)
    assert exc.value.code == "invalid_software_statement"


def test_not_before_in_future_rejected() -> None:
    token = encode_software_statement(_claims(nbf=10_000), "secret-a")
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE, now=100)
    assert exc.value.code == "invalid_software_statement"


def test_malformed_token_rejected() -> None:
    for bad in ["", "only-one", "a.b", "a.b.c.d", 123, None]:
        with pytest.raises(RegistrationError) as exc:
            verify_software_statement(bad, ISSUERS, AUDIENCE)  # type: ignore[arg-type]
        assert exc.value.code == "invalid_software_statement"


def test_algorithm_none_rejected() -> None:
    import base64
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "software-statement"}).encode())
    payload = b64(json.dumps(_claims()).encode())
    token = f"{header}.{payload}."
    with pytest.raises(RegistrationError) as exc:
        verify_software_statement(token, ISSUERS, AUDIENCE)
    assert exc.value.code == "unsupported_signature_algorithm"


def test_secret_hash_roundtrip_and_uniqueness() -> None:
    s1 = generate_client_secret()
    s2 = generate_client_secret()
    assert s1 != s2
    stored = hash_secret(s1)
    assert stored != s1
    assert verify_secret(s1, stored)
    assert not verify_secret(s2, stored)
    assert not verify_secret(s1, "garbage")


def test_generated_identifiers_have_entropy() -> None:
    ids = {generate_client_id() for _ in range(100)}
    secrets = {generate_client_secret() for _ in range(100)}
    assert len(ids) == 100 and len(secrets) == 100
