"""Registration validation, idempotency and HTTP behaviour."""

from __future__ import annotations

import pytest

from app.crypto import encode_software_statement
from app.errors import RegistrationError


def test_registration_success(service, statement) -> None:
    view, secret_issue = None, None
    body = {
        "software_statement": statement("sw-1"),
        "metadata": {"redirect_uris": ["https://app.example.com/cb"], "scope": "read write"},
    }
    view, secret_issue, created = service.register(body)
    assert created is True
    assert view["state"] == "active"
    assert view["version"] == 1
    assert view["has_secret"] is True
    assert secret_issue["client_secret"]
    assert secret_issue["secret_id"]


def test_idempotent_duplicate_returns_existing(service, statement, register) -> None:
    view, _ = register("sw-1")
    body = {
        "software_statement": statement("sw-1"),
        "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
    }
    view2, issue2, created2 = service.register(body)
    assert created2 is False
    assert view2["client_id"] == view["client_id"]
    assert view2["version"] == 1
    assert issue2 == {}


def test_invalid_request_has_no_persistence(service, statement, storage) -> None:
    # invalid metadata must fail before any write
    with pytest.raises(RegistrationError) as exc:
        service.register(
            {
                "software_statement": statement("sw-bad"),
                "metadata": {"redirect_uris": ["http://insecure.example/x"]},
            }
        )
    assert exc.value.code == "invalid_redirect_uri"
    assert storage.get_client_by_software("sw-bad") is None
    assert storage.list_clients(limit=100)[0] == []


def test_expired_statement_rejected(service) -> None:
    from tests.conftest import AUDIENCE, ISSUER, ISSUER_SECRET

    token = encode_software_statement(
        {
            "iss": ISSUER,
            "sub": "v",
            "aud": AUDIENCE,
            "exp": 1,
            "iat": 0,
            "software_id": "sw-exp",
        },
        ISSUER_SECRET,
    )
    with pytest.raises(RegistrationError) as exc:
        service.register({"software_statement": token, "metadata": {}})
    assert exc.value.code == "expired_software_statement"


def test_unknown_issuer_rejected(service, statement) -> None:
    token = statement("sw-x", issuer="unknown", secret="whatever")
    with pytest.raises(RegistrationError) as exc:
        service.register({"software_statement": token, "metadata": {}})
    assert exc.value.code == "unknown_issuer"


def test_forged_statement_rejected(service, statement) -> None:
    token = statement("sw-x")
    forged = token[:-4] + ("ZZZZ" if not token.endswith("ZZZZ") else "YYYY")
    with pytest.raises(RegistrationError) as exc:
        service.register({"software_statement": forged, "metadata": {}})
    assert exc.value.code == "invalid_signature"


def test_invalid_grant_type_rejected(service, statement) -> None:
    with pytest.raises(RegistrationError) as exc:
        service.register(
            {"software_statement": statement("sw-x"), "metadata": {"grant_types": ["bogus"]}}
        )
    assert exc.value.code == "invalid_grant_type"


def test_invalid_token_endpoint_auth_method_rejected(service, statement) -> None:
    with pytest.raises(RegistrationError) as exc:
        service.register(
            {
                "software_statement": statement("sw-x"),
                "metadata": {
                    "redirect_uris": ["https://app.example.com/cb"],
                    "token_endpoint_auth_method": "tls_client_auth",
                },
            }
        )
    assert exc.value.code == "invalid_token_endpoint_auth_method"


def test_update_with_optimistic_version(service, statement, register) -> None:
    view, _ = register("sw-1")
    updated = service.update(
        view["client_id"],
        {
            "software_statement": statement("sw-1"),
            "expected_version": 1,
            "metadata": {"client_name": "New Name"},
        },
    )
    assert updated["version"] == 2
    assert updated["metadata"]["client_name"] == "New Name"
    # stale version rejected and state untouched
    with pytest.raises(RegistrationError) as exc:
        service.update(
            view["client_id"],
            {
                "software_statement": statement("sw-1"),
                "expected_version": 1,
                "metadata": {"client_name": "Racing"},
            },
        )
    assert exc.value.code == "version_conflict"
    again = service.get(view["client_id"])
    assert again["version"] == 2 and again["metadata"]["client_name"] == "New Name"


def test_failed_update_preserves_state(service, statement, register) -> None:
    view, _ = register("sw-1")
    with pytest.raises(RegistrationError):
        service.update(
            view["client_id"],
            {
                "software_statement": statement("sw-1"),
                "expected_version": 1,
                "metadata": {"redirect_uris": ["http://leak.example/x"]},
            },
        )
    after = service.get(view["client_id"])
    assert after["version"] == 1
    assert after["metadata"]["redirect_uris"] == ["https://app.example.com/oauth/callback"]


def test_update_requires_ownership(service, statement, register) -> None:
    view, _ = register("sw-1")
    service.register(
        {
            "software_statement": statement("sw-2"),
            "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
        }
    )
    with pytest.raises(RegistrationError) as exc:
        service.update(
            view["client_id"],
            {
                "software_statement": statement("sw-2"),
                "expected_version": 1,
                "metadata": {"client_name": "Hijack"},
            },
        )
    assert exc.value.code == "ownership_mismatch"


def test_http_register_and_duplicate(client, statement) -> None:
    body = {
        "software_statement": statement("sw-http"),
        "metadata": {"redirect_uris": ["https://app.example.com/cb"]},
    }
    r1 = client.post("/register", json=body)
    assert r1.status_code == 201
    assert r1.json()["client_secret"]
    r2 = client.post("/register", json=body)
    assert r2.status_code == 200
    assert r2.json()["duplicate"] is True
    assert "client_secret" not in r2.json()


def test_http_error_envelope(client, statement) -> None:
    r = client.post(
        "/register",
        json={
            "software_statement": statement("sw-x"),
            "metadata": {"redirect_uris": ["ftp://no"]},
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"
    assert "error_description" in r.json()


def test_http_missing_field_is_400(client) -> None:
    r = client.post("/register", json={})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"
