"""Requirement 1: full request validation with distinguishable error codes."""

from __future__ import annotations

import base64
import json

from dcr.errors import ErrorCode
from dcr.tokens import issue_software_statement


def test_successful_registration(client, make_statement):
    resp = client.post("/register", json=make_statement())
    assert resp.status_code == 201
    body = resp.json()
    assert body["state"] == "active"
    assert body["version"] == 1
    assert body["client_secret"]  # confidential client receives a secret
    assert body["client_id"]
    assert body["redirect_uris"] == ["https://app.example/cb"]


def test_public_client_gets_no_secret(client, make_statement):
    meta = {
        "redirect_uris": ["https://app.example/cb"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "none",
    }
    resp = client.post("/register", json=make_statement("sw-pub", meta))
    assert resp.status_code == 201
    assert "client_secret" not in resp.json()


def test_forged_signature_rejected(client, make_statement):
    payload = make_statement(secret="attacker-secret")
    resp = client.post("/register", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SIGNATURE


def test_tampered_signature_rejected(client, make_statement, tamper_statement):
    resp = client.post("/register", json=tamper_statement(make_statement()))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SIGNATURE


def test_tampered_payload_rejected(client, make_statement, tamper_statement):
    resp = client.post("/register", json=tamper_statement(make_statement(), segment="payload"))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SIGNATURE


def test_malformed_token_rejected(client):
    for bad in ["not-a-jws", "a.b", "", 12345]:
        resp = client.post("/register", json={"software_statement": bad})
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] in {
            ErrorCode.MALFORMED_SOFTWARE_STATEMENT,
            ErrorCode.INVALID_SOFTWARE_STATEMENT,
        }


def test_missing_software_statement(client):
    resp = client.post("/register", json={"foo": "bar"})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SOFTWARE_STATEMENT


def test_body_must_be_json_object(client):
    resp = client.post("/register", content=b"not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REQUEST


def test_expired_statement_rejected(client, make_statement):
    resp = client.post("/register", json=make_statement(ttl=-10))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.SOFTWARE_STATEMENT_EXPIRED


def test_untrusted_issuer_rejected(client, make_statement):
    resp = client.post("/register", json=make_statement(issuer="https://idp.example/foreign"))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.UNTRUSTED_ISSUER


def test_missing_required_claims_rejected(client, settings):
    # token signed by the trusted key but lacking software_id
    token = issue_software_statement({"metadata": {}}, secret="test-signing-secret")
    resp = client.post("/register", json={"software_statement": token})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SOFTWARE_STATEMENT


def test_non_hs256_alg_rejected(client, settings):
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "client-software-statement+jwt", "kid": "k"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps({"iss": settings.trusted_issuer, "software_id": "sw", "iat": 1, "exp": 9999999999,
                    "jti": "j", "metadata": {}}).encode()
    ).rstrip(b"=").decode()
    resp = client.post("/register", json={"software_statement": f"{header}.{body}."})
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_SOFTWARE_STATEMENT


def test_plain_http_redirect_rejected(client, make_statement):
    meta = {"redirect_uris": ["http://app.example/cb"]}
    resp = client.post("/register", json=make_statement("sw-http", meta))
    assert resp.status_code == 400
    assert resp.json()["error"] == ErrorCode.INVALID_REDIRECT_URIS


def test_loopback_http_redirect_allowed(client, make_statement):
    meta = {"redirect_uris": ["http://127.0.0.1:8080/cb", "http://localhost:9000/cb"]}
    resp = client.post("/register", json=make_statement("sw-loop", meta))
    assert resp.status_code == 201


def test_redirect_fragment_rejected(client, make_statement):
    meta = {"redirect_uris": ["https://app.example/cb#frag"]}
    resp = client.post("/register", json=make_statement("sw-frag", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_REDIRECT_URIS


def test_redirect_required_for_auth_code_grant(client, make_statement):
    meta = {"grant_types": ["authorization_code", "refresh_token"]}
    resp = client.post("/register", json=make_statement("sw-noredir", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_REDIRECT_URIS


def test_unknown_grant_type_rejected(client, make_statement):
    meta = {"redirect_uris": ["https://a/cb"], "grant_types": ["password"]}
    resp = client.post("/register", json=make_statement("sw-grant", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_GRANT_TYPES


def test_unknown_token_auth_method_rejected(client, make_statement):
    meta = {"redirect_uris": ["https://a/cb"], "token_endpoint_auth_method": "tls_client_auth"}
    resp = client.post("/register", json=make_statement("sw-auth", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_TOKEN_ENDPOINT_AUTH


def test_none_auth_with_client_credentials_rejected(client, make_statement):
    meta = {"grant_types": ["client_credentials"], "token_endpoint_auth_method": "none"}
    resp = client.post("/register", json=make_statement("sw-cc", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_TOKEN_ENDPOINT_AUTH


def test_unknown_scope_rejected(client, make_statement):
    meta = {"redirect_uris": ["https://a/cb"], "scope": "openid admin:destroy"}
    resp = client.post("/register", json=make_statement("sw-scope", meta))
    assert resp.json()["error"] == ErrorCode.INVALID_SCOPE


def test_invalid_request_has_no_persistence_side_effects(client, make_statement):
    # Forge/illegal metadata must not create any client row.
    before = client.get("/clients").json()["total"]
    bad_requests = [
        make_statement(secret="wrong"),
        make_statement(ttl=-1),
        make_statement(issuer="evil"),
        make_statement("sw-bad", {"redirect_uris": ["http://plain.example/cb"]}),
        make_statement("sw-bad2", {"redirect_uris": ["https://a/cb"], "grant_types": ["nope"]}),
    ]
    for payload in bad_requests:
        resp = client.post("/register", json=payload)
        assert resp.status_code == 400, resp.text
    after = client.get("/clients").json()["total"]
    assert before == after == 0

    # failed client_credentials/none combo also leaves no row under its sw id
    resp = client.post(
        "/register",
        json=make_statement("sw-bad3", {"grant_types": ["client_credentials"], "token_endpoint_auth_method": "none"}),
    )
    assert resp.status_code == 400
    listing = client.get("/clients").json()
    assert listing["total"] == 0
