"""Pytest fixtures: on-disk DB, fast-hash settings, HTTP client, token helper."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from dcr.app import create_app
from dcr.config import Settings
from dcr.repository import ClientRepository
from dcr.service import ClientService
from dcr.tokens import issue_software_statement

SIGNING_SECRET = "test-signing-secret"
TRUSTED_ISSUER = "local-software-statement-authority"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "dcr.sqlite3")


@pytest.fixture
def settings(db_path):
    return Settings(
        database_path=db_path,
        signing_secret=SIGNING_SECRET,
        trusted_issuer=TRUSTED_ISSUER,
        pbkdf2_iterations=1000,
        secret_ttl_seconds=3600,
        overlap_ttl_seconds=300,
    )


@pytest.fixture
def repo(settings):
    r = ClientRepository(settings)
    r.initialize()
    yield r
    r.close()


@pytest.fixture
def service(settings, repo):
    return ClientService(settings, repo)


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def make_statement():
    """Factory producing properly signed software statement payloads."""

    def _make(
        software_id="sw-1",
        metadata=None,
        *,
        client_id=None,
        secret=SIGNING_SECRET,
        issuer=TRUSTED_ISSUER,
        ttl=600,
        jti=None,
        iat=None,
        exp=None,
        header_kid=None,
        raw_claims=None,
    ):
        meta = metadata if metadata is not None else {"redirect_uris": ["https://app.example/cb"]}
        claims = {"software_id": software_id, "metadata": meta}
        if client_id is not None:
            claims["client_id"] = client_id
        if issuer is not None:
            claims["iss"] = issuer
        if jti is not None:
            claims["jti"] = jti
        if iat is not None:
            claims["iat"] = iat
        if exp is not None:
            claims["exp"] = exp
        if raw_claims:
            claims.update(raw_claims)
        token = issue_software_statement(claims, secret=secret, kid=header_kid or "local-key-1", ttl_seconds=ttl)
        return {"software_statement": token}

    return _make


@pytest.fixture
def tamper_statement():
    """Return a payload whose token signature does not match its payload."""

    def _make(payload, *, segment="signature"):
        token = payload["software_statement"]
        header, payload_seg, signature = token.split(".")
        if segment == "signature":
            flipped = "AAAA" if signature != "AAAA" else "BBBB"
            token = f"{header}.{payload_seg}.{flipped}"
        elif segment == "payload":
            token = f"{header}.{payload_seg[:-1]}x.{signature}" if not payload_seg.endswith("x") else f"{header}.{payload_seg[:-1]}y.{signature}"
        return {"software_statement": token}

    return _make


@pytest.fixture
def register_client(client, make_statement):
    """Register a default client, return (client_id, response_json)."""

    def _register(software_id="sw-1", metadata=None, *, token_endpoint_auth_method=None):
        meta = metadata if metadata is not None else {
            "redirect_uris": ["https://app.example/cb"],
            "client_name": "Demo",
        }
        if token_endpoint_auth_method is not None:
            meta = {**meta, "token_endpoint_auth_method": token_endpoint_auth_method}
        resp = client.post("/register", json=make_statement(software_id, meta))
        assert resp.status_code == 201, resp.text
        return resp.json()["client_id"], resp.json()

    return _register


@pytest.fixture
def epoch_now():
    return int(time.time())
