"""Shared pytest fixtures: isolated DB, service and HTTP client."""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.crypto import encode_software_statement
from app.routers import create_app
from app.service import ClientService
from app.storage import Storage

ISSUER = "issuer-a"
ISSUER_SECRET = "test-issuer-secret"
AUDIENCE = "test-dcr"
REDIRECT_URIS = ["https://app.example.com/oauth/callback"]


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        database_path=str(tmp_path / "registry.db"),
        issuer_secrets={ISSUER: ISSUER_SECRET},
        trusted_audience=AUDIENCE,
        old_secret_grace_seconds=0,
    )


@pytest.fixture
def storage(settings) -> Storage:
    store = Storage(settings.database_path)
    yield store
    store.close()


@pytest.fixture
def service(settings, storage) -> ClientService:
    return ClientService(storage, settings)


StatementBuilder = Callable[..., str]


@pytest.fixture
def statement() -> StatementBuilder:
    def _build(
        software_id: str,
        *,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        exp_in: int = 3600,
        iat: int | None = None,
        sub: str = "vendor-1",
        secret: str = ISSUER_SECRET,
        metadata: dict | None = None,
        **extra,
    ) -> str:
        now = int(time.time())
        payload: dict = {
            "iss": issuer,
            "sub": sub,
            "aud": audience,
            "exp": now + exp_in,
            "iat": iat if iat is not None else now,
            "software_id": software_id,
        }
        if metadata is not None:
            payload["metadata"] = metadata
        payload.update(extra)
        return encode_software_statement(payload, secret)

    return _build


RegisterBuilder = Callable[..., dict]


@pytest.fixture
def register(service, statement) -> RegisterBuilder:
    def _register(
        software_id: str = "sw-1",
        *,
        metadata: dict | None = None,
        token: str | None = None,
    ) -> tuple[dict, dict]:
        body = {
            "software_statement": token or statement(software_id),
            "metadata": metadata if metadata is not None else {"redirect_uris": REDIRECT_URIS},
        }
        view, secret_issue, created = service.register(body)
        assert created
        return view, secret_issue

    return _register


@pytest.fixture
def client(service) -> TestClient:
    app = create_app(service)
    with TestClient(app) as test_client:
        yield test_client
