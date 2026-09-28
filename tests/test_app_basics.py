"""Basics: app construction, health and error envelope."""

from __future__ import annotations

from dcr.app import create_app
from dcr.errors import ErrorCode


def test_app_and_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_app_with_default_settings():
    app = create_app()
    assert app.title


def test_not_found_envelope(client):
    resp = client.get("/clients/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"] == ErrorCode.CLIENT_NOT_FOUND
    assert "error_description" in resp.json()
