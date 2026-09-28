"""FastAPI application wiring for the local DCR management endpoints."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .errors import DCR
from .models import ClientState
from .repository import ClientRepository
from .schemas import client_to_public_dict, page_to_dict
from .service import ClientService


def _result_response(result) -> JSONResponse:
    body = client_to_public_dict(
        result.client,
        include_secret=result.has_secret,
        secret_plain=result.secret_plain,
        secret_expires_at=result.secret_expires_at,
    )
    return JSONResponse(status_code=result.status_code, content=body)


async def _json_body(request: Request) -> dict:
    """Parse the request body with a controlled error shape."""
    raw = await request.body()
    if not raw:
        raise DCR("invalid_request", "request body is required", status_code=400)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DCR("invalid_request", f"request body is not valid JSON: {exc.msg}", status_code=400) from exc
    if not isinstance(body, dict):
        raise DCR("invalid_request", "request body must be a JSON object", status_code=400)
    return body


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    repo = ClientRepository(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        repo.initialize()
        try:
            yield
        finally:
            repo.close()

    app = FastAPI(
        title="Local OAuth Dynamic Registered Client Service",
        version="0.1.0",
        lifespan=lifespan,
    )
    service = ClientService(settings, repo)

    @app.exception_handler(DCR)
    async def _dcr_handler(request: Request, exc: DCR) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    # --- RFC 7591 style management endpoints ---------------------------------
    @app.post("/register")
    async def register(request: Request) -> JSONResponse:
        payload = await _json_body(request)
        return _result_response(service.register(payload))

    @app.get("/clients")
    def list_clients(
        state: str | None = None,
        cursor: str | None = None,
        page_size: str | None = None,
    ) -> dict:
        size = int(page_size) if page_size is not None else None
        return page_to_dict(service.list_clients(state=state, cursor=cursor, page_size=size))

    @app.get("/clients/{client_id}")
    def get_client(client_id: str) -> dict:
        return client_to_public_dict(service.get(client_id))

    @app.put("/clients/{client_id}")
    async def update_client(client_id: str, request: Request) -> JSONResponse:
        payload = await _json_body(request)
        return _result_response(service.update(client_id, payload))

    @app.post("/clients/{client_id}/secret/rotate")
    async def rotate_secret(client_id: str, request: Request) -> JSONResponse:
        payload = await _json_body(request)
        return _result_response(service.rotate_secret(client_id, payload))

    @app.post("/clients/{client_id}/secret/revoke")
    async def revoke_secret(client_id: str, request: Request) -> JSONResponse:
        payload = await _json_body(request)
        return _result_response(service.revoke_secret(client_id, payload))

    @app.post("/clients/{client_id}/state/{target_state}")
    async def transition_state(client_id: str, target_state: str, request: Request) -> JSONResponse:
        try:
            target = ClientState(target_state)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": f"unknown target state: {target_state!r}"},
            )
        payload = await _json_body(request)
        return _result_response(service.transition(client_id, target, payload))

    @app.post("/clients/{client_id}/recover")
    async def recover_client(client_id: str, request: Request) -> JSONResponse:
        payload = await _json_body(request)
        return _result_response(service.recover(client_id, payload))

    app.state.settings = settings
    app.state.repository = repo
    app.state.service = service
    return app
