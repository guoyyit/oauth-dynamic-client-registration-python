"""HTTP routers exposing the dynamic client registration API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.errors import ERR_INVALID_REQUEST, RegistrationError
from app.lifecycle import is_known_state
from app.models import (
    RecoverRequest,
    RegisterRequest,
    SecretRevokeRequest,
    SecretRotateRequest,
    StateTransitionRequest,
    UpdateRequest,
)

router = APIRouter()


def _service(request: Request) -> Any:
    return request.app.state.service


def _error_body(code: str, message: str) -> dict[str, Any]:
    return {"error": code, "error_description": message}


def _register_response(view: dict[str, Any], secret_issue: dict[str, Any], created: bool) -> JSONResponse:
    body = dict(view)
    if secret_issue:
        body["client_secret"] = secret_issue["client_secret"]
        body["secret_id"] = secret_issue["secret_id"]
        body["secret_expires_at"] = secret_issue.get("secret_expires_at")
    body["duplicate"] = not created
    return JSONResponse(status_code=201 if created else 200, content=body)


@router.post("/register")
async def register(request: Request) -> JSONResponse:
    payload = await _json_body(request)
    RegisterRequest(**payload)
    view, secret_issue, created = _service(request).register(payload)
    return _register_response(view, secret_issue, created)


@router.get("/clients/{client_id}")
async def get_client(request: Request, client_id: str) -> dict[str, Any]:
    return _service(request).get(client_id)


@router.put("/clients/{client_id}")
async def update_client(request: Request, client_id: str) -> dict[str, Any]:
    payload = await _json_body(request)
    payload["client_id"] = client_id
    UpdateRequest(**payload)
    return _service(request).update(client_id, payload)


@router.post("/clients/{client_id}/secret/rotate")
async def rotate_secret(request: Request, client_id: str) -> dict[str, Any]:
    payload = await _json_body(request)
    SecretRotateRequest(**payload)
    return _service(request).rotate_secret(client_id, payload)


@router.post("/clients/{client_id}/secret/revoke")
async def revoke_secret(request: Request, client_id: str) -> JSONResponse:
    payload = await _json_body(request)
    SecretRevokeRequest(**payload)
    view = _service(request).revoke_secret(client_id, payload)
    return JSONResponse(status_code=200, content=view)


@router.post("/clients/{client_id}/state")
async def transition_state(request: Request, client_id: str) -> dict[str, Any]:
    payload = await _json_body(request)
    StateTransitionRequest(**payload)
    return _service(request).transition_state(client_id, payload)


@router.post("/clients/{client_id}/recover")
async def recover_client(request: Request, client_id: str) -> dict[str, Any]:
    payload = await _json_body(request)
    RecoverRequest(**payload)
    return _service(request).recover(client_id, payload)


@router.get("/clients")
async def list_clients(
    request: Request,
    limit: int | None = None,
    cursor: str | None = None,
    state: str | None = None,
    issuer: str | None = None,
    grant_type: str | None = None,
) -> dict[str, Any]:
    if state is not None and not is_known_state(state):
        raise RegistrationError("invalid_state_transition", "unknown state filter", 400)
    return _service(request).list_clients(
        {"limit": limit, "cursor": cursor, "state": state, "issuer": issuer, "grant_type": grant_type}
    )


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


async def _json_body(request: Request) -> dict[str, Any]:
    from app.errors import ERR_INVALID_REQUEST

    if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
        raise RegistrationError(
            ERR_INVALID_REQUEST, "Content-Type must be application/json", 415
        )
    try:
        payload = await request.json()
    except Exception:
        raise RegistrationError(ERR_INVALID_REQUEST, "request body must be valid JSON", 400) from None
    if not isinstance(payload, dict):
        raise RegistrationError(ERR_INVALID_REQUEST, "request body must be a JSON object", 400)
    return payload


def create_app(service: Any | None = None) -> FastAPI:
    app = FastAPI(
        title="Local OAuth Dynamic Client Registration",
        version="0.1.0",
    )
    app.include_router(router)

    if service is not None:
        app.state.service = service

    @app.exception_handler(RegistrationError)
    async def _registration_error_handler(_request: Request, exc: RegistrationError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message),
        )

    @app.exception_handler(ValidationError)
    async def _pydantic_error_handler(_request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=_error_body(
                ERR_INVALID_REQUEST, _summarize_validation(exc.errors())
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=_error_body(
                ERR_INVALID_REQUEST, _summarize_validation(exc.errors())
            ),
        )

    return app


def _summarize_validation(errors: list[dict[str, Any]]) -> str:
    parts = []
    for err in errors:
        location = ".".join(str(item) for item in err.get("loc", []) if item != "body")
        parts.append(f"{location or 'body'}: {err.get('msg', 'invalid value')}")
    return "; ".join(parts) or "request validation failed"
