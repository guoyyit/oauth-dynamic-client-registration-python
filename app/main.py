"""Application entry point wiring settings, storage, service and HTTP layer."""

from __future__ import annotations

from app.config import get_settings
from app.routers import create_app
from app.service import ClientService
from app.storage import Storage

settings = get_settings()
storage = Storage(settings.database_path)
service = ClientService(storage, settings)
app = create_app(service)
