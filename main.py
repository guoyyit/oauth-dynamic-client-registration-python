"""Development entrypoint: run the local DCR service."""

from dcr.app import create_app

app = create_app()
