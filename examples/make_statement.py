"""Generate a local software statement for manual testing.

Usage:
    uv run python examples/make_statement.py com.example.app
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto import encode_software_statement


def main() -> None:
    software_id = sys.argv[1] if len(sys.argv) > 1 else "com.example.app"
    secret = "dev-only-issuer-secret-change-me"
    now = int(time.time())
    payload = {
        "iss": "local-software-authority",
        "sub": "vendor-1",
        "aud": "local-dcr-service",
        "iat": now,
        "exp": now + 3600,
        "software_id": software_id,
        "metadata": {"redirect_uris": ["https://app.example.com/oauth/callback"]},
    }
    print(encode_software_statement(payload, secret))


if __name__ == "__main__":
    main()
