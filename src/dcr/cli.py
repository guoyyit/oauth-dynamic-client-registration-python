"""Command line helper: mint software statements for the trusted local issuer.

Example::

    python -m dcr.cli --software-id sw-123 \
        --metadata '{"redirect_uris":["https://app.example/cb"]}'
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_settings
from .tokens import issue_software_statement


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint a local software statement (JWS/HS256)")
    parser.add_argument("--software-id", required=True)
    parser.add_argument("--client-id", default=None)
    parser.add_argument("--metadata", default="{}", help="JSON object of client metadata")
    parser.add_argument("--ttl", type=int, default=600, help="seconds until expiry")
    parser.add_argument("--issuer", default=None)
    parser.add_argument("--secret", default=None, help="signing secret (defaults to DCR_SIGNING_SECRET)")
    parser.add_argument("--kid", default=None)
    args = parser.parse_args(argv)

    try:
        metadata = json.loads(args.metadata)
    except json.JSONDecodeError as exc:
        print(f"invalid --metadata JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(metadata, dict):
        print("--metadata must be a JSON object", file=sys.stderr)
        return 2

    settings = load_settings()
    secret = args.secret or settings.signing_secret
    claims = {"software_id": args.software_id, "metadata": metadata}
    if args.client_id:
        claims["client_id"] = args.client_id
    if args.issuer:
        claims["iss"] = args.issuer
    token = issue_software_statement(claims, secret=secret, kid=args.kid or settings.signing_kid, ttl_seconds=args.ttl)
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
