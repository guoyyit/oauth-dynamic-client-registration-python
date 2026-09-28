"""Previous-secret overlap window expires according to the stored policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dcr.tokens import issue_software_statement

SECRET = "test-signing-secret"


def _token(software_id="sw-exp"):
    return issue_software_statement(
        {"software_id": software_id, "metadata": {"redirect_uris": ["https://a/cb"]}},
        secret=SECRET,
    )


def test_previous_secret_rejected_after_overlap_expiry(client):
    reg = client.post("/register", json={"software_statement": _token()})
    cid = reg.json()["client_id"]
    first = reg.json()["client_secret"]
    rot = client.post(f"/clients/{cid}/secret/rotate", json={"software_statement": _token()})
    second = rot.json()["client_secret"]
    svc = client.app.state.service
    assert svc.authenticate(cid, first) and svc.authenticate(cid, second)

    # force the 'previous' secret's expiry into the past via the repository
    repo = client.app.state.repository
    with repo._lock:
        repo.connection.execute(
            "UPDATE client_secrets SET expires_at = ? WHERE client_id = ? AND status = 'previous'",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), cid),
        )

    assert not svc.authenticate(cid, first), "expired previous secret must be refused"
    assert svc.authenticate(cid, second), "current secret must still work"


def test_immediate_revoke_sets_no_overlap_window(client):
    reg = client.post("/register", json={"software_statement": _token("sw-imm")})
    cid = reg.json()["client_id"]
    client.post(
        f"/clients/{cid}/secret/rotate",
        json={"software_statement": _token("sw-imm"), "revoke_previous": True},
    )
    rows = client.app.state.repository.list_secrets(cid)
    statuses = {r.status.value for r in rows}
    assert "previous" not in statuses
    assert "revoked" in statuses
