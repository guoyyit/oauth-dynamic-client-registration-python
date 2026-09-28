"""Pagination, filtering and stable ordering of the list endpoint."""

from __future__ import annotations

import pytest

from app.errors import RegistrationError


def _register_n(service, statement, count: int, start: int = 0) -> list[dict]:
    views = []
    for i in range(start, start + count):
        view, _, created = service.register(
            {
                "software_statement": statement(f"sw-page-{i}"),
                "metadata": {
                    "redirect_uris": ["https://app.example.com/cb"],
                    "grant_types": ["client_credentials"] if i % 2 == 0 else ["authorization_code"],
                },
            }
        )
        assert created
        views.append(view)
    return views


def test_keyset_pagination_visits_every_row_once(service, statement) -> None:
    total = 7
    _register_n(service, statement, total)
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        page = service.list_clients({"limit": 3, "cursor": cursor})
        seen.extend(item["client_id"] for item in page["items"])
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert pages <= total + 1
    assert pages == 3
    assert len(seen) == total
    assert len(set(seen)) == total


def test_ordering_is_stable_by_created_then_id(service, statement) -> None:
    views = _register_n(service, statement, 4)
    page = service.list_clients({"limit": 100})
    ordered = page["items"]
    keys = [(item["created_at"], item["client_id"]) for item in ordered]
    assert keys == sorted(keys)
    assert [v["client_id"] for v in views] == [item["client_id"] for item in ordered]


def test_concurrent_inserts_do_not_duplicate_or_skip(service, statement, storage) -> None:
    """Walk pages while new rows are inserted; keyset order stays consistent."""
    _register_n(service, statement, 3)

    first = service.list_clients({"limit": 2})
    first_ids = {i["client_id"] for i in first["items"]}

    # insert more rows after the first page was served
    _register_n(service, statement, 4, start=100)

    second = service.list_clients({"limit": 100, "cursor": first["next_cursor"]})
    second_ids = {i["client_id"] for i in second["items"]}

    assert first_ids.isdisjoint(second_ids)
    # no row lost: total live clients visible across full walk
    all_page = service.list_clients({"limit": 100})
    assert len({i["client_id"] for i in all_page["items"]}) == 7


def test_filters_by_state_issuer_grant_type(service, storage, statement) -> None:
    _register_n(service, statement, 6)
    # suspend the first client
    first_id = service.list_clients({"limit": 1})["items"][0]["client_id"]
    sw_id = storage.get_client(first_id)["software_id"]
    service.transition_state(
        first_id,
        {"software_statement": statement(sw_id), "target_state": "suspended"},
    )

    suspended = service.list_clients({"limit": 100, "state": "suspended"})
    assert [i["client_id"] for i in suspended["items"]] == [first_id]

    active = service.list_clients({"limit": 100, "state": "active"})
    assert len(active["items"]) == 5

    cc = service.list_clients({"limit": 100, "grant_type": "client_credentials"})
    assert len(cc["items"]) == 3

    ac = service.list_clients({"limit": 100, "grant_type": "authorization_code"})
    assert len(ac["items"]) == 3

    issuer = service.list_clients({"limit": 100, "issuer": "issuer-a"})
    assert len(issuer["items"]) == 6
    assert service.list_clients({"limit": 100, "issuer": "nobody"})["items"] == []


def test_invalid_cursor_and_limit_rejected(service) -> None:
    with pytest.raises(RegistrationError) as exc:
        service.list_clients({"cursor": "not-base64-json!!"})
    assert exc.value.code == "invalid_request"

    with pytest.raises(RegistrationError):
        service.list_clients({"limit": 0})


def test_limit_is_capped(service, statement) -> None:
    _register_n(service, statement, 3)
    page = service.list_clients({"limit": 10_000})
    assert page["limit"] == service._settings.max_page_size


def test_deleted_clients_are_excluded(service, statement) -> None:
    views = _register_n(service, statement, 2)
    cid = views[0]["client_id"]
    sw_id = "sw-page-0"
    service.transition_state(
        cid, {"software_statement": statement(sw_id), "target_state": "deleted"}
    )
    page = service.list_clients({"limit": 100})
    assert cid not in {i["client_id"] for i in page["items"]}
    assert len(page["items"]) == 1
