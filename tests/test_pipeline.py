"""Tests unitaires du Module 2 (pipeline fonctionnel)."""

from __future__ import annotations

import pytest

from src.ingestion.parser import parse_line
from src.pipeline.filters import (
    by_ip,
    by_level,
    drop_invalid,
    drop_invalid_requests,
    failed_logins,
    is_valid_request,
)
from src.pipeline.router import get_route, route_logs
from src.pipeline.transforms import format_timestamp, normalize

LINES = [
    (
        "2026-11-01T10:00:00.123456Z | INFO | 192.168.1.42 | user=Admin "
        '| {"action": "login", "status": "ok"}'
    ),
    (
        "2026-11-01T10:00:01Z | ERROR | 10.0.0.5 | user=bob "
        '| {"action": "login", "status": "failed"}'
    ),
    "2026-11-01T10:00:02Z | WARNING | 10.0.0.6 | user=carol | raw event 1234",
    "2026-11-01T10:00:03Z | CRITICAL | 10.0.0.5 | user=bob | (192.168.1.1, 8080, HTTPS)",
    "ligne sale",
    "",
]

# Requêtes syntaxiquement valides mais inexploitables.
INVALID_REQUESTS = [
    "2026-11-01T10:00:04Z | INFO | 10.0.0.7 | user=dave | {}",
    "2026-11-01T10:00:05Z | INFO | 10.0.0.7 | user=dave | ",
    "2026-11-01T10:00:06Z | INFO | 10.0.0.7 | user=dave | {bad json, not valid}",
    "2026-11-01T10:00:07Z | INFO | 10.0.0.7 | user=dave | [1, 2",
]


def _entries():
    return list(drop_invalid(map(parse_line, LINES)))


# --- filters ---------------------------------------------------------------


def test_drop_invalid_uses_filter_none() -> None:
    result = drop_invalid(map(parse_line, LINES))
    assert isinstance(result, filter)
    assert len(list(result)) == 4


def test_drop_invalid_requests() -> None:
    entries = list(drop_invalid(map(parse_line, LINES + INVALID_REQUESTS)))
    assert len(entries) == 8
    assert len(list(drop_invalid_requests(entries))) == 4


def test_is_valid_request() -> None:
    entries = list(drop_invalid(map(parse_line, INVALID_REQUESTS)))
    assert [is_valid_request(e) for e in entries] == [False, False, False, False]
    assert all(is_valid_request(e) for e in _entries())


def test_by_level() -> None:
    out = list(by_level(_entries(), "ERROR"))
    assert len(out) == 1 and out[0]["user_id"] == "bob"


def test_by_ip() -> None:
    assert len(list(by_ip(_entries(), "10.0.0.5"))) == 2


def test_failed_logins() -> None:
    out = list(failed_logins(_entries()))
    assert len(out) == 1 and out[0]["user_id"] == "bob"


# --- transforms ------------------------------------------------------------


def test_normalize_is_lazy_map() -> None:
    assert isinstance(normalize(_entries()), map)


def test_normalize_does_not_mutate_input() -> None:
    entries = _entries()
    original = dict(entries[0])
    out = list(normalize(entries))
    assert entries[0] == original
    assert out[0] is not entries[0]


def test_normalize_cleans_dirty_entry() -> None:
    dirty = {
        "timestamp": " 2026-11-01T10:00:00.5Z ",
        "level": " warning ",
        "src_ip": " 10.0.0.1 ",
        "user_id": " Bob ",
        "payload": "  hello  ",
    }
    clean = next(normalize([dirty]))
    assert clean == {
        "timestamp": "2026-11-01T10:00:00Z",
        "level": "WARNING",
        "src_ip": "10.0.0.1",
        "user_id": "bob",
        "payload": "hello",
        "summary": "[WARNING ] bob @ 10.0.0.1",
    }


def test_format_timestamp() -> None:
    assert format_timestamp("2026-11-01T10:00:00.123456Z") == "2026-11-01T10:00:00Z"
    assert format_timestamp("2026-11-01T10:00:00Z") == "2026-11-01T10:00:00Z"


# --- router (match-case) ---------------------------------------------------


def _log(payload):
    return {
        "timestamp": "2026-11-01T10:00:00Z",
        "level": "INFO",
        "src_ip": "10.0.0.1",
        "user_id": "bob",
        "payload": payload,
    }


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (("192.168.1.1", 8080, "HTTPS"), "connexion"),
        ({"level": "ERROR", "code": 500}, "dictionnaire"),
        ({"level": "WARNING", "code": 404}, "dictionnaire"),
        ({"action": "login", "status": "ok"}, "dictionnaire"),
        ("raw event 42", "brut"),
        (None, "inconnu"),
    ],
)
def test_get_route(payload, expected) -> None:
    assert get_route(_log(payload)) == expected


def test_route_logs() -> None:
    result = route_logs(_entries())
    assert isinstance(result, map)
    routes = [e["route"] for e in result]
    assert routes == ["dictionnaire", "dictionnaire", "brut", "connexion"]


def test_pipeline_end_to_end() -> None:
    logs = map(parse_line, LINES + INVALID_REQUESTS)
    logs = drop_invalid(logs)
    logs = drop_invalid_requests(logs)
    logs = normalize(logs)
    logs = by_level(logs, "CRITICAL")
    assert [e["route"] for e in route_logs(logs)] == ["connexion"]
