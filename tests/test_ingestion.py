"""Tests unitaires du Module 1 (ingestion & parsing)."""

from __future__ import annotations

import types
from pathlib import Path

from src.ingestion.log_generator import read_log_file, read_multiple_sources
from src.ingestion.parser import parse_line

CLEAN_JSON = (
    "2026-11-01T10:00:00Z | INFO | 192.168.1.42 | user=admin "
    '| {"action": "login", "status": "ok"}'
)
CLEAN_TUPLE = (
    "2026-11-01T10:00:01Z | ERROR | 10.0.0.5 | user=bob " "| (192.168.1.1, 8080, HTTPS)"
)
CLEAN_RAW = "2026-11-01T10:00:02Z | WARNING | 10.0.0.6 | user=carol " "| raw event 1234"


# --- Cas propres -----------------------------------------------------------


def test_parse_json_payload() -> None:
    entry = parse_line(CLEAN_JSON)
    assert entry is not None
    assert entry["level"] == "INFO"
    assert entry["src_ip"] == "192.168.1.42"
    assert entry["user_id"] == "admin"
    assert entry["payload"] == {"action": "login", "status": "ok"}


def test_parse_tuple_payload() -> None:
    entry = parse_line(CLEAN_TUPLE)
    assert entry is not None
    assert entry["payload"] == ("192.168.1.1", 8080, "HTTPS")


def test_parse_raw_payload() -> None:
    entry = parse_line(CLEAN_RAW)
    assert entry is not None
    assert entry["payload"] == "raw event 1234"


# --- Cas sales (consigne prof) --------------------------------------------


def test_rejects_empty() -> None:
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_rejects_none() -> None:
    assert parse_line(None) is None


def test_rejects_comment() -> None:
    assert parse_line("# commentaire à ignorer") is None


def test_rejects_bad_timestamp() -> None:
    bad = "2026/11/04 18:32 | INFO | 192.168.1.42 | user=admin | {}"
    assert parse_line(bad) is None


def test_rejects_bad_ip() -> None:
    bad = "2026-11-01T10:00:00Z | INFO | 999.999.999.999 | user=admin | {}"
    assert parse_line(bad) is None


def test_rejects_garbage_ip() -> None:
    bad = "2026-11-01T10:00:00Z | INFO | abc.def.ghi | user=admin | {}"
    assert parse_line(bad) is None


def test_rejects_unknown_level() -> None:
    bad = "2026-11-01T10:00:00Z | DEBUG | 192.168.1.42 | user=admin | {}"
    assert parse_line(bad) is None


def test_rejects_missing_user() -> None:
    bad = "2026-11-01T10:00:00Z | INFO | 192.168.1.42 | user= | {}"
    assert parse_line(bad) is None


def test_rejects_missing_fields() -> None:
    bad = "2026-11-01T10:00:00Z | INFO | 192.168.1.42"
    assert parse_line(bad) is None


def test_tolerates_leading_trailing_whitespace() -> None:
    entry = parse_line(f"   {CLEAN_JSON}   ")
    assert entry is not None
    assert entry["user_id"] == "admin"


def test_accepts_timestamp_with_microseconds() -> None:
    line = (
        "2026-11-01T00:00:00.520403Z | INFO | 192.168.3.7 "
        '| user=user_037 | {"action": "login"}'
    )
    entry = parse_line(line)
    assert entry is not None
    assert entry["timestamp"].endswith("Z")


# --- Générateurs ------------------------------------------------------------


def test_read_log_file_is_generator(tmp_path: Path) -> None:
    f = tmp_path / "mini.log"
    f.write_text(f"{CLEAN_JSON}\n{CLEAN_RAW}\n", encoding="utf-8")

    gen = read_log_file(f)
    assert isinstance(gen, types.GeneratorType)

    lines = list(gen)
    assert len(lines) == 2
    assert "admin" in lines[0]


def test_read_multiple_sources_uses_yield_from(tmp_path: Path) -> None:
    f1 = tmp_path / "a.log"
    f2 = tmp_path / "b.log"
    f1.write_text(f"{CLEAN_JSON}\n", encoding="utf-8")
    f2.write_text(f"{CLEAN_RAW}\n{CLEAN_TUPLE}\n", encoding="utf-8")

    lines = list(read_multiple_sources([f1, f2]))
    assert len(lines) == 3
    # Ordre préservé : f1 puis f2.
    assert "admin" in lines[0]
    assert "carol" in lines[1]
    assert "bob" in lines[2]
