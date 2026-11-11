"""Tests manuels des modules DEV C, sans pytest.

Depuis la racine du projet : python test_dev_c.py
"""

from src.analytics.bruteforce import detect_bruteforce
from src.analytics.counters import count_by_category
from src.analytics.sets_ops import BLACKLIST, ip_set_analysis, unique_error_ips
from src.engine.audit import audit_runtime_state
from src.engine.rule_engine import apply_security_rules


def test_unique_error_ips():
    logs = [
        {"level": "ERROR", "src_ip": "192.168.1.10"},
        {"level": "INFO", "src_ip": "192.168.1.20"},
        {"level": "ERROR", "src_ip": "192.168.1.10"},
        {"level": "ERROR", "src_ip": "10.0.0.5"},
    ]
    assert unique_error_ips(logs) == {"192.168.1.10", "10.0.0.5"}


def test_ip_set_analysis():
    # 192.168.1.10 est dans BLACKLIST (IPs 1..12 du générateur), 10.0.0.99 non.
    active_ips = {"10.0.0.99", "192.168.1.10"}
    result = ip_set_analysis(active_ips)
    assert result["blacklisted_active"] == {"192.168.1.10"}
    assert result["all_known"] == active_ips | BLACKLIST
    assert result["clean_active"] == {"10.0.0.99"}
    assert result["exclusives"] == active_ips ^ BLACKLIST


def test_count_by_category():
    logs = [
        {"level": "ERROR", "user_id": "alice"},
        {"level": "INFO", "user_id": "bob"},
        {"level": "ERROR", "user_id": "alice"},
    ]
    assert dict(count_by_category(logs)) == {"ERROR": 2, "INFO": 1}
    assert dict(count_by_category(logs, category="user_id")) == {
        "alice": 2,
        "bob": 1,
    }


def test_detect_bruteforce():
    logs = [
        {"src_ip": "192.168.1.50", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.50", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.50", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.50", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.50", "payload": {"action": "login", "status": "failed"}},
    ]
    assert detect_bruteforce(logs, threshold=5) == ["192.168.1.50"]

    # Un succès interrompt la série d'échecs.
    logs_with_success = [
        {"src_ip": "192.168.1.60", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.60", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.60", "payload": {"action": "login", "status": "success"}},
        {"src_ip": "192.168.1.60", "payload": {"action": "login", "status": "failed"}},
        {"src_ip": "192.168.1.60", "payload": {"action": "login", "status": "failed"}},
    ]
    assert detect_bruteforce(logs_with_success, threshold=5) == []


def test_apply_security_rules():
    def rule_one(value, mode="normal"):
        return {"value": value, "mode": mode}

    def rule_two(value, mode="normal"):
        return value > 10

    result = apply_security_rules(rule_one, rule_two, value=12, mode="strict")
    assert len(result) == 2
    assert result[0]["rule"] == "rule_one"
    assert result[0]["value"] == 12
    assert result[0]["mode"] == "strict"
    assert result[1] == {"rule": "rule_two", "result": True}


def test_audit_runtime_state():
    report = audit_runtime_state("test")
    assert report["tag"] == "test"
    assert "audit_runtime_state" in report["globals_keys"]
    assert report["locals_snapshot"]["tag"] == "test"


# ---------------------------------------------------------------------------
# Cas limites supplémentaires (Baptiste — Modules 3 & 4)
# ---------------------------------------------------------------------------


def test_count_by_category_ignores_missing_field():
    """Les logs sans la catégorie demandée sont ignorés, pas 'None' ni ''."""
    logs = [
        {"level": "ERROR", "user_id": "alice"},
        {"level": "INFO"},  # pas de user_id
        {"user_id": "bob"},  # pas de level
        {"level": "", "user_id": "carol"},  # level vide
        {"level": "   ", "user_id": "dan"},  # level whitespace
    ]
    counts = dict(count_by_category(logs, category="level"))
    assert counts == {"ERROR": 1, "INFO": 1}
    user_counts = dict(count_by_category(logs, category="user_id"))
    assert user_counts == {"alice": 1, "bob": 1, "carol": 1, "dan": 1}


def test_count_by_category_skips_non_mapping():
    """Les éléments qui ne sont pas des Mapping sont ignorés sans planter."""
    logs = [
        {"level": "ERROR"},
        None,
        "ligne sale",
        42,
        ["mauvais", "type"],
        {"level": "ERROR"},
    ]
    assert dict(count_by_category(logs)) == {"ERROR": 2}


def test_count_by_category_empty_input():
    """Flux vide → defaultdict vide, pas de KeyError."""
    assert dict(count_by_category([])) == {}
    assert dict(count_by_category(iter([]))) == {}


def test_unique_error_ips_level_case_sensitive():
    """Le niveau 'error' minuscule compte aussi (normalisation .upper())."""
    logs = [
        {"level": "error", "src_ip": "10.0.0.1"},
        {"level": "ERROR", "src_ip": "10.0.0.2"},
        {"level": "  Error  ", "src_ip": "10.0.0.3"},
    ]
    assert unique_error_ips(logs) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_unique_error_ips_ignores_bad_entries():
    """IP manquante, vide, ou log non-Mapping : ignorés."""
    logs = [
        {"level": "ERROR"},  # pas de src_ip
        {"level": "ERROR", "src_ip": ""},  # vide
        {"level": "ERROR", "src_ip": "   "},  # whitespace
        {"level": "ERROR", "src_ip": None},  # None
        {"level": "INFO", "src_ip": "10.0.0.5"},  # pas ERROR
        None,  # pas Mapping
        "ligne sale",  # pas Mapping
        {"level": "ERROR", "src_ip": "10.0.0.9"},  # ok
    ]
    assert unique_error_ips(logs) == {"10.0.0.9"}


def test_unique_error_ips_empty_input():
    assert unique_error_ips([]) == set()


def test_audit_runtime_state_default_tag():
    """Sans argument, tag vaut 'audit'."""
    report = audit_runtime_state()
    assert report["tag"] == "audit"
    assert report["locals_snapshot"]["tag"] == "audit"


def test_audit_runtime_state_structure():
    """Le rapport contient les 3 clés attendues et leurs types."""
    report = audit_runtime_state("check")
    assert set(report.keys()) == {"tag", "globals_keys", "locals_snapshot"}
    assert isinstance(report["tag"], str)
    assert isinstance(report["globals_keys"], list)
    assert isinstance(report["locals_snapshot"], dict)
    # Les globals contiennent au moins le nom de la fonction elle-même
    assert len(report["globals_keys"]) > 0


def test_apply_security_rules_empty_rules():
    """Aucune règle fournie → liste vide, pas d'erreur."""
    assert apply_security_rules(logs=[], threshold=5) == []


def test_apply_security_rules_non_callable_raises():
    """Une règle non-appelable doit lever TypeError."""
    import pytest

    with pytest.raises(TypeError):
        apply_security_rules("pas une fonction", logs=[])


def test_apply_security_rules_preserves_rule_key():
    """Si la règle renvoie déjà un dict avec 'rule', on respecte sa valeur."""

    def rule_custom(**_):
        return {"rule": "custom_name", "value": 42}

    result = apply_security_rules(rule_custom)
    assert result[0]["rule"] == "custom_name"
    assert result[0]["value"] == 42


def test_apply_security_rules_wraps_non_mapping():
    """Si la règle renvoie un non-Mapping (bool, list, …), c'est enveloppé."""

    def rule_bool(**_):
        return True

    def rule_list(**_):
        return [1, 2, 3]

    result = apply_security_rules(rule_bool, rule_list)
    assert result[0] == {"rule": "rule_bool", "result": True}
    assert result[1] == {"rule": "rule_list", "result": [1, 2, 3]}


def test_apply_security_rules_passes_kwargs_to_each_rule():
    """Toutes les règles reçoivent les mêmes kwargs partagés."""
    seen: list[dict] = []

    def rule_spy(**kwargs):
        seen.append(kwargs)
        return {"ok": True}

    def rule_spy_bis(**kwargs):
        seen.append(kwargs)
        return {"ok": True}

    apply_security_rules(rule_spy, rule_spy_bis, logs=[1, 2], threshold=7, tag="x")
    assert len(seen) == 2
    assert seen[0] == {"logs": [1, 2], "threshold": 7, "tag": "x"}
    assert seen[1] == seen[0]


def main():
    tests = [
        test_unique_error_ips,
        test_ip_set_analysis,
        test_count_by_category,
        test_detect_bruteforce,
        test_apply_security_rules,
        test_audit_runtime_state,
        # Cas limites supplémentaires
        test_count_by_category_ignores_missing_field,
        test_count_by_category_skips_non_mapping,
        test_count_by_category_empty_input,
        test_unique_error_ips_level_case_sensitive,
        test_unique_error_ips_ignores_bad_entries,
        test_unique_error_ips_empty_input,
        test_audit_runtime_state_default_tag,
        test_audit_runtime_state_structure,
        test_apply_security_rules_empty_rules,
        test_apply_security_rules_preserves_rule_key,
        test_apply_security_rules_wraps_non_mapping,
        test_apply_security_rules_passes_kwargs_to_each_rule,
    ]
    passed = 0

    print("\n=== TESTS MANUELS — DEV C ===")
    for test in tests:
        try:
            test()
        except AssertionError:
            print(f"[ECHEC] {test.__name__}")
            raise
        except Exception as error:
            print(f"[ERREUR] {test.__name__} : {error}")
            raise
        else:
            print(f"[OK]    {test.__name__}")
            passed += 1

    print(f"\nRésultat : {passed}/{len(tests)} tests réussis.")


if __name__ == "__main__":
    main()
