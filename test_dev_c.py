"""Tests manuels des modules DEV C, sans pytest.

Depuis la racine du projet : python test_dev_c.py
"""

from src.analytics.sets_ops import BLACKLIST, unique_error_ips, ip_set_analysis
from src.analytics.counters import count_by_category
from src.analytics.bruteforce import detect_bruteforce
from src.engine.rule_engine import apply_security_rules
from src.engine.audit import audit_runtime_state


def test_unique_error_ips():
    logs = [
        {"level": "ERROR", "src_ip": "192.168.1.10"},
        {"level": "INFO", "src_ip": "192.168.1.20"},
        {"level": "ERROR", "src_ip": "192.168.1.10"},
        {"level": "ERROR", "src_ip": "10.0.0.5"},
    ]
    assert unique_error_ips(logs) == {"192.168.1.10", "10.0.0.5"}


def test_ip_set_analysis():
    active_ips = {"10.0.0.1", "192.168.1.10"}
    result = ip_set_analysis(active_ips)
    assert result["blacklisted_active"] == {"10.0.0.1"}
    assert result["all_known"] == active_ips | BLACKLIST
    assert result["clean_active"] == {"192.168.1.10"}
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


def main():
    tests = [
        test_unique_error_ips,
        test_ip_set_analysis,
        test_count_by_category,
        test_detect_bruteforce,
        test_apply_security_rules,
        test_audit_runtime_state,
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
