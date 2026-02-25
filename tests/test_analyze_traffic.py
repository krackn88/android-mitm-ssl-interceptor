import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.analyze_traffic import TrafficAnalyzer


def make_options(**overrides):
    base = {"filter": None, "json": False, "output": None, "decode": False, "verbose": False}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_normalize_path_handles_uuid_before_numeric_replacement():
    analyzer = TrafficAnalyzer(make_options())

    normalized = analyzer._normalize_path("/users/123/sessions/550E8400-E29B-41D4-A716-446655440000")

    assert normalized == "/users/{id}/sessions/{uuid}"


def test_prepare_results_sorts_set_derived_fields_for_stable_output():
    analyzer = TrafficAnalyzer(make_options())
    analyzer.domains.update({"b.example.com", "a.example.com"})
    analyzer.content_types.update({"text/plain", "application/json"})
    analyzer.status_codes.update({404: 1, 200: 2})

    analyzer.endpoints["GET /api/items"] = {
        "domain": "a.example.com",
        "path": "/api/items",
        "method": "GET",
        "count": 1,
        "parameters": {"z", "a"},
        "status_codes": {201: 1, 200: 1},
        "headers": {"x-z", "accept"},
        "content_types": {"text/plain", "application/json"},
        "response_types": {"application/json", "text/plain"},
        "sample_url": "https://a.example.com/api/items",
    }

    analyzer.api_patterns["root/api/items"] = {
        "endpoints": ["GET /api/items"],
        "methods": {"POST", "GET"},
        "count": 1,
        "parameters": {"z", "a"},
    }

    results = analyzer._prepare_results()

    assert results["statistics"]["domains"] == ["a.example.com", "b.example.com"]
    assert results["statistics"]["content_types"] == ["application/json", "text/plain"]
    assert list(results["statistics"]["status_codes"].keys()) == ["200", "404"]
    assert results["endpoints"]["GET /api/items"]["parameters"] == ["a", "z"]
    assert results["patterns"]["root/api/items"]["methods"] == ["GET", "POST"]
