import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from types import SimpleNamespace

from tools.extract_payloads import PayloadExtractor


class DummyHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class DummyPart:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class DummyFlow:
    def __init__(self, url, status_code=200, req_type="", resp_type=""):
        self.request = DummyPart(url=url, headers=DummyHeaders({"content-type": req_type}))
        self.response = DummyPart(status_code=status_code, headers=DummyHeaders({"content-type": resp_type}))


def make_options(**overrides):
    base = {
        "output": "./out",
        "filter": None,
        "type": None,
        "status": None,
        "group": "endpoint",
        "decode": False,
        "max_size": 1024,
        "verbose": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_safe_filename_limits_length_and_strips_unsafe_chars():
    extractor = PayloadExtractor(make_options())
    path = "/very/long path/with?unsafe&chars/" + "a" * 140
    filename = extractor._safe_filename(path)

    assert "/" not in filename
    assert " " not in filename
    assert len(filename) <= 60


def test_normalize_path_replaces_ids_and_uuid():
    extractor = PayloadExtractor(make_options())
    normalized = extractor._normalize_path("/api/v1/users/123/orders/550e8400-e29b-41d4-a716-446655440000")

    assert normalized == "/api/v1/users/{id}/orders/{uuid}"


def test_apply_filters_handles_status_type_and_url_filter():
    extractor = PayloadExtractor(make_options(filter="example.com", status=200, type="json"))

    matching = DummyFlow("https://example.com/api", status_code=200, req_type="application/json")
    wrong_status = DummyFlow("https://example.com/api", status_code=404, req_type="application/json")
    wrong_url = DummyFlow("https://other.com/api", status_code=200, req_type="application/json")

    assert extractor._apply_filters(matching) is True
    assert extractor._apply_filters(wrong_status) is False
    assert extractor._apply_filters(wrong_url) is False
