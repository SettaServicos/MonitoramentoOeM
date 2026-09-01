import sys
from pathlib import Path

import pytest
import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import main


class DummyResp:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

    def raise_for_status(self):
        if 400 <= self.status_code:
            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    def __init__(self, behaviors):
        self.behaviors = list(behaviors)

    def request(self, *args, **kwargs):
        item = self.behaviors.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_teams_retry_after_429(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return DummyResp(429, headers={"Retry-After": "3"})
        return DummyResp(200)

    def fake_sleep(sec):
        sleeps.append(sec)

    monkeypatch.setattr(main, "TEAMS_ENABLED", True)
    monkeypatch.setattr(main._teams_session, "post", fake_post)
    monkeypatch.setattr(main.time, "sleep", fake_sleep)

    ok = main._teams_post_card("t", "x")
    assert ok is True
    assert calls["count"] == 2
    assert sleeps and sleeps[0] >= 3


def test_teams_http_200_com_corpo_de_falha_retorna_false(monkeypatch):
    def fake_post(*args, **kwargs):
        return DummyResp(
            200,
            text=(
                "Webhook message delivery failed with error: "
                "Microsoft Teams endpoint returned HTTP error 403"
            ),
        )

    monkeypatch.setattr(main, "TEAMS_ENABLED", True)
    monkeypatch.setattr(main._teams_session, "post", fake_post)

    ok = main._teams_post_card("t", "x", max_tentativas=1)

    assert ok is False


def test_request_with_retry_login_fails_then_succeeds(monkeypatch):
    monkeypatch.setattr(main.PVOperationAPI, "_login", lambda self: True)
    api = main.PVOperationAPI(email="x", password="y", base_url="http://example")

    behaviors = [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ConnectionError("boom2"),
        DummyResp(200),
    ]
    api.session = FakeSession(behaviors)

    login_calls = {"count": 0}

    def fake_login():
        login_calls["count"] += 1
        return login_calls["count"] >= 2

    monkeypatch.setattr(api, "_login", fake_login)
    monkeypatch.setattr(api, "_reset_session", lambda: None)
    monkeypatch.setattr(main.time, "sleep", lambda *_: None)

    resp, timeout_flag = api._request_with_retry("get", "http://example", contexto="test")
    assert timeout_flag is False
    assert resp is not None
    assert resp.status_code == 200
    assert login_calls["count"] == 2


def test_stop_uses_short_scan_lock_timeout(monkeypatch):
    api = type("Api", (), {})()
    service = main.MonitorService(api, api)
    service._threads = []

    captured = {"timeout": None}

    class FakeLock:
        def acquire(self, timeout=None):
            captured["timeout"] = timeout
            return False

        def release(self):
            return None

    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(service, "_release_lock", lambda: None)
    service._scan_lock = FakeLock()

    service.stop()
    assert captured["timeout"] == 1
