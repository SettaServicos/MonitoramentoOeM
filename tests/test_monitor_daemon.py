import importlib
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _reload_monitor_daemon(monkeypatch, **env):
    for name in ("PVOP_BASE_URL", "MONITOR_EMAIL", "MONITOR_PASSWORD", "TEAMS_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    sys.modules.pop("monitor_daemon", None)
    return importlib.import_module("monitor_daemon")


def test_monitor_daemon_le_configuracao_equivalente_ao_main(monkeypatch):
    daemon = _reload_monitor_daemon(
        monkeypatch,
        PVOP_BASE_URL="https://pvop.example/api",
        MONITOR_EMAIL="monitor@example.com",
        MONITOR_PASSWORD="secret",
        TEAMS_WEBHOOK_URL="https://teams.example/webhook",
    )

    assert daemon.PVOP_BASE_URL == "https://pvop.example/api"
    assert daemon.PVOP_EMAIL == "monitor@example.com"
    assert daemon.PVOP_PASSWORD == "secret"
    assert daemon.TEAMS_WEBHOOK_URL == "https://teams.example/webhook"
    assert daemon.TEAMS_ENABLED is True


def test_monitor_daemon_validate_config_exige_env_sem_expor_segredos(monkeypatch):
    daemon = _reload_monitor_daemon(monkeypatch)
    monkeypatch.setattr(daemon, "PVOP_BASE_URL", "")

    with pytest.raises(SystemExit) as exc:
        daemon.validate_config()

    msg = str(exc.value)
    assert "PVOP_BASE_URL" in msg
    assert "MONITOR_EMAIL" in msg
    assert "MONITOR_PASSWORD" in msg
    assert "TEAMS_WEBHOOK_URL" in msg
    assert "monitoramento@empresa.com" not in msg
    assert "senha-super-secreta" not in msg
    assert "IncomingWebhook" not in msg
