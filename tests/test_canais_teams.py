# -*- coding: utf-8 -*-
"""Testes de roteamento das notificações Teams por canal (relé / inversor / geral)."""
import sys
from pathlib import Path

import pytest
import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import main


class DummyResp:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


@pytest.fixture
def urls_capturadas(monkeypatch):
    """Mocka _teams_session.post e devolve a lista de URLs recebidas."""
    capturadas = []

    def fake_post(url, *args, **kwargs):
        capturadas.append(url)
        return DummyResp(200)

    monkeypatch.setattr(main, "TEAMS_ENABLED", True)
    monkeypatch.setattr(main._teams_session, "post", fake_post)
    monkeypatch.setattr(main.time, "sleep", lambda *_: None)
    return capturadas


def test_teams_post_card_usa_webhook_url_explicito(urls_capturadas, monkeypatch):
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    ok = main._teams_post_card("t", "x", webhook_url="https://canal-rele")
    assert ok is True
    assert urls_capturadas == ["https://canal-rele"]


def test_teams_post_card_sem_webhook_url_usa_geral(urls_capturadas, monkeypatch):
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    ok = main._teams_post_card("t", "x")
    assert ok is True
    assert urls_capturadas == ["https://geral"]


PACOTE_RELE = {
    "usina": "Usina A",
    "capacidade": 500,
    "novos": [{"rele": "R1", "tipo": "SOBRETENSÃO", "horario": "12:00", "parametros": "r59A"}],
    "normalizados": [{"rele": "R1", "tipo": "SUBTENSÃO", "horario": "13:00", "parametros": "r27A"}],
}


def _service():
    return main.MonitorService.__new__(main.MonitorService)


def test_rele_roteia_para_canal_rele(urls_capturadas, monkeypatch):
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_RELE", "https://canal-rele")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_INVERSOR", "https://canal-inversor")

    ok_novos, ok_norm = _service()._notificar_rele_agrupado(dict(PACOTE_RELE))

    assert ok_novos is True and ok_norm is True
    assert urls_capturadas == ["https://canal-rele", "https://canal-rele"]


def test_rele_fallback_para_canal_geral_quando_variavel_ausente(urls_capturadas, monkeypatch):
    # Simula .env sem TEAMS_WEBHOOK_URL_RELE: o import resolveu para o geral.
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_RELE", "https://geral")

    _service()._notificar_rele_agrupado({**PACOTE_RELE, "normalizados": []})

    assert urls_capturadas == ["https://geral"]


ALERTA_INV = {
    "usina": "Usina B",
    "inversor": "INV-01",
    "status": "FALHA",
    "horario": "10:30",
    "capacidade": 300,
    "indicadores": {"pac": 0.0},
}


def test_inversor_falha_roteia_para_canal_inversor(urls_capturadas, monkeypatch):
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_RELE", "https://canal-rele")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_INVERSOR", "https://canal-inversor")

    ok = _service()._notificar_inversor(dict(ALERTA_INV))

    assert ok is True
    assert urls_capturadas == ["https://canal-inversor"]


def test_inversor_recuperado_roteia_para_canal_inversor(urls_capturadas, monkeypatch):
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "https://geral")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_INVERSOR", "https://canal-inversor")

    ok = _service()._notificar_inversor_recuperado({**ALERTA_INV, "status": "NORMALIZADO"})

    assert ok is True
    assert urls_capturadas == ["https://canal-inversor"]
