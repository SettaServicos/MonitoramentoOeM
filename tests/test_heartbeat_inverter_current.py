from datetime import datetime, timedelta

import pytest

import main


@pytest.mark.parametrize("pac,minutes,active,expected", [
    (0, 10, True, True), (0, 30, True, True), (0, 31, True, False),
    (0, -1, True, False), (100, 5, True, True), (-1, 5, True, True),
    (None, 5, True, False), (0, 5, False, False),
])
def test_heartbeat_respects_detection_state(pac, minutes, active, expected):
    now = datetime(2026, 10, 29, 12)
    state = {"ativa": active, "ultima_leitura_pac": pac,
             "ultima_leitura_ts": (now - timedelta(minutes=minutes)).isoformat(),
             "ultima_confirmacao_ts": (now - timedelta(minutes=5)).isoformat()}
    assert main.MonitorService._inversor_conta_no_heartbeat(state, now) is expected


def test_heartbeat_keeps_unresolved_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 10, 29, 12, 29)
    monkeypatch.setattr(main, "datetime", Clock)
    service = main.MonitorService(object())
    for serial, pac, time in [("ZERO", 0, "12:20:00"), ("POSITIVE", 10, "12:20:00"),
                              ("STALE", 0, "11:50:00")]:
        service.estado_inversores[f"1:{serial}"] = {
            "ativa": True, "ultima_leitura_pac": pac,
            "ultima_leitura_ts": f"2026-10-29T{time}",
            "ultima_confirmacao_ts": f"2026-10-29T{time}",
            "alerta": {"usina": "Usina 1", "inversor": serial},
        }
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw))
    service._enviar_heartbeat(Clock(2026, 10, 29, 12))
    assert "**Falhas de inversor confirmadas: 2**" in payload["text"]
    assert "Usina 1 (2)" in payload["text"]
    assert "Série: ZERO" in payload["text"]
    assert "POSITIVE" in payload["text"]
    assert "STALE" in payload["text"]
    assert "sem confirmação recente" not in payload["text"]
    assert "Recuperação em confirmação" in payload["text"]
    assert service.estado_inversores["1:POSITIVE"]["ativa"]


def test_heartbeat_refreshes_relay_then_inverters_before_sending(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    service = main.MonitorService(object())
    calls = []
    def relay():
        assert not service._scan_lock.locked()
        calls.append("relay")
        service.rele_alertas_ativos.add("1:R1")
        service.rele_alerta_chave["1:R1"] = {"usina": "Usina 1"}
    def inverter():
        assert calls == ["relay"]
        calls.append("inverter")
        service.estado_inversores["2:INV"] = {
            "ativa": True, "ultima_leitura_pac": 0,
            "ultima_leitura_ts": "2026-11-01T17:00:00",
            "alerta": {"usina": "Usina 2", "inversor": "INV"}}
    payload = {}
    def send(**kwargs):
        calls.append("heartbeat")
        payload.update(kwargs)
    monkeypatch.setattr(service, "executar_varredura_rele", relay)
    monkeypatch.setattr(service, "executar_varredura_inversor", inverter)
    monkeypatch.setattr(main, "_teams_post_card", send)
    service._enviar_heartbeat(datetime(2026, 11, 3, 9))
    assert calls == ["relay", "inverter", "heartbeat"]
    assert "Falhas de inversor confirmadas: 0" in payload["text"]
    assert "Usina 1" in payload["text"]
    assert "01/11/2026 17:00:00" in payload["text"]
    assert "Falhas anteriores sem dados recentes: 1" in payload["text"]


def test_heartbeat_reports_refresh_exception_and_still_sends(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    service = main.MonitorService(object())
    service.estado_inversores["1:LEGACY"] = {"ativa": True}
    def fail():
        raise RuntimeError("API unavailable")
    monkeypatch.setattr(service, "executar_varredura_rele", fail)
    monkeypatch.setattr(service, "executar_varredura_inversor", fail)
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw))
    service._enviar_heartbeat(datetime(2026, 11, 3, 9))
    assert "Falhas de inversor confirmadas: 0" in payload["text"]
    assert "LEGACY" in payload["text"]
    assert "Exibindo estados conhecidos" in payload["text"]
    assert "N/D" in payload["text"]

