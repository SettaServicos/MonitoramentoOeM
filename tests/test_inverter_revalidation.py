from datetime import datetime, timedelta

import pytest

import main


class API:
    last_get_plants_error = False
    last_get_plants_timeout = False
    last_post_day_error = False

    def __init__(self, records):
        self.records = records
        self.timeout = False
        self.calls = []

    def get_plants(self):
        return [{"id": 1, "nome": "Usina teste"}]

    def post_day(self, endpoint, plant_id, date):
        self.calls.append(date.date())
        return [r for r in self.records if r["conteudojson"]["tsleitura"].startswith(str(date.date()))], self.timeout


def reading(inv, ts, pac, serial=None):
    return {"idinversor": inv, "conteudojson": {"tsleitura": ts.isoformat(sep=" "), "Pac": pac, "esn": serial}}


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 10, 29, 12, 30)
    monkeypatch.setattr(main, "datetime", Clock)
    svc = main.MonitorService(API([]))
    svc.ultima_varredura_inversor_por_usina["1"] = datetime(2026, 10, 29, 12)
    svc.estado_inversores["1:SLOW"] = {
        "ativa": True, "rec_seq": 0, "seq_zero": 3, "notificado": True,
        "alerta": {"usina": "Usina teste", "inversor": "SLOW", "ts_iso": "2026-10-12T10:00:00"},
        "ultima_confirmacao_ts": "2026-10-12T10:00:00",
    }
    return svc


def test_scan_recovers_delayed_inverter_and_closes_incident(service):
    service._registrar_inicio_incidente_inversor("1:SLOW", "1", "Usina teste", "SLOW", datetime(2026, 10, 12, 10))
    service.api_inversor.records = [
        reading("FAST", datetime(2026, 10, 29, 12, 15), 100),
        reading("SLOW", datetime(2026, 10, 29, 11, 40), 100),
        reading("SLOW", datetime(2026, 10, 29, 11, 45), 100),
    ]
    service.executar_varredura_inversor()
    assert not service.estado_inversores["1:SLOW"]["ativa"]
    assert "1:SLOW" not in service.incidentes_inv_ativos
    assert len(service.historico_incidentes) == 1
    service.executar_varredura_inversor()
    assert len(service.historico_incidentes) == 1


def test_single_reading_never_recovers_even_after_restart(service):
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 11, 45), 100)] * 3
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["rec_seq"] == 1
    restarted = main.MonitorService(service.api_inversor)
    restarted._load_state()
    restarted.executar_varredura_inversor()
    assert restarted.estado_inversores["1:SLOW"]["ativa"]
    assert restarted.estado_inversores["1:SLOW"]["rec_seq"] == 1
    restarted.api_inversor.records.append(reading("SLOW", datetime(2026, 10, 29, 11, 50), 100))
    restarted.executar_varredura_inversor()
    assert not restarted.estado_inversores["1:SLOW"]["ativa"]


def test_repeated_zero_does_not_create_failure(service):
    service.estado_inversores.clear()
    service.api_inversor.records = [reading("NEW", datetime(2026, 10, 29, 11, 45), 0)] * 3
    for _ in range(4):
        service.executar_varredura_inversor()
    assert not service.estado_inversores["1:NEW"]["ativa"]
    assert service.estado_inversores["1:NEW"]["seq_zero"] == 1


def test_changed_id_uses_unique_serial_without_orphan(service):
    service.api_inversor.records = [reading("NEW-ID", datetime(2026, 10, 29, 11, m), 100, "SLOW") for m in (40, 45)]
    service.executar_varredura_inversor()
    assert not service.estado_inversores["1:SLOW"]["ativa"]
    assert "1:NEW-ID" not in service.estado_inversores


def test_ambiguous_serial_does_not_recover_other_devices(service):
    service.estado_inversores["1:OTHER"] = {**service.estado_inversores["1:SLOW"], "serial": "SLOW"}
    service.api_inversor.records = [reading("NEW-ID", datetime(2026, 10, 29, 11, m), 100, "SLOW") for m in (40, 45)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert service.estado_inversores["1:OTHER"]["ativa"]


def test_timeout_does_not_commit_checkpoint_or_recovery(service):
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 11, m), 100) for m in (40, 45)]
    service.api_inversor.timeout = True
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert not service.estado_inversores["1:SLOW"].get("ultima_leitura_ts")
    service.api_inversor.timeout = False
    service.executar_varredura_inversor()
    assert not service.estado_inversores["1:SLOW"]["ativa"]


def test_scan_consulta_somente_o_dia_corrente(service):
    # Decisao operacional (2026-11-04): a varredura de inversor e continua
    # dentro do dia corrente; leituras do dia anterior nao sao reconsultadas.
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 28, 16, m), 100) for m in (40, 45)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert set(service.api_inversor.calls) == {datetime(2026, 10, 29).date()}


def test_parada_longa_nao_reconsulta_dias_anteriores(service):
    # Apos parada do monitor, a varredura retoma no dia corrente; o historico
    # anterior fica a cargo do relatorio semanal (coleta propria pela API).
    service.ultima_varredura_inversor_por_usina["1"] = datetime(2026, 10, 26, 12)
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 26, 12, m), 100) for m in (40, 45)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert set(service.api_inversor.calls) == {datetime(2026, 10, 29).date()}


def test_absence_preserves_last_failure_confirmation(service):
    for _ in range(4):
        service._reconciliar_inversores_ausentes("1", {"1:FAST"})
    assert service.estado_inversores["1:SLOW"]["ultima_confirmacao_ts"] == "2026-10-12T10:00:00"
    assert service.estado_inversores["1:SLOW"]["ativa"]


def test_legacy_recovery_counter_is_not_added_to_replayed_sample(service):
    service.estado_inversores["1:SLOW"]["rec_seq"] = 1
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 11, 45), 100)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert service.estado_inversores["1:SLOW"]["rec_seq"] == 1


@pytest.mark.parametrize("records", [[], [reading("SLOW", datetime(2026, 10, 29, 11, 45), None)]])
def test_missing_data_does_not_clear_failure_or_advance_device_cursor(service, records):
    service.api_inversor.records = records
    for _ in range(4):
        service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    # Migration can anchor at the known failure, never at the time of a failed read.
    assert service.estado_inversores["1:SLOW"].get("ultima_leitura_ts") in (None, "2026-10-12T10:00:00")


def test_failure_sequence_survives_repeated_scan_and_restart(service):
    service.estado_inversores.clear()
    service.api_inversor.records = [reading("NEW", datetime(2026, 10, 29, 11, 40), 0)]
    service.executar_varredura_inversor()
    service.executar_varredura_inversor()
    restarted = main.MonitorService(service.api_inversor)
    restarted._load_state()
    for i in range(1, main.INVERTER_CONSECUTIVE_READINGS):
        restarted.api_inversor.records.append(reading("NEW", datetime(2026, 10, 29, 11, 40) + timedelta(minutes=5*i), 0))
    restarted.executar_varredura_inversor()
    assert restarted.estado_inversores["1:NEW"]["ativa"]
    assert len(restarted.incidentes_inv_ativos) == 1


def test_exact_id_conflicting_with_serial_does_not_merge_states(service):
    service.estado_inversores["1:NEW-ID"] = {"ativa": False, "serial": "DIFFERENT"}
    service.api_inversor.records = [reading("NEW-ID", datetime(2026, 10, 29, 11, m), 100, "SLOW") for m in (40, 45)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]


def test_old_positive_readings_before_failure_do_not_recover(service):
    service.estado_inversores["1:SLOW"]["ultima_confirmacao_ts"] = "2026-10-29T12:00:00"
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 11, m), 100) for m in (40, 45)]
    service.executar_varredura_inversor()
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert service.estado_inversores["1:SLOW"]["rec_seq"] == 0


def test_first_positive_keeps_heartbeat_until_recovery_and_survives_restart(service):
    state = service.estado_inversores["1:SLOW"]
    state.update(ultima_leitura_ts="2026-10-29T12:00:00", ultima_leitura_pac=0,
                 ultima_confirmacao_ts="2026-10-29T12:00:00")
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 12, 20), 100)]
    service.executar_varredura_inversor()
    state = service.estado_inversores["1:SLOW"]
    assert state["ativa"]
    assert state["rec_seq"] == 1
    assert service._inversor_conta_no_heartbeat(state, datetime(2026, 10, 29, 12, 30))
    restarted = main.MonitorService(service.api_inversor)
    restarted._load_state()
    state = restarted.estado_inversores["1:SLOW"]
    assert state["ultima_leitura_pac"] == 100
    assert restarted._inversor_conta_no_heartbeat(state, datetime(2026, 10, 29, 12, 30))
    restarted.api_inversor.records.append(reading("SLOW", datetime(2026, 10, 29, 12, 25), 0))
    restarted.executar_varredura_inversor()
    assert restarted._inversor_conta_no_heartbeat(restarted.estado_inversores["1:SLOW"], datetime(2026, 10, 29, 12, 30))


@pytest.mark.parametrize("reference, expected", [(datetime(2026, 10, 28, 17, 15), True), (datetime(2026, 10, 28, 23), True), (datetime(2026, 10, 29, 12), False)])
def test_heartbeat_keeps_active_failure_overnight(reference, expected):
    state = {"ativa": True, "ultima_leitura_pac": 0, "ultima_leitura_ts": "2026-10-28T17:00:00", "alerta": {"usina": "Usina teste"}}
    assert main.MonitorService._inversor_conta_no_heartbeat(state, reference) is expected


def test_heartbeat_refresh_does_not_double_count_recovery(service, monkeypatch):
    monkeypatch.setattr(service, "executar_varredura_rele", lambda: None)
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw))
    service.api_inversor.records = [reading("SLOW", datetime(2026, 10, 29, 12, 20), 100)]
    for _ in range(2):
        service._enviar_heartbeat(datetime(2026, 10, 29, 12, 30))
        assert service.estado_inversores["1:SLOW"]["rec_seq"] == 1
        assert "Falhas de inversor confirmadas: 1" in payload["text"]
        assert "100 kW" in payload["text"]
    service.api_inversor.records.append(reading("SLOW", datetime(2026, 10, 29, 12, 25), 100))
    service._enviar_heartbeat(datetime(2026, 10, 29, 12, 30))
    assert not service.estado_inversores["1:SLOW"]["ativa"]
    assert "Falhas de inversor confirmadas: 0" in payload["text"]


def test_heartbeat_preserves_failure_on_api_timeout(service, monkeypatch):
    monkeypatch.setattr(service, "executar_varredura_rele", lambda: None)
    service.api_inversor.timeout = True
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw))
    service._enviar_heartbeat(datetime(2026, 10, 29, 12, 30))
    assert service.estado_inversores["1:SLOW"]["ativa"]
    assert "Falhas de inversor confirmadas: 0" in payload["text"]

    assert "Falhas anteriores sem dados recentes: 1" in payload["text"]
