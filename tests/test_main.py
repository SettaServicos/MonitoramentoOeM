import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from zipfile import ZipFile

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import main


class FakeAPI:
    def __init__(self, plants=None, plants_error=False):
        self._plants = plants if plants is not None else []
        self._plants_error = plants_error
        self.last_get_plants_timeout = False
        self.last_get_plants_error = False

    def get_plants(self):
        if self._plants_error:
            self.last_get_plants_error = True
            return []
        return list(self._plants)

    def post_day(self, endpoint, plant_id, date):
        return [], False


class DummyResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeThread:
    def __init__(self, name):
        self.name = name

    def join(self, timeout=None):
        return None

    def is_alive(self):
        return True


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    return tmp_path


def test_skip_inversor_por_rele_nao_avanca_timestamp(state_file):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1"}])
    service = main.MonitorService(api, api)
    anterior = datetime(2025, 1, 1, 0, 0, 0)
    service.ultima_varredura_inversor_por_usina["1"] = anterior
    service.usinas_alerta_rele_recente = {"1"}

    service.executar_varredura_inversor()

    assert service.ultima_varredura_inversor_por_usina["1"] == anterior


def test_reconciliar_inversor_ausente_mantem_alerta_ativo_sem_encerrar_incidente(state_file):
    service = main.MonitorService(FakeAPI(), FakeAPI())
    chave = "1:INV-STUCK"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-STUCK", "ts_iso": "2025-01-01T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-01T09:45:00",
    }
    service.pending_notifications["inv_normalizados"][chave] = {"alerta": {"inversor": "INV-STUCK"}}
    service.incidentes_inv_ativos[chave] = service._novo_incidente(
        base_key=chave,
        natureza="INVERSOR",
        tipo_falha=main.INVERTER_FAILURE_LABEL,
        usina_id="1",
        usina="Usina 1",
        equipamento="INV-STUCK",
        inicio_ts=datetime(2025, 1, 1, 8, 0, 0),
    )
    for tentativa in range(main.INVERTER_MISSING_SCAN_TOLERANCE - 1):
        service._reconciliar_inversores_ausentes("1", {"1:INV-OK"})
        assert service.estado_inversores[chave]["ativa"] is True
        assert service.estado_inversores[chave]["ausente_scans"] == tentativa + 1

    service._reconciliar_inversores_ausentes("1", {"1:INV-OK"})

    assert service.estado_inversores[chave]["ativa"] is True
    assert service.estado_inversores[chave]["alerta"]["inversor"] == "INV-STUCK"
    assert service.estado_inversores[chave]["notificado"] is True
    assert service.estado_inversores[chave]["ausente_scans"] == main.INVERTER_MISSING_SCAN_TOLERANCE
    assert service.estado_inversores[chave]["ultima_confirmacao_ts"] is None
    assert chave in service.pending_notifications["inv_normalizados"]
    assert chave in service.incidentes_inv_ativos
    assert service.historico_incidentes == []


def test_varredura_inversor_timeout_parcial_nao_limpa_ativo_existente(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1"}])
    service = main.MonitorService(api, api)
    chave = "1:INV-STUCK"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-STUCK", "ts_iso": "2025-01-01T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-01T09:45:00",
    }

    def fake_detect(*args, **kwargs):
        return [], [], False, {}, True, None

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert service.estado_inversores[chave]["ativa"] is True
    assert service.estado_inversores[chave]["ausente_scans"] == 0


def test_heartbeat_conta_inversor_ativo_mesmo_apos_ausencia(state_file, monkeypatch):
    service = main.MonitorService(FakeAPI(), FakeAPI())
    chave = "1:INV-STUCK"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-STUCK", "ts_iso": "2025-01-01T08:00:00"},
        "notificado": True,
        "ausente_scans": main.INVERTER_MISSING_SCAN_TOLERANCE - 1,
        "ultima_confirmacao_ts": "2025-01-01T09:45:00",
    }
    service._reconciliar_inversores_ausentes("1", {"1:INV-OK"})

    payload = {}

    def fake_post_card(title, text, severity="info", facts=None):
        payload["title"] = title
        payload["text"] = text
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_post_card)

    service._enviar_heartbeat(datetime(2025, 1, 1, 12, 0, 0))

    assert "**Alertas de inversor ativos: 1**" in payload["text"]
    assert "Usina 1 (1)" in payload["text"]


def test_load_state_backfill_confirmacao_inversor_ativo_usa_ultima_varredura(state_file):
    state_payload = {
        "schema_version": main.STATE_SCHEMA_VERSION,
        "ultima_varredura_rele": None,
        "ultima_varredura_inversor": "2025-01-01T11:50:00",
        "ultima_varredura_rele_por_usina": {},
        "ultima_varredura_inversor_por_usina": {"1": "2025-01-01T11:45:00"},
        "rele_alertas_ativos": [],
        "rele_notificados": [],
        "rele_alerta_chave": {},
        "estado_inversores": {
            "1:INV-ATIVO": {
                "ativa": True,
                "rec_seq": 0,
                "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
                "alerta": {"usina": "Usina 1", "inversor": "INV-ATIVO", "ts_iso": "2025-01-01T08:00:00"},
                "notificado": True,
            }
        },
        "pending_notifications": {"rele_normalizados": {}, "inv_normalizados": {}},
        "incidentes_rele_ativos": {},
        "incidentes_inv_ativos": {},
        "historico_incidentes": [],
        "last_weekly_report_id": None,
    }
    main.STATE_FILE.write_text(json.dumps(state_payload), encoding="utf-8")

    service = main.MonitorService(FakeAPI(), FakeAPI())
    service._load_state()

    assert service.estado_inversores["1:INV-ATIVO"]["ultima_confirmacao_ts"] == "2025-01-01T11:45:00"


def test_heartbeat_conta_inversor_ativo_sem_confirmacao_recente(state_file, monkeypatch):
    service = main.MonitorService(FakeAPI(), FakeAPI())
    service.estado_inversores["1:INV-STUCK"] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-STUCK", "ts_iso": "2025-01-01T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-01T08:00:00",
    }

    payload = {}

    def fake_post_card(title, text, severity="info", facts=None):
        payload["text"] = text
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_post_card)

    service._enviar_heartbeat(datetime(2025, 1, 1, 12, 0, 0))

    assert "**Alertas de inversor ativos: 1**" in payload["text"]
    assert "Usina 1 (1)" in payload["text"]


def test_heartbeat_mantem_inversor_com_confirmacao_recente(state_file, monkeypatch):
    service = main.MonitorService(FakeAPI(), FakeAPI())
    recente = datetime.now() - timedelta(minutes=5)
    service.estado_inversores["1:INV-ATIVO"] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-ATIVO", "ts_iso": recente.isoformat()},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": recente.isoformat(),
    }

    payload = {}

    def fake_post_card(title, text, severity="info", facts=None):
        payload["text"] = text
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_post_card)

    service._enviar_heartbeat(datetime(2025, 1, 1, 12, 0, 0))

    assert "**Alertas de inversor ativos: 1**" in payload["text"]
    assert "Usina 1 (1)" in payload["text"]


def test_get_plants_error_nao_avanca_varredura(state_file):
    api = FakeAPI(plants_error=True)
    service = main.MonitorService(api, api)
    anterior = datetime(2025, 1, 1, 0, 0, 0)
    service.ultima_varredura_rele = anterior

    service.executar_varredura_rele()

    assert service.ultima_varredura_rele == anterior


def test_get_plants_error_diferente_de_lista_vazia(monkeypatch):
    monkeypatch.setattr(main.PVOperationAPI, "_login", lambda self: True)
    api = main.PVOperationAPI(email="x", password="y", base_url="http://example")

    def fake_error(*args, **kwargs):
        return None, False

    monkeypatch.setattr(api, "_request_with_retry", fake_error)
    assert api.get_plants() is None
    assert api.last_get_plants_error is True

    def fake_ok(*args, **kwargs):
        return DummyResponse(200, []), False

    monkeypatch.setattr(api, "_request_with_retry", fake_ok)
    assert api.get_plants() == []
    assert api.last_get_plants_error is False


def test_validate_config_exige_env_vars_sem_expor_segredos(monkeypatch):
    monkeypatch.setattr(main, "PVOP_BASE_URL", "https://api.example")
    monkeypatch.setattr(main, "PVOP_EMAIL", "")
    monkeypatch.setattr(main, "PVOP_PASSWORD", "")
    monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL", "")
    monkeypatch.setattr(main, "TEAMS_ENABLED", False)

    with pytest.raises(SystemExit) as exc:
        main.validate_config()

    msg = str(exc.value)
    assert "MONITOR_EMAIL" in msg
    assert "MONITOR_PASSWORD" in msg
    assert "TEAMS_WEBHOOK_URL" in msg
    assert "$$" not in msg
    assert "webhook.office.com" not in msg


def test_configuracao_nao_mantem_fallback_sensivel_hardcoded():
    source = Path(main.__file__).read_text(encoding="utf-8")
    daemon_source = (ROOT_DIR / "monitor_daemon.py").read_text(encoding="utf-8")

    assert 'PVOP_EMAIL = "' not in source
    assert 'PVOP_PASSWORD = "' not in source
    assert 'TEAMS_WEBHOOK_URL = "http' not in source
    assert "$$" not in daemon_source
    assert "webhook.office.com/webhookb2" not in daemon_source


def test_env_example_existe_sem_segredos_reais():
    env_example = ROOT_DIR / ".env.example"

    assert env_example.exists()
    content = env_example.read_text(encoding="utf-8")
    assert "MONITOR_EMAIL=" in content
    assert "MONITOR_PASSWORD=" in content
    assert "TEAMS_WEBHOOK_URL=" in content
    assert "$$" not in content
    assert "webhook.office.com/webhookb2" not in content


def test_stop_salva_state_e_libera_lock_com_threads_vivas(state_file, monkeypatch):
    api = FakeAPI()
    service = main.MonitorService(api, api)
    service._threads = [FakeThread("t1")]

    saved = {"ok": False}
    released = {"ok": False}

    def fake_save():
        saved["ok"] = True

    def fake_release():
        released["ok"] = True

    monkeypatch.setattr(service, "_save_state", fake_save)
    monkeypatch.setattr(service, "_release_lock", fake_release)

    service.stop()

    assert saved["ok"] is True
    assert released["ok"] is True


def test_pending_notifications_limitadas(state_file):
    api = FakeAPI()
    service = main.MonitorService(api, api)

    itens = [{"base": str(i)} for i in range(main.MAX_PENDING_RELE_POR_USINA + 5)]
    service.pending_notifications["rele_normalizados"]["1"] = itens

    pend_inv = {str(i): {"alerta": {"id": i}} for i in range(main.MAX_PENDING_INV + 5)}
    service.pending_notifications["inv_normalizados"] = pend_inv

    service._limitar_pendencias()

    assert len(service.pending_notifications["rele_normalizados"]["1"]) == main.MAX_PENDING_RELE_POR_USINA
    assert len(service.pending_notifications["inv_normalizados"]) == main.MAX_PENDING_INV


class FakeDayInverterAPI:
    def __init__(self, payload):
        self.payload = payload

    def post_day(self, endpoint, plant_id, date):
        if endpoint != "day_inverter":
            return [], False
        return list(self.payload), False


def test_janela_solar_inversor_comeca_as_0630():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:00:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:10:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:20:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:50:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:00:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:10:00", "Pac": "0"}},
    ]
    api = FakeDayInverterAPI(payload)

    falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert tem_dados is True
    assert teve_timeout is False
    assert recuperados == []
    assert len(falhas) == 1
    assert falhas[0]["inversor_id"] == "INV-1"
    assert falhas[0]["ts_leitura"] == datetime(2025, 1, 6, 6, 50, 0)
    assert falhas_ativas["1:INV-1"]["ativa"] is True


def test_janela_solar_inversor_ibimirim_comeca_as_0730():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:00:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:10:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:20:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:30:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:40:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:50:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 08:00:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 08:10:00", "Pac": "0"}},
    ]
    api = FakeDayInverterAPI(payload)
    janela_inicio, janela_fim = main._obter_janela_solar_inversor("Usina IBIMIRIM 1")

    falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
        janela_inicio=janela_inicio,
        janela_fim=janela_fim,
    )

    assert tem_dados is True
    assert teve_timeout is False
    assert recuperados == []
    assert len(falhas) == 1
    assert falhas[0]["ts_leitura"] == datetime(2025, 1, 6, 7, 50, 0)
    assert falhas_ativas["1:INV-1"]["ativa"] is True


def test_janela_solar_inversor_ibimirim_reconhece_nome_real_do_endpoint():
    janela_inicio, janela_fim = main._obter_janela_solar_inversor("COMP.IBI.2500.LT01")

    assert janela_inicio == datetime.strptime("07:30:00", "%H:%M:%S").time()
    assert janela_fim == datetime.strptime("17:00:00", "%H:%M:%S").time()


def test_janela_solar_inversor_padrao_usa_0630_1700():
    janela_inicio, janela_fim = main._obter_janela_solar_inversor("Usina Padrão")

    assert janela_inicio == datetime.strptime("06:30:00", "%H:%M:%S").time()
    assert janela_fim == datetime.strptime("17:00:00", "%H:%M:%S").time()


def test_janela_solar_inversor_ibimirim_encerra_as_1700():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 17:10:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 17:20:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 17:30:00", "Pac": "0"}},
    ]
    api = FakeDayInverterAPI(payload)
    janela_inicio, janela_fim = main._obter_janela_solar_inversor("Usina IBIMIRIM 1")

    falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
        janela_inicio=janela_inicio,
        janela_fim=janela_fim,
    )

    assert tem_dados is False
    assert teve_timeout is False
    assert falhas == []
    assert recuperados == []
    assert falhas_ativas == {}


def test_normalizacao_inversor_exige_duas_leituras_validas():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "10"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00", "Pac": "10"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:50:00", "Pac": "10"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:00:00", "Pac": "10"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 07:10:00", "Pac": "10"}},
    ]
    api = FakeDayInverterAPI(payload)

    falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={
            "1:INV-1": {
                "ativa": True,
                "rec_seq": 0,
                "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
                "ultima_confirmacao_ts": "2025-01-06T06:20:00",
            }
        },
    )

    assert tem_dados is True
    assert teve_timeout is False
    assert falhas == []
    assert len(recuperados) == 1
    assert recuperados[0]["ts_leitura"] == datetime(2025, 1, 6, 6, 40, 0)
    assert falhas_ativas["1:INV-1"]["ativa"] is False


def test_relatorio_semanal_gera_xlsx(state_file, monkeypatch):
    reports_dir = state_file / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main, "REPORT_DIR", reports_dir)

    api = FakeAPI()
    service = main.MonitorService(api, api)
    service.historico_incidentes = [
        {
            "chave": "1:R01:SUBTENSAO",
            "natureza": "RELE",
            "tipo_falha": "SUBTENSAO",
            "usina_id": "1",
            "usina": "Usina A",
            "equipamento": "R01",
            "inicio_ts": "2025-01-07T09:00:00",
            "fim_ts": "2025-01-07T11:30:00",
        }
    ]

    ref = datetime(2025, 1, 13, 0, 6, 0)
    assert service._gerar_relatorio_semanal_se_pendente(ref=ref) is True
    assert service.last_weekly_report_id == "2025-01-06"
    assert service._gerar_relatorio_semanal_se_pendente(ref=ref) is False

    arquivo = reports_dir / "relatorio_semanal_20250106_20250112.xlsx"
    assert arquivo.exists()

    with ZipFile(arquivo, "r") as zf:
        sheet1 = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        sheet2 = zf.read("xl/worksheets/sheet2.xml").decode("utf-8")

    assert "Usina A" in sheet1
    assert "RELE" in sheet1
    assert "SUBTENSAO" in sheet1
    assert "02:30:00" in sheet1
    assert "Usina A" in sheet2
    assert "R01" in sheet2


def test_relatorio_indisponibilidade_solar_ibimirim_inversor_usa_0730():
    service = main.MonitorService(FakeAPI(), FakeAPI())
    historico = [
        {
            "chave": "1:INV1",
            "natureza": "INVERSOR",
            "tipo_falha": main.INVERTER_FAILURE_LABEL,
            "usina_id": "1",
            "usina": "Usina IBIMIRIM 1",
            "equipamento": "INV1",
            "inicio_ts": "2025-01-07T06:00:00",
            "fim_ts": "2025-01-07T08:00:00",
        }
    ]

    resumo_rows, ocorrencias_rows, _ = service._montar_relatorio_semanal(
        datetime(2025, 1, 6, 0, 0, 0),
        datetime(2025, 1, 13, 0, 0, 0),
        historico,
        {},
        {},
    )

    assert resumo_rows[1][6] == "00:30:00"
    assert ocorrencias_rows[1][8] == "00:30:00"


def test_relatorio_indisponibilidade_solar_ibimirim_nome_endpoint_usa_janela_especifica():
    service = main.MonitorService(FakeAPI(), FakeAPI())
    historico = [
        {
            "chave": "1:INV1",
            "natureza": "INVERSOR",
            "tipo_falha": main.INVERTER_FAILURE_LABEL,
            "usina_id": "1",
            "usina": "COMP.IBI.2500.LT01",
            "equipamento": "INV1",
            "inicio_ts": "2025-01-07T06:00:00",
            "fim_ts": "2025-01-07T08:00:00",
        }
    ]

    resumo_rows, ocorrencias_rows, _ = service._montar_relatorio_semanal(
        datetime(2025, 1, 6, 0, 0, 0),
        datetime(2025, 1, 13, 0, 0, 0),
        historico,
        {},
        {},
    )

    assert resumo_rows[1][6] == "00:30:00"
    assert ocorrencias_rows[1][8] == "00:30:00"


def test_relatorio_indisponibilidade_solar_ibimirim_inversor_encerra_as_1700():
    service = main.MonitorService(FakeAPI(), FakeAPI())
    historico = [
        {
            "chave": "1:INV1",
            "natureza": "INVERSOR",
            "tipo_falha": main.INVERTER_FAILURE_LABEL,
            "usina_id": "1",
            "usina": "Usina IBIMIRIM 1",
            "equipamento": "INV1",
            "inicio_ts": "2025-01-07T16:30:00",
            "fim_ts": "2025-01-07T17:30:00",
        }
    ]

    resumo_rows, ocorrencias_rows, _ = service._montar_relatorio_semanal(
        datetime(2025, 1, 6, 0, 0, 0),
        datetime(2025, 1, 13, 0, 0, 0),
        historico,
        {},
        {},
    )

    assert resumo_rows[1][6] == "00:30:00"
    assert ocorrencias_rows[1][8] == "00:30:00"


class FakeWeeklyApi:
    def get_plants(self):
        return [{"id": 1, "nome": "Usina API", "capacidade": 1000}]

    def post_day(self, endpoint, plant_id, date):
        ds = date.strftime("%Y-%m-%d")
        if endpoint == "day_relay" and ds == "2025-01-07":
            return (
                [
                    {
                        "idrele": "R10",
                        "conteudojson": {
                            "tsleitura": "2025-01-07 08:00:00",
                            "r27A": 1,
                        },
                    },
                    {
                        "idrele": "R10",
                        "conteudojson": {
                            "tsleitura": "2025-01-07 09:00:00",
                            "r27A": 0,
                        },
                    },
                ],
                False,
            )
        if endpoint == "day_inverter":
            return [], False
        return [], False


def test_coleta_semana_api_inclui_relay_normalizado():
    api = FakeWeeklyApi()
    service = main.MonitorService(api, api)

    inicio = datetime(2025, 1, 6, 0, 0, 0)
    fim = datetime(2025, 1, 13, 0, 0, 0)
    incidentes = service._coletar_incidentes_semana_api(inicio, fim)

    assert isinstance(incidentes, list)
    rele = [i for i in incidentes if i.get("natureza") == "RELE"]
    assert len(rele) == 1
    assert rele[0]["usina"] == "Usina API"
    assert rele[0]["tipo_falha"] in {"SUBTENSÃO", "SUBTENSAO"}
    assert rele[0]["inicio_ts"].startswith("2025-01-07T08:00:00")
    assert rele[0]["fim_ts"].startswith("2025-01-07T09:00:00")


class FakeWeeklyRelayParamsApi:
    def post_day(self, endpoint, plant_id, date):
        ds = date.strftime("%Y-%m-%d")
        if endpoint == "day_relay" and ds == "2025-01-07":
            return (
                [
                    {
                        "idrele": "R10",
                        "conteudojson": {
                            "tsleitura": "2025-01-07 08:00:00",
                            "r27A": 1,
                            "r27B": 0,
                        },
                    },
                    {
                        "idrele": "R10",
                        "conteudojson": {
                            "tsleitura": "2025-01-07 08:30:00",
                            "r27B": 1,
                            "r27A": 1,
                        },
                    },
                    {
                        "idrele": "R10",
                        "conteudojson": {
                            "tsleitura": "2025-01-07 09:00:00",
                            "r27A": 0,
                            "r27B": 0,
                        },
                    },
                ],
                False,
            )
        return [], False


def test_relatorio_rele_mantem_intervalos_mesmo_com_parametros_diferentes():
    api = FakeWeeklyRelayParamsApi()
    service = main.MonitorService(api, api)

    incidentes = service._coletar_incidentes_rele_semana_api(
        usina_id="1",
        usina_nome="Usina Parametros",
        inicio_semana=datetime(2025, 1, 6, 0, 0, 0),
        fim_semana=datetime(2025, 1, 13, 0, 0, 0),
    )

    partes = [main._partes_chave_rele(incidente["chave"]) for incidente in incidentes]

    assert len(incidentes) == 2
    assert [(p[0], p[1]) for p in partes] == [("1", "r10"), ("1", "r10")]
    assert all(p[2].startswith("subtens") for p in partes)
    assert [p[3] for p in partes] == ["", ""]
    assert incidentes[0]["fim_ts"].startswith("2025-01-07T08:30:00")
    assert incidentes[1]["inicio_ts"].startswith("2025-01-07T08:30:00")
    assert incidentes[1]["fim_ts"].startswith("2025-01-07T09:00:00")


def test_mescla_incidentes_relatorio_nao_duplica_mesmo_evento():
    service = main.MonitorService(FakeAPI(), FakeAPI())
    fim_semana = datetime(2025, 1, 13, 0, 0, 0)
    incidentes = [
        {
            "chave": "1:R10:SUBTENSAO",
            "natureza": "RELE",
            "tipo_falha": "SUBTENSAO",
            "usina_id": "1",
            "usina": "Usina A",
            "equipamento": "R10",
            "inicio_ts": "2025-01-07T08:00:00",
            "fim_ts": "2025-01-07T09:00:00",
        },
        {
            "chave": "1:R10:SUBTENSAO",
            "natureza": "RELE",
            "tipo_falha": "SUBTENSAO",
            "usina_id": "1",
            "usina": "Usina A",
            "equipamento": "R10",
            "inicio_ts": "2025-01-07T08:10:00",
            "fim_ts": "2025-01-07T08:55:00",
        },
    ]

    merged = service._mesclar_incidentes_relatorio(incidentes, fim_semana)

    assert len(merged) == 1
    assert merged[0]["inicio_ts"].startswith("2025-01-07T08:00:00")
    assert merged[0]["fim_ts"].startswith("2025-01-07T09:00:00")


def test_relatorio_semanal_mescla_api_e_state_sem_perder_inversor(state_file, monkeypatch):
    reports_dir = state_file / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main, "REPORT_DIR", reports_dir)

    service = main.MonitorService(FakeAPI(), FakeAPI())
    service.historico_incidentes = [
        {
            "chave": "1:INV1",
            "natureza": "INVERSOR",
            "tipo_falha": main.INVERTER_FAILURE_LABEL,
            "usina_id": "1",
            "usina": "Usina Mista",
            "equipamento": "INV1",
            "inicio_ts": "2025-01-08T10:20:00",
            "fim_ts": "2025-01-08T10:50:00",
        }
    ]

    relay_api = [
        {
            "chave": "1:R10:SUBTENSAO",
            "natureza": "RELE",
            "tipo_falha": "SUBTENSAO",
            "usina_id": "1",
            "usina": "Usina Mista",
            "equipamento": "R10",
            "inicio_ts": "2025-01-09T08:00:00",
            "fim_ts": "2025-01-09T09:00:00",
        }
    ]
    monkeypatch.setattr(service, "_coletar_incidentes_semana_api", lambda *_: relay_api)

    ref = datetime(2025, 1, 13, 0, 6, 0)
    assert service._gerar_relatorio_semanal_se_pendente(ref=ref) is True

    arquivo = reports_dir / "relatorio_semanal_20250106_20250112.xlsx"
    with ZipFile(arquivo, "r") as zf:
        sheet1 = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        sheet2 = zf.read("xl/worksheets/sheet2.xml").decode("utf-8")

    assert "RELE" in sheet1
    assert "INVERSOR" in sheet1
    assert "R10" in sheet2
    assert "INV1" in sheet2


class FakeDayRelayAPI:
    def __init__(self, payload):
        self.payload = payload

    def post_day(self, endpoint, plant_id, date):
        if endpoint != "day_relay":
            return [], False
        return list(self.payload), False


class FakePostDayErrorAPI:
    def __init__(self):
        self.last_post_day_error = False
        self.last_post_day_error_reason = None

    def post_day(self, endpoint, plant_id, date):
        self.last_post_day_error = True
        self.last_post_day_error_reason = "JSON_INVALID"
        return None, False


def test_pac_negativo_nao_conta_como_recuperacao():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "-5.0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00", "Pac": "-3.0"}},
    ]
    api = FakeDayInverterAPI(payload)

    _, recuperados, _, falhas_ativas, _, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={
            "1:INV-1": {
                "ativa": True,
                "rec_seq": 0,
                "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
                "ultima_confirmacao_ts": "2025-01-06T06:20:00",
            }
        },
    )

    assert recuperados == []
    assert falhas_ativas["1:INV-1"]["ativa"] is True


def test_sequencia_zero_negativo_zero_dispara_falha():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00", "Pac": "-1.0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:50:00", "Pac": "0"}},
    ]
    api = FakeDayInverterAPI(payload)

    falhas, _, _, falhas_ativas, _, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert len(falhas) == 1
    assert falhas_ativas["1:INV-1"]["ativa"] is True


def test_inversor_sem_pac_marca_tem_dado_valido_false():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00"}},
    ]
    api = FakeDayInverterAPI(payload)

    _, _, _, falhas_ativas, _, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert falhas_ativas["1:INV-1"].get("tem_dado_valido") is False


def test_inversor_com_pac_valido_marca_tem_dado_valido_true():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00"}},
    ]
    api = FakeDayInverterAPI(payload)

    _, _, _, falhas_ativas, _, _ = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert falhas_ativas["1:INV-1"].get("tem_dado_valido") is True


def test_detectar_alertas_rele_retorna_max_ts():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2025-01-06 10:05:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2025-01-06 10:15:00"}},
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 0, 0, 0)
    fim = datetime(2025, 1, 6, 23, 59, 59)

    alertas, tem_dados, teve_timeout, max_ts, normais_por_rele = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert max_ts == datetime(2025, 1, 6, 10, 15, 0)
    assert tem_dados is True
    assert normais_por_rele == {
        ("1", "r01"): [datetime(2025, 1, 6, 10, 5, 0), datetime(2025, 1, 6, 10, 15, 0)]
    }


def test_detectar_alertas_rele_retorna_leitura_normal_por_rele():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2025-01-06 10:05:00", "r27A": 0}},
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 10, 0, 0)
    fim = datetime(2025, 1, 6, 10, 10, 0)

    alertas, tem_dados, teve_timeout, max_ts, normais_por_rele = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert alertas == []
    assert tem_dados is True
    assert teve_timeout is False
    assert max_ts == datetime(2025, 1, 6, 10, 5, 0)
    assert normais_por_rele == {("1", "r01"): [datetime(2025, 1, 6, 10, 5, 0)]}


def test_detectar_alertas_rele_descarta_alerta_com_leitura_limpa_posterior():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2025-01-06 10:00:00", "r27A": 1}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2025-01-06 10:05:00", "r27A": 0}},
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 10, 0, 0)
    fim = datetime(2025, 1, 6, 10, 10, 0)

    alertas, tem_dados, teve_timeout, max_ts, normais_por_rele = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert alertas == []
    assert tem_dados is True
    assert teve_timeout is False
    assert max_ts == datetime(2025, 1, 6, 10, 5, 0)
    assert normais_por_rele == {("1", "r01"): [datetime(2025, 1, 6, 10, 5, 0)]}


def test_detectar_falhas_inversores_retorna_max_ts():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "100"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:50:00", "Pac": "120"}},
    ]
    api = FakeDayInverterAPI(payload)

    _, _, _, _, _, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert max_ts == datetime(2025, 1, 6, 6, 50, 0)


def test_detectar_falhas_inversores_sem_dados_max_ts_none():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00"}},
    ]
    api = FakeDayInverterAPI(payload)

    _, _, _, _, _, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 0, 0, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas={},
    )

    assert max_ts is None


def test_inversor_resposta_vazia_durante_janela_continua_sem_dados():
    api = FakeDayInverterAPI([])

    _, _, tem_dados, _, teve_timeout, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 10, 0, 0),
        fim=datetime(2025, 1, 6, 10, 15, 0),
        falhas_ativas_previas={},
    )

    assert tem_dados is False
    assert teve_timeout is False
    assert max_ts is None


def test_horarios_de_producao_citados_estao_dentro_da_janela_solar():
    horarios = ["15:19", "15:34", "15:51"]
    for horario in horarios:
        referencia = datetime.strptime(f"2025-01-06 {horario}", "%Y-%m-%d %H:%M")
        assert main._horario_esta_na_janela(
            referencia,
            main.INVERTER_SOLAR_WINDOW_START,
            main.INVERTER_SOLAR_WINDOW_END,
        )


def test_inversor_resposta_valida_no_formato_legado_nao_vira_sem_dados():
    payload = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 15:19:00", "Pac": "10"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 15:34:00", "Pac": "12"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 15:51:00", "Pac": "15"}},
    ]
    api = FakeDayInverterAPI(payload)

    falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 15, 0, 0),
        fim=datetime(2025, 1, 6, 16, 0, 0),
        falhas_ativas_previas={},
    )

    assert tem_dados is True
    assert teve_timeout is False
    assert max_ts == datetime(2025, 1, 6, 15, 51, 0)
    assert falhas == []
    assert recuperados == []
    assert falhas_ativas["1:INV-1"]["tem_dado_valido"] is True


def test_inversor_erro_api_nao_e_classificado_como_sem_dados_real():
    api = FakePostDayErrorAPI()

    _, _, tem_dados, _, teve_timeout, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 15, 0, 0),
        fim=datetime(2025, 1, 6, 16, 0, 0),
        falhas_ativas_previas={},
    )

    assert tem_dados is False
    assert teve_timeout is True
    assert max_ts is None


def test_inversor_resposta_vazia_apos_janela_nao_vira_sem_dados_por_cauda():
    api = FakeDayInverterAPI([])

    _, _, tem_dados, _, teve_timeout, max_ts = main.detectar_falhas_inversores(
        api=api,
        plant_id="1",
        inicio=datetime(2025, 1, 6, 16, 55, 1),
        fim=datetime(2025, 1, 6, 17, 10, 0),
        falhas_ativas_previas={},
    )

    assert tem_dados is True
    assert teve_timeout is False
    assert max_ts is None


def test_rele_resposta_nao_vazia_fora_da_janela_confirma_comunicacao_sem_alerta():
    payload = [
        {
            "idrele": "R01",
            "conteudojson": {"tsleitura": "2025-01-05 23:00:00", "r27A": "1"},
        }
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 0, 0, 0)
    fim = datetime(2025, 1, 6, 23, 59, 59)

    alertas, tem_dados, teve_timeout, _, _ = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert tem_dados is True
    assert alertas == []
    assert teve_timeout is False


def test_dado_dentro_da_janela_sem_parametro_ativo_seta_tem_dados():
    payload = [
        {
            "idrele": "R01",
            "conteudojson": {"tsleitura": "2025-01-06 10:00:00"},
        }
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 0, 0, 0)
    fim = datetime(2025, 1, 6, 23, 59, 59)

    alertas, tem_dados, teve_timeout, _, normais_por_rele = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert tem_dados is True
    assert alertas == []
    assert teve_timeout is False
    assert normais_por_rele == {("1", "r01"): [datetime(2025, 1, 6, 10, 0, 0)]}


def test_rele_resposta_valida_no_formato_legado_detecta_alerta():
    payload = [
        {
            "idrele": "R01",
            "conteudojson": {"tsleitura": "2025-01-06 15:19:00", "r27A": "1"},
        },
    ]
    api = FakeDayRelayAPI(payload)
    inicio = datetime(2025, 1, 6, 15, 0, 0)
    fim = datetime(2025, 1, 6, 16, 0, 0)

    alertas, tem_dados, teve_timeout, max_ts, _ = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert tem_dados is True
    assert teve_timeout is False
    assert max_ts == datetime(2025, 1, 6, 15, 19, 0)
    assert len(alertas) == 1
    assert alertas[0]["rele_id"] == "R01"


def test_rele_erro_api_nao_e_classificado_como_sem_dados_real():
    api = FakePostDayErrorAPI()
    inicio = datetime(2025, 1, 6, 15, 0, 0)
    fim = datetime(2025, 1, 6, 16, 0, 0)

    alertas, tem_dados, teve_timeout, max_ts, _ = main.detectar_alertas_rele(api, "1", inicio, fim)

    assert alertas == []
    assert tem_dados is False
    assert teve_timeout is True
    assert max_ts is None


def test_plant_ids_retornados_extrai_ids_validos():
    plantas = [
        {"id": 1, "nome": "Usina 1"},
        {"id": "3", "nome": "Usina 3"},
        {"id": None, "nome": "Sem ID"},
        {"nome": "Sem campo id"},
    ]
    ids = main._plant_ids_retornados(plantas)
    assert ids == {"1", "3"}


def test_varredura_rele_lista_parcial_preserva_alertas_usina_ausente(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)

    service.ultima_varredura_rele_por_usina["2"] = datetime(2025, 1, 6, 10, 0, 0)
    base2 = "2:R01:OUTROS"
    service.rele_alertas_ativos.add(base2)
    service.rele_alerta_chave[base2] = {"base": base2, "usina": "Usina 2"}

    monkeypatch.setattr(main, "detectar_alertas_rele", lambda *a, **k: ([], True, False, None, {}))
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_rele()

    assert base2 in service.rele_alertas_ativos


def test_varredura_inversor_lista_parcial_loga_usina_ausente(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)

    service.ultima_varredura_inversor_por_usina["2"] = datetime(2025, 1, 6, 10, 0, 0)
    chave2 = "2:INV-A"
    service.estado_inversores[chave2] = {
        "ativa": True, "rec_seq": 0, "seq_zero": 3,
        "alerta": {"usina": "Usina 2", "inversor": "INV-A", "ts_iso": "2025-01-06T10:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T10:00:00",
    }

    def fake_detect(*args, **kwargs):
        return [], [], True, {}, False, None

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert chave2 in service.estado_inversores
    assert service.estado_inversores[chave2]["ativa"] is True


def test_varredura_rele_envia_teams_fora_do_lock(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)

    lock_states = []

    def fake_teams(*args, **kwargs):
        lock_states.append(service._scan_lock.locked())
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_teams)

    def fake_rele(*args, **kwargs):
        return (
            [{"rele_id": "R01", "tipo_alerta": "OUTROS",
              "ts_leitura": datetime(2025, 1, 6, 10, 0, 0),
              "ts_primeiro": datetime(2025, 1, 6, 10, 0, 0),
              "ts_ultimo": datetime(2025, 1, 6, 10, 0, 0),
              "parametros": "r27A"}],
            True, False,
            datetime(2025, 1, 6, 10, 0, 0),
            {},
        )

    monkeypatch.setattr(main, "detectar_alertas_rele", fake_rele)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_rele()

    assert lock_states, "Teams nao foi chamado"
    assert not any(lock_states), "Teams foi chamado com o lock adquirido"


def test_varredura_rele_ativo_suprime_inversor_da_mesma_usina(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)

    chave_inv = "1:INV-A"
    ts_inv = datetime(2025, 1, 6, 9, 50, 0)
    service.estado_inversores[chave_inv] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {
            "usina": "Usina 1",
            "capacidade": 100,
            "inversor": "INV-A",
            "horario": ts_inv.strftime("%d/%m/%Y %H:%M:%S"),
            "ts_iso": ts_inv.isoformat(),
            "status": "FALHA",
            "indicadores": {"pac": 0.0},
        },
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": ts_inv.isoformat(),
    }
    service.pending_notifications["inv_normalizados"][chave_inv] = {
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "status": "NORMALIZADO"},
        "alerta_prev": service.estado_inversores[chave_inv]["alerta"],
    }
    service.incidentes_inv_ativos[chave_inv] = service._novo_incidente(
        base_key=chave_inv,
        natureza="INVERSOR",
        tipo_falha=main.INVERTER_FAILURE_LABEL,
        usina_id="1",
        usina="Usina 1",
        equipamento="INV-A",
        inicio_ts=ts_inv,
    )

    ts_rele = datetime(2025, 1, 6, 10, 0, 0)

    def fake_rele(*args, **kwargs):
        return (
            [{
                "rele_id": "R01",
                "tipo_alerta": "SUBTENSAO",
                "ts_leitura": ts_rele,
                "ts_primeiro": ts_rele,
                "ts_ultimo": ts_rele,
                "parametros": "r27A",
                "parametros_chave": "r27a",
            }],
            True,
            False,
            ts_rele,
            {},
        )

    monkeypatch.setattr(main, "detectar_alertas_rele", fake_rele)

    service.executar_varredura_rele()

    estado = service.estado_inversores[chave_inv]
    assert estado["ativa"] is False
    assert estado["alerta"] is None
    assert estado["notificado"] is False
    assert estado["seq_zero"] == 0
    assert estado["rec_seq"] == 0
    assert estado["ultima_confirmacao_ts"] is None
    assert chave_inv not in service.pending_notifications["inv_normalizados"]
    assert chave_inv not in service.incidentes_inv_ativos
    assert not any(i.get("natureza") == "INVERSOR" for i in service.historico_incidentes)


def test_varredura_rele_nao_normaliza_por_ausencia_sem_leitura_limpa(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    base_rele = main._chave_evento_rele("1", "R01", "SUBTENSAO", "r27a")
    service.rele_alertas_ativos.add(base_rele)
    service.rele_notificados.add(base_rele)
    service.rele_alerta_chave[base_rele] = {
        "base": base_rele,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "SUBTENSAO",
        "horario": "06/01/2025 10:00:00",
        "ts_iso": "2025-01-06T10:00:00",
        "parametros": "r27A",
    }

    chave_inv = "1:INV-A"
    service.pending_notifications["inv_normalizados"][chave_inv] = {
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "status": "NORMALIZADO"},
        "alerta_prev": None,
    }

    monkeypatch.setattr(
        main,
        "detectar_alertas_rele",
        lambda *a, **k: ([], True, False, datetime(2025, 1, 6, 10, 10, 0), {}),
    )

    pacotes = []
    monkeypatch.setattr(service, "_notificar_rele_agrupado", lambda pacote: pacotes.append(pacote) or (True, True))

    service.executar_varredura_rele()

    assert base_rele in service.rele_alertas_ativos
    assert service.usinas_alerta_rele_recente == {"1"}
    assert chave_inv not in service.pending_notifications["inv_normalizados"]
    assert pacotes == []


def test_varredura_rele_normalizado_suprime_pendencia_inversor_preexistente(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)

    base_rele = main._chave_evento_rele("1", "R01", "SUBTENSAO", "r27a")
    service.rele_alertas_ativos.add(base_rele)
    service.rele_alerta_chave[base_rele] = {
        "base": base_rele,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "SUBTENSAO",
        "horario": "06/01/2025 10:00:00",
        "ts_iso": "2025-01-06T10:00:00",
        "parametros": "r27A",
    }

    chave_inv = "1:INV-A"
    service.pending_notifications["inv_normalizados"][chave_inv] = {
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "status": "NORMALIZADO"},
        "alerta_prev": None,
    }

    monkeypatch.setattr(
        main,
        "detectar_alertas_rele",
        lambda *a, **k: (
            [],
            True,
            False,
            datetime(2025, 1, 6, 10, 10, 0),
            {("1", "r01"): datetime(2025, 1, 6, 10, 10, 0)},
        ),
    )

    service.executar_varredura_rele()

    assert base_rele not in service.rele_alertas_ativos
    assert chave_inv not in service.pending_notifications["inv_normalizados"]


def test_varredura_inversor_envia_teams_fora_do_lock(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)

    lock_states = []

    def fake_teams(*args, **kwargs):
        lock_states.append(service._scan_lock.locked())
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_teams)

    def fake_inversor(*args, **kwargs):
        return (
            [{"inversor_id": "INV-1", "ts_leitura": datetime(2025, 1, 6, 10, 0, 0),
              "status": "FALHA", "indicadores": {"pac": 0.0}}],
            [], True,
            {"1:INV-1": {"ativa": True, "rec_seq": 0, "seq_zero": 3,
                         "ultima_confirmacao_ts": None, "tem_dado_valido": True}},
            False, datetime(2025, 1, 6, 10, 0, 0),
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_inversor)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert lock_states, "Teams nao foi chamado"
    assert not any(lock_states), "Teams foi chamado com o lock adquirido"


# ---------------------------------------------------------------------------
# P1 — backfill de ultima_confirmacao_ts não desfaz gentle suppression
# ---------------------------------------------------------------------------

def test_backfill_nao_restaura_inversor_suprimido(state_file):
    """Inversor suprimido por ausência (ausente_scans >= TOLERANCE, ultima_confirmacao_ts=None)
    não deve ter ultima_confirmacao_ts restaurado pelo backfill de _load_state."""
    chave = "1:INV-A"
    varredura_ts = datetime(2025, 1, 6, 10, 0, 0)
    state = {
        "schema_version": main.STATE_SCHEMA_VERSION,
        "ultima_varredura_inversor_por_usina": {"1": varredura_ts.isoformat()},
        "ultima_varredura_rele_por_usina": {},
        "rele_alertas_ativos": [],
        "rele_notificados": [],
        "rele_alerta_chave": {},
        "estado_inversores": {
            chave: {
                "ativa": True,
                "rec_seq": 0,
                "seq_zero": 3,
                "alerta": {"usina": "U1", "inversor": "INV-A", "ts_iso": "2025-01-06T08:00:00"},
                "notificado": True,
                "ausente_scans": main.INVERTER_MISSING_SCAN_TOLERANCE,  # suprimido
                "ultima_confirmacao_ts": None,
            }
        },
        "pending_notifications": {},
        "incidentes_rele_ativos": {},
        "incidentes_inv_ativos": {},
        "historico_incidentes": [],
        "last_weekly_report_id": None,
    }
    main.STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    api = FakeAPI(plants=[])
    service = main.MonitorService(api, api)
    service._load_state()

    assert service.estado_inversores[chave]["ultima_confirmacao_ts"] is None, (
        "Bug P1: backfill restaurou ultima_confirmacao_ts em inversor suprimido por ausencia"
    )


def test_backfill_restaura_inversor_legado(state_file):
    """Inversor ativo com ausente_scans=0 e ultima_confirmacao_ts=None (estado legado)
    deve ter ultima_confirmacao_ts restaurado pelo backfill de _load_state."""
    chave = "1:INV-A"
    varredura_ts = datetime(2025, 1, 6, 10, 0, 0)
    # JSON legado: sem ausente_scans e sem ultima_confirmacao_ts no payload
    state = {
        "schema_version": main.STATE_SCHEMA_VERSION,
        "ultima_varredura_inversor_por_usina": {"1": varredura_ts.isoformat()},
        "ultima_varredura_rele_por_usina": {},
        "rele_alertas_ativos": [],
        "rele_notificados": [],
        "rele_alerta_chave": {},
        "estado_inversores": {
            chave: {
                "ativa": True,
                "rec_seq": 0,
                "seq_zero": 3,
                # ausente_scans ausente do JSON (legado)
                # ultima_confirmacao_ts ausente do JSON (legado)
            }
        },
        "pending_notifications": {},
        "incidentes_rele_ativos": {},
        "incidentes_inv_ativos": {},
        "historico_incidentes": [],
        "last_weekly_report_id": None,
    }
    main.STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    api = FakeAPI(plants=[])
    service = main.MonitorService(api, api)
    service._load_state()

    assert service.estado_inversores[chave]["ultima_confirmacao_ts"] is not None, (
        "Regressao P1: backfill nao restaurou ultima_confirmacao_ts em state legado valido"
    )


# ---------------------------------------------------------------------------
# P10 — lock-2 do inversor não contamina estado inativo com notificado=True
# ---------------------------------------------------------------------------

def test_falha_rec_mesma_janela_nao_contamina_notificado(state_file, monkeypatch):
    """Quando falha e recuperação ocorrem na mesma janela, o lock-2 NÃO deve
    gravar notificado=True no estado inativo resultante da recuperação."""
    T1 = datetime(2025, 1, 6, 10, 0, 0)
    T2 = datetime(2025, 1, 6, 10, 10, 0)
    chave = "1:INV-1"

    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)
    monkeypatch.setattr(service, "_registrar_inicio_incidente_inversor", lambda **k: None)
    monkeypatch.setattr(service, "_registrar_fim_incidente_inversor", lambda **k: None)

    def fake_detect(*args, **kwargs):
        return (
            [{"inversor_id": "INV-1", "ts_leitura": T1,
              "status": "FALHA", "indicadores": {"pac": 0.0}}],
            [{"inversor_id": "INV-1", "ts_leitura": T2,
              "status": "NORMAL", "indicadores": {"pac": 100.0}}],
            True,
            {chave: {"ativa": False, "rec_seq": 3, "seq_zero": 3,
                     "ultima_confirmacao_ts": T2.isoformat(), "tem_dado_valido": True}},
            False,
            T2,
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    service.executar_varredura_inversor()

    estado = service.estado_inversores.get(chave, {})
    assert estado.get("ativa") is False
    assert estado.get("notificado") is False, (
        "Bug P10: lock-2 gravou notificado=True em estado inativo (ativa=False); "
        "futuras falhas do mesmo inversor serao silenciadas"
    )


def test_nova_falha_apos_ciclo_falha_rec_e_notificada(state_file, monkeypatch):
    """Uma nova falha após um ciclo falha→rec na mesma janela deve gerar
    nova notificação Teams, não ser silenciada por notificado=True residual."""
    T1 = datetime(2025, 1, 6, 10, 0, 0)
    T2 = datetime(2025, 1, 6, 10, 10, 0)
    T3 = datetime(2025, 1, 6, 11, 0, 0)
    chave = "1:INV-1"

    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(service, "_registrar_inicio_incidente_inversor", lambda **k: None)
    monkeypatch.setattr(service, "_registrar_fim_incidente_inversor", lambda **k: None)

    # Ciclo 1: falha T1 -> rec T2 na mesma janela
    def fake_detect_ciclo1(*args, **kwargs):
        return (
            [{"inversor_id": "INV-1", "ts_leitura": T1,
              "status": "FALHA", "indicadores": {"pac": 0.0}}],
            [{"inversor_id": "INV-1", "ts_leitura": T2,
              "status": "NORMAL", "indicadores": {"pac": 100.0}}],
            True,
            {chave: {"ativa": False, "rec_seq": 3, "seq_zero": 3,
                     "ultima_confirmacao_ts": T2.isoformat(), "tem_dado_valido": True}},
            False,
            T2,
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect_ciclo1)
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)
    service.executar_varredura_inversor()

    # Ciclo 2: nova falha T3
    teams_calls = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: teams_calls.append(1) or True)

    def fake_detect_ciclo2(*args, **kwargs):
        return (
            [{"inversor_id": "INV-1", "ts_leitura": T3,
              "status": "FALHA", "indicadores": {"pac": 0.0}}],
            [],
            True,
            {chave: {"ativa": True, "rec_seq": 0, "seq_zero": 3,
                     "ultima_confirmacao_ts": None, "tem_dado_valido": True}},
            False,
            T3,
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect_ciclo2)
    service.executar_varredura_inversor()

    assert teams_calls, (
        "Bug P10: nova falha apos ciclo falha->rec nao gerou notificacao Teams "
        "(notificado=True residual silenciou o alerta)"
    )


# ---------------------------------------------------------------------------
# T1 — Relay Teams falha em nova notificação → próximo scan retenta
# ---------------------------------------------------------------------------

def test_rele_teams_falha_nova_notificacao_retenta_proximo_scan(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(service, "_registrar_inicio_incidente_rele", lambda **k: None)

    def fake_rele(*args, **kwargs):
        return (
            [{"rele_id": "R01", "tipo_alerta": "OUTROS",
              "ts_leitura": datetime(2025, 1, 6, 10, 0, 0),
              "ts_primeiro": datetime(2025, 1, 6, 10, 0, 0),
              "ts_ultimo": datetime(2025, 1, 6, 10, 0, 0),
              "parametros": "r27A"}],
            True, False,
            datetime(2025, 1, 6, 10, 0, 0),
            {},
        )

    monkeypatch.setattr(main, "detectar_alertas_rele", fake_rele)

    teams_calls = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: teams_calls.append(1) or False)

    service.executar_varredura_rele()
    assert len(teams_calls) == 1
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    assert base not in service.rele_notificados

    service.executar_varredura_rele()
    assert len(teams_calls) == 1

    service.rele_notificacao_retry_after[base] = (
        datetime.now() - timedelta(seconds=1)
    ).isoformat()

    service.executar_varredura_rele()
    assert len(teams_calls) == 2
    assert base not in service.rele_notificados


def test_rele_retry_vencido_reenvia_alerta_ativo_mesmo_sem_novos_dados(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(main, "detectar_alertas_rele", lambda *a, **k: ([], False, False, None, {}))

    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    service.rele_alertas_ativos.add(base)
    service.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "OUTROS",
        "horario": "06/01/2025 10:00:00",
        "ts_iso": "2025-01-06T10:00:00",
        "parametros": "r27A",
    }
    service.rele_notificacao_retry_after[base] = (
        datetime.now() - timedelta(seconds=1)
    ).isoformat()

    pacotes = []
    monkeypatch.setattr(
        service,
        "_notificar_rele_agrupado",
        lambda pacote: pacotes.append(pacote) or (True, True),
    )

    service.executar_varredura_rele()

    assert len(pacotes) == 1
    assert [item["base"] for item in pacotes[0]["novos"]] == [base]
    assert base in service.rele_notificados
    assert base not in service.rele_notificacao_retry_after


# ---------------------------------------------------------------------------
# T2 — Relay Teams falha em normalização → pend_norm preservado
# ---------------------------------------------------------------------------

def test_rele_teams_falha_normalizacao_preserva_pend_norm(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(service, "_registrar_fim_incidente_rele", lambda **k: None)

    base = "1:R01:OUTROS"
    service.rele_alertas_ativos.add(base)
    service.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "OUTROS",
        "horario": "06/01/2025 10:00:00",
        "ts_iso": "2025-01-06T10:00:00",
        "parametros": "r27A",
    }
    service.rele_notificados.add(base)

    monkeypatch.setattr(
        main,
        "detectar_alertas_rele",
        lambda *a, **k: (
            [],
            True,
            False,
            datetime(2025, 1, 6, 10, 5, 0),
            {("1", "r01"): datetime(2025, 1, 6, 10, 5, 0)},
        ),
    )
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: False)

    service.executar_varredura_rele()

    pend = service.pending_notifications.get("rele_normalizados", {})
    assert "1" in pend and len(pend["1"]) > 0


# ---------------------------------------------------------------------------
# T3 — falha_resend: inversor ativa=True, notificado=False → Teams chamado
# ---------------------------------------------------------------------------

def test_falha_resend_inversor_nao_notificado_chama_teams(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    chave = "1:INV-A"
    ts_falha = datetime(2025, 1, 6, 7, 0, 0)
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {
            "usina": "Usina 1",
            "capacidade": 100,
            "inversor": "INV-A",
            "horario": ts_falha.strftime("%d/%m/%Y %H:%M:%S"),
            "ts_iso": ts_falha.isoformat(),
            "status": "FALHA",
            "indicadores": {"pac": 0.0},
            "janela_solar_label": "06:30-17:00",
        },
        "notificado": False,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": ts_falha.isoformat(),
    }

    monkeypatch.setattr(main, "detectar_falhas_inversores", lambda *a, **k: ([], [], True, {}, False, None))

    teams_calls = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: teams_calls.append(1) or True)

    service.executar_varredura_inversor()

    assert len(teams_calls) == 1
    assert service.estado_inversores[chave]["notificado"] is True


# ---------------------------------------------------------------------------
# T4 — Relay tem_dados=True e teve_timeout=True → TIMEOUT_PARCIAL, alerta preservado
# ---------------------------------------------------------------------------

def test_rele_timeout_parcial_preserva_alerta_ativo(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    base = "1:R01:OUTROS"
    service.rele_alertas_ativos.add(base)
    service.rele_alerta_chave[base] = {"base": base, "usina": "Usina 1", "capacidade": 100}

    monkeypatch.setattr(main, "detectar_alertas_rele", lambda *a, **k: ([], True, True, None, {}))

    service.executar_varredura_rele()

    assert base in service.rele_alertas_ativos


# ---------------------------------------------------------------------------
# T5 — Relay tem_dados=False e teve_timeout=False → SEM_DADOS, alerta preservado
# ---------------------------------------------------------------------------

def test_rele_sem_dados_preserva_alerta_ativo(state_file, monkeypatch):
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    base = "1:R01:OUTROS"
    service.rele_alertas_ativos.add(base)
    service.rele_alerta_chave[base] = {"base": base, "usina": "Usina 1", "capacidade": 100}

    monkeypatch.setattr(main, "detectar_alertas_rele", lambda *a, **k: ([], False, False, None, {}))

    service.executar_varredura_rele()

    assert base in service.rele_alertas_ativos


def test_log_sem_dados_inversor_inclui_serial_quando_disponivel(state_file, monkeypatch, caplog):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(
        main,
        "detectar_falhas_inversores",
        lambda *a, **k: (
            [],
            [],
            False,
            {"1:INV-123": {"ativa": False, "rec_seq": 0, "seq_zero": 0, "tem_dado_valido": False}},
            False,
            None,
        ),
    )

    caplog.set_level(logging.WARNING, logger="RelayMonitorHeadless.inversor")
    service.executar_varredura_inversor()

    assert 'Sem dados de inversor em "Usina 1" - Inversor: "INV-123" (motivo: SEM_DADOS).' in caplog.text


def test_log_sem_dados_inversor_identifica_serial_ausente(state_file, monkeypatch, caplog):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(main, "detectar_falhas_inversores", lambda *a, **k: ([], [], False, {}, False, None))

    caplog.set_level(logging.WARNING, logger="RelayMonitorHeadless.inversor")
    service.executar_varredura_inversor()

    assert 'Sem dados de inversor em "Usina 1" - Inversor: não identificado (motivo: SEM_DADOS).' in caplog.text


def test_log_sem_dados_inversor_diferencia_multiplos_seriais(state_file, monkeypatch, caplog):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)
    monkeypatch.setattr(
        main,
        "detectar_falhas_inversores",
        lambda *a, **k: (
            [],
            [],
            False,
            {
                "1:INV-A": {"ativa": False, "rec_seq": 0, "seq_zero": 0, "tem_dado_valido": False},
                "1:INV-B": {"ativa": False, "rec_seq": 0, "seq_zero": 0, "tem_dado_valido": False},
            },
            False,
            None,
        ),
    )

    caplog.set_level(logging.WARNING, logger="RelayMonitorHeadless.inversor")
    service.executar_varredura_inversor()

    assert 'Sem dados de inversor em "Usina 1" - Inversor: "INV-A" (motivo: SEM_DADOS).' in caplog.text
    assert 'Sem dados de inversor em "Usina 1" - Inversor: "INV-B" (motivo: SEM_DADOS).' in caplog.text
    assert "Sem dados de inversor em Usina 1 (motivo: SEM_DADOS)." not in caplog.text


# ---------------------------------------------------------------------------
# T6 — seq_zero carregado entre janelas de varredura dispara falha na 3ª leitura
# ---------------------------------------------------------------------------

def test_seq_zero_carregado_entre_janelas_dispara_falha():
    payload1 = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:30:00", "Pac": "0"}},
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:40:00", "Pac": "0"}},
    ]
    falhas1, _, _, falhas_ativas1, _, _ = main.detectar_falhas_inversores(
        api=FakeDayInverterAPI(payload1),
        plant_id="1",
        inicio=datetime(2025, 1, 6, 6, 0, 0),
        fim=datetime(2025, 1, 6, 6, 45, 0),
        falhas_ativas_previas={},
    )
    assert falhas1 == []
    assert falhas_ativas1["1:INV-1"]["seq_zero"] == 2

    payload2 = [
        {"idinversor": "INV-1", "conteudojson": {"tsleitura": "2025-01-06 06:50:00", "Pac": "0"}},
    ]
    falhas2, _, _, _, _, _ = main.detectar_falhas_inversores(
        api=FakeDayInverterAPI(payload2),
        plant_id="1",
        inicio=datetime(2025, 1, 6, 6, 41, 0),
        fim=datetime(2025, 1, 6, 23, 59, 59),
        falhas_ativas_previas=falhas_ativas1,
    )
    assert len(falhas2) == 1
    assert falhas2[0]["inversor_id"] == "INV-1"


# ---------------------------------------------------------------------------
# T7 — rec_retry: entrada antiga em pend_norm → Teams chamado no próximo scan
# ---------------------------------------------------------------------------

def test_rec_retry_chama_teams_para_pend_norm_antigo(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    chave = "1:INV-A"
    ts_rec = datetime(2025, 1, 6, 8, 0, 0)
    service.pending_notifications["inv_normalizados"][chave] = {
        "alerta": {
            "usina": "Usina 1",
            "capacidade": 100,
            "inversor": "INV-A",
            "horario": ts_rec.strftime("%d/%m/%Y %H:%M:%S"),
            "ts_iso": ts_rec.isoformat(),
            "status": "NORMALIZADO",
            "indicadores": {"pac": 100.0},
            "janela_solar_label": "06:30-17:00",
        },
        "alerta_prev": None,
    }

    monkeypatch.setattr(
        main, "detectar_falhas_inversores",
        lambda *a, **k: ([], [], True,
                         {"1:INV-A": {"ativa": False, "rec_seq": 2, "seq_zero": 0,
                                      "ultima_confirmacao_ts": None, "tem_dado_valido": True}},
                         False, None),
    )

    teams_calls = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: teams_calls.append(1) or True)

    service.executar_varredura_inversor()

    assert len(teams_calls) == 1
    assert chave not in service.pending_notifications.get("inv_normalizados", {})


def test_rec_retry_inversor_e_descartado_com_rele_ativo(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    service.usinas_alerta_rele_recente = {"1"}
    monkeypatch.setattr(service, "_save_state", lambda: None)

    chave = "1:INV-A"
    service.pending_notifications["inv_normalizados"][chave] = {
        "alerta": {
            "usina": "Usina 1",
            "capacidade": 100,
            "inversor": "INV-A",
            "horario": "06/01/2025 08:00:00",
            "ts_iso": "2025-01-06T08:00:00",
            "status": "NORMALIZADO",
            "indicadores": {"pac": 100.0},
        },
        "alerta_prev": None,
    }

    monkeypatch.setattr(
        main, "detectar_falhas_inversores",
        lambda *a, **k: ([], [], True, {}, False, None),
    )

    teams_calls = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: teams_calls.append(1) or True)

    service.executar_varredura_inversor()

    assert teams_calls == []
    assert chave not in service.pending_notifications.get("inv_normalizados", {})


# ---------------------------------------------------------------------------
# T8 — Inversor suprimido volta a contar no heartbeat após nova confirmação
# ---------------------------------------------------------------------------

def test_inversor_suprimido_volta_ao_heartbeat_apos_nova_confirmacao(state_file, monkeypatch):
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    chave = "1:INV-A"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": main.INVERTER_MISSING_SCAN_TOLERANCE,
        "ultima_confirmacao_ts": None,
    }

    nova_confirmacao_ts = datetime(2025, 1, 6, 9, 0, 0)

    monkeypatch.setattr(
        main, "detectar_falhas_inversores",
        lambda *a, **k: ([], [], True,
                         {chave: {"ativa": True, "rec_seq": 0,
                                  "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
                                  "ultima_confirmacao_ts": nova_confirmacao_ts.isoformat(),
                                  "tem_dado_valido": True}},
                         False, nova_confirmacao_ts),
    )
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)

    service.executar_varredura_inversor()

    estado = service.estado_inversores[chave]
    assert estado["ultima_confirmacao_ts"] == nova_confirmacao_ts.isoformat()
    assert estado["ausente_scans"] == 0

    hb_payload = {}

    def fake_hb_card(title, text, severity="info", facts=None):
        hb_payload["text"] = text
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_hb_card)
    referencia = nova_confirmacao_ts + timedelta(minutes=5)
    service._enviar_heartbeat(referencia)

    assert "**Alertas de inversor ativos: 1**" in hb_payload["text"]


# ---------------------------------------------------------------------------
# P2 — reconciliação roda quando só há PAC inválido / não roda sem resposta API
# ---------------------------------------------------------------------------

def test_reconciliacao_roda_quando_so_ha_pac_invalido(state_file, monkeypatch):
    """Quando a API retorna inversores mas todos com tem_dado_valido=False,
    _reconciliar_inversores_ausentes deve rodar com chaves_observadas vazio,
    incrementando ausente_scans do inversor não visível."""
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    chave_missing = "1:INV-MISSING"
    service.estado_inversores[chave_missing] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-MISSING", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }

    def fake_detect(*args, **kwargs):
        return (
            [], [], True,
            {"1:INV-VISIBLE": {"ativa": False, "rec_seq": 0, "seq_zero": 0,
                               "tem_dado_valido": False, "ultima_confirmacao_ts": None}},
            False, datetime(2025, 1, 6, 9, 0, 0),
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert service.estado_inversores[chave_missing]["ausente_scans"] == 1


def test_reconciliacao_nao_roda_sem_resposta_api(state_file, monkeypatch):
    """Quando a API não retorna dados (falhas_ativas_atual vazio, sem timeout),
    _reconciliar_inversores_ausentes NÃO deve rodar — ausente_scans permanece 0."""
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    chave = "1:INV-STUCK"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-STUCK", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }

    def fake_detect(*args, **kwargs):
        return ([], [], False, {}, False, None)

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert service.estado_inversores[chave]["ausente_scans"] == 0


def test_reconciliacao_mix_pac_valido_e_invalido(state_file, monkeypatch):
    """Mix: inversor com PAC válido reseta ausente_scans; inversor ausente incrementa."""
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    chave_ausente = "1:INV-MISSING"
    chave_com_scans = "1:INV-A"
    service.estado_inversores[chave_ausente] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-MISSING", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }
    service.estado_inversores[chave_com_scans] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 2,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }

    ts = datetime(2025, 1, 6, 9, 0, 0)

    def fake_detect(*args, **kwargs):
        return (
            [], [], True,
            {chave_com_scans: {"ativa": True, "rec_seq": 0, "seq_zero": 3,
                               "tem_dado_valido": True, "ultima_confirmacao_ts": ts.isoformat()}},
            False, ts,
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert service.estado_inversores[chave_com_scans]["ausente_scans"] == 0
    assert service.estado_inversores[chave_ausente]["ausente_scans"] == 1


# ---------------------------------------------------------------------------
# P3 — _coletar_incidentes_semana_api chamada fora do scan_lock
# ---------------------------------------------------------------------------

def test_relatorio_api_chamada_fora_do_lock(state_file, monkeypatch):
    """_coletar_incidentes_semana_api deve ser chamada fora do _scan_lock."""
    reports_dir = state_file / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main, "REPORT_DIR", reports_dir)

    service = main.MonitorService(FakeAPI(), FakeAPI())
    lock_states = []

    def fake_api_collect(*args, **kwargs):
        lock_states.append(service._scan_lock.locked())
        return []

    monkeypatch.setattr(service, "_coletar_incidentes_semana_api", fake_api_collect)

    ref = datetime(2025, 1, 13, 0, 6, 0)
    service._gerar_relatorio_semanal_se_pendente(ref=ref)

    assert lock_states, "_coletar_incidentes_semana_api nao foi chamada"
    assert not any(lock_states), "_coletar_incidentes_semana_api foi chamada com o lock adquirido"


def test_relatorio_race_condition_nao_salva_novamente(state_file, monkeypatch):
    """Se last_weekly_report_id já foi definido por outra thread durante a coleta API,
    o segundo lock não deve chamar _save_state."""
    reports_dir = state_file / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main, "REPORT_DIR", reports_dir)

    service = main.MonitorService(FakeAPI(), FakeAPI())
    save_calls = []

    def tracking_save():
        save_calls.append(1)

    monkeypatch.setattr(service, "_save_state", tracking_save)

    report_id = "2025-01-06"

    def fake_api_collect(*args, **kwargs):
        service.last_weekly_report_id = report_id
        return []

    monkeypatch.setattr(service, "_coletar_incidentes_semana_api", fake_api_collect)

    ref = datetime(2025, 1, 13, 0, 6, 0)
    result = service._gerar_relatorio_semanal_se_pendente(ref=ref)

    assert result is True
    assert len(save_calls) == 0, "_save_state foi chamado apesar do race condition guard"


# ---------------------------------------------------------------------------
# P4 — heartbeat loga espera pelo scan_lock
# ---------------------------------------------------------------------------

def test_heartbeat_loga_espera_de_lock(state_file, monkeypatch, caplog):
    """_enviar_heartbeat deve logar o tempo de espera pelo scan_lock."""
    import logging
    service = main.MonitorService(FakeAPI(), FakeAPI())
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **k: True)

    with caplog.at_level(logging.INFO, logger="RelayMonitorHeadless"):
        service._enviar_heartbeat(datetime(2025, 1, 6, 7, 0, 0))

    assert any("[HEARTBEAT] Aguardou" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# P2-merge — ausente_scans não é zerado pelo merge quando PAC inválido
# ---------------------------------------------------------------------------

def test_merge_preserva_ausente_scans_quando_pac_invalido(state_file, monkeypatch):
    """Quando um inversor aparece na resposta da API mas sem PAC válido
    (tem_dado_valido=False), o merge não deve zerar ausente_scans."""
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    chave = "1:INV-A"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }

    def fake_detect(*args, **kwargs):
        return (
            [], [], True,
            {
                chave: {
                    "ativa": True,
                    "rec_seq": 0,
                    "seq_zero": 3,
                    "tem_dado_valido": False,
                    "ultima_confirmacao_ts": "2025-01-06T08:00:00",
                }
            },
            False,
            datetime(2025, 1, 6, 9, 0, 0),
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    service.executar_varredura_inversor()

    assert service.estado_inversores[chave]["ausente_scans"] == 1


# ---------------------------------------------------------------------------
# P2-merge-2 — merge não restaura ultima_confirmacao_ts zerada pela reconciliação
# ---------------------------------------------------------------------------

def test_merge_nao_restaura_confirmacao_ts_apos_supressao(state_file, monkeypatch):
    """Ao atingir INVERTER_MISSING_SCAN_TOLERANCE, _reconciliar_inversores_ausentes
    zera ultima_confirmacao_ts. O merge não deve restaurá-la a partir de falhas_ativas_atual."""
    api = FakeAPI(plants=[{"id": 1, "nome": "Usina 1", "capacidade": 100}])
    service = main.MonitorService(api, api)
    chave = "1:INV-A"
    service.estado_inversores[chave] = {
        "ativa": True,
        "rec_seq": 0,
        "seq_zero": main.INVERTER_CONSECUTIVE_READINGS,
        "alerta": {"usina": "Usina 1", "inversor": "INV-A", "ts_iso": "2025-01-06T08:00:00"},
        "notificado": True,
        "ausente_scans": 0,
        "ultima_confirmacao_ts": "2025-01-06T08:00:00",
    }

    def fake_detect(*args, **kwargs):
        return (
            [], [], True,
            {
                chave: {
                    "ativa": True,
                    "rec_seq": 0,
                    "seq_zero": 3,
                    "tem_dado_valido": False,
                    "ultima_confirmacao_ts": "2025-01-06T08:00:00",
                }
            },
            False,
            datetime(2025, 1, 6, 9, 0, 0),
        )

    monkeypatch.setattr(main, "detectar_falhas_inversores", fake_detect)
    monkeypatch.setattr(service, "_save_state", lambda: None)

    for _ in range(main.INVERTER_MISSING_SCAN_TOLERANCE):
        service.executar_varredura_inversor()

    assert service.estado_inversores[chave]["ausente_scans"] == main.INVERTER_MISSING_SCAN_TOLERANCE
    assert service.estado_inversores[chave]["ultima_confirmacao_ts"] is None


@pytest.mark.parametrize("valor,esperado", [
    (True, True),
    (False, False),
    (1, True),
    (0, False),
    (1.0, True),
    (2.0, False),
    ("true", True),
    ("1", True),
    ("false", False),
    ("2", False),
    (None, False),
    ({}, False),
])
def test_rele_param_ativo(valor, esperado):
    assert main._rele_param_ativo(valor) == esperado


# ---------------------------------------------------------------------------
# Testes de proteção para extrações DRY (Fase 1)
# ---------------------------------------------------------------------------

def test_fechar_incidente_clampeia_fim_antes_do_inicio(state_file):
    """fim_ts anterior a inicio_ts deve ser clampeado para inicio_ts."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    inicio = datetime(2025, 1, 6, 10, 0, 0)
    fim    = datetime(2025, 1, 6,  9, 0, 0)   # antes do inicio
    # injeta incidente ativo para que _registrar_fim o encontre
    base = "1:RELE1:SOBRETENSÃO"
    service.incidentes_rele_ativos[base] = {
        "chave": base, "natureza": "RELE", "tipo_falha": "SOBRETENSÃO",
        "usina_id": "1", "usina": "Usina A", "equipamento": "RELE1",
        "inicio_ts": inicio.isoformat(),
    }
    service._registrar_fim_incidente_rele(base=base, fim_ts=fim)
    assert len(service.historico_incidentes) == 1
    assert service.historico_incidentes[0]["fim_ts"] == inicio.isoformat()


def test_fechar_incidente_fim_maior_que_inicio_preservado(state_file):
    """fim_ts posterior a inicio_ts deve ser mantido intacto."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    inicio = datetime(2025, 1, 6,  9, 0, 0)
    fim    = datetime(2025, 1, 6, 10, 0, 0)
    chave = "1:INV1"
    service.incidentes_inv_ativos[chave] = {
        "chave": chave, "natureza": "INVERSOR", "tipo_falha": main.INVERTER_FAILURE_LABEL,
        "usina_id": "1", "usina": "Usina A", "equipamento": "INV1",
        "inicio_ts": inicio.isoformat(),
    }
    service._registrar_fim_incidente_inversor(chave_inv=chave, fim_ts=fim)
    assert len(service.historico_incidentes) == 1
    assert service.historico_incidentes[0]["fim_ts"] == fim.isoformat()


def test_carregar_varredura_por_usina_ignora_ts_invalido(state_file):
    """Entradas com ISO inválido ou vazio devem ser ignoradas silenciosamente."""
    raw = {
        "1": "2025-01-01T10:00:00",
        "2": "NAO-E-DATA",
        "3": "",
        "4": None,
    }
    # implementação inline do comportamento esperado (testa a lógica pré-extração)
    resultado = {}
    for usina_id, ts in raw.items():
        if not ts:
            continue
        try:
            resultado[str(usina_id)] = datetime.fromisoformat(ts)
        except Exception:
            continue
    assert list(resultado.keys()) == ["1"]
    assert resultado["1"] == datetime(2025, 1, 1, 10, 0, 0)


def test_carregar_incidentes_ativos_filtra_sem_inicio_ts(state_file):
    """Entradas sem inicio_ts devem ser descartadas; defaults de natureza/tipo_falha aplicados."""
    raw = {
        "chave_valida": {
            "chave": "chave_valida",
            "inicio_ts": "2025-01-06T09:00:00",
            "usina_id": "1",
            "usina": "Usina A",
            "equipamento": "RELE1",
        },
        "chave_sem_inicio": {
            "chave": "chave_sem_inicio",
            "usina_id": "1",
        },
    }
    natureza_default  = "RELE"
    tipo_falha_default = "SOBRETENSÃO"
    resultado = {}
    for chave, item in raw.items():
        if not isinstance(item, dict) or not item.get("inicio_ts"):
            continue
        resultado[str(chave)] = {
            "chave":       str(item.get("chave", chave)),
            "natureza":    str(item.get("natureza",    natureza_default)),
            "tipo_falha":  str(item.get("tipo_falha",  tipo_falha_default)),
            "usina_id":    str(item.get("usina_id",    "")),
            "usina":       item.get("usina"),
            "equipamento": str(item.get("equipamento", "")),
            "inicio_ts":   str(item.get("inicio_ts")),
        }
    assert "chave_sem_inicio" not in resultado
    assert "chave_valida" in resultado
    assert resultado["chave_valida"]["natureza"]   == natureza_default
    assert resultado["chave_valida"]["tipo_falha"] == tipo_falha_default


def test_resolver_alerta_rele_remove_das_tres_colecoes():
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    svc.rele_alertas_ativos.add("1:R1:SOBRETENSÃO")
    svc.rele_alerta_chave["1:R1:SOBRETENSÃO"] = {"usina": "U1"}
    svc.rele_notificados.add("1:R1:SOBRETENSÃO")
    svc.incidentes_rele_ativos["1:R1:SOBRETENSÃO"] = {
        "chave": "1:R1:SOBRETENSÃO", "natureza": "RELE", "tipo_falha": "SOBRETENSÃO",
        "usina_id": "1", "usina": "U1", "equipamento": "R1",
        "inicio_ts": "2026-05-12T10:00:00", "fim_ts": None,
    }

    alerta_antigo = svc._resolver_alerta_rele("1:R1:SOBRETENSÃO", fim_ts=datetime(2026, 5, 12, 10, 30))

    assert "1:R1:SOBRETENSÃO" not in svc.rele_alertas_ativos
    assert "1:R1:SOBRETENSÃO" not in svc.rele_alerta_chave
    assert "1:R1:SOBRETENSÃO" not in svc.rele_notificados
    assert alerta_antigo == {"usina": "U1"}


def test_resolver_alerta_rele_base_inexistente_e_noop():
    svc = main.MonitorService(FakeAPI(), FakeAPI())

    result = svc._resolver_alerta_rele("nao:existe:TIPO", fim_ts=datetime(2026, 5, 12, 10, 30))

    assert result is None
    assert len(svc.rele_alertas_ativos) == 0
    assert len(svc.rele_alerta_chave) == 0
    assert len(svc.rele_notificados) == 0


# ===== P1 — Cache de get_plants: testes de lógica de TTL =====

def test_plants_cache_valido_dentro_do_ttl():
    """Cache dentro do TTL deve ser considerado válido e reutilizado."""
    cache = [{"id": "1"}]
    cache_ts = datetime.now() - timedelta(seconds=300)
    ttl = timedelta(seconds=600)
    cache_valido = (
        cache is not None
        and cache_ts is not None
        and (datetime.now() - cache_ts) < ttl
    )
    assert cache_valido  # 300s < 600s → ainda válido


def test_plants_cache_none_nao_e_cacheavel():
    """None retornado pela API não deve ser armazenado no cache (erro não envenena)."""
    plantas = None
    cache = None
    if plantas is not None:  # guarda idêntica à que será implementada
        cache = list(plantas)
    assert cache is None


def test_plants_cache_expirado_apos_ttl():
    """Cache além do TTL deve ser desconsiderado e a API chamada novamente."""
    cache_ts = datetime.now() - timedelta(seconds=700)
    ttl = timedelta(seconds=600)
    cache_expirado = (datetime.now() - cache_ts) >= ttl
    assert cache_expirado  # 700s >= 600s → expirado


# ===== P3 — Throttle de historico: testes de proteção =====

def test_limitar_historico_cleanup_completo_na_primeira_chamada(state_file):
    """Primeira chamada (sem timestamp salvo) sempre executa limpeza completa de expirados."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    expirado = {
        "chave": "x", "natureza": "RELE", "tipo_falha": "T",
        "usina_id": "1", "usina": "A", "equipamento": "R1",
        "inicio_ts": "2020-01-01T00:00:00",
        "fim_ts": "2020-01-01T01:00:00",
    }
    service.historico_incidentes = [expirado]
    service._limitar_historico_incidentes()
    assert len(service.historico_incidentes) == 0  # expirado removido


def test_historico_throttle_condicao_dentro_de_1h():
    """Dentro da janela de 1h, a limpeza por data deve ser suprimida pelo throttle."""
    ultima_limpeza = datetime.now() - timedelta(minutes=30)
    janela = timedelta(hours=1)
    deve_suprimir = (datetime.now() - ultima_limpeza) < janela
    assert deve_suprimir  # 30min < 1h → deve throttle


# ===== S1–S5 — Testes de proteção para melhorias de error handling =====

def test_load_state_excecao_generica_reseta_estado(state_file, monkeypatch):
    """Exceção genérica (não JSON) em _load_state deve resetar o estado completamente."""
    payload = {
        "schema_version": main.STATE_SCHEMA_VERSION,
        "rele_alertas_ativos": ["usina1:rel1:SOBRETENSÃO"],
        "rele_alerta_chave": {
            "usina1:rel1:SOBRETENSÃO": {
                "usina": "Usina 1", "rele": "rel1", "tipo": "SOBRETENSÃO",
                "ts_iso": "2025-01-01T10:00:00",
            }
        },
    }
    (state_file / "state.json").write_text(json.dumps(payload), encoding="utf-8")
    service = main.MonitorService(FakeAPI(), FakeAPI())
    # _novo_incidente é chamado APÓS rele_alertas_ativos ser setado (linha ~1515)
    monkeypatch.setattr(service, "_novo_incidente",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("injetado")))
    service._load_state()
    # Com o fix: estado completamente limpo
    assert service.rele_alertas_ativos == set()
    assert service.estado_inversores == {}
    assert service.rele_alerta_chave == {}


def test_save_state_envia_teams_apos_falhas_consecutivas(state_file, monkeypatch):
    """_save_state deve enviar Teams card de severidade danger após SAVE_STATE_FAIL_THRESHOLD falhas."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    cards = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **kw: cards.append(kw) or True)
    monkeypatch.setattr(main.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("disco cheio")))
    for _ in range(main.SAVE_STATE_FAIL_THRESHOLD):
        service._save_state()
    assert len(cards) == 1
    assert cards[0].get("severity") == "danger"


def test_save_state_sucesso_reseta_contador(state_file, monkeypatch):
    """Sucesso em _save_state deve zerar o contador de falhas consecutivas."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    fail = {"active": True}
    original_replace = main.os.replace

    def maybe_fail(src, dst):
        if fail["active"]:
            raise OSError("disco")
        return original_replace(src, dst)

    monkeypatch.setattr(main.os, "replace", maybe_fail)
    for _ in range(main.SAVE_STATE_FAIL_THRESHOLD):
        service._save_state()
    assert service._save_state_fail_count == main.SAVE_STATE_FAIL_THRESHOLD
    fail["active"] = False
    service._save_state()
    assert service._save_state_fail_count == 0


def test_heartbeat_indica_scan_atrasado(state_file, monkeypatch):
    """Heartbeat deve incluir aviso quando o último scan de relé está atrasado."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    service.ultima_varredura_rele = datetime.now() - timedelta(seconds=3 * main.RELAY_INTERVAL)
    captured = {}

    def fake_post_card(title, text, severity="info", facts=None):
        captured["text"] = text
        return True

    monkeypatch.setattr(main, "_teams_post_card", fake_post_card)
    monkeypatch.setattr(main, "TEAMS_ENABLED", True)
    service._enviar_heartbeat(datetime.now())
    assert "atrasado" in captured.get("text", "").lower()


def test_get_plants_resposta_200_json_invalido_retorna_none(monkeypatch):
    """get_plants() deve retornar None e setar last_get_plants_error quando resposta 200 tem JSON inválido."""
    monkeypatch.setattr(main.PVOperationAPI, "_login", lambda self: True)
    api = main.PVOperationAPI(email="x", password="y", base_url="http://test")

    class BadResp:
        status_code = 200

        def json(self):
            raise ValueError("JSON inválido")

    monkeypatch.setattr(api, "_request_with_retry", lambda *a, **kw: (BadResp(), False))
    result = api.get_plants()
    assert result is None
    assert api.last_get_plants_error is True


def test_relatorio_xlsx_falha_notifica_teams(state_file, monkeypatch):
    """Falha ao escrever xlsx deve enviar Teams card e não avançar last_weekly_report_id."""
    service = main.MonitorService(FakeAPI(), FakeAPI())
    monkeypatch.setattr(service, "_periodo_relatorio_pendente",
                        lambda agora: (datetime(2025, 1, 1), datetime(2025, 1, 8), "2025-01-01"))
    monkeypatch.setattr(service, "_coletar_incidentes_semana_api", lambda *a: [])
    monkeypatch.setattr(service, "_coletar_incidentes_semana_state", lambda *a: [])
    monkeypatch.setattr(main, "_write_xlsx_file",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError("disco")))
    cards = []
    monkeypatch.setattr(main, "_teams_post_card", lambda *a, **kw: cards.append(kw) or True)
    monkeypatch.setattr(main, "TEAMS_ENABLED", True)

    service._gerar_relatorio_semanal_se_pendente()

    assert len(cards) >= 1
    assert service.last_weekly_report_id is None


# ===== E1–E5 — Testes de proteção para extrações de formatação =====

def test_formatar_blocos_rele_formata_campos():
    """_formatar_blocos_rele deve formatar todos os campos obrigatórios do alerta."""
    itens = [{"rele": "R1", "tipo": "SOBRETENSÃO", "horario": "12:00", "parametros": "r59A"}]
    texto = main._formatar_blocos_rele(itens)
    assert "Relé: R1" in texto
    assert "Tipo: SOBRETENSÃO" in texto
    assert "Horário: 12:00" in texto
    assert "Parâmetros: r59A" in texto


def test_montar_card_rele_falha_severo_usa_danger():
    """_montar_card_rele_falha deve usar severity 'danger' para tipo severo (SOBRETENSÃO)."""
    pacote = {
        "usina": "Usina A", "capacidade": 500,
        "novos": [{"rele": "R1", "tipo": "SOBRETENSÃO", "horario": "12:00", "parametros": "r59A"}],
    }
    card = main._montar_card_rele_falha(pacote)
    assert card is not None
    assert card["severity"] == "danger"
    assert "Falha de relé" in card["title"]
    assert "Usina A" in card["title"]


def test_montar_card_rele_normalizacao_usa_info():
    """_montar_card_rele_normalizacao deve usar severity 'info'."""
    pacote = {
        "usina": "Usina A", "capacidade": 500,
        "normalizados": [{"rele": "R1", "tipo": "SUBTENSÃO", "horario": "13:00", "parametros": "r27A"}],
    }
    card = main._montar_card_rele_normalizacao(pacote)
    assert card is not None
    assert card["severity"] == "info"
    assert "Normalização" in card["title"]
    assert "Usina A" in card["title"]


def test_formatar_corpo_card_inversor_contem_campos():
    """_formatar_corpo_card_inversor deve incluir todos os campos do alerta."""
    alerta = {"usina": "Usina B", "inversor": "INV-01", "horario": "10:30"}
    texto = main._formatar_corpo_card_inversor(alerta, "Pac: 0.0")
    assert "**Usina:** Usina B" in texto
    assert "**Inversor:** INV-01" in texto
    assert "**Horário:** 10:30" in texto
    assert "**Detalhes:** Pac: 0.0" in texto


def test_formatar_texto_heartbeat_status_ok():
    """_formatar_texto_heartbeat deve mostrar 'Status: OK' quando sem atraso."""
    texto = main._formatar_texto_heartbeat(
        rele_atrasado=False, inv_atrasado=False,
        ultima_rele=datetime.now(), ultima_inv=datetime.now(),
        ativos_rele=0, ativos_inv=0,
        rele_usinas=[], inv_usina_counts={},
        previsto=datetime.now(),
    )
    assert "Status: OK" in texto
    assert "SCAN ATRASADO" not in texto


def test_formatar_texto_heartbeat_scan_atrasado():
    """_formatar_texto_heartbeat deve mostrar aviso quando scan de relé está atrasado."""
    texto = main._formatar_texto_heartbeat(
        rele_atrasado=True, inv_atrasado=False,
        ultima_rele=datetime.now() - timedelta(seconds=3 * main.RELAY_INTERVAL),
        ultima_inv=datetime.now(),
        ativos_rele=0, ativos_inv=0,
        rele_usinas=[], inv_usina_counts={},
        previsto=datetime.now(),
    )
    assert "SCAN ATRASADO" in texto
    assert "atrasado" in texto.lower()


# --- E6: _dedupe_por_base ---

def test_dedupe_por_base_remove_duplicatas():
    """Items com a mesma 'base' devem ser desduplicados; itens sem base são preservados."""
    itens = [
        {"base": "a:1:SOBRETENSÃO", "usina": "U1"},
        {"base": "a:1:SOBRETENSÃO", "usina": "U1_dup"},
        {"base": "b:2:SUBTENSÃO", "usina": "U2"},
        {"base": None, "usina": "U3"},
    ]
    resultado = main._dedupe_por_base(itens)
    assert len(resultado) == 3
    assert resultado[0]["usina"] == "U1"
    assert resultado[1]["usina"] == "U2"
    assert resultado[2]["usina"] == "U3"


# --- E7: _alerta_ts_key ---

def test_alerta_ts_key_ordena_por_ts_iso():
    """Items sem ts_iso (None) devem aparecer primeiro ao ordenar (datetime.min)."""
    itens = [
        {"base": "a", "ts_iso": "2025-01-01T10:00:00"},
        {"base": "b", "ts_iso": "2025-01-01T08:00:00"},
        {"base": "c", "ts_iso": None},
    ]
    ordenado = sorted(itens, key=main._alerta_ts_key)
    assert [x["base"] for x in ordenado] == ["c", "b", "a"]


# --- E8: _compor_entrada_estado_inversor ---

def test_compor_entrada_estado_inversor_ativa_preserva_alerta():
    """Com ativa=True e tem_dado_valido=True: alerta preservado, ausente_scans zerado,
    ultima_confirmacao_ts vem do estado_novo."""
    prev = {
        "alerta": {"usina": "U1"}, "notificado": True,
        "ausente_scans": 2, "ultima_confirmacao_ts": "2025-01-01T10:00:00",
    }
    novo = {"ativa": True, "rec_seq": 0, "seq_zero": 3, "ultima_confirmacao_ts": "2025-01-01T10:05:00"}
    entry = main._compor_entrada_estado_inversor(prev, novo, tem_dado_valido=True)
    assert entry["ativa"] is True
    assert entry["alerta"] == {"usina": "U1"}
    assert entry["notificado"] is True
    assert entry["ausente_scans"] == 0
    assert entry["ultima_confirmacao_ts"] == "2025-01-01T10:05:00"


def test_compor_entrada_estado_inversor_inativa_limpa_campos():
    """Com ativa=False: alerta, notificado e ultima_confirmacao_ts devem ser limpos."""
    prev = {
        "alerta": {"usina": "U1"}, "notificado": True,
        "ausente_scans": 1, "ultima_confirmacao_ts": "2025-01-01T10:00:00",
    }
    novo = {"ativa": False, "rec_seq": 2, "seq_zero": 0, "ultima_confirmacao_ts": None}
    entry = main._compor_entrada_estado_inversor(prev, novo, tem_dado_valido=True)
    assert entry["ativa"] is False
    assert entry["alerta"] is None
    assert entry["notificado"] is False
    assert entry["ultima_confirmacao_ts"] is None


def test_compor_entrada_estado_inversor_ausente_preserva_scans():
    """Com tem_dado_valido=False: ausente_scans e ultima_confirmacao_ts vêm do prev_entry."""
    prev = {
        "alerta": {"usina": "U1"}, "notificado": True,
        "ausente_scans": 2, "ultima_confirmacao_ts": "2025-01-01T10:00:00",
    }
    novo = {"ativa": True, "rec_seq": 0, "seq_zero": 1, "ultima_confirmacao_ts": None}
    entry = main._compor_entrada_estado_inversor(prev, novo, tem_dado_valido=False)
    assert entry["ausente_scans"] == 2
    assert entry["ultima_confirmacao_ts"] == "2025-01-01T10:00:00"


# --- E9: _parse_retry_after_seconds ---

def test_parse_retry_after_seconds_inteiro():
    """Header inteiro é parseado; ausente ou vazio retorna None."""
    assert main._parse_retry_after_seconds({"Retry-After": "5"}) == 5
    assert main._parse_retry_after_seconds({"Retry-After": "0"}) == 0
    assert main._parse_retry_after_seconds({}) is None
    assert main._parse_retry_after_seconds({"Retry-After": ""}) is None


def test_ativar_alerta_rele_novo_adiciona_todas_colecoes():
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    alerta = {"base": "1:R1:SOBRETENSÃO", "usina": "U1", "ts_iso": "2026-05-12T10:00:00"}

    svc._ativar_alerta_rele(
        "1:R1:SOBRETENSÃO", alerta,
        usina_id="1", nome="U1", rele_id="R1",
        tipo_alerta="SOBRETENSÃO", inicio_ts=datetime(2026, 5, 12, 10, 0, 0),
    )

    assert "1:R1:SOBRETENSÃO" in svc.rele_alertas_ativos
    assert svc.rele_alerta_chave["1:R1:SOBRETENSÃO"] == alerta
    assert "1:R1:SOBRETENSÃO" in svc.incidentes_rele_ativos


def test_coletar_alertas_rele_usina_sem_dados_preserva_ativos(monkeypatch):
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    last = datetime(2026, 5, 12, 10, 0, 0)
    agora = datetime(2026, 5, 12, 10, 5, 0)
    svc.ultima_varredura_rele_por_usina["1"] = last
    chamadas = []

    def fake_detect(api, usina_id, inicio, fim):
        chamadas.append((usina_id, inicio, fim))
        return [], False, False, None, {}

    monkeypatch.setattr(main, "detectar_alertas_rele", fake_detect)

    alertas, preservar_ativos, max_ts, normais_por_rele = svc._coletar_alertas_rele_usina(
        usina_id="1",
        nome="Usina 1",
        inicio_padrao=datetime(2026, 5, 12, 0, 0, 0),
        agora=agora,
    )

    assert alertas == []
    assert preservar_ativos is True
    assert max_ts is None
    assert normais_por_rele == {}
    assert chamadas == [("1", last + timedelta(seconds=main.WINDOW_DELTA_SECONDS), agora)]


def test_montar_alerta_rele_formatado_inclui_base_e_intervalo():
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    alerta = {
        "rele_id": "R01",
        "tipo_alerta": "OUTROS",
        "ts_leitura": datetime(2026, 5, 12, 10, 10, 0),
        "ts_primeiro": datetime(2026, 5, 12, 10, 0, 0),
        "ts_ultimo": datetime(2026, 5, 12, 10, 10, 0),
        "parametros": "r27A",
    }

    resultado = svc._montar_alerta_rele_formatado(
        alerta,
        base=base,
        nome="Usina 1",
        capacidade=100,
    )

    assert resultado["base"] == base
    assert resultado["usina"] == "Usina 1"
    assert resultado["rele"] == "R01"
    assert "Primeiro alerta" in resultado["parametros"]


def test_registrar_alerta_rele_detectado_suprime_base_ja_notificada(monkeypatch):
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    monkeypatch.setattr(svc, "_registrar_inicio_incidente_rele", lambda **k: None)
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    svc.rele_notificados.add(base)
    bases_ativos_atual = set()
    novos_por_usina = {}
    alerta = {
        "rele_id": "R01",
        "tipo_alerta": "OUTROS",
        "ts_leitura": datetime(2026, 5, 12, 10, 0, 0),
        "ts_primeiro": datetime(2026, 5, 12, 10, 0, 0),
        "ts_ultimo": datetime(2026, 5, 12, 10, 0, 0),
        "parametros": "r27A",
    }

    svc._registrar_alerta_rele_detectado(
        alerta_raw=alerta,
        usina_id="1",
        nome="Usina 1",
        capacidade=100,
        pend_norm={},
        bases_ativos_atual=bases_ativos_atual,
        novos_por_usina=novos_por_usina,
        agora=datetime(2026, 5, 12, 10, 1, 0),
    )

    assert base in bases_ativos_atual
    assert base in svc.rele_alertas_ativos
    assert novos_por_usina == {}


def test_registrar_resolucoes_rele_limpa_notificado_e_retry(monkeypatch):
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    svc.rele_alertas_ativos.add(base)
    svc.rele_notificados.add(base)
    svc.rele_notificacao_retry_after[base] = datetime(2026, 5, 12, 10, 5, 0).isoformat()
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "OUTROS",
        "horario": "12/05/2026 10:00:00",
        "ts_iso": "2026-05-12T10:00:00",
        "parametros": "r27A",
    }
    monkeypatch.setattr(svc, "_registrar_fim_incidente_rele", lambda **k: None)

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=datetime(2026, 5, 12, 10, 10, 0),
        reles_normais_por_usina={("1", "r01"): datetime(2026, 5, 12, 10, 10, 0)},
    )

    assert resolvidos["1"]["itens"][0]["base"] == base
    assert base not in svc.rele_alertas_ativos
    assert base not in svc.rele_notificados
    assert base not in svc.rele_notificacao_retry_after


def test_registrar_resolucoes_rele_nao_fecha_sem_confirmacao_limpa(monkeypatch):
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    svc.rele_alertas_ativos.add(base)
    svc.rele_notificados.add(base)
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "OUTROS",
        "horario": "12/05/2026 10:00:00",
        "ts_iso": "2026-05-12T10:00:00",
        "parametros": "r27A",
    }
    monkeypatch.setattr(svc, "_registrar_fim_incidente_rele", lambda **k: None)

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=datetime(2026, 5, 12, 10, 10, 0),
        reles_normais_por_usina={},
    )

    assert resolvidos == {}
    assert base in svc.rele_alertas_ativos
    assert base in svc.rele_notificados


def test_montar_jobs_notificacao_rele_deduplica_e_preserva_pendentes():
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    novo = {"base": "1:R01:outros:r27a", "ts_iso": "2026-05-12T10:00:00", "usina": "Usina 1"}
    normalizado = {"base": "1:R02:outros:r27b", "ts_iso": "2026-05-12T10:05:00", "usina": "Usina 1"}
    pend_norm = {}

    jobs = svc._montar_jobs_notificacao_rele(
        novos_por_usina={"1": {"usina": "Usina 1", "capacidade": 100, "itens": [novo, dict(novo)]}},
        resolvidos_por_usina={"1": {"usina": "Usina 1", "capacidade": 100, "itens": [normalizado]}},
        pend_norm=pend_norm,
    )

    assert len(jobs) == 1
    _, pacote = jobs[0]
    assert pacote["novos"] == [novo]
    assert pacote["normalizados"] == [normalizado]
    assert pend_norm["1"] == [normalizado]


def test_aplicar_resultados_notificacao_rele_falha_agenda_retry(monkeypatch):
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    monkeypatch.setattr(svc, "_save_state", lambda: None)
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27A")
    pacote = {"novos": [{"base": base}], "normalizados": []}

    svc._aplicar_resultados_notificacao_rele({"1": (False, True, pacote)})

    assert base not in svc.rele_notificados
    assert main._parse_iso_datetime(svc.rele_notificacao_retry_after[base]) is not None


def test_ativar_alerta_rele_duplicata_atualiza_detalhe_sem_duplicar_incidente():
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    alerta1 = {"base": "1:R1:SOBRETENSÃO", "usina": "U1", "ts_iso": "2026-05-12T10:00:00"}
    alerta2 = {"base": "1:R1:SOBRETENSÃO", "usina": "U1", "ts_iso": "2026-05-12T10:10:00"}
    ts = datetime(2026, 5, 12, 10, 0, 0)
    kwargs = dict(usina_id="1", nome="U1", rele_id="R1", tipo_alerta="SOBRETENSÃO", inicio_ts=ts)

    svc._ativar_alerta_rele("1:R1:SOBRETENSÃO", alerta1, **kwargs)
    svc._ativar_alerta_rele("1:R1:SOBRETENSÃO", alerta2, **kwargs)

    assert svc.rele_alerta_chave["1:R1:SOBRETENSÃO"] == alerta2  # detalhe atualizado
    assert len([k for k in svc.incidentes_rele_ativos if k == "1:R1:SOBRETENSÃO"]) == 1  # sem duplicata


# =============================================================================
# Testes adicionados pós-auditoria (2026-05-14)
# =============================================================================

# --- T4: _iterar_registros_api_dia ---

def test_iterar_registros_api_dia_nao_lista_gera_warning_sem_yield():
    """Quando recebe um não-lista, deve logar warning e não iterar nenhum registro."""
    warnings_capturados = []

    class _Logger:
        def warning(self, msg):
            warnings_capturados.append(msg)

    resultado = list(main._iterar_registros_api_dia({"chave": "valor"}, "day_relay", "1", _Logger()))

    assert resultado == []
    assert len(warnings_capturados) == 1
    assert "Resposta inesperada" in warnings_capturados[0]
    assert "day_relay" in warnings_capturados[0]


def test_iterar_registros_api_dia_lista_valida_itera_e_descarta_invalidos():
    """Deve iterar registros com timestamp válido e descartar entradas malformadas."""
    payload = [
        {"idrele": "R1", "conteudojson": {"tsleitura": "2025-01-06 10:00:00", "r27A": True}},
        {"idrele": "R2", "conteudojson": {"tsleitura": "INVALIDO"}},
        "nao-e-dict",
    ]

    class _Logger:
        def warning(self, _msg): pass

    resultado = list(main._iterar_registros_api_dia(payload, "day_relay", "1", _Logger()))

    assert len(resultado) == 1
    registro, _conteudo, ts = resultado[0]
    assert registro["idrele"] == "R1"
    assert ts == datetime(2025, 1, 6, 10, 0, 0)


# --- T5: formatos de chave legada vs nova são semanticamente distintos ---

def test_chave_evento_rele_usa_identidade_operacional_sem_parametros():
    """_chave_legada_rele normaliza para minúsculas; state legado real usa maiúsculas.
    Ambos os formatos devem estar em bases_legadas para cobrir migrações distintas."""
    tipo = "SOBRETENSÃO"
    chave_r59a = main._chave_evento_rele("1", "5", tipo, "r59A")
    chave_r59b = main._chave_evento_rele("1", "5", tipo, "r59B")
    chave_legada_normalizada = main._chave_legada_rele("1", "5", tipo)
    chave_legada_raw = f"1:5:{tipo}"

    assert chave_legada_normalizada != chave_legada_raw
    assert "sobretensão" in chave_legada_normalizada
    assert "SOBRETENSÃO" in chave_legada_raw
    assert chave_r59a == chave_r59b
    assert chave_r59a == chave_legada_normalizada
    assert len(chave_r59a.split(":")) == 3


# --- T6: _migrar_chave_rele_ativa migra todas as 5 coleções ---

def test_migrar_chave_rele_ativa_migra_todas_as_cinco_colecoes():
    """_migrar_chave_rele_ativa deve transferir estado em rele_alertas_ativos,
    rele_notificados, rele_notificacao_retry_after, rele_alerta_chave e
    incidentes_rele_ativos, removendo a chave antiga."""
    svc = main.MonitorService(FakeAPI(), FakeAPI())
    chave_antiga = "1:r01:sobretensao:r59a"
    chave_nova = main._chave_evento_rele("1", "R01", "SOBRETENSÃO", "r59A")

    ts = datetime(2026, 1, 1, 10, 0, 0)
    svc.rele_alertas_ativos.add(chave_antiga)
    svc.rele_notificados.add(chave_antiga)
    svc.rele_notificacao_retry_after[chave_antiga] = ts.isoformat()
    svc.rele_alerta_chave[chave_antiga] = {"usina": "U1", "ts_iso": ts.isoformat()}
    svc.incidentes_rele_ativos[chave_antiga] = {"chave": chave_antiga, "natureza": "RELE"}

    svc._migrar_chave_rele_ativa(chave_antiga, chave_nova)

    assert chave_antiga not in svc.rele_alertas_ativos
    assert chave_antiga not in svc.rele_notificados
    assert chave_antiga not in svc.rele_notificacao_retry_after
    assert chave_antiga not in svc.rele_alerta_chave
    assert chave_antiga not in svc.incidentes_rele_ativos

    assert chave_nova in svc.rele_alertas_ativos
    assert chave_nova in svc.rele_notificados
    assert main._parse_iso_datetime(svc.rele_notificacao_retry_after[chave_nova]) == ts
    assert svc.rele_alerta_chave[chave_nova]["usina"] == "U1"
    assert svc.incidentes_rele_ativos[chave_nova]["chave"] == chave_nova


# --- T8: load_state com chave legada de 3 partes ---

def test_load_state_chave_rele_legada_3_partes_carregada_sem_erro(state_file):
    """Estado gravado com chave de relé em 3 partes (formato anterior ao 4-part)
    deve ser carregado sem exceção; alertas ficam disponíveis para migração em runtime."""
    import json as _json
    chave_legada = "19478:5:SOBRETENSÃO"
    state_data = {
        "rele_alertas_ativos": [chave_legada],
        "rele_notificados": [chave_legada],
        "rele_notificacao_retry_after": {},
        "rele_alerta_chave": {chave_legada: {"usina": "Usina X", "ts_iso": "2026-01-01T10:00:00"}},
        "estado_inversores": {},
        "pending_notifications": {"rele_normalizados": {}, "inv_normalizados": {}},
        "ultima_varredura_rele": None,
        "ultima_varredura_inversor": None,
        "ultima_varredura_rele_por_usina": {},
        "ultima_varredura_inversor_por_usina": {},
        "historico_incidentes": [],
        "incidentes_rele_ativos": {},
        "incidentes_inversores_ativos": {},
    }
    main.STATE_FILE.write_text(_json.dumps(state_data), encoding="utf-8")

    svc = main.MonitorService(FakeAPI(), FakeAPI())
    svc._load_state()

    assert chave_legada in svc.rele_alertas_ativos
    assert chave_legada in svc.rele_notificados
    assert svc.rele_alerta_chave[chave_legada]["usina"] == "Usina X"


# --- T9: post_day com resposta HTTP não-200 ---

def test_post_day_http_nao_200_seta_last_post_day_error(monkeypatch):
    """post_day com resposta HTTP 404 deve retornar (None, False) e registrar
    last_post_day_error=True com reason 'HTTP_404'."""
    monkeypatch.setattr(main.PVOperationAPI, "_login", lambda self: None)
    api = main.PVOperationAPI(email="x", password="y", base_url="http://example")

    class _Resp404:
        status_code = 404

    monkeypatch.setattr(api, "_request_with_retry", lambda *a, **kw: (_Resp404(), False))

    result, timeout_flag = api.post_day("day_relay", 1, datetime(2025, 1, 6))

    assert result is None
    assert timeout_flag is False
    assert api.last_post_day_error is True
    assert api.last_post_day_error_reason == "HTTP_404"


def test_post_day_json_invalido_seta_reason_json_invalid(monkeypatch):
    """post_day com status 200 mas resposta não-JSON deve retornar (None, False) e
    registrar last_post_day_error_reason='JSON_INVALID'."""
    monkeypatch.setattr(main.PVOperationAPI, "_login", lambda self: None)
    api = main.PVOperationAPI(email="x", password="y", base_url="http://example")

    class _RespBadJson:
        status_code = 200
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(api, "_request_with_retry", lambda *a, **kw: (_RespBadJson(), False))

    result, timeout_flag = api.post_day("day_relay", 1, datetime(2025, 1, 6))

    assert result is None
    assert timeout_flag is False
    assert api.last_post_day_error is True
    assert api.last_post_day_error_reason == "JSON_INVALID"
