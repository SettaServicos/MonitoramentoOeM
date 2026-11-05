"""Passo 3a: confiabilidade da coleta e do envio do relatorio semanal (sem mudar Resumo/Ocorrencias)."""
from datetime import datetime, timedelta
from zipfile import ZipFile

import pytest

import main

INICIO = datetime(2025, 1, 6)
FIM = datetime(2025, 1, 13)
REF = datetime(2025, 1, 13, 0, 6)


class WeeklyApi:
    def __init__(self, plants=(1,), relay=None, falha=None):
        self.plants = list(plants)
        self.relay = relay or {}          # dia (date) -> lista de registros day_relay
        self.falha = falha or set()       # {(endpoint, date)} que falham
        self.calls = []
        self.get_plants_calls = 0
        self.last_post_day_error = False
        self.last_post_day_error_reason = None

    def get_plants(self):
        self.get_plants_calls += 1
        return [{"id": p, "nome": f"Usina {p}"} for p in self.plants]

    def post_day(self, endpoint, plant_id, date):
        self.calls.append((endpoint, int(plant_id), date.date()))
        if (endpoint, date.date()) in self.falha:
            self.last_post_day_error = True
            self.last_post_day_error_reason = "TIMEOUT"
            return None, True
        self.last_post_day_error = False
        self.last_post_day_error_reason = None
        if endpoint == "day_relay":
            return list(self.relay.get(date.date(), [])), False
        return [], False


def leitura_rele(ts, ativo=False):
    return {"idrele": "R1", "conteudojson": {"tsleitura": ts.strftime("%Y-%m-%d %H:%M:%S"), "r27A": 1 if ativo else 0}}


@pytest.fixture
def ambiente(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(main, "REPORT_DIR", tmp_path)
    monkeypatch.setattr(main, "RELE_PLANT_IDS", {"1"})
    return tmp_path


def _abas(arquivo):
    with ZipFile(arquivo) as zf:
        return [zf.read(f"xl/worksheets/sheet{i}.xml").decode("utf-8") for i in (1, 2, 3)]


def test_coleta_semanal_consulta_rele_somente_em_usinas_com_rele(ambiente):
    api = WeeklyApi(plants=(1, 2))
    main.MonitorService(api, api)._coletar_incidentes_semana_api(INICIO, FIM)
    assert {p for e, p, _ in api.calls if e == "day_relay"} == {1}
    assert {p for e, p, _ in api.calls if e == "day_inverter"} == {1, 2}


def test_relatorio_usa_conexao_dedicada_quando_informada(ambiente):
    varredura, relatorio = WeeklyApi(), WeeklyApi()
    service = main.MonitorService(varredura, varredura, relatorio)
    assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is True
    assert varredura.calls == [] and varredura.get_plants_calls == 0
    assert relatorio.calls and relatorio.get_plants_calls == 1


def test_falha_de_email_reenvia_sem_nova_coleta_e_avisa_uma_vez(ambiente, monkeypatch):
    api = WeeklyApi()
    service = main.MonitorService(api, api)
    tentativas = []

    class Outlook:
        def send_weekly_report(self, arquivo, periodo):
            tentativas.append(arquivo)
            if len(tentativas) < 3:
                raise RuntimeError("graph fora")
            return 202

    monkeypatch.setattr(main, "_get_outlook_service", lambda: Outlook())
    cards = []
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: cards.append(kw) or True)

    assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is False
    assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is False
    assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is True
    assert api.get_plants_calls == 1
    assert len(tentativas) == 3 and len(set(tentativas)) == 1
    assert len([c for c in cards if "e-mail" in c["title"]]) == 1
    assert service.last_weekly_report_id == "2025-01-06"
    assert service._relatorio_gerado is None


def test_aba_cobertura_registra_falha_de_api_e_lacuna_de_rele(ambiente):
    dia = datetime(2025, 1, 8)
    leituras = [leitura_rele(dia + timedelta(hours=8, minutes=5 * i)) for i in range(12)]
    leituras += [leitura_rele(dia + timedelta(hours=11, minutes=5 * i)) for i in range(3)]  # lacuna 08:55-11:00
    api = WeeklyApi(relay={dia.date(): leituras}, falha={("day_inverter", datetime(2025, 1, 9).date())})
    service = main.MonitorService(api, api)
    assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is True
    resumo, ocorrencias, cobertura = _abas(ambiente / "relatorio_semanal_20250106_20250112.xlsx")
    assert "FALHA NA CONSULTA A API" in cobertura and "day_inverter" in cobertura and "09/01/2025 00:00:00" in cobertura
    assert "LACUNA DE COMUNICACAO DO RELE (&gt; 45 min)" in cobertura
    assert "08/01/2025 08:55:00" in cobertura and "08/01/2025 11:00:00" in cobertura and "02:05:00" in cobertura
    assert "Sem leitura desde o inicio da semana" in cobertura
    assert "Sem leitura ate o fim da semana" in cobertura
    # Abas usadas pela equipe continuam com o mesmo cabecalho.
    assert "Indisponibilidade Janela Solar (h)" in resumo and "Periodo Considerado (Semana)" in ocorrencias


def test_aba_cobertura_sem_ocorrencias_informa_explicitamente(ambiente):
    service = main.MonitorService(WeeklyApi(plants=()), WeeklyApi(plants=()))
    rows = service._montar_aba_cobertura(INICIO, FIM, [], [], True)
    assert rows[1][2] == "SEM FALHAS DE CONSULTA OU LACUNAS DETECTADAS"
    rows = service._montar_aba_cobertura(INICIO, FIM, [], [], False)
    assert rows[1][2] == "COLETA DIRETA DA API INDISPONIVEL"


def test_falha_ao_gravar_xlsx_avisa_uma_vez(ambiente, monkeypatch):
    service = main.MonitorService(WeeklyApi(), WeeklyApi())
    monkeypatch.setattr(main, "_write_xlsx_file", lambda *a, **k: (_ for _ in ()).throw(OSError("disco")))
    cards = []
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: cards.append(kw) or True)
    for _ in range(3):
        assert service._gerar_relatorio_semanal_se_pendente(ref=REF) is False
    assert len(cards) == 1
    assert service.last_weekly_report_id is None
