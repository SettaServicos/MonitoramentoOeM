# -*- coding: utf-8 -*-
"""Passo 4a: falha aberta de inversor substituido/retirado no cadastro (plant_devices)."""
from datetime import datetime, timedelta

import pytest

import main

AGORA = datetime(2026, 11, 6, 12, 0)
BLOQUEIO = datetime(2026, 11, 2, 9, 30)


def dev(esn, status=1, nome="L01"):
    # Mesmo device_name = mesma posicao na usina (pareamento antigo -> substituto).
    return {"device_esn": esn, "device_status": status, "device_name": nome}


def esn_bloqueado(serial, quando=BLOQUEIO):
    return f"{serial}@{int(quando.timestamp())}"


class API:
    last_get_plants_error = False
    last_get_plants_timeout = False
    last_post_day_error = False

    def __init__(self, cadastro=None):
        self.cadastro = cadastro or {}
        self.consultas = []

    def get_plants(self):
        return []

    def post_day(self, endpoint, plant_id, date):
        return [], False

    def get_plant_devices(self, plant_id):
        self.consultas.append(str(plant_id))
        valor = self.cadastro.get(str(plant_id))
        if isinstance(valor, Exception):
            raise valor
        return valor


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(main, "SUBSTITUICAO_VERIFICAR", True)
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", True)
    teams = []
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: teams.append(kw) or True)
    service = main.MonitorService(API())
    service.teams = teams
    return service


def falha(service, usina, serial, ultima=datetime(2026, 10, 20, 10), inicio=datetime(2026, 10, 1, 10)):
    chave = f"{usina}:{serial}"
    service.estado_inversores[chave] = {
        "ativa": True, "rec_seq": 0, "seq_zero": 6, "notificado": True, "ausente_scans": 0,
        "serial": serial, "ultima_leitura_ts": ultima.isoformat() if ultima else None,
        "ultima_leitura_pac": 0.0, "ultima_confirmacao_ts": None,
        "alerta": {"usina": f"Usina {usina}", "inversor": serial, "ts_iso": inicio.isoformat()},
    }
    service._registrar_inicio_incidente_inversor(chave, str(usina), f"Usina {usina}", serial, inicio)
    return chave


# ---------- classificacao pura ----------

@pytest.mark.parametrize("devices,esperado", [
    ([dev("A1", 4), dev("B2")], "RETIRADO"),
    ([dev("A1", 3), dev("B2")], "RETIRADO"),
    ([dev(esn_bloqueado("A1"), 1), dev("B2")], "RETIRADO"),
    ([dev(esn_bloqueado("A1"), 4), dev("A1", 1)], "ATIVO"),       # reinstalado
    ([dev("A1", 2), dev("B2")], "ATIVO"),                          # manutencao: falha real
    ([dev("A1", 1)], "ATIVO"),
    ([dev("B2")], "NAO_ENCONTRADO"),
    ([], "CADASTRO_INDISPONIVEL"),
    (None, "CADASTRO_INDISPONIVEL"),
    ("lixo", "CADASTRO_INDISPONIVEL"),
    ([dev("A1", 4), dev("B2", 4)], "CADASTRO_SUSPEITO"),          # nenhum ativo na usina
    ([dev("X", 4, nome="A1"), dev("B2")], "NAO_ENCONTRADO"),       # so casa por serial (esn)
    ([dev("A1", 4, nome="L01"), dev("B2", nome="L02")], "RETIRADO_SEM_SUBSTITUTO"),
    ([dev("A1", 4, nome=""), dev("B2", nome="")], "RETIRADO_SEM_SUBSTITUTO"),
    ([dev("A1", 4, nome="A1"), dev("B2", nome="A1")], "RETIRADO_SEM_SUBSTITUTO"),  # nome = serial
    ([dev("A1", 4), dev("B2", 2), dev("C3", nome="L09")], "RETIRADO_SEM_SUBSTITUTO"),  # substituto em manutencao
    ([dev("A1", 4), dev(esn_bloqueado("B2"), 4), dev("C3", nome="L09")], "RETIRADO_SEM_SUBSTITUTO"),
    ([dev("A1", 9), dev("B2")], "STATUS_DESCONHECIDO"),
])
def test_classificacao(devices, esperado):
    assert main._classificar_substituicao({"A1"}, devices)[0] == esperado


def test_classificacao_sem_serial():
    assert main._classificar_substituicao({None, " "}, [dev("B2")])[0] == "SEM_SERIAL"


def test_data_bloqueio():
    assert main._data_bloqueio_cadastro(esn_bloqueado("A1")) == BLOQUEIO
    assert main._data_bloqueio_cadastro("A1") is None
    assert main._data_bloqueio_cadastro("A1@abc") is None
    assert main._esn_base_cadastro(" A1@123 ") == "A1"


# ---------- servico ----------

def test_encerra_falha_de_inversor_retirado(svc):
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    estado = svc.estado_inversores[chave]
    assert not estado["ativa"] and estado["alerta"] is None and not estado["notificado"]
    assert chave not in svc.incidentes_inv_ativos
    assert len(svc.historico_incidentes) == 1
    item = svc.historico_incidentes[0]
    assert item["encerramento"] == "SUBSTITUICAO_CADASTRO"
    assert item["fim_ts"] == BLOQUEIO.isoformat()
    assert svc.teams == []                                  # D1: sem card no Teams


def test_modo_observacao_nao_altera_nada(svc, monkeypatch, caplog):
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", False)
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    with caplog.at_level("WARNING"):
        svc._verificar_substituicoes_inversor(AGORA)
    assert svc.estado_inversores[chave]["ativa"]
    assert chave in svc.incidentes_inv_ativos
    assert svc.historico_incidentes == []
    assert "[SUBSTITUICAO][OBSERVACAO] Encerraria falha de Usina 10 - Série A1" in caplog.text
    # Uma vez por usina por dia: nao repete o log no mesmo dia.
    caplog.clear()
    with caplog.at_level("WARNING"):
        svc._verificar_substituicoes_inversor(AGORA + timedelta(hours=1))
    assert "OBSERVACAO" not in caplog.text
    assert svc.api_inversor.consultas == ["10"]


def test_chave_geral_desligada_nao_consulta(svc, monkeypatch):
    monkeypatch.setattr(main, "SUBSTITUICAO_VERIFICAR", False)
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.api_inversor.consultas == []
    assert svc.estado_inversores[chave]["ativa"]


def test_api_sem_metodo_nao_faz_nada(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_FILE", tmp_path / "state.json")
    service = main.MonitorService(object())
    chave = falha(service, 10, "A1")
    service._verificar_substituicoes_inversor(AGORA)
    assert service.estado_inversores[chave]["ativa"]


def test_leitura_recente_nao_e_candidata(svc):
    chave = falha(svc, 10, "A1", ultima=AGORA - timedelta(hours=23))
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.api_inversor.consultas == []
    assert svc.estado_inversores[chave]["ativa"]


@pytest.mark.parametrize("cadastro", [
    None, [], [dev("A1", 4)], [dev("A1", 2), dev("B")], [dev("A1", 1)], [dev("OUTRO")],
])
def test_duvida_mantem_falha_aberta(svc, cadastro):
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = cadastro
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.estado_inversores[chave]["ativa"]
    assert chave in svc.incidentes_inv_ativos


def test_cadastro_indisponivel_tenta_de_novo_depois_de_uma_hora(svc):
    falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = None
    svc._verificar_substituicoes_inversor(AGORA)
    svc._verificar_substituicoes_inversor(AGORA + timedelta(minutes=30))
    assert svc.api_inversor.consultas == ["10"]
    svc._verificar_substituicoes_inversor(AGORA + timedelta(minutes=61))
    assert svc.api_inversor.consultas == ["10", "10"]


def test_limite_diario_de_encerramentos(svc):
    for i in range(5):
        falha(svc, 10 + i, f"S{i}")
        svc.api_inversor.cadastro[str(10 + i)] = [dev(f"S{i}", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    abertas = [c for c, e in svc.estado_inversores.items() if e["ativa"]]
    assert len(abertas) == 2
    assert len(svc.historico_incidentes) == 3
    svc._verificar_substituicoes_inversor(AGORA + timedelta(days=1))
    assert not any(e["ativa"] for e in svc.estado_inversores.values())
    assert len(svc.historico_incidentes) == 5


def test_maximo_de_usinas_por_varredura(svc, monkeypatch):
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", False)
    for i in range(7):
        falha(svc, 10 + i, f"S{i}")
        svc.api_inversor.cadastro[str(10 + i)] = [dev(f"S{i}", 1)]
    svc._verificar_substituicoes_inversor(AGORA)
    assert len(svc.api_inversor.consultas) == 5
    svc._verificar_substituicoes_inversor(AGORA + timedelta(minutes=15))
    assert len(svc.api_inversor.consultas) == 7


def test_usina_com_rele_ativo_fica_de_fora(svc):
    chave = falha(svc, 10, "A1")
    svc.usinas_alerta_rele_recente.add("10")
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.api_inversor.consultas == []
    assert svc.estado_inversores[chave]["ativa"]


def test_bloqueio_antes_do_inicio_usa_ultima_leitura(svc):
    ultima = datetime(2026, 10, 20, 10)
    falha(svc, 10, "A1", ultima=ultima, inicio=datetime(2026, 10, 10))
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1", datetime(2026, 9, 1)), 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.historico_incidentes[0]["fim_ts"] == ultima.isoformat()


def test_mesmo_serial_ativo_em_outra_usina_nao_interfere(svc):
    # ECO3 L33 bloqueado aqui; o mesmo equipamento ativo em outra usina (ECO4 L49).
    chave = falha(svc, 10, "A2003030248")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A2003030248"), 4), dev("A2003030288")]
    svc.api_inversor.cadastro["11"] = [dev("A2003030248", 1)]
    svc._verificar_substituicoes_inversor(AGORA)
    assert not svc.estado_inversores[chave]["ativa"]
    assert svc.api_inversor.consultas == ["10"]


def test_estado_encerrado_sobrevive_ao_reinicio(svc, tmp_path):
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    svc._save_state()
    novo = main.MonitorService(API())
    novo._load_state()
    assert not novo.estado_inversores[chave]["ativa"]
    assert chave not in novo.incidentes_inv_ativos
    assert novo.historico_incidentes[0]["encerramento"] == "SUBSTITUICAO_CADASTRO"


def test_heartbeat_deixa_de_listar_inversor_encerrado(svc, monkeypatch):
    falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev("A1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    monkeypatch.setattr(svc, "executar_varredura_rele", lambda: None)
    monkeypatch.setattr(svc, "executar_varredura_inversor", lambda: None)
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw) or True)
    svc._enviar_heartbeat(AGORA)
    assert "A1" not in payload["text"]
    assert "Falhas anteriores sem dados recentes: 0" in payload["text"]


def test_erro_na_verificacao_nao_derruba_varredura(svc, monkeypatch):
    def explode(agora):
        raise RuntimeError("boom")
    monkeypatch.setattr(svc, "_verificar_substituicoes_inversor", explode)
    salvos = []
    monkeypatch.setattr(svc, "_save_state", lambda: salvos.append(1))
    svc.executar_varredura_inversor()
    assert salvos


def test_varredura_chama_verificacao(svc, monkeypatch):
    chamadas = []
    monkeypatch.setattr(svc, "_verificar_substituicoes_inversor", lambda agora: chamadas.append(agora))
    svc.executar_varredura_inversor()
    assert len(chamadas) == 1


def test_get_plant_devices_formatos(monkeypatch):
    api = main.PVOperationAPI.__new__(main.PVOperationAPI)
    api.base_url = "http://x"

    class R:
        def __init__(self, status, corpo):
            self.status_code, self._corpo = status, corpo

        def json(self):
            if isinstance(self._corpo, Exception):
                raise self._corpo
            return self._corpo

    casos = [
        (R(200, [{"plant_devices": [dev("A1"), "x"]}]), [dev("A1")]),
        (R(200, {"plant_devices": [dev("A1")]}), [dev("A1")]),
        (R(200, {"plant_devices": None}), None),
        (R(200, []), None),
        (R(200, ValueError("nao json")), None),
        (R(500, {}), None),
        (None, None),
    ]
    for resp, esperado in casos:
        monkeypatch.setattr(api, "_request_with_retry", lambda *a, _r=resp, **k: (_r, False))
        assert api.get_plant_devices(10) == esperado


def test_excecao_na_consulta_vira_cadastro_indisponivel(svc):
    chave = falha(svc, 10, "A1")
    falha(svc, 11, "B1")
    svc.api_inversor.cadastro["10"] = RuntimeError("rede")
    svc.api_inversor.cadastro["11"] = [dev("B1", 4), dev("NOVO")]
    svc._verificar_substituicoes_inversor(AGORA)
    assert svc.estado_inversores[chave]["ativa"]
    assert not svc.estado_inversores["11:B1"]["ativa"]
    svc._verificar_substituicoes_inversor(AGORA + timedelta(minutes=15))
    assert svc.api_inversor.consultas == ["10", "11"]          # so tenta de novo depois de 1 h


# ---------- inversor enviado para reparo (sem substituto) ----------

def test_retirado_sem_substituto_mantem_falha_aberta(svc, caplog):
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4, nome="L04"), dev("OUTRO", nome="L05")]
    with caplog.at_level("WARNING"):
        svc._verificar_substituicoes_inversor(AGORA)
    assert svc.estado_inversores[chave]["ativa"]
    assert chave in svc.incidentes_inv_ativos
    assert svc.historico_incidentes == []
    assert "sem substituto" in caplog.text


def test_substituto_informado_no_log(svc, caplog):
    falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4, nome="L33"), dev("NOVO9", nome="L33")]
    with caplog.at_level("WARNING"):
        svc._verificar_substituicoes_inversor(AGORA)
    assert "substituto NOVO9" in caplog.text


# ---------- heartbeat das 07:00 ----------

def _heartbeat(svc, monkeypatch, quando):
    monkeypatch.setattr(svc, "executar_varredura_rele", lambda: None)
    monkeypatch.setattr(svc, "executar_varredura_inversor", lambda: None)
    payload = {}
    monkeypatch.setattr(main, "_teams_post_card", lambda **kw: payload.update(kw) or True)
    svc._enviar_heartbeat(quando)
    return payload["text"]


def test_heartbeat_0700_mostra_observacao(svc, monkeypatch):
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", False)
    falha(svc, 10, "A1")
    falha(svc, 11, "R1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4, nome="L33"), dev("NOVO9", nome="L33")]
    svc.api_inversor.cadastro["11"] = [dev(esn_bloqueado("R1"), 4, nome="L04"), dev("X", nome="L05")]
    svc._verificar_substituicoes_inversor(datetime(2026, 11, 6, 0, 10))
    texto = _heartbeat(svc, monkeypatch, datetime(2026, 11, 6, 7, 0))
    assert "Cadastro indica substituição (observação, nada foi encerrado): 1" in texto
    assert "Usina 10 — Série A1 → NOVO9 (bloqueio 02/11/2026) — seria encerrada" in texto
    assert "Retirados no cadastro sem substituto (falha mantida): 1" in texto
    assert "Usina 11 — Série R1" in texto
    # A falha continua contada como antes (observacao nao muda nada).
    assert "Falhas anteriores sem dados recentes: 2" in texto


def test_heartbeat_fora_das_0700_nao_mostra(svc, monkeypatch):
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", False)
    falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4), dev("NOVO9")]
    svc._verificar_substituicoes_inversor(datetime(2026, 11, 6, 0, 10))
    texto = _heartbeat(svc, monkeypatch, datetime(2026, 11, 6, 12, 0))
    assert "Cadastro" not in texto and "substitu" not in texto


def test_heartbeat_0700_mostra_encerradas(svc, monkeypatch):
    falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4), dev("NOVO9")]
    svc._verificar_substituicoes_inversor(datetime(2026, 11, 6, 0, 10))
    texto = _heartbeat(svc, monkeypatch, datetime(2026, 11, 6, 7, 0))
    assert "Encerradas por substituição no cadastro (últimas 24 h): 1" in texto
    assert "Série A1 → NOVO9" in texto
    # Some depois de 26 h (o heartbeat usa o relogio real como referencia).
    assert svc._linhas_heartbeat_substituicao(datetime(2026, 11, 7, 2, 9))
    assert svc._linhas_heartbeat_substituicao(datetime(2026, 11, 7, 2, 11)) == []


def test_heartbeat_0700_retira_item_que_se_recuperou(svc, monkeypatch):
    monkeypatch.setattr(main, "SUBSTITUICAO_ENCERRAR", False)
    chave = falha(svc, 10, "A1")
    svc.api_inversor.cadastro["10"] = [dev(esn_bloqueado("A1"), 4), dev("NOVO9")]
    svc._verificar_substituicoes_inversor(datetime(2026, 11, 6, 0, 10))
    svc.estado_inversores[chave]["ativa"] = False
    texto = _heartbeat(svc, monkeypatch, datetime(2026, 11, 6, 7, 0))
    assert "Cadastro indica" not in texto


def test_formatador_sem_linhas_de_cadastro_igual_ao_anterior():
    base = dict(rele_atrasado=False, inv_atrasado=False, ultima_rele=None, ultima_inv=None,
                ativos_rele=0, ativos_inv=0, rele_usinas=[], inv_usina_counts={},
                previsto=datetime(2026, 11, 6, 7))
    assert main._formatar_texto_heartbeat(**base) == main._formatar_texto_heartbeat(**base, cadastro_linhas=[])
