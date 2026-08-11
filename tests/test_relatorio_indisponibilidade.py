# -*- coding: utf-8 -*-
"""Regressao do calculo de indisponibilidade do relatorio semanal.

Casos A-G do incidente da semana 27/07/2026-02/08/2026:
- clipping semanal preservado (parcela da semana != duracao integral);
- fim_ts de rele gravado com o timestamp da leitura que comprovou a
  normalizacao (nao o datetime.now() da varredura);
- nenhuma linha pode ganhar +1s por microsegundos herdados de fim_ts
  legados gravados com datetime.now().
"""
import sys
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import main


class FakeAPI:
    def get_plants(self):
        return []

    def post_day(self, endpoint, plant_id, date):
        return [], False


class FakeDayRelayAPI:
    def __init__(self, payload):
        self._payload = payload

    def get_plants(self):
        return []

    def post_day(self, endpoint, plant_id, date):
        return list(self._payload), False


SEMANA_INI = datetime(2026, 7, 27, 0, 0, 0)
SEMANA_FIM = datetime(2026, 8, 3, 0, 0, 0)

# Indices das colunas na aba Ocorrencias
COL_INICIO = 4
COL_FIM = 5
COL_PERIODO = 6
COL_DUR = 7
COL_SOLAR = 8

# Indices das colunas na aba Resumo
RES_QTD = 4
RES_DUR = 5
RES_SOLAR = 6


def _svc():
    return main.MonitorService(FakeAPI(), FakeAPI())


def _occ(usina, natureza, tipo, equip, inicio_ts, fim_ts, usina_id="1"):
    return {
        "chave": f"{usina_id}:{equip}",
        "natureza": natureza,
        "tipo_falha": tipo,
        "usina_id": usina_id,
        "usina": usina,
        "equipamento": equip,
        "inicio_ts": inicio_ts,
        "fim_ts": fim_ts,
    }


def _montar(historico):
    return _svc()._montar_relatorio_semanal(SEMANA_INI, SEMANA_FIM, historico, {}, {})


# ---------------------------------------------------------------------------
# Caso A - rele comeca antes da semana e normaliza dentro dela
# ---------------------------------------------------------------------------

def test_caso_a_rele_atravessa_inicio_da_semana():
    inicio = datetime(2026, 7, 25, 16, 58, 26)
    fim = datetime(2026, 7, 27, 7, 40, 57)

    # metricas do incidente integral (nao aparecem na planilha, mas nao podem
    # ganhar segundo artificial)
    assert main._formatar_duracao((fim - inicio).total_seconds()) == "38:42:31"
    assert main._formatar_duracao(
        main._calcular_sobreposicao_janela_solar(inicio, fim)
    ) == "13:42:31"

    _, occ_rows, _ = _montar([
        _occ("SETGE7.SCT.4130.LT03", "RELE", "SOBRETENSÃO", "2140",
             "2026-07-25T16:58:26", "2026-07-27T07:40:57")
    ])
    row = occ_rows[1]
    assert row[COL_INICIO] == "25/07/2026 16:58:26"
    assert row[COL_FIM] == "27/07/2026 07:40:57"
    assert row[COL_PERIODO] == "27/07/2026 00:00:00 ate 27/07/2026 07:40:57"
    assert row[COL_DUR] == "07:40:57"
    assert row[COL_SOLAR] == "01:40:57"


# ---------------------------------------------------------------------------
# Caso B - inversor fechado atravessando o inicio da semana
# ---------------------------------------------------------------------------

def test_caso_b_inversor_atravessa_inicio_da_semana():
    inicio = datetime(2026, 7, 23, 6, 50, 0)
    fim = datetime(2026, 7, 28, 12, 2, 22)

    assert main._formatar_duracao((fim - inicio).total_seconds()) == "125:12:22"
    assert main._formatar_duracao(
        main._calcular_sobreposicao_janela_solar(
            inicio, fim,
            janela_inicio=main.INVERTER_SOLAR_WINDOW_START,
            janela_fim=main.INVERTER_SOLAR_WINDOW_END,
        )
    ) == "57:42:22"

    _, occ_rows, _ = _montar([
        _occ("SETGE6.GRA.2750.LT01", "INVERSOR", main.INVERTER_FAILURE_LABEL,
             "118212237260027", "2026-07-23T06:50:00", "2026-07-28T12:02:22")
    ])
    row = occ_rows[1]
    assert row[COL_PERIODO] == "27/07/2026 00:00:00 ate 28/07/2026 12:02:22"
    assert row[COL_DUR] == "36:02:22"
    assert row[COL_SOLAR] == "16:02:22"


# ---------------------------------------------------------------------------
# Caso C - incidente inteiramente dentro da semana (deve permanecer igual)
# ---------------------------------------------------------------------------

def test_caso_c_incidente_inteiro_dentro_da_semana():
    _, occ_rows, _ = _montar([
        _occ("ECB.SER.1900.8 L15", "INVERSOR", main.INVERTER_FAILURE_LABEL,
             "114212225220103", "2026-07-29T14:26:50", "2026-07-30T11:52:08")
    ])
    row = occ_rows[1]
    assert row[COL_PERIODO] == "29/07/2026 14:26:50 ate 30/07/2026 11:52:08"
    assert row[COL_DUR] == "21:25:18"
    assert row[COL_SOLAR] == "07:55:18"


# ---------------------------------------------------------------------------
# Caso D - ocorrencia aberta antes da semana fica limitada a semana
# ---------------------------------------------------------------------------

def test_caso_d_aberto_antes_da_semana_limita_ao_periodo():
    resumo_rows, occ_rows, _ = _montar([
        _occ("ECO3.INA.2500.17 L33", "INVERSOR", main.INVERTER_FAILURE_LABEL,
             "A2003030248", "2026-06-04T10:40:00", None)
    ])
    row = occ_rows[1]
    assert row[COL_FIM] == "EM ABERTO"
    assert row[COL_PERIODO] == "27/07/2026 00:00:00 ate 03/08/2026 00:00:00"
    assert row[COL_DUR] == "168:00:00"          # exatamente a semana, nunca mais
    assert row[COL_SOLAR] == "73:30:00"         # 7 dias x 10h30 (06:30-17:00)
    assert resumo_rows[1][RES_QTD] == 1
    assert resumo_rows[1][RES_DUR] == "168:00:00"
    assert resumo_rows[1][RES_SOLAR] == "73:30:00"


# ---------------------------------------------------------------------------
# Caso E - ocorrencia fora da janela solar
# ---------------------------------------------------------------------------

def test_caso_e_rele_noturno_janela_solar_zero():
    _, occ_rows, _ = _montar([
        _occ("SETGE7.BON.6880.LT05", "RELE", "SOBRETENSÃO", "2406",
             "2026-08-02T20:06:01", None)
    ])
    row = occ_rows[1]
    assert row[COL_PERIODO] == "02/08/2026 20:06:01 ate 03/08/2026 00:00:00"
    assert row[COL_DUR] == "03:53:59"
    assert row[COL_SOLAR] == "00:00:00"


# ---------------------------------------------------------------------------
# Caso F - Ibimirim usa janela 07:30-17:00
# ---------------------------------------------------------------------------

def test_caso_f_ibimirim_janela_0730_1700():
    _, occ_rows, _ = _montar([
        _occ("COMP.IBI.2500.LT01", "INVERSOR", main.INVERTER_FAILURE_LABEL,
             "A2320855290", "2026-07-30T07:00:00", "2026-07-30T08:00:00")
    ])
    row = occ_rows[1]
    assert row[COL_DUR] == "01:00:00"
    assert row[COL_SOLAR] == "00:30:00"


# ---------------------------------------------------------------------------
# Caso G (relatorio) - fim_ts legado com microsegundos nao gera +1s
# ---------------------------------------------------------------------------

def test_caso_g_fim_ts_com_microsegundos_nao_diverge_do_timestamp_impresso():
    # Reproducao da linha 8 do relatorio 20260727-20260802: fim_ts gravado
    # pela varredura com datetime.now() (fracao >= 0.5s). A duracao impressa
    # nao pode divergir dos timestamps impressos.
    _, occ_rows, _ = _montar([
        _occ("SETGE7.SCT.4130.LT03", "RELE", "SOBRETENSÃO", "2140",
             "2026-07-25T16:58:26", "2026-07-27T07:40:57.600000")
    ])
    row = occ_rows[1]
    assert row[COL_FIM] == "27/07/2026 07:40:57"
    assert row[COL_PERIODO] == "27/07/2026 00:00:00 ate 27/07/2026 07:40:57"
    assert row[COL_DUR] == "07:40:57"      # bug reproduzia "07:40:58"
    assert row[COL_SOLAR] == "01:40:57"    # bug reproduzia "01:40:58"


def test_caso_g_inicio_com_microsegundos_tambem_normalizado():
    # Simetria: inicio_ts com fracao tambem nao pode desalinhar a duracao.
    _, occ_rows, _ = _montar([
        _occ("Usina X", "INVERSOR", main.INVERTER_FAILURE_LABEL, "INV1",
             "2026-07-29T10:00:00.900000", "2026-07-29T11:00:00")
    ])
    row = occ_rows[1]
    assert row[COL_INICIO] == "29/07/2026 10:00:00"
    assert row[COL_DUR] == "01:00:00"


# ---------------------------------------------------------------------------
# Caso G (origem) - normalizacao de rele grava fim_ts da leitura, nao da varredura
# ---------------------------------------------------------------------------

def test_normalizacao_rele_usa_timestamp_da_leitura_nao_da_varredura():
    svc = _svc()
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27a")
    svc.rele_alertas_ativos.add(base)
    svc.rele_notificados.add(base)
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": "OUTROS",
        "horario": "27/07/2026 06:58:26",
        "ts_iso": "2026-07-27T06:58:26",
        "parametros": "r27A",
    }
    svc.incidentes_rele_ativos[base] = svc._novo_incidente(
        base_key=base,
        natureza="RELE",
        tipo_falha="OUTROS",
        usina_id="1",
        usina="Usina 1",
        equipamento="R01",
        inicio_ts=datetime(2026, 7, 27, 6, 58, 26),
    )

    ts_leitura_normal = datetime(2026, 7, 27, 7, 40, 57)
    agora_varredura = datetime(2026, 7, 27, 7, 45, 12, 600000)

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=agora_varredura,
        reles_normais_por_usina={("1", "r01"): ts_leitura_normal},
    )

    assert resolvidos["1"]["itens"][0]["base"] == base
    assert base not in svc.rele_alertas_ativos
    assert len(svc.historico_incidentes) == 1
    incidente = svc.historico_incidentes[-1]
    # bug: gravava agora_varredura (07:45:12.600000) em vez da leitura
    assert incidente["fim_ts"] == "2026-07-27T07:40:57"
    assert "." not in incidente["fim_ts"]


def test_normalizacao_rele_sem_leitura_limpa_continua_preservando_alerta():
    svc = _svc()
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27a")
    svc.rele_alertas_ativos.add(base)
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "ts_iso": "2026-07-27T06:58:26",
    }

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=datetime(2026, 7, 27, 7, 45, 12),
        reles_normais_por_usina={},
    )

    assert resolvidos == {}
    assert base in svc.rele_alertas_ativos
    assert svc.historico_incidentes == []


# ---------------------------------------------------------------------------
# Caso H - multiplas leituras normais na mesma varredura: fecha na PRIMEIRA
# evidencia de normalizacao posterior ao alerta, nao na ultima processada
# ---------------------------------------------------------------------------

def _svc_com_alerta_rele_ativo(api_rele, ts_iso_alerta, inicio_incidente, tipo="OUTROS", parametros="r27a"):
    svc = main.MonitorService(api_rele, FakeAPI())
    base = main._chave_evento_rele("1", "R01", tipo, parametros)
    svc.rele_alertas_ativos.add(base)
    svc.rele_notificados.add(base)
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "capacidade": 100,
        "rele": "R01",
        "tipo": tipo,
        "horario": main.MonitorService._fmt_ts(inicio_incidente),
        "ts_iso": ts_iso_alerta,
        "parametros": parametros,
    }
    svc.incidentes_rele_ativos[base] = svc._novo_incidente(
        base_key=base,
        natureza="RELE",
        tipo_falha=tipo,
        usina_id="1",
        usina="Usina 1",
        equipamento="R01",
        inicio_ts=inicio_incidente,
    )
    return svc, base


def test_caso_h_detectar_alertas_rele_expoe_leituras_normais_ordenadas():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:42:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:40:57"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:46:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:44:00"}},
    ]
    api = FakeDayRelayAPI(payload)

    alertas, tem_dados, teve_timeout, _, normais = main.detectar_alertas_rele(
        api, "1", datetime(2026, 7, 27, 7, 35, 0), datetime(2026, 7, 27, 7, 50, 0)
    )

    assert alertas == []
    assert tem_dados is True
    assert teve_timeout is False
    # todas as leituras limpas, em ordem cronologica: a ultima serve a
    # supressao de candidatos; a primeira posterior ao alerta, ao fechamento.
    assert normais == {
        ("1", "r01"): [
            datetime(2026, 7, 27, 7, 40, 57),
            datetime(2026, 7, 27, 7, 42, 0),
            datetime(2026, 7, 27, 7, 44, 0),
            datetime(2026, 7, 27, 7, 46, 0),
        ]
    }


def test_caso_h_fecha_na_primeira_leitura_normal_posterior_ao_alerta():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:40:57"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:42:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:44:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:46:00"}},
    ]
    svc, base = _svc_com_alerta_rele_ativo(
        FakeDayRelayAPI(payload),
        ts_iso_alerta="2026-07-27T07:30:00",
        inicio_incidente=datetime(2026, 7, 27, 7, 30, 0),
    )
    agora = datetime(2026, 7, 27, 7, 50, 0)

    alertas, preservar_ativos, _, normais = svc._coletar_alertas_rele_usina(
        usina_id="1",
        nome="Usina 1",
        inicio_padrao=datetime(2026, 7, 27, 7, 35, 0),
        agora=agora,
    )
    assert alertas == []
    assert preservar_ativos is False

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=agora,
        reles_normais_por_usina=dict(normais),
    )

    assert resolvidos["1"]["itens"][0]["base"] == base
    assert len(svc.historico_incidentes) == 1
    # primeira evidencia real de normalizacao, nao a ultima leitura da janela
    assert svc.historico_incidentes[-1]["fim_ts"] == "2026-07-27T07:40:57"


# ---------------------------------------------------------------------------
# Caso I - divergencia API x state no merge: max(fim_real) prevalece
# (comportamento documentado; a correcao elimina a divergencia na origem)
# ---------------------------------------------------------------------------

def test_caso_i_merge_api_state_divergentes_max_prevalece():
    svc = _svc()
    api_inc = _occ("Usina 1", "RELE", "SOBRETENSÃO", "R01",
                   "2026-07-27T07:30:00", "2026-07-27T07:40:57")
    state_inc = _occ("Usina 1", "RELE", "SOBRETENSÃO", "R01",
                     "2026-07-27T07:30:00", "2026-07-27T07:46:00")

    merged = svc._mesclar_incidentes_relatorio([api_inc, state_inc], SEMANA_FIM)

    assert len(merged) == 1
    # Regra atual e mantida: uniao dos intervalos sobrepostos (max protege
    # contra subnotificacao quando o state fecha cedo demais em flapping).
    # Com o fechamento na primeira leitura normal, state e API passam a
    # emitir o mesmo fim e o max torna-se neutro para incidentes novos.
    assert merged[0]["fim_ts"] == "2026-07-27T07:46:00"


# ---------------------------------------------------------------------------
# Caso J - state legado fechado no horario da varredura (com microsegundos)
# ---------------------------------------------------------------------------

def test_caso_j_state_legado_atrasado_prevalece_mas_sem_segundo_artificial():
    svc = _svc()
    api_inc = _occ("Usina 1", "RELE", "SOBRETENSÃO", "R01",
                   "2026-07-27T07:30:00", "2026-07-27T07:40:57")
    state_inc = _occ("Usina 1", "RELE", "SOBRETENSÃO", "R01",
                     "2026-07-27T07:30:00", "2026-07-27T07:45:12.600000")

    merged = svc._mesclar_incidentes_relatorio([api_inc, state_inc], SEMANA_FIM)
    assert len(merged) == 1
    # Limitacao transitoria documentada: para incidentes LEGADOS ja gravados
    # com o horario da varredura, o merge ainda escolhe o fim mais tardio
    # (superestimacao de ate ~1 intervalo de varredura). Sem migracao de
    # state (proibida), isso se esgota naturalmente apos o deploy.
    assert merged[0]["fim_ts"] == "2026-07-27T07:45:12.600000"

    _, occ_rows, _ = svc._montar_relatorio_semanal(SEMANA_INI, SEMANA_FIM, merged, {}, {})
    row = occ_rows[1]
    # A planilha permanece internamente consistente (sem +1s fantasma).
    assert row[COL_FIM] == "27/07/2026 07:45:12"
    assert row[COL_PERIODO] == "27/07/2026 07:30:00 ate 27/07/2026 07:45:12"
    assert row[COL_DUR] == "00:15:12"
    assert row[COL_SOLAR] == "00:15:12"


# ---------------------------------------------------------------------------
# Caso K - mudanca de identidade (SOBRETENSÃO -> normal -> SUBTENSÃO)
# nao une, nao suprime e nao corrompe incidentes distintos
# ---------------------------------------------------------------------------

def test_caso_k_mudanca_de_identidade_mantem_incidentes_distintos():
    payload = [
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:30:00", "r59A": 1}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:40:00"}},
        {"idrele": "R01", "conteudojson": {"tsleitura": "2026-07-27 07:45:00", "r27A": 1}},
    ]
    svc, base_sobre = _svc_com_alerta_rele_ativo(
        FakeDayRelayAPI(payload),
        ts_iso_alerta="2026-07-27T07:25:00",
        inicio_incidente=datetime(2026, 7, 27, 7, 25, 0),
        tipo="SOBRETENSÃO",
        parametros="r59a",
    )
    agora = datetime(2026, 7, 27, 7, 50, 0)

    alertas, preservar_ativos, _, normais = svc._coletar_alertas_rele_usina(
        usina_id="1",
        nome="Usina 1",
        inicio_padrao=datetime(2026, 7, 27, 7, 25, 1),
        agora=agora,
    )
    assert preservar_ativos is False
    # SOBRETENSÃO foi suprimida pela leitura limpa posterior; so SUBTENSÃO segue
    assert [a["tipo_alerta"] for a in alertas] == ["SUBTENSÃO"]

    bases_ativos = set()
    for a in alertas:
        svc._registrar_alerta_rele_detectado(
            alerta_raw=a,
            usina_id="1",
            nome="Usina 1",
            capacidade=100,
            pend_norm={},
            bases_ativos_atual=bases_ativos,
            novos_por_usina={},
            agora=agora,
        )

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=bases_ativos,
        agora=agora,
        reles_normais_por_usina=dict(normais),
    )

    # incidente de SOBRETENSÃO fechado na leitura limpa entre os dois alarmes
    assert resolvidos["1"]["itens"][0]["base"] == base_sobre
    assert len(svc.historico_incidentes) == 1
    fechado = svc.historico_incidentes[-1]
    assert fechado["tipo_falha"] == "SOBRETENSÃO"
    assert fechado["fim_ts"] == "2026-07-27T07:40:00"

    # incidente de SUBTENSÃO permanece aberto e distinto
    base_sub = main._chave_evento_rele("1", "R01", "SUBTENSÃO", "r27a")
    assert base_sub in svc.rele_alertas_ativos
    assert svc.incidentes_rele_ativos[base_sub]["inicio_ts"] == "2026-07-27T07:45:00"


def test_normalizacao_rele_leitura_anterior_ao_alerta_nao_fecha():
    svc = _svc()
    base = main._chave_evento_rele("1", "R01", "OUTROS", "r27a")
    svc.rele_alertas_ativos.add(base)
    svc.rele_alerta_chave[base] = {
        "base": base,
        "usina": "Usina 1",
        "ts_iso": "2026-07-27T06:58:26",
    }

    resolvidos = svc._registrar_resolucoes_rele(
        bases_ativos_atual=set(),
        agora=datetime(2026, 7, 27, 7, 45, 12),
        reles_normais_por_usina={("1", "r01"): datetime(2026, 7, 27, 6, 0, 0)},
    )

    assert resolvidos == {}
    assert base in svc.rele_alertas_ativos
    assert svc.historico_incidentes == []
