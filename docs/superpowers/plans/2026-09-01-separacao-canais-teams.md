# Separação dos canais Teams (RELÉS / INVERSORES / HEARTBEAT) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rotear as notificações de relé e de inversor para webhooks Teams dedicados, mantendo heartbeat e erros de sistema no webhook geral, sem alterar nenhuma lógica de detecção.

**Architecture:** Uma única função de envio (`_teams_post_card`) ganha um parâmetro opcional `webhook_url`. Duas constantes de ambiente novas (`TEAMS_WEBHOOK_URL_RELE`, `TEAMS_WEBHOOK_URL_INVERSOR`) são resolvidas no import com fallback para `TEAMS_WEBHOOK_URL`. Só os 4 call-sites de relé/inversor passam a nova URL; heartbeat e erros de sistema continuam no default. Mudança puramente aditiva — os testes existentes que mockam `_teams_post_card` não quebram.

**Tech Stack:** Python 3.12, `requests`, `pytest`, `python-dotenv`.

**Spec:** `docs/superpowers/specs/2026-09-01-separacao-canais-teams-design.md`

---

## Estrutura de arquivos

| Arquivo | Ação | Responsabilidade |
|---|---|---|
| `main.py` | Modificar | Constantes de canal (~linha 47); parâmetro `webhook_url` em `_teams_post_card` (~linha 285); roteamento em `_notificar_rele_agrupado` (~linha 3504/3531), `_notificar_inversor` (~linha 3561), `_notificar_inversor_recuperado` (~linha 3576). |
| `tests/test_canais_teams.py` | Criar | Testes de roteamento e fallback dos 3 canais. |
| `.env.example` | Modificar | Documentar as 2 variáveis opcionais novas. |
| `README.md` | Modificar | Tabela de variáveis opcionais + subseção de roteamento por canal. |

Nenhum outro arquivo é tocado. `monitor_daemon.py` está **fora de escopo**.

---

## Contexto de código (ler antes de começar)

`_teams_post_card` hoje (`main.py:285`):

```python
def _teams_post_card(
    title: str,
    text: str,
    severity: SeverityLevel = "info",
    facts: list[tuple[str, str]] | None = None,
    max_tentativas: int = 3,
) -> bool:
    """Envia um 'MessageCard' para um Incoming Webhook do Microsoft Teams."""
    if not TEAMS_ENABLED:
        return False

    colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
    payload = {
        ...
    }
    ...
    for tentativa in range(1, max_tentativas + 1):
        try:
            r = _teams_session.post(
                TEAMS_WEBHOOK_URL,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
```

Bloco de constantes hoje (`main.py:47`):

```python
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)
```

`_notificar_rele_agrupado` chama `_teams_post_card(**card)` em dois pontos (`main.py:3504` falha, `main.py:3531` normalização). `_notificar_inversor` (`main.py:3561`) e `_notificar_inversor_recuperado` (`main.py:3576`) chamam `_teams_post_card(title=..., text=..., severity=..., facts=...)`.

`_notificar_rele_agrupado` e `_notificar_inversor` **não usam `self`** além de chamar staticmethods — nos testes dá para instanciar com `main.MonitorService.__new__(main.MonitorService)`.

---

## Task 1: Constantes de canal + parâmetro `webhook_url` em `_teams_post_card`

**Files:**
- Create: `tests/test_canais_teams.py`
- Modify: `main.py` (bloco de constantes ~linha 47; `_teams_post_card` ~linha 285-322)

- [ ] **Step 1: Criar o arquivo de teste com T1 e T2 (falhando)**

Criar `tests/test_canais_teams.py` com este conteúdo exato:

```python
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
```

- [ ] **Step 2: Rodar os testes e ver falhar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v`
Expected: `test_teams_post_card_usa_webhook_url_explicito` FALHA com `TypeError: _teams_post_card() got an unexpected keyword argument 'webhook_url'`.

- [ ] **Step 3: Adicionar as constantes de canal**

Em `main.py`, localizar:

```python
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)
```

Substituir por:

```python
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
# Canais dedicados. Se a variável específica não estiver no ambiente/.env,
# cai para TEAMS_WEBHOOK_URL — permite implantação incremental sem perder alerta.
TEAMS_WEBHOOK_URL_RELE = os.environ.get("TEAMS_WEBHOOK_URL_RELE", "").strip() or TEAMS_WEBHOOK_URL
TEAMS_WEBHOOK_URL_INVERSOR = os.environ.get("TEAMS_WEBHOOK_URL_INVERSOR", "").strip() or TEAMS_WEBHOOK_URL
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)
```

- [ ] **Step 4: Adicionar o parâmetro `webhook_url` na assinatura**

Em `main.py`, localizar a assinatura de `_teams_post_card`:

```python
def _teams_post_card(
    title: str,
    text: str,
    severity: SeverityLevel = "info",
    facts: list[tuple[str, str]] | None = None,
    max_tentativas: int = 3,
) -> bool:
```

Substituir por:

```python
def _teams_post_card(
    title: str,
    text: str,
    severity: SeverityLevel = "info",
    facts: list[tuple[str, str]] | None = None,
    max_tentativas: int = 3,
    webhook_url: str | None = None,
) -> bool:
```

- [ ] **Step 5: Resolver a URL dentro da função**

Em `main.py`, dentro de `_teams_post_card`, localizar:

```python
    if not TEAMS_ENABLED:
        return False

    colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
```

Substituir por:

```python
    if not TEAMS_ENABLED:
        return False

    # webhook_url explícito tem prioridade; senão usa o canal geral.
    url = webhook_url or TEAMS_WEBHOOK_URL

    colors = {"info": "0078D4", "warning": "FFA000", "danger": "D13438"}
```

- [ ] **Step 6: Usar `url` no POST**

Em `main.py`, dentro do loop de tentativas de `_teams_post_card`, localizar:

```python
            r = _teams_session.post(
                TEAMS_WEBHOOK_URL,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
```

Substituir por:

```python
            r = _teams_session.post(
                url,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
```

- [ ] **Step 7: Rodar os testes e ver passar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v`
Expected: 2 passed.

- [ ] **Step 8: Rodar a suíte completa (regressão)**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest -q`
Expected: mesma contagem de `passed` de antes da mudança, 0 `failed`. (Se algum teste que mocka `_teams_session.post` reclamar de assinatura, revisar — mas o mock aceita `*args, **kwargs`.)

- [ ] **Step 9: Commit**

```bash
cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM
git add main.py tests/test_canais_teams.py
git commit -m "feat: parametro webhook_url em _teams_post_card + constantes de canal

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Roteamento das notificações de relé

**Files:**
- Modify: `main.py` (`_notificar_rele_agrupado`, ~linha 3504 e ~linha 3531)
- Modify: `tests/test_canais_teams.py` (adicionar T3 e T5)

- [ ] **Step 1: Adicionar T3 e T5 ao arquivo de teste (falhando)**

Em `tests/test_canais_teams.py`, acrescentar ao final:

```python
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
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v -k rele`
Expected: `test_rele_roteia_para_canal_rele` FALHA — `urls_capturadas` contém `["https://geral", "https://geral"]` em vez de `["https://canal-rele", "https://canal-rele"]`.

- [ ] **Step 3: Rotear o envio de falha de relé**

Em `main.py`, dentro de `_notificar_rele_agrupado`, localizar:

```python
                try:
                    # Mesma politica de retry do inversor (default 3 tentativas).
                    ok_novos = _teams_post_card(**card)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele falha)")
                    ok_novos = False
```

Substituir por:

```python
                try:
                    # Mesma politica de retry do inversor (default 3 tentativas).
                    ok_novos = _teams_post_card(**card, webhook_url=TEAMS_WEBHOOK_URL_RELE)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele falha)")
                    ok_novos = False
```

- [ ] **Step 4: Rotear o envio de normalização de relé**

Em `main.py`, dentro de `_notificar_rele_agrupado`, localizar:

```python
                try:
                    ok_norm = _teams_post_card(**card)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele normalizacao)")
                    ok_norm = False
```

Substituir por:

```python
                try:
                    ok_norm = _teams_post_card(**card, webhook_url=TEAMS_WEBHOOK_URL_RELE)
                except Exception:
                    logger_rele.exception("Falha ao notificar Teams (rele normalizacao)")
                    ok_norm = False
```

- [ ] **Step 5: Rodar os testes de relé e ver passar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v -k rele`
Expected: 2 passed.

- [ ] **Step 6: Rodar a suíte completa**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest -q`
Expected: 0 failed.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM
git add main.py tests/test_canais_teams.py
git commit -m "feat: rotear alertas de rele para TEAMS_WEBHOOK_URL_RELE

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Roteamento das notificações de inversor

**Files:**
- Modify: `main.py` (`_notificar_inversor` ~linha 3561; `_notificar_inversor_recuperado` ~linha 3576)
- Modify: `tests/test_canais_teams.py` (adicionar T4)

- [ ] **Step 1: Adicionar T4 ao arquivo de teste (falhando)**

Em `tests/test_canais_teams.py`, acrescentar ao final:

```python
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
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v -k inversor`
Expected: ambos FALHAM — `urls_capturadas == ["https://geral"]`.

- [ ] **Step 3: Rotear `_notificar_inversor`**

Em `main.py`, localizar (dentro de `_notificar_inversor`):

```python
        try:
            return _teams_post_card(
                title=f"⚠️ Falha de Inversor (Pac=0; {INVERTER_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="danger",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (inversor)")
            return False
```

Substituir por:

```python
        try:
            return _teams_post_card(
                title=f"⚠️ Falha de Inversor (Pac=0; {INVERTER_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="danger",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
                webhook_url=TEAMS_WEBHOOK_URL_INVERSOR,
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (inversor)")
            return False
```

- [ ] **Step 4: Rotear `_notificar_inversor_recuperado`**

Em `main.py`, localizar (dentro de `_notificar_inversor_recuperado`):

```python
        try:
            return _teams_post_card(
                title=f"✔️ Normalização de Inversor (Pac normalizado; {INVERTER_RECOVERY_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="info",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (recuperacao inversor)")
            return False
```

Substituir por:

```python
        try:
            return _teams_post_card(
                title=f"✔️ Normalização de Inversor (Pac normalizado; {INVERTER_RECOVERY_CONSECUTIVE_READINGS} leituras; {janela_label})",
                text=_formatar_corpo_card_inversor(alerta, detalhes_txt),
                severity="info",
                facts=[("Capacidade", f"{alerta['capacidade']} kWp")],
                webhook_url=TEAMS_WEBHOOK_URL_INVERSOR,
            )
        except Exception:
            logger_inv.exception("Falha ao notificar Teams (recuperacao inversor)")
            return False
```

- [ ] **Step 5: Rodar os testes de inversor e ver passar**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v -k inversor`
Expected: 2 passed.

- [ ] **Step 6: Rodar a suíte completa de canais**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_canais_teams.py -v`
Expected: 6 passed (T1, T2, T3, T5, T4-falha, T4-recuperado).

- [ ] **Step 7: Commit**

```bash
cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM
git add main.py tests/test_canais_teams.py
git commit -m "feat: rotear alertas de inversor para TEAMS_WEBHOOK_URL_INVERSOR

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Documentação (`.env.example` + `README.md`)

**Files:**
- Modify: `.env.example`
- Modify: `README.md` (linha ~113; tabela de opcionais ~linha 117-121; seção "Notificações Teams" ~linha 771)

- [ ] **Step 1: Atualizar `.env.example`**

Localizar:

```
TEAMS_WEBHOOK_URL=https://seu-webhook.office.com/...

# Opcional: bundle CA customizado, se exigido pela infraestrutura.
```

Substituir por:

```
TEAMS_WEBHOOK_URL=https://seu-webhook.office.com/...

# Opcional: canais dedicados. Se vazios, os alertas caem no TEAMS_WEBHOOK_URL acima.
# TEAMS_WEBHOOK_URL_RELE=https://webhook-do-canal-reles/...
# TEAMS_WEBHOOK_URL_INVERSOR=https://webhook-do-canal-inversores/...

# Opcional: bundle CA customizado, se exigido pela infraestrutura.
```

- [ ] **Step 2: Atualizar a descrição de `TEAMS_WEBHOOK_URL` no README**

Em `README.md`, localizar:

```
| `TEAMS_WEBHOOK_URL` | Incoming Webhook do Teams. |
```

Substituir por:

```
| `TEAMS_WEBHOOK_URL` | Incoming Webhook do Teams (canal geral: heartbeat + erros de sistema). É também o fallback dos canais dedicados. |
```

- [ ] **Step 3: Acrescentar as variáveis opcionais no README**

Em `README.md`, localizar a linha da variável `RELE_DEBUG` na tabela de "Variáveis opcionais" (começa com `` | `RELE_DEBUG` | Quando `1` ``). Logo **acima** dessa linha, inserir duas linhas novas:

```
| `TEAMS_WEBHOOK_URL_RELE` | Webhook do canal dedicado a alertas de relé. Se ausente, usa `TEAMS_WEBHOOK_URL`. |
| `TEAMS_WEBHOOK_URL_INVERSOR` | Webhook do canal dedicado a alertas de inversor. Se ausente, usa `TEAMS_WEBHOOK_URL`. |
```

- [ ] **Step 4: Adicionar subseção de roteamento na seção "Notificações Teams"**

Em `README.md`, localizar (final da tabela de severidades, antes de "### Política de retry"):

```
| `danger` | `D13438` |

### Política de retry
```

Substituir por:

```
| `danger` | `D13438` |

### Roteamento por canal

Cada envio vai para um webhook conforme a natureza do alerta:

| Origem | Variável | Canal Teams |
|---|---|---|
| Falha / normalização de relé | `TEAMS_WEBHOOK_URL_RELE` | `RELÉS` |
| Falha / normalização de inversor | `TEAMS_WEBHOOK_URL_INVERSOR` | `INVERSORES` |
| Heartbeat, falha ao salvar estado, falha no relatório semanal | `TEAMS_WEBHOOK_URL` | `HEARTBEAT` (canal geral) |

`_teams_post_card()` aceita `webhook_url`. Quando não recebe, usa `TEAMS_WEBHOOK_URL`. As duas variáveis dedicadas são resolvidas no import: se não estiverem no ambiente, viram cópia de `TEAMS_WEBHOOK_URL` — nada é perdido durante uma implantação incremental.

### Política de retry
```

- [ ] **Step 5: Verificar que a doc não quebrou nenhum teste de doc**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest tests/test_main.py -q -k "env_example or webhook or config"`
Expected: 0 failed. (Testes checam que `.env.example` contém `TEAMS_WEBHOOK_URL=` e que não há URL real `webhook.office.com/webhookb2` — as linhas novas são comentadas e usam placeholders, então passam.)

- [ ] **Step 6: Commit**

```bash
cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM
git add .env.example README.md
git commit -m "docs: documentar canais Teams dedicados (rele/inversor) e fallback

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Verificação final e fechamento

**Files:** nenhum (só verificação)

- [ ] **Step 1: Compilar `main.py`**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m py_compile main.py && echo OK`
Expected: `OK`

- [ ] **Step 2: Rodar a suíte completa**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && python -m pytest -q`
Expected: todos `passed`, 0 `failed`. Anotar a contagem final.

- [ ] **Step 3: Conferir os call-sites que NÃO devem ter mudado**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && git grep -n "_teams_post_card(" main.py`
Expected: 8 ocorrências (1 definição + 7 chamadas). As chamadas em `_save_state` (falha ao salvar estado), `_gerar_relatorio_semanal*` (2x) e `_enviar_heartbeat` **não** têm `webhook_url=`. Só as 4 de relé/inversor têm.

- [ ] **Step 4: Diff de revisão**

Run: `cd /c/Users/ARTHUR/Desktop/monitor/MonitoramentoOeM && git diff main --stat`
Expected: `main.py`, `tests/test_canais_teams.py`, `.env.example`, `README.md` — mais o spec e este plano em `docs/`.

- [ ] **Step 5: Parar e entregar para revisão humana**

Não fazer merge. Apresentar ao usuário:
- contagem de testes;
- resumo do diff;
- lembrete de que a FASE 2 (adicionar `TEAMS_WEBHOOK_URL_RELE` e `TEAMS_WEBHOOK_URL_INVERSOR` no `.env` local e no `.env` de produção do EC2 + `sudo systemctl restart monitoramento_oem`) é manual e pode ser feita a qualquer momento — sem ela, relé e inversor continuam no canal geral.

---

## Self-Review (feito pelo autor do plano)

**Cobertura do spec:**
- Constantes com fallback → Task 1 Step 3 ✓
- Parâmetro `webhook_url` sem trocar o guard `TEAMS_ENABLED` → Task 1 Steps 4-6 ✓
- Roteamento relé (2 pontos) → Task 2 ✓
- Roteamento inversor (2 funções) → Task 3 ✓
- `validate_config()` sem mudança → não há task (correto, é ausência de mudança) ✓
- `.env.example` + `README.md` → Task 4 ✓
- 5 testes do spec → T1/T2 (Task 1), T3/T5 (Task 2), T4 x2 (Task 3) ✓
- Testes existentes intactos → verificado em Task 1 Step 8, Task 5 Step 2 ✓
- `monitor_daemon.py` fora de escopo → não tocado ✓

**Placeholders:** nenhum "TBD"/"TODO"; todo step de código mostra o código.

**Consistência de nomes:** `webhook_url` (param), `TEAMS_WEBHOOK_URL_RELE`, `TEAMS_WEBHOOK_URL_INVERSOR`, `url` (local) — usados igual em todas as tasks. `_service()` helper definido em Task 2 Step 1 e reusado em Task 3.
