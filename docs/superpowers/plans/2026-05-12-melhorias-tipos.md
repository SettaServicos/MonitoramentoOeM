# Melhorias de Tipagem — `main.py`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar TypedDicts, `Literal` e anotações ausentes a `main.py` para documentar as estruturas de dados principais e eliminar inconsistências de tipagem — sem alterar nenhum comportamento em tempo de execução.

**Architecture:** Todas as mudanças são puramente aditivas: Python avalia anotações como strings no Python 3.10+ (exceto em contextos de runtime como `isinstance`). Nenhum TypedDict é usado em `isinstance`. Verificação = `py_compile` + `pytest -q` (100 passed). Nenhum novo teste comportamental é necessário.

**Tech Stack:** Python 3.12, `typing.TypedDict`, `typing.Literal`

---

## Estrutura de arquivos

Apenas um arquivo é modificado:

- Modificar: `main.py`
  - Bloco de imports (linha 32) — adicionar `from typing import TypedDict, Literal`
  - Após constantes, antes de `_configurar_logger_arquivo` (linha ~148) — inserir 4 TypedDicts + 1 Literal alias
  - Linha 215 — `_parse_retry_after_seconds`: corrigir `"int | None"` → `int | None`
  - Linha 236 — `_teams_post_card`: adicionar anotações de parâmetros e retorno
  - Linha 428 — `get_plants`: adicionar `-> list`
  - Linha 460 — `post_day`: adicionar `-> tuple`
  - Linha 486 — `extrair_valor_numerico`: adicionar `(valor: str | int | float | bool | None) -> float | None`
  - Linha 661 — `_montar_card_rele_falha`: `"dict | None"` → `CardTeams | None`
  - Linha 677 — `_montar_card_rele_normalizacao`: `"dict | None"` → `CardTeams | None`
  - Linha 700 — `_formatar_texto_heartbeat`: anotar `ultima_rele`, `ultima_inv`, `previsto`
  - Linha 741 — `_obter_janela_solar_inversor`: adicionar `-> tuple[dtime, dtime]`
  - Linha 1087 — `_compor_entrada_estado_inversor`: `-> dict` → `-> EstadoInversor`
  - Linha 1359 — `_novo_incidente`: adicionar `-> Incidente`
  - Linha 2721 — `formatar_intervalo_alerta`: anotar `ts_first`, `ts_last`
  - Linha 2729 — `_inversor_conta_no_heartbeat`: anotar `estado`
  - Linha 2825 — `_notificar_rele_agrupado`: anotar `pacote` e retorno
  - Linha 2879 — `_notificar_inversor`: anotar `alerta` e retorno
  - Linha 2894 — `_notificar_inversor_recuperado`: anotar `alerta`, `alerta_prev`, retorno

Nenhum outro arquivo é modificado.

---

## Task 1: Import de `typing` + definição dos tipos base

**Files:**
- Modify: `main.py` (imports, linhas 11-32; bloco de tipos, inserir após linha ~147)

### Por que estes tipos?

| Tipo | Usado em |
|---|---|
| `SeverityLevel` | `_teams_post_card`, `_montar_card_*`, ~10 call-sites |
| `CardTeams` | retorno de `_montar_card_rele_falha/normalizacao`; desempacotado com `**card` em 5 lugares |
| `EstadoInversor` | `self.estado_inversores` dict, `_compor_entrada_estado_inversor`, heartbeat |
| `Incidente` | `_novo_incidente`, `incidentes_rele_ativos`, `incidentes_inv_ativos`, `historico_incidentes` |

- [ ] **Passo 1: Adicionar import de `typing` na seção de imports**

Localizar a linha 32 (último import):
```
from zipfile import ZipFile, ZIP_DEFLATED
```

Inserir logo abaixo:
```python
from typing import TypedDict, Literal
```

- [ ] **Passo 2: Inserir bloco de tipos após constantes**

Localizar linha ~148 (a linha em branco antes de `def _configurar_logger_arquivo`):
```python
WINDOW_DELTA_SECONDS = 1
STATE_SCHEMA_VERSION = 1


def _configurar_logger_arquivo(
```

Inserir o bloco de tipos entre `STATE_SCHEMA_VERSION = 1` e `def _configurar_logger_arquivo`:

```python
WINDOW_DELTA_SECONDS = 1
STATE_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Tipos de dados — puramente documentais, sem efeito em runtime
# ---------------------------------------------------------------------------
SeverityLevel = Literal["info", "warning", "danger"]


class CardTeams(TypedDict):
    title: str
    text: str
    severity: SeverityLevel
    facts: list[tuple[str, str]] | None


class EstadoInversor(TypedDict):
    ativa: bool
    rec_seq: int
    seq_zero: int
    alerta: dict | None
    notificado: bool
    ausente_scans: int
    ultima_confirmacao_ts: str | None


class Incidente(TypedDict):
    chave: str
    natureza: str
    tipo_falha: str
    usina_id: str
    usina: str | None
    equipamento: str
    inicio_ts: str
    fim_ts: str | None


def _configurar_logger_arquivo(
```

- [ ] **Passo 3: Verificar sintaxe e testes**

```
python -m py_compile main.py
pytest -q
```

Esperado: nenhum erro de compilação, **100 passed**.

---

## Task 2: Aplicar TypedDicts às funções puras

**Files:**
- Modify: `main.py` (linhas ~661, ~677, ~1087, ~1359)

Estas funções constroem ou retornam as estruturas definidas em Task 1. Substituir anotações genéricas de `dict` pelo TypedDict correto.

- [ ] **Passo 1: `_montar_card_rele_falha` — corrigir retorno**

Localizar:
```python
def _montar_card_rele_falha(pacote: dict) -> "dict | None":
```

Substituir por:
```python
def _montar_card_rele_falha(pacote: dict) -> CardTeams | None:
```

- [ ] **Passo 2: `_montar_card_rele_normalizacao` — corrigir retorno**

Localizar:
```python
def _montar_card_rele_normalizacao(pacote: dict) -> "dict | None":
```

Substituir por:
```python
def _montar_card_rele_normalizacao(pacote: dict) -> CardTeams | None:
```

- [ ] **Passo 3: `_compor_entrada_estado_inversor` — corrigir retorno**

Localizar:
```python
def _compor_entrada_estado_inversor(prev_entry: dict, estado_novo: dict, tem_dado_valido: bool) -> dict:
```

Substituir por:
```python
def _compor_entrada_estado_inversor(prev_entry: dict, estado_novo: dict, tem_dado_valido: bool) -> EstadoInversor:
```

- [ ] **Passo 4: `_novo_incidente` — adicionar retorno**

Localizar:
```python
    def _novo_incidente(base_key: str, natureza: str, tipo_falha: str, usina_id: str, usina: str, equipamento: str, inicio_ts: datetime, fim_ts=None):
```

Substituir por:
```python
    def _novo_incidente(base_key: str, natureza: str, tipo_falha: str, usina_id: str, usina: str, equipamento: str, inicio_ts: datetime, fim_ts: str | None = None) -> Incidente:
```

- [ ] **Passo 5: Verificar sintaxe e testes**

```
python -m py_compile main.py
pytest -q
```

Esperado: **100 passed**.

---

## Task 3: Corrigir anotações quoted + adicionar tipos ausentes

**Files:**
- Modify: `main.py` (múltiplas localizações — ver abaixo)

Todas as mudanças neste task são mecânicas: trocar strings por tipos nativos ou adicionar anotações onde estão faltando.

- [ ] **Passo 1: `_parse_retry_after_seconds` — remover aspas**

Localizar:
```python
def _parse_retry_after_seconds(headers: dict) -> "int | None":
```

Substituir por:
```python
def _parse_retry_after_seconds(headers: dict) -> int | None:
```

- [ ] **Passo 2: `_teams_post_card` — adicionar anotações completas**

Localizar:
```python
def _teams_post_card(title, text, severity="info", facts=None):
```

Substituir por:
```python
def _teams_post_card(title: str, text: str, severity: SeverityLevel = "info", facts: list[tuple[str, str]] | None = None) -> bool:
```

- [ ] **Passo 3: `get_plants` — adicionar retorno**

Localizar (método da classe `PVOperationAPI`):
```python
    def get_plants(self):
```

Substituir por:
```python
    def get_plants(self) -> list:
```

- [ ] **Passo 4: `post_day` — adicionar retorno**

Localizar:
```python
    def post_day(self, endpoint: str, plant_id: int, date: datetime):
```

Substituir por:
```python
    def post_day(self, endpoint: str, plant_id: int, date: datetime) -> tuple:
```

- [ ] **Passo 5: `extrair_valor_numerico` — adicionar anotações**

Localizar:
```python
def extrair_valor_numerico(valor):
```

Substituir por:
```python
def extrair_valor_numerico(valor: str | int | float | bool | None) -> float | None:
```

- [ ] **Passo 6: `_obter_janela_solar_inversor` — adicionar retorno**

Localizar:
```python
def _obter_janela_solar_inversor(usina_nome: str = None):
```

Substituir por:
```python
def _obter_janela_solar_inversor(usina_nome: str | None = None) -> tuple[dtime, dtime]:
```

- [ ] **Passo 7: `_formatar_texto_heartbeat` — anotar parâmetros sem tipo**

Localizar:
```python
def _formatar_texto_heartbeat(
    *,
    rele_atrasado: bool,
    inv_atrasado: bool,
    ultima_rele,
    ultima_inv,
    ativos_rele: int,
    ativos_inv: int,
    rele_usinas: list,
    inv_usina_counts: dict,
    previsto,
) -> str:
```

Substituir por:
```python
def _formatar_texto_heartbeat(
    *,
    rele_atrasado: bool,
    inv_atrasado: bool,
    ultima_rele: datetime | None,
    ultima_inv: datetime | None,
    ativos_rele: int,
    ativos_inv: int,
    rele_usinas: list,
    inv_usina_counts: dict,
    previsto: datetime,
) -> str:
```

- [ ] **Passo 8: `formatar_intervalo_alerta` — anotar parâmetros**

Localizar:
```python
    def formatar_intervalo_alerta(ts_first, ts_last) -> str:
```

Substituir por:
```python
    def formatar_intervalo_alerta(ts_first: datetime | None, ts_last: datetime | None) -> str:
```

- [ ] **Passo 9: `_inversor_conta_no_heartbeat` — anotar `estado`**

Localizar:
```python
    def _inversor_conta_no_heartbeat(estado, referencia: datetime) -> bool:
```

Substituir por:
```python
    def _inversor_conta_no_heartbeat(estado: EstadoInversor | dict, referencia: datetime) -> bool:
```

- [ ] **Passo 10: `_notificar_rele_agrupado` — anotar `pacote` e retorno**

Localizar:
```python
    def _notificar_rele_agrupado(self, pacote):
```

Substituir por:
```python
    def _notificar_rele_agrupado(self, pacote: dict) -> tuple[bool, bool]:
```

- [ ] **Passo 11: `_notificar_inversor` — anotar `alerta` e retorno**

Localizar:
```python
    def _notificar_inversor(self, alerta):
```

Substituir por:
```python
    def _notificar_inversor(self, alerta: dict) -> bool:
```

- [ ] **Passo 12: `_notificar_inversor_recuperado` — anotar parâmetros e retorno**

Localizar:
```python
    def _notificar_inversor_recuperado(self, alerta, alerta_prev=None):
```

Substituir por:
```python
    def _notificar_inversor_recuperado(self, alerta: dict, alerta_prev: dict | None = None) -> bool:
```

- [ ] **Passo 13: Verificação final**

```
python -m py_compile main.py
pytest -q
```

Esperado: **100 passed**, nenhum erro de compilação.

---

## Checkpoints

| Task | Ação | Meta pytest |
|---|---|---|
| 0 | Estado atual | 100 passed |
| 1 | Import + TypedDicts | 100 passed |
| 2 | TypedDicts em retornos | 100 passed |
| 3 | Corrigir quoted + ausentes | 100 passed |

---

## O que NÃO será alterado

- Nenhuma lógica de negócio
- Nenhum método de scan (`executar_varredura_*`, `_loop_*`)
- `monitor_daemon.py`
- `tests/test_main.py`
- `tests/test_hardening.py`
- Credenciais (`PVOP_PASSWORD`, `TEAMS_WEBHOOK_URL`) — decisão operacional vigente

---

## Notas de implementação

**Sem `from __future__ import annotations`:** Python 3.12 — sintaxe nativa `X | Y` funciona sem quotes e sem future imports.

**`CardTeams.facts`:** Definido como `list[tuple[str, str]] | None` para refletir o uso real: `[("Capacidade", "500 kWp")]`. Nunca passa lista vazia — ou é `None` ou tem pelo menos um item.

**`EstadoInversor.alerta`:** Mantido como `dict | None` (não `Incidente | None`) porque o alerta no estado de inversor é uma estrutura diferente do `Incidente` do histórico — contém chaves como `usina`, `inversor`, `horario`, `capacidade` usadas diretamente nas notificações.

**`_inversor_conta_no_heartbeat` — `EstadoInversor | dict`:** O `isinstance(estado, dict)` já presente no método protege contra valores inválidos; o tipo `EstadoInversor | dict` documenta que ambas as formas são aceitas sem exigir refatoração do callable.

**`get_plants` retorno `list`:** A função pode retornar lista de plantas ou `None` em caso de erro — mas o contrato documentado pelo retorno `list` é o caminho normal. Uma futura melhoria poderia ser `list | None`, mas `list` é suficiente para documentação sem introduzir falsas expectativas nos callers atuais.

**`post_day` retorno `tuple`:** Retorna `(dados, timeout_flag)` onde `dados` pode ser `dict | None` e `timeout_flag` é `bool`. `tuple` genérico é suficiente; `tuple[dict | None, bool]` seria mais preciso mas exige análise do contrato completo da função.
