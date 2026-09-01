# Separação de Responsabilidades E6–E9 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extrair 4 funções puras de módulo a partir de métodos de orquestração e API, eliminando inner functions não-testáveis e uma duplicação de lógica de retry.

**Architecture:** Todas as 4 funções tornam-se funções de módulo, seguindo o padrão já estabelecido de `_formatar_blocos_rele`, `_montar_card_rele_falha`, etc. TDD: testes de proteção são escritos antes de qualquer mudança de código e devem falhar até a implementação correspondente. `PVOperationAPI._retry_after_seconds` é removido — seu único caller é atualizado para chamar a função de módulo diretamente.

**Tech Stack:** Python 3.10+, pytest, sem dependências novas.

---

## Mapa de arquivos

| Arquivo | O que muda |
|---|---|
| `main.py` | +4 funções de módulo; remoção de 2 inner functions + 1 método; 5 call sites atualizados |
| `tests/test_main.py` | +6 testes de proteção (1×E6, 1×E7, 3×E8, 1×E9) |

**Localização das novas funções em `main.py`:**
- `_parse_retry_after_seconds` → antes de `_teams_post_card` (linha ~214)
- `_dedupe_por_base` e `_alerta_ts_key` → após `_plant_ids_retornados` (linha ~1076), antes de `class MonitorService`
- `_compor_entrada_estado_inversor` → junto com as anteriores, no mesmo bloco

---

## Checkpoints de contagem de testes

| Passo | Ação | Meta pytest |
|---|---|---|
| 0 | Estado atual | 94 passed |
| 1 | Fase 1: 6 testes (todos falham) | 94 passed + 6 failed |
| 2 | E9: `_parse_retry_after_seconds` | 95 passed + 5 failed |
| 3 | E6+E7: `_dedupe_por_base` + `_alerta_ts_key` | 97 passed + 3 failed |
| 4 | E8: `_compor_entrada_estado_inversor` | 100 passed |
| 5 | `py_compile main.py` | OK |

---

## Fase 0 — Baseline

- [ ] Confirmar ponto de partida

```bash
python -m pytest -q
```

Esperado: `94 passed`

---

## Task 1 — Fase 1: Escrever os 6 testes de proteção

**Arquivo:** `tests/test_main.py`
**Ação:** Adicionar ao final do arquivo

- [ ] **Passo 1.1 — Adicionar testes ao final de `tests/test_main.py`**

```python
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
```

- [ ] **Passo 1.2 — Confirmar que os novos testes falham (funções ainda não existem)**

```bash
python -m pytest -q
```

Esperado: `94 passed, 6 failed` (AttributeError para todos os 6 novos testes)

---

## Task 2 — E9: Extrair `_parse_retry_after_seconds`

**Arquivo:** `main.py`
**Risco:** Baixo — substitui lógica idêntica em dois lugares. O teste `test_teams_retry_after_429` em `test_hardening.py` valida o comportamento end-to-end após a mudança.

- [ ] **Passo 2.1 — Adicionar função de módulo antes de `_teams_post_card` (linha ~214)**

Inserir antes da linha `# Envia cartao padrao...`:

```python
def _parse_retry_after_seconds(headers: dict) -> "int | None":
    retry_after = (headers or {}).get("Retry-After")
    if not retry_after:
        return None
    try:
        return max(0, int(retry_after))
    except (TypeError, ValueError):
        pass
    try:
        parsed = parsedate_to_datetime(retry_after)
    except Exception:
        return None
    if not parsed:
        return None
    now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
    delta = (parsed - now).total_seconds()
    return max(0, int(delta))

```

- [ ] **Passo 2.2 — Remover inner function de `_teams_post_card` e atualizar call site**

Em `_teams_post_card`, remover o bloco:
```python
    def _retry_after_seconds(resp):
        retry_after = resp.headers.get("Retry-After")
        if not retry_after:
            return None
        try:
            return max(0, int(retry_after))
        except (TypeError, ValueError):
            pass
        try:
            parsed = parsedate_to_datetime(retry_after)
        except Exception:
            return None
        if not parsed:
            return None
        now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
        delta = (parsed - now).total_seconds()
        return max(0, int(delta))
```

E atualizar o call site (linha ~259):
```python
# Antes:
                espera = _retry_after_seconds(r)
# Depois:
                espera = _parse_retry_after_seconds(r.headers)
```

- [ ] **Passo 2.3 — Remover `PVOperationAPI._retry_after_seconds` e atualizar call site em `_request_with_retry`**

Remover o método completo de `PVOperationAPI` (linhas ~303–319):
```python
    def _retry_after_seconds(self, response):
        retry_after = response.headers.get("Retry-After")
        if not retry_after:
            return None
        try:
            return max(0, int(retry_after))
        except (TypeError, ValueError):
            pass
        try:
            parsed = parsedate_to_datetime(retry_after)
        except Exception:
            return None
        if not parsed:
            return None
        now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
        delta = (parsed - now).total_seconds()
        return max(0, int(delta))
```

Atualizar call site em `_request_with_retry` (linha ~394):
```python
# Antes:
                    espera = self._retry_after_seconds(resp)
# Depois:
                    espera = _parse_retry_after_seconds(resp.headers)
```

- [ ] **Passo 2.4 — Rodar testes**

```bash
python -m pytest -q
```

Esperado: `95 passed, 5 failed`

Verificação extra — o teste de hardening de 429 deve continuar passando:
```bash
python -m pytest tests/test_hardening.py::test_teams_retry_after_429 -v
```
Esperado: `PASSED`

---

## Task 3 — E6+E7: Extrair `_dedupe_por_base` e `_alerta_ts_key`

**Arquivo:** `main.py`
**Risco:** Baixo — `_dedupe_por_base` é definida antes do `for` loop (mas dentro do `with self._scan_lock:`). `_alerta_ts_key` é redefinida em cada iteração do `for` — ambas são puramente locais e não capturam variáveis do escopo externo.

- [ ] **Passo 3.1 — Adicionar as duas funções após `_plant_ids_retornados` (linha ~1076), antes de `class MonitorService`**

Inserir antes do comentário `# Servico central que orquestra...`:

```python
def _dedupe_por_base(itens: list) -> list:
    vistos = set()
    saida = []
    for item in itens:
        base = item.get("base")
        if base and base in vistos:
            continue
        if base:
            vistos.add(base)
        saida.append(item)
    return saida


def _alerta_ts_key(item: dict):
    ts = item.get("ts_iso")
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min


```

- [ ] **Passo 3.2 — Remover `_dedupe_por_base` inner function de `executar_varredura_rele`**

Dentro de `executar_varredura_rele`, remover o bloco (definido dentro de `with self._scan_lock:`, antes de `notification_jobs = []`):

```python
            def _dedupe_por_base(itens):
                vistos = set()
                saida = []
                for item in itens:
                    base = item.get("base")
                    if base and base in vistos:
                        continue
                    if base:
                        vistos.add(base)
                    saida.append(item)
                return saida
```

As duas chamadas `_dedupe_por_base(pacote["novos"])` e `_dedupe_por_base(pacote["normalizados"])` permanecem inalteradas — o nome é o mesmo.

- [ ] **Passo 3.3 — Remover `_ts_key` closure e atualizar calls**

Dentro do `for usina_id in usinas:` em `executar_varredura_rele`, remover:

```python
                def _ts_key(item):
                    ts = item.get("ts_iso")
                    if not ts:
                        return datetime.min
                    try:
                        return datetime.fromisoformat(ts)
                    except Exception:
                        return datetime.min
```

Atualizar os dois `sorted(..., key=_ts_key)`:
```python
# Antes:
                pacote["novos"] = sorted(pacote["novos"], key=_ts_key)
                pacote["normalizados"] = sorted(pacote["normalizados"], key=_ts_key)
# Depois:
                pacote["novos"] = sorted(pacote["novos"], key=_alerta_ts_key)
                pacote["normalizados"] = sorted(pacote["normalizados"], key=_alerta_ts_key)
```

- [ ] **Passo 3.4 — Rodar testes**

```bash
python -m pytest -q
```

Esperado: `97 passed, 3 failed`

---

## Task 4 — E8: Extrair `_compor_entrada_estado_inversor`

**Arquivo:** `main.py`
**Risco:** Médio — esta função encapsula a regra de **gentle suppression + carry-across de estado**, que é a mais sutil do sistema. Os 3 testes de E8 cobrem os 3 ramos críticos: ativa com dado válido, inativa (limpeza de campos), e ausente (preservação de contadores). A extração deve ser bytewise-idêntica ao bloco original — sem alterar a lógica.

**Invariante a preservar:** As guards `isinstance(estado, bool)` e `if not isinstance(estado, dict): continue` ficam no loop — a função recebe `prev_entry: dict` e `estado_novo: dict` já validados.

- [ ] **Passo 4.1 — Adicionar função após `_alerta_ts_key` (mesmo bloco, antes de `class MonitorService`)**

```python
def _compor_entrada_estado_inversor(prev_entry: dict, estado_novo: dict, tem_dado_valido: bool) -> dict:
    entry = {
        "ativa": bool(estado_novo.get("ativa", False)),
        "rec_seq": int(estado_novo.get("rec_seq", 0)),
        "seq_zero": int(estado_novo.get("seq_zero", 0)),
        "alerta": prev_entry.get("alerta"),
        "notificado": bool(prev_entry.get("notificado", False)),
        "ausente_scans": (
            0 if tem_dado_valido
            else int(prev_entry.get("ausente_scans", 0))
        ),
        "ultima_confirmacao_ts": (
            estado_novo.get("ultima_confirmacao_ts")
            if tem_dado_valido
            else prev_entry.get("ultima_confirmacao_ts")
        ),
    }
    if not entry["ativa"]:
        entry["alerta"] = None
        entry["notificado"] = False
        entry["ultima_confirmacao_ts"] = None
    return entry

```

- [ ] **Passo 4.2 — Substituir bloco inline em `executar_varredura_inversor` (linhas ~2651–2673)**

Dentro do `for chave_inv, estado in falhas_ativas_atual.items():`, substituir:

```python
                    prev_entry = self.estado_inversores.get(chave_inv, {})
                    tem_dado_valido = chave_inv in chaves_observadas
                    entry = {
                        "ativa": bool(estado.get("ativa", False)),
                        "rec_seq": int(estado.get("rec_seq", 0)),
                        "seq_zero": int(estado.get("seq_zero", 0)),
                        "alerta": prev_entry.get("alerta"),
                        "notificado": bool(prev_entry.get("notificado", False)),
                        "ausente_scans": (
                            0 if tem_dado_valido
                            else int(prev_entry.get("ausente_scans", 0))
                        ),
                        "ultima_confirmacao_ts": (
                            estado.get("ultima_confirmacao_ts")
                            if tem_dado_valido
                            else prev_entry.get("ultima_confirmacao_ts")
                        ),
                    }
                    if not entry["ativa"]:
                        entry["alerta"] = None
                        entry["notificado"] = False
                        entry["ultima_confirmacao_ts"] = None
                    self.estado_inversores[chave_inv] = entry
```

Por:

```python
                    prev_entry = self.estado_inversores.get(chave_inv, {})
                    tem_dado_valido = chave_inv in chaves_observadas
                    self.estado_inversores[chave_inv] = _compor_entrada_estado_inversor(
                        prev_entry, estado, tem_dado_valido
                    )
```

- [ ] **Passo 4.3 — Rodar testes**

```bash
python -m pytest -q
```

Esperado: `100 passed`

---

## Task 5 — Verificação Final

- [ ] **Passo 5.1 — Verificar sintaxe**

```bash
python -m py_compile main.py && echo OK
```

Esperado: `OK`

- [ ] **Passo 5.2 — Rodar suíte completa**

```bash
python -m pytest -q
```

Esperado: `100 passed`

---

## Notas de segurança

**E9 — remoção de `PVOperationAPI._retry_after_seconds`:** O método não tem teste direto nem é referenciado externamente. O único caller (`_request_with_retry`) é atualizado no mesmo passo. Nenhum comportamento muda — a lógica é identica.

**E6 — `_dedupe_por_base` dentro de `with self._scan_lock:`:** A função não captura nenhuma variável do escopo externo (sem closure real). Promovê-la ao módulo é seguro.

**E7 — `_ts_key` redefinida a cada iteração:** Além de ser ineficiente, cria um novo objeto função em cada volta do loop. A promoção elimina esse overhead. Não há diferença comportamental.

**E8 — `_compor_entrada_estado_inversor`:** A substituição é bytewise-idêntica ao bloco original. As guards de tipo (`isinstance(estado, bool)`, `if not isinstance(estado, dict): continue`) ficam no loop chamador, não entram na função pura.
