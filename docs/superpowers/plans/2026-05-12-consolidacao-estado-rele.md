# Plano: Consolidação de Estado de Relé + Consistência de Mutação de Inversor

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extrair dois helpers de estado de relé (`_ativar_alerta_rele`, `_resolver_alerta_rele`) que consolidam mutações espalhadas por `executar_varredura_rele`, e corrigir a inconsistência de mutação de subdicionário no branch de recuperação de inversor.

**Architecture:** Mesmo padrão das extrações E1–E9: proteção via testes escritos antes da implementação, extração de função pura, refatoração dos call-sites, pytest verde. Nenhuma lógica de negócio é alterada — as funções apenas reagrupam operações que já ocorrem juntas.

**Tech Stack:** Python 3.12, pytest, `main.py` (serviço headless)

---

## Análise de risco

### O que é alterado

| ID | Extração | Linhas afetadas | Risco |
|---|---|---|---|
| R1 | `_resolver_alerta_rele` | 2438–2443 | Muito baixo — agrupa 4 ops sequenciais que já ocorrem juntas |
| R2 | `_ativar_alerta_rele` | 2400–2428 | Baixo — consolida 2 patterns que diferem só no `add()` inicial |
| R3 | Consistência de mutação em inversor `rec` | 2629–2631 | Nulo — comportamento idêntico (Python mutação inline == get→mutate→assign) |

### O que NÃO é alterado

- Toda a lógica de detecção (`detectar_alertas_rele`, `detectar_falhas_inversores`)
- Lógica de lock (`_scan_lock`, `_state_lock`)
- Serialização de estado (`_save_state`, `_load_state`)
- Notificações Teams (`_notificar_rele_agrupado`, `_enviar_heartbeat`)
- Loop de scans (`_loop_scans`, `executar_varredura_inversor`)
- Sem novos commits — usuário commita ao final

### Invariantes preservadas

**R1 — `_resolver_alerta_rele`:**  
O conjunto `{rele_alertas_ativos, rele_alerta_chave, rele_notificados}` antes e depois da resolução deve ser idêntico ao comportamento atual.  
`rele_alertas_ativos.discard` + `rele_alerta_chave.pop` + `rele_notificados.discard` + `_registrar_fim_incidente_rele` sempre ocorrem juntos no mesmo ponto.

**R2 — `_ativar_alerta_rele`:**  
`rele_alertas_ativos.add` + `rele_alerta_chave[base] = alerta_fmt` + `_registrar_inicio_incidente_rele` sempre ocorrem juntos.  
`_registrar_inicio_incidente_rele` já tem guard interno (`if base not in self.incidentes_rele_ativos:`), tornando a chamada idempotente — elimina a verificação explícita redundante no Pattern 1.  
Lógica de notificação (`novos_por_usina`) permanece no caller.

**R3 — Consistência inversor:**  
`dict[key]["subkey"] = value` e `entry = dict[key]; entry["subkey"] = value; dict[key] = entry` são semanticamente idênticos em Python para o mesmo objeto dict. Sem mudança comportamental.

---

## Estrutura de arquivos

Apenas `main.py` é modificado:
- Adicionar `_resolver_alerta_rele` e `_ativar_alerta_rele` como métodos de `MonitorService`, próximos a `_registrar_inicio_incidente_rele` (linha ~1406)
- Refatorar `executar_varredura_rele` (linhas 2400–2443)
- Corrigir linhas 2629–2631

`tests/test_main.py` recebe 4 novos testes.

---

## Task R1: Extrair `_resolver_alerta_rele`

**Files:**
- Modify: `main.py` (novo método + refatoração de call-site)
- Test: `tests/test_main.py` (2 novos testes)

### Código a extrair

Linha atual 2438–2443 em `executar_varredura_rele` (dentro de `with self._scan_lock:`):
```python
for base in resolved:
    alerta_antigo = self.rele_alerta_chave.get(base)
    self.rele_alertas_ativos.discard(base)
    self.rele_alerta_chave.pop(base, None)
    self.rele_notificados.discard(base)
    self._registrar_fim_incidente_rele(base=base, fim_ts=agora, fallback_alerta=alerta_antigo)
    if alerta_antigo:
        ...
```

### Novo método (inserir após `_registrar_fim_incidente_rele`, ~linha 1430)

```python
def _resolver_alerta_rele(self, base: str, fim_ts: datetime) -> dict | None:
    alerta_antigo = self.rele_alerta_chave.get(base)
    self.rele_alertas_ativos.discard(base)
    self.rele_alerta_chave.pop(base, None)
    self.rele_notificados.discard(base)
    self._registrar_fim_incidente_rele(base=base, fim_ts=fim_ts, fallback_alerta=alerta_antigo)
    return alerta_antigo
```

### Call-site refatorado

```python
for base in resolved:
    alerta_antigo = self._resolver_alerta_rele(base, fim_ts=agora)
    if alerta_antigo:
        usina_id, rele_id, tipo = base.split(":", 2)
        resolvidos_por_usina.setdefault(
            usina_id, {"usina": alerta_antigo.get("usina"), "capacidade": alerta_antigo.get("capacidade"), "itens": []}
        )["itens"].append(
            {
                "base": base,
                "usina": alerta_antigo.get("usina"),
                "capacidade": alerta_antigo.get("capacidade"),
                "rele": alerta_antigo.get("rele", rele_id),
                "tipo": alerta_antigo.get("tipo", tipo),
                "horario": alerta_antigo.get("horario"),
                "ts_iso": alerta_antigo.get("ts_iso"),
                "parametros": alerta_antigo.get("parametros"),
            }
        )
```

- [ ] **Passo 1: Escrever os 2 testes de proteção (devem FALHAR antes da implementação)**

Adicionar ao final de `tests/test_main.py`:

```python
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
```

- [ ] **Passo 2: Confirmar que os novos testes falham**

```
cd c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM && python -m pytest tests/test_main.py -k "test_resolver_alerta_rele" -v
```

Esperado: 2 falhas com `AttributeError: '_resolver_alerta_rele'`

- [ ] **Passo 3: Implementar `_resolver_alerta_rele`**

Localizar em `main.py` o método `_registrar_fim_incidente_rele` (linha ~1418). Inserir o novo método logo após ele (antes de `_registrar_inicio_incidente_inversor`):

```python
    def _registrar_fim_incidente_rele(self, base: str, fim_ts: datetime, fallback_alerta=None):
        # ... (método existente, não alterar)
        ...

    def _resolver_alerta_rele(self, base: str, fim_ts: datetime) -> dict | None:
        alerta_antigo = self.rele_alerta_chave.get(base)
        self.rele_alertas_ativos.discard(base)
        self.rele_alerta_chave.pop(base, None)
        self.rele_notificados.discard(base)
        self._registrar_fim_incidente_rele(base=base, fim_ts=fim_ts, fallback_alerta=alerta_antigo)
        return alerta_antigo
```

- [ ] **Passo 4: Refatorar call-site em `executar_varredura_rele`**

Localizar o bloco `for base in resolved:` (linha ~2438). Substituir:

```python
            for base in resolved:
                alerta_antigo = self.rele_alerta_chave.get(base)
                self.rele_alertas_ativos.discard(base)
                self.rele_alerta_chave.pop(base, None)
                self.rele_notificados.discard(base)
                self._registrar_fim_incidente_rele(base=base, fim_ts=agora, fallback_alerta=alerta_antigo)
```

Por:

```python
            for base in resolved:
                alerta_antigo = self._resolver_alerta_rele(base, fim_ts=agora)
```

- [ ] **Passo 5: Verificar**

```
python -m py_compile c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM\main.py
cd c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM && python -m pytest -q
```

Esperado: **102 passed**.

---

## Task R2: Extrair `_ativar_alerta_rele`

**Files:**
- Modify: `main.py` (novo método + refatoração de call-site)
- Test: `tests/test_main.py` (2 novos testes)

### Contexto atual

`executar_varredura_rele` tem dois patterns que fazem operações sobrepostas:

**Pattern 1 — alerta existente** (linhas ~2400–2416):
```python
if base in self.rele_alertas_ativos:
    self.rele_alerta_chave[base] = alerta_fmt              # atualiza detalhe
    if base not in self.incidentes_rele_ativos:
        self._registrar_inicio_incidente_rele(...)         # garante incidente (redundante: registrar já tem guard)
    if base not in self.rele_notificados:
        novos_por_usina.setdefault(...)["itens"].append(alerta_fmt)
    continue
```

**Pattern 2 — alerta novo** (linhas ~2418–2428):
```python
self.rele_alertas_ativos.add(base)
self.rele_alerta_chave[base] = alerta_fmt
self._registrar_inicio_incidente_rele(...)
novos_por_usina.setdefault(...)["itens"].append(alerta_fmt)
```

**Diferença real entre os patterns:**
- Pattern 1: já está em `alertas_ativos`, só atualiza chave + garante incidente
- Pattern 2: ainda não está em `alertas_ativos`, adiciona tudo

A distinção `add()` / sem `add()` é o único delta de estado. A notificação (`novos_por_usina`) fica no caller porque depende de `novos_por_usina` (variável local).

### Novo método (inserir após `_resolver_alerta_rele`)

```python
def _ativar_alerta_rele(
    self,
    base: str,
    alerta_fmt: dict,
    *,
    usina_id: str,
    nome: str | None,
    rele_id: str,
    tipo_alerta: str,
    inicio_ts: datetime,
) -> None:
    self.rele_alertas_ativos.add(base)
    self.rele_alerta_chave[base] = alerta_fmt
    self._registrar_inicio_incidente_rele(
        base=base,
        usina_id=usina_id,
        usina=nome,
        rele_id=rele_id,
        tipo_falha=tipo_alerta,
        inicio_ts=inicio_ts,
    )
```

**Por que `add()` é idempotente:** `set.add(x)` em Python não duplica se `x` já existe. Chamar `_ativar_alerta_rele` para um alerta existente é seguro — o efeito é equivalente ao Pattern 1 original.

### Call-site refatorado

O bloco `if base in self.rele_alertas_ativos: ... else: ...` (linhas ~2400–2428) é substituído por:

```python
                    is_novo = base not in self.rele_alertas_ativos
                    self._ativar_alerta_rele(
                        base, alerta_fmt,
                        usina_id=usina_id,
                        nome=nome,
                        rele_id=a["rele_id"],
                        tipo_alerta=a["tipo_alerta"],
                        inicio_ts=a["ts_leitura"],
                    )
                    if is_novo or base not in self.rele_notificados:
                        novos_por_usina.setdefault(
                            usina_id, {"usina": nome, "capacidade": cap, "itens": []}
                        )["itens"].append(alerta_fmt)
```

**Verificação de equivalência da condição de notificação:**
| Caso | Original | Refatorado |
|---|---|---|
| Alerta novo | sempre appenda | `is_novo=True` → append ✓ |
| Existente, não notificado | `base not in rele_notificados` → append | `is_novo=False and base not in rele_notificados` → append ✓ |
| Existente, já notificado | skip | `is_novo=False and base in rele_notificados` → skip ✓ |

- [ ] **Passo 1: Escrever os 2 testes de proteção (devem FALHAR antes da implementação)**

Adicionar ao final de `tests/test_main.py`:

```python
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
```

- [ ] **Passo 2: Confirmar que os novos testes falham**

```
cd c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM && python -m pytest tests/test_main.py -k "test_ativar_alerta_rele" -v
```

Esperado: 2 falhas com `AttributeError: '_ativar_alerta_rele'`

- [ ] **Passo 3: Implementar `_ativar_alerta_rele`**

Inserir logo após `_resolver_alerta_rele` (que foi criado em Task R1):

```python
    def _ativar_alerta_rele(
        self,
        base: str,
        alerta_fmt: dict,
        *,
        usina_id: str,
        nome: str | None,
        rele_id: str,
        tipo_alerta: str,
        inicio_ts: datetime,
    ) -> None:
        self.rele_alertas_ativos.add(base)
        self.rele_alerta_chave[base] = alerta_fmt
        self._registrar_inicio_incidente_rele(
            base=base,
            usina_id=usina_id,
            usina=nome,
            rele_id=rele_id,
            tipo_falha=tipo_alerta,
            inicio_ts=inicio_ts,
        )
```

- [ ] **Passo 4: Refatorar call-site em `executar_varredura_rele`**

Localizar o bloco (linhas ~2400–2428):

```python
                    if base in self.rele_alertas_ativos:
                        # atualiza detalhes com o último evento
                        self.rele_alerta_chave[base] = alerta_fmt
                        if base not in self.incidentes_rele_ativos:
                            self._registrar_inicio_incidente_rele(
                                base=base,
                                usina_id=usina_id,
                                usina=nome,
                                rele_id=a["rele_id"],
                                tipo_falha=a["tipo_alerta"],
                                inicio_ts=a["ts_leitura"],
                            )
                        if base not in self.rele_notificados:
                            novos_por_usina.setdefault(
                                usina_id, {"usina": nome, "capacidade": cap, "itens": []}
                            )["itens"].append(alerta_fmt)
                        continue

                    self.rele_alertas_ativos.add(base)
                    self.rele_alerta_chave[base] = alerta_fmt
                    self._registrar_inicio_incidente_rele(
                        base=base,
                        usina_id=usina_id,
                        usina=nome,
                        rele_id=a["rele_id"],
                        tipo_falha=a["tipo_alerta"],
                        inicio_ts=a["ts_leitura"],
                    )
                    novos_por_usina.setdefault(usina_id, {"usina": nome, "capacidade": cap, "itens": []})["itens"].append(alerta_fmt)
```

Substituir por:

```python
                    is_novo = base not in self.rele_alertas_ativos
                    self._ativar_alerta_rele(
                        base, alerta_fmt,
                        usina_id=usina_id,
                        nome=nome,
                        rele_id=a["rele_id"],
                        tipo_alerta=a["tipo_alerta"],
                        inicio_ts=a["ts_leitura"],
                    )
                    if is_novo or base not in self.rele_notificados:
                        novos_por_usina.setdefault(
                            usina_id, {"usina": nome, "capacidade": cap, "itens": []}
                        )["itens"].append(alerta_fmt)
```

- [ ] **Passo 5: Verificar**

```
python -m py_compile c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM\main.py
cd c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM && python -m pytest -q
```

Esperado: **104 passed**.

---

## Task R3: Consistência de mutação em branch `rec` de inversor

**Files:**
- Modify: `main.py` (2 linhas, ~2629–2631)

Esta é uma mudança puramente cosmética — comportamento idêntico. Não requer novos testes.

O objetivo é unificar o estilo de mutação de `estado_inversores` com o padrão já usado em linhas 2744–2747.

**Padrão inconsistente atual** (linhas ~2629–2631):
```python
if chave_inv in self.estado_inversores:
    self.estado_inversores[chave_inv]["alerta"] = None
    self.estado_inversores[chave_inv]["notificado"] = False
```

**Padrão consistente com o restante do arquivo** (linhas ~2744–2747):
```python
estado = self.estado_inversores.get(chave)
if isinstance(estado, dict) and estado.get("ativa"):
    estado["notificado"] = True
    self.estado_inversores[chave] = estado
```

- [ ] **Passo 1: Corrigir as linhas 2629–2631**

Localizar:
```python
                        if chave_inv in self.estado_inversores:
                            self.estado_inversores[chave_inv]["alerta"] = None
                            self.estado_inversores[chave_inv]["notificado"] = False
```

Substituir por:
```python
                        if chave_inv in self.estado_inversores:
                            entry_rec = self.estado_inversores[chave_inv]
                            entry_rec["alerta"] = None
                            entry_rec["notificado"] = False
                            self.estado_inversores[chave_inv] = entry_rec
```

- [ ] **Passo 2: Verificar**

```
python -m py_compile c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM\main.py
cd c:\Users\ARTHUR\Desktop\monitor\MonitoramentoOeM && python -m pytest -q
```

Esperado: **104 passed**.

---

## Checkpoints

| Task | Ação | Meta pytest |
|---|---|---|
| 0 | Estado atual | 100 passed |
| R1 | Testes (falham) + `_resolver_alerta_rele` | 102 passed |
| R2 | Testes (falham) + `_ativar_alerta_rele` | 104 passed |
| R3 | Correção cosmética inversor | 104 passed |
| Final | `py_compile main.py` | OK |

---

## O que NÃO será alterado

- `executar_varredura_inversor` (exceto as 2 linhas da Task R3)
- `_load_state`, `_save_state`, locking
- Nenhum método de notificação
- `monitor_daemon.py`, `README.md`, `tests/test_hardening.py`
- Sem commits — usuário commita ao final

---

## Notas de implementação

**`_registrar_inicio_incidente_rele` é idempotente por design** (linha 1407: `if base not in self.incidentes_rele_ativos:`). Por isso `_ativar_alerta_rele` chama-o incondicionalmente — sem risco de duplicar incidentes.

**`is_novo` deve ser capturado antes de `_ativar_alerta_rele`** porque o método faz `rele_alertas_ativos.add(base)`. Após a chamada, `base` sempre estará no set, então `is_novo` seria sempre `False`.

**R3 é puramente documental:** `dict[key]["subkey"] = v` e `entry = dict[key]; entry["subkey"] = v; dict[key] = entry` produzem o mesmo resultado em Python porque `entry` é referência ao mesmo objeto. O ganho é de legibilidade e consistência de estilo, não de corretude.
