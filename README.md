# Monitor de Usinas Fotovoltaicas — main.py

Monitor headless que varre relés e inversores via API PVOperation e envia alertas para Microsoft Teams. Roda como serviço contínuo sem UI.

---

## O que o sistema faz

- Detecta falhas e normalizações em **relés** de proteção.
- Detecta falhas e normalizações em **inversores** (potência zero dentro da janela solar).
- Envia **notificações para o Teams** via Incoming Webhook.
- Envia **heartbeat** em horários fixos para confirmar que o monitor está ativo.
- Persiste estado em disco para sobreviver a reinícios sem reeditar alertas.
- Gera **relatório semanal** compactado com histórico de incidentes.
- Garante **instância única** via lock de arquivo.

---
''  


## Arquivo de produção recomendado

| Arquivo | Uso |
|---|---|
| `main.py` | **Produção** — lógica completa e validada |
| `monitor_daemon.py` | Alternativa simplificada — veja `README_daemon.md` |

---

## Monitoramento de Relés

### Como funciona

- Varredura a cada **10 minutos** (`RELAY_INTERVAL = 600`).
- Apenas usinas da allowlist `RELE_PLANT_IDS` são varridas no fluxo de relé.
- Para cada usina, consulta `day_relay` no intervalo `[ultima_varredura + 1s, agora]`.
- Registros são filtrados pelo timestamp `tsleitura` dentro do intervalo.
- `tem_dados` só é `True` após passar o filtro temporal — dado fora da janela não conta.
- O checkpoint avança por `max_ts_processado` (timestamp máximo processado), não por `datetime.now()`.

### Detecção de alerta.

- Parâmetros do relé (`RELAY_PARAMETROS`) com valor ativo (`True`, `1`, `"true"`) indicam falha.
- Alertas são agrupados por `(usina, rele_id, tipo_alerta)` e acumulam todos os parâmetros ativos do intervalo.
- **Todos os alertas** do intervalo são retornados e processados (não apenas o primeiro).

### Classificação

| Tipo | Parâmetros |
|---|---|
| SOBRETENSÃO | r59A, r59B, r59C, r59N |
| SUBTENSÃO | r27A, r27B, r27C, r27_0 |
| FREQUÊNCIA | r81O, r81U |
| TÉRMICO | r49, r49_2 |
| BLOQUEIO | rAR, rBA, rDO |
| OUTROS | demais parâmetros de `RELAY_PARAMETROS` |

### Lista parcial de usinas

- Se a API retorna menos usinas que o estado salvo, é detectado como lista parcial.
- Usinas ausentes em lista parcial **preservam alertas ativos** — sem falsa normalização.

### Normalização

- Quando um alerta some da API e não aparece mais no intervalo, ele é normalizado.
- Notificação de normalização é enviada ao Teams.

---

## Monitoramento de Inversores

### Como funciona

- Varredura a cada **15 minutos** (`INVERTER_INTERVAL = 900`).
- Para cada usina, consulta `day_inverter` no intervalo `[ultima_varredura + 1s, agora]`.
- Registros fora da **janela solar** são ignorados.
- O checkpoint avança por `max_ts_processado`.

### Janelas solares

| Usina | Início | Fim |
|---|---|---|
| Padrão | 06:30 | 17:00 |
| Ibimirim (`COMP.IBI.2500.LT01`–`LT05`) | 07:30 | 17:00 |

A detecção Ibimirim usa matching por substring no nome da usina (`_is_ibimirim_usina`).

### Regras de falha

- `PAC <= 0` (incluindo negativos) = leitura com `pac_zero = True`.
- PAC ausente ou não parseável **não conta** como leitura válida — não mascara ausência de dado.
- **Falha confirmada:** `INVERTER_CONSECUTIVE_READINGS = 3` leituras consecutivas com `pac_zero`.
- Ao confirmar falha, notificação enviada ao Teams.

### Regras de recuperação

- **Recuperação confirmada:** `INVERTER_RECOVERY_CONSECUTIVE_READINGS = 2` leituras consecutivas com `PAC > 0`.
- Gap temporal entre leituras (> 2× intervalo mediano) reseta os contadores `seq_zero` e `rec_seq`.

### Carry-across de estado entre janelas

- `seq_zero` e `rec_seq` são persistidos no state e carregados na próxima varredura.
- A sequência de falha ou recuperação **acumula entre scans**.

### Gentle suppression (inversor ausente)

- Se um inversor some da lista por `INVERTER_MISSING_SCAN_TOLERANCE = 3` scans seguidos:
  - `ultima_confirmacao_ts` é zerado (sai do heartbeat).
  - `ativa = True` é preservado — não é normalizado.
  - Modelo at-least-once: duplicata eventual é preferível ao silêncio.

### Prioridade Relé → Inversor

- Se uma usina tem alerta de relé ativo, a varredura de inversores para essa usina é pulada.
- Evita alertas redundantes sobre a mesma causa raiz.

### Lista parcial de usinas (inversores)

- Usinas ausentes em lista parcial **não têm estado limpo** — estado de falha é preservado.

---

## Heartbeat

Mensagem enviada ao Teams confirmando que o monitor está ativo.

**Horários fixos:**
- 07:00, 12:00, 17:00, 20:00, 23:00

O heartbeat inclui contagem de alertas ativos de relé e inversores, além da última confirmação de cada inversor ativo. Um inversor só conta no heartbeat se sua `ultima_confirmacao_ts` estiver dentro de `INVERTER_HEARTBEAT_CONFIRMATION_TTL` (3 × `INVERTER_INTERVAL` + 60 s).

---

## Notificações Teams

- Envio via Incoming Webhook usando `_teams_post_card`.
- Retry automático em HTTP 429 respeitando o header `Retry-After` (`_parse_retry_after_seconds`).
- Retry em erros de rede (`Timeout`, `ConnectionError`) e HTTP 5xx com backoff exponencial.
- Notificações **não são enviadas dentro de locks** de threading — sempre fora do `_scan_lock`.
- Modelo at-least-once: falha no envio gera nova tentativa no próximo scan via `pending_notifications`.
- `notificado=True` não é marcado se o inversor já estiver `ativa=False`.
- Tipos de severidade: `"info"`, `"warning"`, `"danger"` (`SeverityLevel = Literal[...]`).

---

## Persistência de Estado

Arquivo: `state/monitor_state.json`

Escrita atômica via arquivo temporário + `os.replace` — sem corrupção parcial em caso de falha.

Campos relevantes:

| Campo | Descrição |
|---|---|
| `ultima_varredura_rele_por_usina` | Checkpoint por usina para relés |
| `ultima_varredura_inversor_por_usina` | Checkpoint por usina para inversores |
| `rele_alertas_ativos` | Alertas de relé em aberto |
| `estado_inversores` | Estado `EstadoInversor` por chave `usina_id:inversor_id` |
| `pending_notifications` | Notificações pendentes de retry |
| `historico_incidentes` | Incidentes encerrados (até `MAX_INCIDENT_HISTORY = 10000`, retenção 180 dias) |

`EstadoInversor` contém: `ativa`, `rec_seq`, `seq_zero`, `alerta`, `notificado`, `ausente_scans`, `ultima_confirmacao_ts`.

**Não edite o arquivo manualmente enquanto o monitor estiver rodando.**
Em caso de corrupção, o monitor faz backup (`.corrupt.TIMESTAMP`) e reinicia com estado limpo.

Falhas consecutivas ao salvar estado (`SAVE_STATE_FAIL_THRESHOLD = 3`) disparam notificação ao Teams.

---

## Relatório Semanal

- Gerado automaticamente às **00:05** (`WEEKLY_REPORT_GENERATION_TIME`).
- Verifica pendência a cada `WEEKLY_REPORT_CHECK_INTERVAL = 300` segundos.
- Exportado como `.zip` com XLSX de histórico de incidentes da semana.
- XLSX gerado sem dependências externas — implementação própria (`_write_xlsx_file`).
- Inclui `WEEKLY_REPORT_WARMUP_DAYS = 7` dias extras para reconstruir estado na borda da semana.
- Log de geração inclui janelas solares ativas: relé, inversor padrão e Ibimirim.

---

## Threading

Três threads permanentes gerenciadas por `stop_event` (`threading.Event`):

| Thread | Função | Intervalo |
|---|---|---|
| `_loop_scans` | Relé (10 min) e inversor (15 min) em sequência determinística | Espera `min(next_rele, next_inv)` |
| `_loop_heartbeat` | Heartbeat nos horários fixos | Espera até próximo horário |
| `_loop_weekly_report` | Relatório semanal | Verifica a cada 300 s |

- `_scan_lock` serializa varreduras; `_state_lock` protege leitura/escrita do state.
- Entre a varredura de relé e a de inversor, `_loop_scans` verifica `stop_event` — encerramento limpo mesmo no meio do ciclo.
- `STOP_JOIN_TIMEOUT = 35` s de espera para join das threads antes de forçar saída.

---

## Como rodar localmente

```bash
python main.py
```

Interrompa com `Ctrl+C`. O monitor salva estado e libera o lock antes de encerrar.

**Verificação de sintaxe:**
```bash
python -m py_compile main.py monitor_daemon.py
```

---

## Como rodar os testes

```bash
python -m pytest -q
```

A suíte cobre **104 testes** distribuídos em dois arquivos:

| Arquivo | Testes | Cobertura |
|---|---|---|
| `tests/test_main.py` | 101 | Relé, inversor, heartbeat, retry, gentle suppression, seq_zero carry-across, Teams 429, locking, reconciliação, merge de estado, relatório semanal, `_rele_param_ativo` (parametrizado) |
| `tests/test_hardening.py` | 3 | Teams retry/429, login retry com backoff, stop com scan_lock timeout |

**Sem chamadas reais à API ou ao Teams** — todos os testes usam mocks/monkeypatch.

---

## Como validar sem consumir API/Teams real

1. `TEAMS_ENABLED = False` no topo do `main.py` desabilita qualquer envio.
2. Defina uma URL de webhook inválida — as chamadas falharão silenciosamente (log de warning).
3. Use os testes existentes (`pytest -q`) para validar lógica sem dependências externas.
4. Para testar um fluxo manualmente, edite `monitor_state.json` para simular estado anterior.

---

## Deploy como serviço (Linux/systemd)

```ini
[Unit]
Description=PV Monitor Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/pvmonitor
ExecStart=/opt/pvmonitor/venv/bin/python3 /opt/pvmonitor/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable pvmonitor.service
sudo systemctl start pvmonitor.service
sudo systemctl status pvmonitor.service
```

**Windows:** use NSSM ou Task Scheduler apontando para `python main.py`.

---

## Logs

Rotacionados diariamente (retenção 7 arquivos):

| Logger | Arquivo |
|---|---|
| Geral | `logs/rele/rele.log` |
| Inversores | `logs/inversor/inversor.log` |

Marcadores úteis nos logs:
- `[HEARTBEAT]` — pulsação do monitor
- `[RELE] Falha` / `[RELE] Normalizacao`
- `[ALERTA INVERSOR]` / `[RECUPERACAO INVERSOR]`
- `[TEAMS] Falha ao enviar webhook`

---

## Configuração

Credenciais e webhook estão hardcoded em `main.py` por decisão operacional. Para ambientes onde isso não for aceitável, use variáveis de ambiente com substituição manual ou um sistema de segredos.

```python
PVOP_BASE_URL = "https://apipv.pvoperation.com.br/api/v1"
PVOP_EMAIL    = "..."
PVOP_PASSWORD = "..."
TEAMS_WEBHOOK_URL = "..."
TEAMS_ENABLED = True
```

SSL: defina `SSL_CERT_FILE` ou `REQUESTS_CA_BUNDLE` para apontar ao bundle de CA do servidor. Por padrão, `VERIFY_CA` lê essas variáveis e usa `True` (verificação padrão do `requests`) se nenhuma estiver definida.

---

## Checklist de Deploy

- [ ] Dependências instaladas: `pip install requests==2.32.3`
- [ ] Credenciais corretas em `main.py`
- [ ] Diretórios `state/`, `logs/` e `reports/` com permissão de escrita para o usuário do serviço
- [ ] `VERIFY_CA` aponta para o bundle de CA correto (se aplicável)
- [ ] Testes passando: `python -m pytest -q`
- [ ] Sintaxe validada: `python -m py_compile main.py`
- [ ] Serviço configurado para restart automático

---

## Estrutura dos principais arquivos

```
main.py                    — monitor principal (produção, ~2985 linhas)
monitor_daemon.py          — alternativa simplificada (legado)
state/monitor_state.json   — estado persistido entre execuções
state/.monitor_lock        — lock de instância única
logs/rele/rele.log         — logs de relé (rotação diária)
logs/inversor/inversor.log — logs de inversor (rotação diária)
reports/                   — relatórios semanais .zip gerados automaticamente
tests/test_main.py         — suíte principal (101 testes)
tests/test_hardening.py    — testes de endurecimento (3 testes)
```

---

## Arquitetura interna (funções de módulo)

Principais funções extraídas para nível de módulo (testáveis independentemente da classe):

| Função | Responsabilidade |
|---|---|
| `detectar_alertas_rele` | Avalia registros de relé e retorna alertas/normalizações |
| `detectar_falhas_inversores` | Avalia leituras de inversor e retorna falhas/recuperações |
| `_intervalo_atinge_janela` | Verifica se um intervalo de tempo toca a janela solar |
| `_montar_alerta_inversor` | Constrói o dict de alerta de inversor (DRY entre `rec` e `falha`) |
| `_compor_entrada_estado_inversor` | Monta `EstadoInversor` a partir do estado anterior e do novo |
| `_dedupe_por_base` | Remove alertas de relé duplicados pela chave base |
| `_alerta_ts_key` | Chave de ordenação estável para alertas por timestamp |
| `_resolver_alerta_rele` / `_ativar_alerta_rele` | Transições de estado de relé |
| `_parse_retry_after_seconds` | Extrai segundos do header `Retry-After` do Teams |
| `_is_ibimirim_usina` | Detecta usinas Ibimirim para aplicar janela solar diferenciada |
| `_obter_janela_solar_inversor` | Retorna `(janela_inicio, janela_fim)` de acordo com a usina |

A classe `MonitorService` orquestra os loops e usa essas funções como primitivas.

---

## Tipos de dados (TypedDicts)

Definidos em `main.py` para documentação — sem efeito em runtime:

| Tipo | Campos principais |
|---|---|
| `CardTeams` | `title`, `text`, `severity: SeverityLevel`, `facts` |
| `EstadoInversor` | `ativa`, `rec_seq`, `seq_zero`, `alerta`, `notificado`, `ausente_scans`, `ultima_confirmacao_ts` |
| `Incidente` | `chave`, `natureza`, `tipo_falha`, `usina_id`, `usina`, `equipamento`, `inicio_ts`, `fim_ts` |
| `SeverityLevel` | `Literal["info", "warning", "danger"]` |

---

## Limitações conhecidas

- Sem suporte a múltiplos webhooks Teams (apenas um canal configurado).
- Relatório semanal não inclui dados em tempo real da API no momento da geração — usa histórico do state.
- Gentle suppression não envia notificação explícita de "inversor sumiu" — apenas deixa de confirmar no heartbeat.
- `TEAMS_WEBHOOK_URL` hardcoded no repositório — não use este repositório em ambientes públicos.
