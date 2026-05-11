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

## Arquivo de produção recomendado

| Arquivo | Uso |
|---|---|
| `main.py` | **Produção** — lógica completa e validada |
| `monitor_daemon.py` | Alternativa simplificada — veja `README_daemon.md` |

---

## Monitoramento de Relés

### Como funciona

- Varredura a cada **10 minutos** (`RELAY_INTERVAL = 600`).
- Para cada usina, consulta `day_relay` no intervalo `[ultima_varredura + 1s, agora]`.
- Registros são filtrados pelo timestamp `tsleitura` dentro do intervalo.
- `tem_dados` só é `True` após passar o filtro temporal — dado fora da janela não conta.
- O checkpoint avança por `max_ts_processado` (timestamp máximo processado), não por `datetime.now()`.

### Detecção de alerta

- Parâmetros do relé (`PARAMETROS_RELE`) com valor ativo (`True`, `1`, `"true"`) indicam falha.
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
| OUTROS | demais parâmetros |

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
| Ibimirim (`COMP.IBI.2500.*`) | 07:30 | 17:00 |

### Regras de falha

- `PAC <= 0` (incluindo negativos) = leitura de falha.
- PAC ausente ou não parseável **não conta** como leitura válida — não mascara ausência de dado.
- **Falha confirmada:** `INVERTER_CONSECUTIVE_READINGS = 3` leituras consecutivas com `PAC <= 0`.
- Ao confirmar falha, notificação enviada ao Teams.

### Regras de recuperação

- **Recuperação confirmada:** `INVERTER_RECOVERY_CONSECUTIVE_READINGS = 2` leituras consecutivas com `PAC > 0`.
- Gap temporal entre leituras (> 2× intervalo mediano) reseta os contadores de sequência.

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

---

## Notificações Teams

- Envio via Incoming Webhook.
- Retry automático em HTTP 429 respeitando o header `Retry-After`.
- Notificações **não são enviadas dentro de locks** de threading.
- Modelo at-least-once: falha no envio gera nova tentativa no próximo scan.
- `notificado=True` não é marcado se o inversor já estiver `ativa=False`.

---

## Persistência de Estado

Arquivo: `state/monitor_state.json`

Campos relevantes:

| Campo | Descrição |
|---|---|
| `ultima_varredura_rele_por_usina` | Checkpoint por usina para relés |
| `ultima_varredura_inversor_por_usina` | Checkpoint por usina para inversores |
| `rele_alertas_ativos` | Alertas de relé em aberto |
| `estado_inversores` | Estado de falha/seq por inversor (inclui `seq_zero`, `rec_seq`, `ultima_confirmacao_ts`) |
| `pending_notifications` | Notificações pendentes de retry |
| `historico_incidentes` | Incidentes encerrados (até `MAX_INCIDENT_HISTORY = 10000`, retenção 180 dias) |

**Não edite o arquivo manualmente enquanto o monitor estiver rodando.**
Em caso de corrupção, o monitor faz backup (`.corrupt.TIMESTAMP`) e reinicia com estado limpo.

---

## Relatório Semanal

- Gerado automaticamente às **00:05** de uma data configurada (`WEEKLY_REPORT_GENERATION_TIME`).
- Verifica pendência a cada `WEEKLY_REPORT_CHECK_INTERVAL = 300` segundos.
- Exportado como arquivo compactado `.zip` com histórico de incidentes da semana.
- Log de geração inclui janelas solares ativas: relé, inversor padrão e Ibimirim.

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

A suíte cobre 61 casos: fluxos de relé, inversor, heartbeat, retry, gentle suppression, seq_zero carry-across, Teams 429, locking, reconciliação P2/P3/P4 e merge de estado.

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

Rotacionados diariamente:

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

SSL: defina `SSL_CERT_FILE` ou `REQUESTS_CA_BUNDLE` para apontar ao bundle de CA do servidor.

---

## Checklist de Deploy

- [ ] Dependências instaladas: `pip install requests`
- [ ] Credenciais corretas em `main.py` ou variáveis de ambiente configuradas no serviço
- [ ] Diretórios `state/` e `logs/` com permissão de escrita para o usuário do serviço
- [ ] `VERIFY_CA` aponta para o bundle de CA correto (se aplicável)
- [ ] Testes passando: `python -m pytest -q`
- [ ] Sintaxe validada: `python -m py_compile main.py`
- [ ] Serviço configurado para restart automático

---

## Estrutura dos principais arquivos

```
main.py                  — monitor principal (produção)
monitor_daemon.py        — alternativa simplificada (legado)
state/monitor_state.json — estado persistido entre execuções
state/.monitor_lock      — lock de instância única
logs/rele/rele.log       — logs de relé
logs/inversor/inversor.log — logs de inversor
tests/test_main.py       — suíte principal (58 testes)
tests/test_hardening.py  — testes de endurecimento (3 testes)
```

---

## Limitações conhecidas

- Sem detecção de lista parcial para `day_relay` individual (apenas para a lista de usinas).
- Sem suporte a múltiplos webhooks Teams (apenas um canal configurado).
- Relatório semanal não inclui dados em tempo real da API no momento da geração — usa histórico do state.
- Gentle suppression não envia notificação explícita de "inversor sumiu" — apenas deixa de confirmar no heartbeat.
- `TEAMS_WEBHOOK_URL` hardcoded no repositório — não use este repositório público.
