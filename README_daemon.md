# monitor_daemon.py - Daemon Simplificado

Alternativa simplificada ao `main.py` para monitoramento de reles e inversores. Ele roda como processo unico com lock de instancia, adequado para servico continuo.

> Recomendacao operacional: use `main.py` em producao. O `monitor_daemon.py` e uma versao de referencia mais enxuta e ainda nao possui todas as protecoes e refinamentos do `main.py`.

---

## Status

| | `main.py` | `monitor_daemon.py` |
|---|---|---|
| Uso recomendado | Producao | Alternativa / legado |
| Suite de testes | `pytest` do projeto | Testes de configuracao + validacao sintatica |
| Configuracao via ambiente | Sim | Sim |
| `PVOP_BASE_URL` configuravel | Sim | Sim |
| Gentle suppression | Sim | Nao |
| Retry Teams 429 com `Retry-After` | Sim | Nao |
| Checkpoint por `max_ts_processado` | Sim | Nao, usa `datetime.now()` |
| Janela Ibimirim | Sim | Nao |
| Relatorio semanal | Sim | Nao |
| Gap detection de `seq_zero` | Sim | Nao |
| Heartbeat | Sim | Nao |
| `tem_dados` rele so apos filtro temporal | Sim | Sim |
| Leituras sem PAC nao resetam sequencia | Sim | Sim |
| Lista parcial de usinas no rele | Sim | Sim |
| Estado preservado ao pular usina com rele | Sim | Sim |
| Lista parcial de usinas no inversor | Sim, com preservacao explicita | Parcial, apenas log |

---

## Configuracao

O daemon agora segue o mesmo contrato de configuracao sensivel do `main.py`: credenciais e webhook devem vir de variaveis de ambiente. Nao edite credenciais diretamente no `.py`.

| Variavel | Obrigatoria | Descricao |
|---|---:|---|
| `PVOP_BASE_URL` | Opcional | Endpoint base da API PVOperation. Tem default para o endpoint oficial, mas pode ser definido explicitamente para espelhar o `main.py`. |
| `MONITOR_EMAIL` | Sim | Usuario da API PVOperation |
| `MONITOR_PASSWORD` | Sim | Senha da API PVOperation |
| `TEAMS_WEBHOOK_URL` | Sim | URL do Incoming Webhook do Teams |
| `SSL_CERT_FILE` | Opcional | Bundle CA customizado |
| `REQUESTS_CA_BUNDLE` | Opcional | Bundle CA customizado |

Se uma variavel obrigatoria estiver ausente ou com placeholder, o daemon encerra na inicializacao com erro claro, sem imprimir valores sensiveis.

---

## Como executar

Linux/macOS:

```bash
export PVOP_BASE_URL="https://apipv.pvoperation.com.br/api/v1"
export MONITOR_EMAIL="seu_email@empresa.com"
export MONITOR_PASSWORD="sua_senha"
export TEAMS_WEBHOOK_URL="https://seu-webhook.office.com/..."
python monitor_daemon.py
```

Windows PowerShell:

```powershell
$env:PVOP_BASE_URL = "https://apipv.pvoperation.com.br/api/v1"
$env:MONITOR_EMAIL = "seu_email@empresa.com"
$env:MONITOR_PASSWORD = "sua_senha"
$env:TEAMS_WEBHOOK_URL = "https://seu-webhook.office.com/..."
python monitor_daemon.py
```

Interrompa com `Ctrl+C`. O monitor salva estado e libera o lock.

---

## Como testar sem API/Teams real

Nao execute `run_daemon()` contra API ou Teams reais em teste local.

Use mock/stub para `PVOperationAPI` e para o envio Teams, como nos testes do projeto. Para validacao local basica:

```bash
python -m py_compile monitor_daemon.py
python -m pytest -q
```

---

## Rodando como servico

Linux systemd:

```ini
[Unit]
Description=PV Monitor Daemon
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/pvmonitor
ExecStart=/opt/pvmonitor/venv/bin/python3 /opt/pvmonitor/monitor_daemon.py
Restart=always
Environment="PVOP_BASE_URL=https://apipv.pvoperation.com.br/api/v1" "MONITOR_EMAIL=email" "MONITOR_PASSWORD=senha" "TEAMS_WEBHOOK_URL=url"

[Install]
WantedBy=multi-user.target
```

Windows: use NSSM ou Task Scheduler. Nao use cron, porque o daemon roda continuamente.

Lock de instancia: `.monitor_lock` na pasta do script. Apenas uma instancia por vez.

---

## Diferencas intencionais em relacao ao main.py

As diferencas abaixo continuam documentadas de proposito. Nao porte comportamento novo para o daemon sem testes especificos e sem comparar com o `main.py`.

### 1. Sem gentle suppression

O daemon nao implementa `ultima_confirmacao_ts` nem o mecanismo de suprimir inversores ausentes. Um inversor que some dos dados sem normalizar permanece em `falhas_ativas_por_inv` ate que a API retorne dados de recuperacao.

### 2. Sem retry Teams 429 com `Retry-After`

O daemon nao le o header `Retry-After` nem implementa backoff em caso de 429 do Teams. Falhas de envio sao logadas.

### 3. Checkpoint por `datetime.now()`

A janela de cada varredura avanca pelo horario da chamada, nao pelo maior timestamp processado. Isso pode gerar pequenas sobreposicoes ou lacunas se a API retornar dados com atraso.

### 4. Lista parcial de usinas no inversor

O daemon detecta e loga lista parcial de usinas para inversores, mas nao implementa a preservacao explicita de estado ativo equivalente ao `main.py`. A ausencia de uma usina na lista nao atualiza seu estado em `falhas_ativas_por_inv`.

Para reles, a lista parcial e tratada: normalizacao fica limitada as usinas presentes na resposta da API.

### 5. Sem janela solar especial para Ibimirim

Todas as usinas usam a mesma janela solar de inversores. As usinas `COMP.IBI.2500.*` nao recebem a janela diferenciada que o `main.py` aplica.

### 6. Sem gap detection entre leituras

O daemon nao detecta saltos temporais entre leituras consecutivas. No `main.py`, um gap maior que 2 vezes o intervalo mediano reseta `seq_zero` e `rec_seq`.

### 7. Sem relatorio semanal

O daemon nao gera relatorios semanais.

### 8. `get_plants()` retorna `[]` em erro

No `main.py`, `get_plants()` retorna `None` para erro de API, diferenciando de lista vazia legitima. No daemon, qualquer erro retorna `[]`.

### 9. Sem heartbeat

O daemon nao envia heartbeat em horarios fixos. O `main.py` envia confirmacao de atividade em horarios configurados.

### 10. Normalizacao de rele sem notificacao Teams

Quando um alerta de rele e resolvido, o daemon remove o registro interno. O `main.py` envia notificacao de normalizacao ao Teams.

### 11. Estado de inversores mais simples

O daemon usa `falhas_ativas_por_inv` com estrutura `{chave: {ativa, rec_seq, seq_zero}}`. O `main.py` usa `estado_inversores` com campos adicionais como `alerta`, `notificado`, `ausente_scans` e `ultima_confirmacao_ts`.

---

## Arquivos relevantes

```text
monitor_daemon.py   - daemon simplificado
monitor_state.json  - estado persistido legado do daemon
.monitor_lock       - lock de instancia unica
```
