# Monitoramento OeM - Monitor Headless PVOperation

Este repositório contém um monitor headless para usinas fotovoltaicas. O processo principal é o `main.py`: ele consulta a API PVOperation, detecta falhas de relés e inversores, envia notificações para Microsoft Teams, mantém estado persistente em disco, gera heartbeat operacional e monta relatório semanal de incidentes.

O objetivo deste README é permitir que um desenvolvedor leia o projeto e entenda o funcionamento completo antes de alterar qualquer regra de negócio.

---

## Sumário

- [Visão geral](#visão-geral)
- [Arquivos principais](#arquivos-principais)
- [Dependências](#dependências)
- [Configuração](#configuração)
- [Como executar](#como-executar)
- [Arquitetura do main.py](#arquitetura-do-mainpy)
- [Fluxo de inicialização](#fluxo-de-inicialização)
- [Cliente PVOperation](#cliente-pvoperation)
- [Monitoramento de relés](#monitoramento-de-relés)
- [Monitoramento de inversores](#monitoramento-de-inversores)
- [Notificações Teams](#notificações-teams)
- [Heartbeat](#heartbeat)
- [Persistência de estado](#persistência-de-estado)
- [Relatório semanal](#relatório-semanal)
- [Threads, locks e concorrência](#threads-locks-e-concorrência)
- [Logs](#logs)
- [Testes](#testes)
- [Pontos sensíveis para manutenção](#pontos-sensíveis-para-manutenção)
- [Checklist antes de alterar o monitor](#checklist-antes-de-alterar-o-monitor)

---

## Visão geral

O monitor roda continuamente, sem interface gráfica. Ele executa três rotinas permanentes:

1. Varredura de relés e inversores.
2. Heartbeat em horários fixos.
3. Relatório semanal de incidentes.

As fontes de dados são os endpoints da API PVOperation:

- `GET /plants`
- `POST /day_relay`
- `POST /day_inverter`
- `POST /authenticate`

As notificações são enviadas via Incoming Webhook do Microsoft Teams. O monitor usa um modelo de entrega "at-least-once": em caso de falha no envio, ele prefere tentar reenviar depois, mesmo que isso possa gerar duplicidade eventual, em vez de perder um alerta real.

O estado é salvo em `state/monitor_state.json`. Esse arquivo é crítico: ele guarda checkpoints, alertas ativos, notificações pendentes, incidentes abertos e histórico de incidentes encerrados.

---

## Arquivos principais

| Caminho | Função |
|---|---|
| `main.py` | Monitor principal de produção. Contém configuração, API client, detecção, notificações, estado, heartbeat e relatório semanal. |
| `README.md` | Documentação principal do monitor completo. |
| `.env.example` | Modelo de variáveis de ambiente sem segredos reais. |
| `requirements.txt` | Dependências Python diretas. |
| `tests/` | Suíte de testes automatizados. |
| `diagnostics/diagnose_pvop_api.py` | Script auxiliar de diagnóstico da API PVOperation. |
| `state/monitor_state.json` | Estado persistido em runtime. Criado/atualizado pelo monitor. |
| `state/.monitor_lock` | Lock de instância única. |
| `logs/rele/rele.log` | Log rotativo específico do fluxo de relé. |
| `logs/inversor/inversor.log` | Log rotativo específico do fluxo de inversor. |
| `reports/` | Saída dos relatórios semanais `.xlsx`. |

---

## Dependências

O projeto usa poucas dependências externas:

```txt
requests==2.32.3
python-dotenv
```

Instalação recomendada:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
```

No Linux/macOS, a ativação do ambiente virtual muda para:

```bash
source .venv/bin/activate
```

Observação: `pytest` não está no `requirements.txt`, mas é necessário para rodar a suíte de testes local.

---

## Configuração

O `main.py` carrega `.env` automaticamente com `load_dotenv()` e também aceita variáveis já definidas no ambiente do processo.

Variáveis obrigatórias:

| Variável | Descrição |
|---|---|
| `PVOP_BASE_URL` | URL base da API PVOperation. Padrão de fallback: `https://apipv.pvoperation.com.br/api/v1`. |
| `MONITOR_EMAIL` | Usuário usado no `/authenticate`. |
| `MONITOR_PASSWORD` | Senha usada no `/authenticate`. |
| `TEAMS_WEBHOOK_URL` | Incoming Webhook do Teams. |

Variáveis opcionais:

| Variável | Descrição |
|---|---|
| `SSL_CERT_FILE` | Bundle CA customizado usado pelo `requests`. |
| `REQUESTS_CA_BUNDLE` | Alternativa ao `SSL_CERT_FILE`. |
| `RELE_DEBUG` | Quando `1` (ou `true`/`yes`/`on`), liga logs verbosos do circuito de relé: contagem de estado por varredura, payload bruto enviado ao Teams e resposta recebida. Use apenas para diagnóstico — desligue depois para não inchar `logs/rele/rele.log`. |

Exemplo:

```env
PVOP_BASE_URL=https://apipv.pvoperation.com.br/api/v1
MONITOR_EMAIL=monitoramento@empresa.com
MONITOR_PASSWORD=sua_senha
TEAMS_WEBHOOK_URL=https://seu-webhook.office.com/...
```

### Validação de configuração

Antes de iniciar, `main()` chama `validate_config()`. A validação encerra o processo com `SystemExit` se alguma variável obrigatória estiver vazia ou com placeholder.

São considerados inválidos:

- valor vazio;
- `None`;
- `COLE_AQUI`.

Mensagem de erro esperada:

```txt
Configuracao obrigatoria ausente ou placeholder em variaveis de ambiente: ...
```

Importante: o código atual exige `TEAMS_WEBHOOK_URL`. Mesmo que `_teams_post_card()` tenha uma guarda interna baseada em `TEAMS_ENABLED`, a inicialização de produção não passa sem webhook configurado.

### Segurança de segredos

Não coloque credenciais reais em `.env.example`, README, commits ou issues. O arquivo `.env` local não deve ser versionado. Os testes verificam que o exemplo não contém segredos reais.

---

## Como executar

Execução local:

```bash
python main.py
```

Encerramento:

```txt
Ctrl+C
```

Ao receber `SIGINT`, `SIGTERM` ou `KeyboardInterrupt`, o monitor chama `service.stop()`, salva estado e libera o lock de instância.

Validação rápida de sintaxe:

```bash
python -m py_compile main.py
```

Execução dos testes:

```bash
python -m pytest -q
```

---

## Arquitetura do main.py

O `main.py` está organizado em quatro camadas lógicas:

1. **Configuração e infraestrutura**
   - Variáveis de ambiente.
   - Diretórios.
   - Logging.
   - Validação de configuração.
   - Lock de instância.

2. **Integrações externas**
   - `PVOperationAPI`.
   - `_teams_post_card()`.

3. **Funções puras/de apoio**
   - Parsing numérico.
   - Geração XLSX.
   - Formatação de mensagens.
   - Extração/classificação de parâmetros de relé.
   - Detecção de falha de relé.
   - Detecção de falha de inversor.
   - Normalização de chaves.

4. **Orquestração**
   - `MonitorService`.
   - Loops de scan, heartbeat e relatório semanal.
   - Persistência de estado.
   - Transições de incidentes.
   - Envio de notificações.

### Tipos documentais

O arquivo define `TypedDicts` para documentar estruturas centrais:

| Tipo | Campos |
|---|---|
| `CardTeams` | `title`, `text`, `severity`, `facts` |
| `EstadoInversor` | `ativa`, `rec_seq`, `seq_zero`, `alerta`, `notificado`, `ausente_scans`, `ultima_confirmacao_ts` |
| `Incidente` | `chave`, `natureza`, `tipo_falha`, `usina_id`, `usina`, `equipamento`, `inicio_ts`, `fim_ts` |
| `SeverityLevel` | `Literal["info", "warning", "danger"]` |

Esses tipos ajudam os testes e a leitura, mas não impõem validação em runtime.

---

## Fluxo de inicialização

O fluxo de `main()` é:

1. `validate_config()`.
2. Cria um `PVOperationAPI` para relés.
3. Cria outro `PVOperationAPI` para inversores.
4. Cria `MonitorService(api_rele, api_inv)`.
5. Registra handlers para `SIGINT` e `SIGTERM`.
6. Chama `service.start()`.
7. Mantém o processo vivo em loop com `time.sleep(1)`.

O `service.start()` faz:

1. Adquire lock de instância única (`state/.monitor_lock`).
2. Carrega estado salvo (`_load_state()`).
3. Registra cleanup com `atexit`.
4. Cria e inicia três threads internas em segundo plano:
   - `_loop_scans`;
   - `_loop_heartbeat`;
   - `_loop_weekly_report`.

---

## Cliente PVOperation

Classe: `PVOperationAPI`.

Responsabilidades:

- manter `requests.Session`;
- autenticar no endpoint `/authenticate`;
- guardar `x-access-token`;
- renovar token em `401`;
- encapsular `get_plants()`;
- encapsular `post_day(endpoint, plant_id, date)`;
- aplicar retry/backoff em chamadas HTTP.

### Autenticação

`_login()` chama:

```http
POST {PVOP_BASE_URL}/authenticate
```

Payload:

```json
{
  "username": "MONITOR_EMAIL",
  "password": "MONITOR_PASSWORD"
}
```

Se a resposta for `200`, o cliente espera um campo `token` no JSON e passa a enviar:

```http
x-access-token: <token>
```

### Retry HTTP

Método central: `_request_with_retry()`.

Comportamento geral:

- retry padrão para `429` e `5xx`;
- retry configurável por chamada;
- recria sessão em `ConnectionError`/`RequestException`;
- tenta reautenticar quando aplicável;
- respeita `Retry-After` para `429`;
- faz backoff simples entre tentativas.

Configuração atual:

| Chamada | Timeout | Tentativas | Retry |
|---|---:|---:|---|
| `get_plants()` | 20s | 3 | padrão (`429`, `5xx`) |
| `post_day()` | 30s | 3 | `408`, `429`, `5xx` |
| `_login()` | 20s | sem wrapper central | sem loop próprio |
| `_teams_post_card()` | 10s | 3 | exceções e `429` |

### Flags de erro

O cliente mantém flags como:

- `last_get_plants_timeout`;
- `last_get_plants_error`;
- `last_post_day_timeout`;
- `last_post_day_error`;
- `last_post_day_error_reason`.

Essas flags são lidas pelo scanner para distinguir `TIMEOUT`, erro de API e ausência real de dados. No desenho atual, cada scan lê as flags imediatamente depois da chamada que acabou de fazer. Se algum dia houver paralelismo por usina, ou se a coleta semanal passar a compartilhar mais chamadas simultâneas com o scan, esse contrato precisará ser revisto, porque flags compartilhadas podem ser sobrescritas por outra chamada.

---

## Monitoramento de relés

Intervalo:

```python
RELAY_INTERVAL = 600  # 10 minutos
```

Endpoint consultado:

```txt
day_relay
```

Funções centrais:

- `detectar_alertas_rele()`;
- `_coletar_alertas_rele_usina()`;
- `_registrar_alerta_rele_detectado()`;
- `_registrar_resolucoes_rele()`;
- `_montar_jobs_notificacao_rele()`;
- `_aplicar_resultados_notificacao_rele()`;
- `_notificar_rele_agrupado()`.

### Quais usinas são varridas

O fluxo de relé só processa usinas cujo `id` está em `RELE_PLANT_IDS`.

Essa allowlist existe porque nem todas as usinas possuem relé de proteção monitorável. Se uma usina com relé real não estiver nessa lista, o monitor não detectará falhas de relé nela.

### Janela de busca

Na primeira execução do dia/processo sem checkpoint, o scanner usa:

```python
inicio_padrao = datetime.combine(agora.date(), datetime.min.time())
```

Depois disso, usa checkpoint por usina:

```python
ultima_varredura_rele_por_usina[usina_id] + 1 segundo
```

O checkpoint por usina avança com `max_ts_rele`, que é o maior `tsleitura` válido processado, não simplesmente `datetime.now()`.

Isso reduz risco de pular leituras atrasadas, desde que a API retorne dados com timestamps consistentes.

### Como os dados são lidos

`detectar_alertas_rele()` percorre do dia de `inicio` até o dia de `fim`. Para cada dia:

1. chama `api.post_day("day_relay", plant_id, data)`;
2. ignora resposta `None`;
3. itera registros com `_iterar_registros_api_dia()`;
4. extrai `conteudojson`;
5. parseia `tsleitura` no formato `%Y-%m-%d %H:%M:%S`;
6. filtra registros fora de `[inicio, fim]`;
7. extrai o identificador do relé;
8. extrai parâmetros ativos;
9. agrupa eventos por chave de alerta.

Campos aceitos para identificar relé:

- `idrele`;
- `idRele`;
- `IdRele`;
- `id_rele`;
- `conteudojson.idrele`;
- `conteudojson.Rele`;
- `conteudojson.rele`.

### O que conta como dado de relé

`tem_dados` vira `True` em duas situações:

1. a API retorna uma lista não-vazia para o dia, mesmo que nenhuma leitura esteja dentro da janela `[inicio, fim]`. Isso confirma comunicação com a usina e evita classificar como "sem dados" usinas com leituras esparsas;
2. existe pelo menos um registro com `conteudojson` válido, `tsleitura` parseável, timestamp dentro da janela e `idrele`/equivalente identificado.

A primeira regra foi reintroduzida porque a versão anterior só marcava `tem_dados=True` se houvesse leitura dentro da janela exata — o que jogava várias usinas para `usinas_sem_dados` em janelas vazias e pulava o processamento. O comportamento atual está alinhado com a versão funcional histórica (commit `7ac5717`).

Um payload sem parâmetro ativo ainda conta como dado: "sem parâmetro ativo" significa relé normal, não ausência de comunicação.

### O que conta como parâmetro ativo

Função: `_rele_param_ativo()`.

Valores ativos:

- booleano `True`;
- número exatamente `1`;
- string numérica equivalente a `1`;
- strings como `true`, `on`, `yes`, `sim`, `ativo`, `active`, `alarm`, `alarme`, `trip`, `tripped`, `y`, `t`.

Valores não ativos:

- `None`;
- `False`;
- `0`;
- números diferentes de `1`;
- strings vazias;
- strings não reconhecidas.

### Parâmetros monitorados

`RELAY_PARAMETROS` define os parâmetros conhecidos. O lookup é case-insensitive via `RELAY_PARAMETROS_LOOKUP`, então variações de capitalização da API não quebram a detecção.

Classificação atual:

| Tipo | Parâmetros |
|---|---|
| `SOBRETENSÃO` | `r59A`, `r59B`, `r59C`, `r59N` |
| `SUBTENSÃO` | `r27A`, `r27B`, `r27C`, `r27_0` |
| `FREQUÊNCIA` | `r81O`, `r81U` |
| `TÉRMICO` | `r49`, `r49_2` |
| `BLOQUEIO` | `rAR`, `rBA`, `rDO` |
| `OUTROS` | qualquer outro parâmetro conhecido ativo |

Se um registro tiver parâmetros de mais de uma classe, a primeira classe encontrada na ordem de `RELAY_PARAMS_CLASSIF` define o tipo do alerta.

### Chave de alerta de relé

A chave atual é:

```txt
usina_id:rele_id:tipo_alerta:parametros_normalizados
```

O código também reconhece chaves legadas sem parâmetros:

```txt
usina_id:rele_id:tipo_alerta
```

Quando encontra chave legada ativa, `_migrar_chave_rele_ativa()` migra o estado para a chave nova, incluindo:

- `rele_alertas_ativos`;
- `rele_notificados`;
- `rele_notificacao_retry_after`;
- `rele_alerta_chave`;
- `incidentes_rele_ativos`.

### Agrupamento

Dentro de uma mesma janela, alertas são agrupados por chave. O alerta final guarda:

- primeiro timestamp observado;
- último timestamp observado;
- relé;
- tipo;
- parâmetros;
- base/chave;
- usina;
- capacidade;
- texto de intervalo.

Se houver múltiplos registros da mesma falha, a notificação mostra o intervalo, por exemplo:

```txt
Primeiro alerta às 10:15 e último às 10:45
```

### Sem dados e timeout

Se uma usina não retorna dados de relé:

- o código loga `Sem dados de relé`;
- classifica o motivo como `TIMEOUT` ou `SEM_DADOS`;
- preserva alertas ativos daquela usina;
- não normaliza falhas por ausência de dado.

Se houver timeout parcial:

- o código loga `TIMEOUT_PARCIAL`;
- preserva alertas ativos;
- não normaliza falhas com base em leitura incompleta.

Essa decisão evita falso "normalizado" quando o problema está na coleta/API.

### Lista parcial de usinas

`_detectar_lista_parcial()` compara:

- usinas retornadas por `get_plants()`;
- usinas que já existem nos checkpoints;
- usinas presentes em alertas/estado.

Se uma usina esperada não aparece na lista da API, ela é considerada ausente em lista parcial. Para relés, essas usinas entram em `usinas_sem_dados`, preservando alertas ativos.

### Normalização de relé

Depois de processar as leituras válidas, o scanner compara:

- `rele_alertas_ativos` persistidos;
- `bases_ativos_atual` detectados na varredura atual.

Se uma base estava ativa antes e não apareceu agora, ela é resolvida por `_registrar_resolucoes_rele()`, desde que a usina não esteja em condição de sem dados/lista parcial.

Ao resolver:

- remove de `rele_alertas_ativos`;
- remove de `rele_alerta_chave`;
- remove de `rele_notificados`;
- remove de `rele_notificacao_retry_after`;
- fecha incidente em `incidentes_rele_ativos`;
- adiciona incidente encerrado ao histórico.

---

## Monitoramento de inversores

Intervalo:

```python
INVERTER_INTERVAL = 900  # 15 minutos
```

Endpoint consultado:

```txt
day_inverter
```

Funções centrais:

- `detectar_falhas_inversores()`;
- `_montar_alerta_inversor()`;
- `_compor_entrada_estado_inversor()`;
- `_reconciliar_inversores_ausentes()`;
- `_notificar_inversor()`;
- `_notificar_inversor_recuperado()`.

### Prioridade relé sobre inversor

Se uma usina possui alerta de relé ativo, o scanner de inversor pula essa usina:

```txt
Pulando inversores de <usina> devido a alerta de rele recente.
```

Motivo operacional: uma falha de relé pode ser causa raiz para inversores parados. O monitor evita gerar ruído redundante de inversor quando já existe alerta ativo de relé na mesma usina.

Ao pular por relé, o estado de inversor não é avançado nem limpo.

### Janelas solares

Inversores só são avaliados dentro da janela solar.

| Caso | Início | Fim |
|---|---:|---:|
| Padrão | 06:30 | 17:00 |
| Ibimirim (`COMP.IBI.2500.LT01` a `COMP.IBI.2500.LT05`) | 07:30 | 17:00 |

O nome de Ibimirim é detectado por substring case-insensitive em `_is_ibimirim_usina()`.

Relés usam a janela `SOLAR_WINDOW_START = 06:00` e `SOLAR_WINDOW_END = 17:30` para cálculo de indisponibilidade no relatório, não para filtrar a detecção operacional de relés.

### Janela de busca

Assim como no relé, a primeira varredura sem checkpoint começa em `00:00` do dia atual. Depois disso, cada usina usa:

```python
ultima_varredura_inversor_por_usina[usina_id] + 1 segundo
```

O checkpoint avança com `max_ts_inv`, o maior `tsleitura` válido com PAC parseável dentro da janela.

### Identificação do inversor

Campos aceitos:

- `idinversor`;
- `conteudojson.Inversor`;
- `conteudojson.esn`.

### Campos de potência aceitos

O código procura o primeiro campo existente nesta ordem:

1. `Pac`;
2. `PAC`;
3. `Potencia_Saida`;
4. `Pout`;
5. `Potencia`.

O valor é normalizado por `extrair_valor_numerico()`, que aceita:

- `int`;
- `float`;
- `bool`;
- strings numéricas;
- vírgula decimal;
- strings com unidade ou caracteres extras, desde que seja possível extrair um número.

### Falha de inversor

Regra:

```python
INVERTER_CONSECUTIVE_READINGS = 3
```

Uma falha é confirmada quando o inversor tem 3 leituras válidas consecutivas com:

```python
PAC <= 0
```

Isso inclui PAC negativo. PAC negativo não conta como recuperação.

PAC ausente ou não parseável:

- entra como leitura `sem_dados`;
- não incrementa `seq_zero`;
- não incrementa `rec_seq`;
- não confirma falha;
- não confirma recuperação.

### Recuperação de inversor

Regra:

```python
INVERTER_RECOVERY_CONSECUTIVE_READINGS = 2
```

Um inversor ativo é normalizado quando tem 2 leituras válidas consecutivas com PAC positivo.

Ao normalizar:

- `ativa` vira `False`;
- `alerta` é limpo;
- `notificado` volta para `False`;
- `ultima_confirmacao_ts` é zerado;
- o incidente ativo é encerrado;
- uma notificação de normalização é enviada.

### Contadores persistidos

O estado por inversor preserva:

- `seq_zero`: sequência atual de PAC zero/negativo;
- `rec_seq`: sequência atual de PAC positivo;
- `ultima_confirmacao_ts`: última leitura que confirmou que a falha ainda estava ativa;
- `ausente_scans`: quantas varreduras válidas não viram mais aquele inversor.

Isso permite que a confirmação de falha ou recuperação continue entre scans diferentes.

### Gaps temporais

Para cada inversor, o código calcula o intervalo mediano entre leituras válidas. Se houver gap maior que duas vezes esse intervalo esperado, os contadores `seq_zero` e `rec_seq` são resetados.

Objetivo: evitar que leituras muito distantes sejam tratadas como sequência contínua.

### Sem dados de inversor

Se `detectar_falhas_inversores()` não encontra dados válidos:

- durante janela solar: a usina segue como sem dados;
- depois da janela solar, uma resposta vazia pode ser tratada como cauda normal e não como sem dados real;
- erros de API e timeouts não são tratados como ausência real de dados.

O log tenta informar o serial do inversor quando existe estado anterior ou dados parciais suficientes.

### Reconciliação de inversores ausentes

Função: `_reconciliar_inversores_ausentes()`.

Quando uma usina tem resposta válida, mas um inversor ativo não aparece entre os observados:

1. incrementa `ausente_scans`;
2. enquanto estiver abaixo de `INVERTER_MISSING_SCAN_TOLERANCE`, mantém tudo;
3. ao atingir a tolerância, limpa `ultima_confirmacao_ts`;
4. mantém `ativa=True`.

Configuração:

```python
INVERTER_MISSING_SCAN_TOLERANCE = 3
```

Isso faz o inversor sair do heartbeat, mas não encerra o incidente. A regra evita normalização falsa quando o equipamento simplesmente deixou de aparecer nos dados.

---

## Notificações Teams

Função central:

```python
_teams_post_card()
```

Formato enviado:

- MessageCard;
- `summary`;
- `themeColor`;
- `title`;
- `text`;
- `sections.facts`, quando houver.

Severidades:

| Severidade | Cor |
|---|---|
| `info` | `0078D4` |
| `warning` | `FFA000` |
| `danger` | `D13438` |

### Política de retry

O envio tenta até 3 vezes por padrão. Esse mesmo valor é usado tanto para relé quanto para inversor — não há mais a configuração antiga `max_tentativas=1` que era exclusiva do relé.

Tratamentos:

- HTTP `429`: respeita `Retry-After`, limitado a 60s;
- exceções: retry com backoff simples;
- resposta com corpo contendo `Webhook message delivery failed`: tratada como falha mesmo se HTTP for `200`. O corpo completo da resposta (até 500 chars) é logado em `WARNING` para diagnóstico;
- toda tentativa que falha (não só a última) é logada como `WARNING` com `status` HTTP, tipo de exceção e prefixo do corpo. Isso é essencial para diagnosticar webhooks que falham sistematicamente;
- falha final: retorna `False`.

### Cooldown de retry de relé

Quando o envio de um alerta de relé falha, o sistema agenda um retry para evitar marteladas:

```python
RELAY_NOTIFICATION_RETRY_COOLDOWN = timedelta(seconds=RELAY_INTERVAL // 2)  # 5 minutos
```

O cooldown é deliberadamente menor que `RELAY_INTERVAL` (10 min). Se fosse igual, a varredura seguinte cairia exatamente no instante em que `_retry_rele_adiado()` ainda retorna `True`, e o alerta ficaria pulando uma execução inteira. Com cooldown de 5 min, a próxima varredura sempre reprocessa.

Além dos alertas redetectados pela API, cada varredura chama `_reenfileirar_retries_rele_ativos()`. Essa função reconstrói o lote de envio a partir de `rele_alertas_ativos` e `rele_alerta_chave` quando:

- a base ainda está ativa;
- a base ainda não está em `rele_notificados`;
- não existe `retry_after` futuro bloqueando o envio.

Isso evita perder a notificação quando o primeiro envio falha e, nos scans seguintes, a usina passa a retornar `SEM_DADOS`, timeout parcial ou lista parcial. Nesses casos, o alerta ativo continua preservado no state e o retry é remontado a partir dos detalhes persistidos, sem depender de a API repetir a leitura ativa do relé.

### Relés

Relés são notificados agrupados por usina.

Tipos de card:

- falha de relé: `danger` para `SOBRETENSÃO`/`TÉRMICO`/`BLOQUEIO`, `warning` para os demais tipos;
- normalização de relé: `info`.

O `text` dos cards de relé usa o mesmo padrão markdown do card de inversor (`**Campo:** valor`), alinhando o renderer no Teams e evitando que o card seja rejeitado por regras de conteúdo que recusam texto iniciado por whitespace.

Falha no envio de alerta novo:

- a base fica ativa;
- não entra em `rele_notificados`;
- recebe `retry_after` em `rele_notificacao_retry_after`;
- será reenviada em scan futuro quando a API redetectar o alerta ou quando `_reenfileirar_retries_rele_ativos()` reconstruir o job a partir do state ativo.

Falha no envio de normalização:

- a normalização fica em `pending_notifications["rele_normalizados"]`;
- será reenviada depois.

### Inversores

Inversores são notificados por evento.

Tipos:

- `falha`;
- `falha_resend`;
- `rec`;
- `rec_retry`.

Falha ativa não notificada pode gerar `falha_resend` no próximo scan. Normalização pendente fica em `pending_notifications["inv_normalizados"]`.

### Importante sobre ordem de persistência

O código evita marcar uma falha como notificada antes de confirmar sucesso no Teams. Isso é essencial para não perder alertas.

---

## Heartbeat

O heartbeat é enviado ao Teams em horários fixos:

```python
HEARTBEAT_TIMES = [
    dtime(7, 0),
    dtime(12, 0),
    dtime(17, 0),
    dtime(20, 0),
    dtime(23, 0),
]
```

Função central:

```python
_enviar_heartbeat()
```

O texto inclui:

- status geral;
- indicação de scan de relé atrasado;
- indicação de scan de inversor atrasado;
- última varredura de relé;
- última varredura de inversor;
- host/PID;
- horário previsto do heartbeat;
- quantidade de alertas de relé ativos;
- lista de usinas com relé ativo;
- quantidade de inversores ativos;
- contagem de inversores ativos por usina.

### Scan atrasado

Relé atrasado:

```python
agora - ultima_varredura_rele > 2 * RELAY_INTERVAL
```

Inversor atrasado:

```python
agora - ultima_varredura_inversor > 2 * INVERTER_INTERVAL
```

### Inversor no heartbeat

Um inversor só entra no heartbeat se:

- `ativa=True`;
- possui `ultima_confirmacao_ts`;
- a confirmação é recente.

TTL:

```python
INVERTER_HEARTBEAT_CONFIRMATION_TTL = (INVERTER_INTERVAL * 3) + 60s
```

Com `INVERTER_INTERVAL = 900`, isso equivale a 46 minutos.

Se o inversor ativo deixa de aparecer por scans consecutivos, `ultima_confirmacao_ts` é removido e ele sai do heartbeat sem encerrar o incidente.

---

## Persistência de estado

Arquivo:

```txt
state/monitor_state.json
```

Schema atual:

```python
STATE_SCHEMA_VERSION = 1
```

Escrita:

1. monta payload completo;
2. escreve em `monitor_state.json.tmp`;
3. substitui o arquivo real com `os.replace()`.

Isso reduz risco de arquivo parcialmente escrito.

### Campos principais

| Campo | Descrição |
|---|---|
| `schema_version` | Versão do schema de estado. |
| `ultima_varredura_rele` | Última varredura global de relé. |
| `ultima_varredura_inversor` | Última varredura global de inversor. |
| `ultima_varredura_rele_por_usina` | Checkpoint por usina para relé. |
| `ultima_varredura_inversor_por_usina` | Checkpoint por usina para inversor. |
| `rele_alertas_ativos` | Bases de alertas de relé atualmente ativos. |
| `rele_notificados` | Bases de relé já notificadas com sucesso. |
| `rele_notificacao_retry_after` | Próximo momento permitido para retry de alerta de relé. |
| `rele_alerta_chave` | Detalhes formatados de cada alerta de relé ativo. Também é usado para reconstruir retries de alertas ativos ainda não notificados. |
| `estado_inversores` | Estado por chave `usina_id:inversor_id`. |
| `pending_notifications` | Normalizações pendentes de envio. |
| `incidentes_rele_ativos` | Incidentes de relé em aberto. |
| `incidentes_inv_ativos` | Incidentes de inversor em aberto. |
| `historico_incidentes` | Incidentes encerrados. |
| `last_weekly_report_id` | Semana já reportada. |

### Limites

```python
MAX_PENDING_RELE_POR_USINA = 200
MAX_PENDING_INV = 400
MAX_INCIDENT_HISTORY = 10000
INCIDENT_RETENTION_DAYS = 180
```

`_limitar_historico_incidentes()` aplica:

- truncamento por tamanho sempre que necessário;
- limpeza por data com throttle de 1 hora.

### Recuperação de state legado

`_load_state()` contém migração/compatibilidade para formatos antigos:

- chaves de inversor com `_` são convertidas para `:`;
- estruturas booleanas antigas viram dicts;
- `inv_notificados`, `falhas_ativas_por_inv` e `inversores_ativos` são reconciliados;
- chaves legadas de relé são carregadas sem quebrar.

### State corrompido

Se o JSON estiver inválido ou o schema for incompatível:

1. o arquivo atual é movido para backup `.corrupt.<timestamp>`;
2. o processo reinicia com estado default;
3. o evento é logado.

Isso evita que o processo fique preso em loop por state inválido.

### Falha ao salvar state

Se `_save_state()` falhar, incrementa `_save_state_fail_count`. Ao atingir:

```python
SAVE_STATE_FAIL_THRESHOLD = 3
```

o monitor envia alerta Teams:

```txt
Monitor: falha ao salvar estado
```

---

## Relatório semanal

Thread:

```python
_loop_weekly_report()
```

Configuração:

```python
WEEKLY_REPORT_CHECK_INTERVAL = 300  # 5 minutos
WEEKLY_REPORT_GENERATION_TIME = dtime(0, 5)
WEEKLY_REPORT_WARMUP_DAYS = 7
```

O relatório é gerado após 00:05 da segunda-feira, para a semana anterior.

### Período

`_inicio_semana()` usa segunda-feira como início da semana:

```python
dt_ref.date() - timedelta(days=dt_ref.weekday())
```

O `report_id` é a data ISO do início da semana reportada. Isso impede gerar o mesmo relatório mais de uma vez.

### Fontes

O relatório combina:

1. incidentes do state local;
2. incidentes reconstruídos diretamente da API.

Se a coleta da API falhar, o relatório ainda pode ser gerado usando apenas o state local.

### Backfill da API

Para reduzir erro na borda da semana, a coleta direta da API busca a semana reportada mais 7 dias de warmup anteriores.

Relés:

- reconstrói incidentes por relé a partir das mudanças de identidade ativa;
- separa eventos de mesmo tipo com parâmetros diferentes.

Inversores:

- reutiliza `detectar_falhas_inversores()` sobre o período semanal;
- reconstrói pares falha/recuperação.

### Saída

Arquivo:

```txt
reports/relatorio_semanal_<inicio>_<fim>.xlsx
```

O XLSX é escrito sem dependência externa. O código monta internamente:

- `[Content_Types].xml`;
- `_rels/.rels`;
- `xl/workbook.xml`;
- `xl/worksheets/sheet*.xml`;
- demais arquivos mínimos do formato.

Abas:

| Aba | Conteúdo |
|---|---|
| `Resumo` | Agregado por semana, usina, natureza e tipo de falha. |
| `Ocorrencias` | Lista detalhada de cada ocorrência, equipamento e duração. |

### Métricas de indisponibilidade

Cada ocorrência calcula:

- duração total no período da semana;
- duração dentro da janela solar aplicável;
- horas de indisponibilidade solar.

Para inversores, a janela solar respeita regra especial de Ibimirim. Para relés, usa `SOLAR_WINDOW_START = 06:00` e `SOLAR_WINDOW_END = 17:30`.

---

## Threads, locks e concorrência

O monitor usa três threads internas em segundo plano:

| Thread | Função |
|---|---|
| `_loop_scans` | Executa relé e inversor em sequência. |
| `_loop_heartbeat` | Espera próximo horário fixo e envia heartbeat. |
| `_loop_weekly_report` | Verifica e gera relatório semanal. |

### `_scan_lock`

Serializa:

- atualização de estado durante scans;
- leitura de estado pelo heartbeat;
- aplicação de resultados de notificação;
- parte final do relatório semanal.

Chamadas de API de scan hoje ocorrem dentro do `_scan_lock`. Envio para Teams acontece fora do lock principal nos scans, o que reduz bloqueio enquanto o webhook responde.

### `_state_lock`

Protege escrita atômica do arquivo de state.

### Lock de instância

Arquivo:

```txt
state/.monitor_lock
```

No Unix, usa `fcntl`. No Windows, usa `msvcrt`. O objetivo é impedir duas instâncias simultâneas do monitor usando o mesmo state.

### Encerramento

`stop()`:

1. seta `stop_event`;
2. aguarda cada thread por até `STOP_JOIN_TIMEOUT = 35` segundos;
3. tenta adquirir `_scan_lock` por até 1 segundo;
4. salva state;
5. libera lock de instância.

Mesmo se alguma thread estiver viva, o código tenta persistir um snapshot antes de sair.

---

## Logs

Configuração:

- logger base: `RelayMonitorHeadless`;
- logger de relé: `RelayMonitorHeadless.rele`;
- logger de inversor: `RelayMonitorHeadless.inversor`.

Saídas:

| Logger | Destino |
|---|---|
| `RelayMonitorHeadless` | Console. |
| `RelayMonitorHeadless.rele` | Console + `logs/rele/rele.log`. |
| `RelayMonitorHeadless.inversor` | Console + `logs/inversor/inversor.log`. |

Arquivos usam `TimedRotatingFileHandler`:

- rotação diária à meia-noite;
- `backupCount=7`;
- encoding UTF-8.

Marcadores úteis:

| Marcador | Significado |
|---|---|
| `[HEARTBEAT]` | Heartbeat gerado/logado. |
| `[SCAN]` | Duração de fase de scan. |
| `[RELE]` | Eventos internos do fluxo de relé (detecção, supressão, retry adiado). |
| `[RELE][SEND]` | Tentativa de envio de card de relé para Teams. Loga `title`, `severity`, `bases` e o resultado (`ok=True/False`). |
| `[RELE][DEBUG]` | Diagnóstico verboso do relé. Aparece apenas com `RELE_DEBUG=1`. |
| `[ALERTA INVERSOR]` | Falha de inversor notificada/logada. |
| `[RECUPERACAO INVERSOR]` | Recuperação de inversor notificada/logada. |
| `[TEAMS]` | Tentativa, falha ou detalhe de webhook. Toda tentativa que falha vira `WARNING` (não só a última), com `status` HTTP e prefixo do corpo da resposta. |
| `[TEAMS][DEBUG]` | Payload bruto enviado e corpo de resposta recebido. Aparece apenas com `RELE_DEBUG=1`. |
| `[RELATORIO]` | Coleta e geração do relatório semanal. |

---

## Testes

Comando:

```bash
python -m pytest -q
```

Coleta atual:

```txt
134 tests collected
```

Na última execução local nesta estação:

```txt
134 passed in 2.10s
```

Arquivos:

| Arquivo | Foco |
|---|---|
| `tests/test_main.py` | Regras principais de relé, inversor, estado, heartbeat, relatório, Teams e edge cases. |
| `tests/test_hardening.py` | Retry, 429, falhas de Teams, login e shutdown. |

Áreas cobertas:

- validação de configuração sem expor segredos;
- `.env.example` sem segredos reais;
- janela solar padrão e Ibimirim;
- falha de inversor por 3 leituras PAC zero/negativo;
- recuperação por 2 leituras PAC positivo;
- PAC ausente/inválido;
- resposta vazia dentro e fora da janela solar;
- erro de API versus ausência real de dados;
- lista parcial de usinas;
- preservação de alertas ativos em timeout;
- notificações Teams fora do `_scan_lock`;
- retry de Teams;
- retry de alerta de relé ativo mesmo sem nova leitura válida da API;
- falha de webhook com HTTP 200 mas corpo de erro;
- pending notifications;
- state legado;
- incidentes ativos e encerrados;
- relatório semanal XLSX;
- merge de API + state no relatório;
- heartbeat OK e scan atrasado;
- cache de plantas;
- backup/reset de state inválido;
- limites de histórico e pendências;
- chaves legadas e novas de relé.

Os testes usam mocks/fakes/monkeypatch. Eles não fazem chamada real à API PVOperation nem ao Teams.

## Pontos sensíveis para manutenção

### 1. Não confundir "sem dados" com "normalizado"

Relés e inversores preservam estado ativo quando a API falha, retorna timeout, lista parcial ou dados insuficientes. Alterar isso pode gerar normalização falsa.

### 2. Ordem de persistência e notificação importa

Não marque alerta como notificado antes do Teams confirmar sucesso. Se fizer isso, uma queda de rede pode causar perda definitiva de alerta.

### 3. Chaves de relé incluem parâmetros

A chave nova de relé inclui parâmetros normalizados. Isso permite separar falhas de mesmo relé e mesmo tipo, mas com parâmetros diferentes.

### 4. Inversor ativo pode sair do heartbeat sem normalizar

Isso é intencional. `ausente_scans` e `ultima_confirmacao_ts` controlam visibilidade no heartbeat, mas não encerram o incidente.

### 5. O cliente API não é preparado para paralelismo amplo

`PVOperationAPI` possui `Session`, token e flags de erro mutáveis. Antes de paralelizar chamadas, revise esse contrato.

### 6. O relatório semanal usa API e state

O relatório não depende somente do state local. Ele também tenta reconstruir incidentes pela API com warmup. Mudanças no scanner podem afetar relatório indiretamente.

### 7. O agendamento é baseado no fim do scan

O próximo scan é calculado depois que a varredura termina. Se uma varredura demorar, o intervalo real aumenta. Isso é simples e evita acúmulo de execuções, mas impacta tempo de detecção sob lentidão da API.

### 8. `.env` é obrigatório em produção

O código atual não mantém credenciais hardcoded sensíveis. Se o processo iniciar sem `.env`/variáveis reais, ele deve falhar rápido.

---

## Checklist antes de alterar o monitor

Antes de qualquer mudança funcional:

1. Leia a regra atual no `main.py`.
2. Identifique se a mudança afeta relé, inversor, Teams, state, heartbeat ou relatório.
3. Verifique se existe teste cobrindo o comportamento atual.
4. Se mexer em notificação, teste:
   - sucesso de envio;
   - falha de envio;
   - retry;
   - reinício com estado pendente.
5. Se mexer em detecção, teste:
   - falha nova;
   - falha já ativa;
   - normalização;
   - timeout;
   - resposta vazia;
   - lista parcial;
   - dado inválido.
6. Se mexer em state, teste carregamento de state antigo e state corrompido.
7. Rode:

```bash
python -m py_compile main.py
python -m pytest -q
```

8. Confira `git diff` para garantir que não houve alteração acidental em credenciais, state real ou logs.

---

## Resumo operacional rápido

| Item | Valor atual |
|---|---|
| Relé | Scan a cada 10 minutos. |
| Inversor | Scan a cada 15 minutos. |
| Heartbeat | 07:00, 12:00, 17:00, 20:00, 23:00. |
| Relatório semanal | Segunda-feira após 00:05, referente à semana anterior. |
| Falha de inversor | 3 leituras consecutivas com `PAC <= 0`. |
| Recuperação de inversor | 2 leituras consecutivas com `PAC > 0`. |
| Supressão de inversor ausente | 3 scans válidos sem observação. |
| TTL de inversor no heartbeat | 46 minutos. |
| Retry Teams | 3 tentativas. |
| Timeout `post_day` | 30 segundos por tentativa. |
| State | `state/monitor_state.json`. |
| Lock | `state/.monitor_lock`. |
| Logs de relé | `logs/rele/rele.log`. |
| Logs de inversor | `logs/inversor/inversor.log`. |
| Testes | 135 casos coletados pelo pytest. |
