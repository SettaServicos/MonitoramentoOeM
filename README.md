# Monitoramento OeM (Runtime)

Documento operacional do servico headless que monitora reles e inversores via PVOperation API, gera alertas e envia notificacoes para o Microsoft Teams. O sistema opera 24/7, preserva estado persistente e publica heartbeat periodico.

## 1. Visao geral
- Monitora reles e inversores com varreduras periodicas.
- Deduplica alertas por base (usina:rele:tipo).
- Envia notificacoes de falha e normalizacao via Teams.
- Mantem estado e lock de instancia unica.

## 2. Escopo funcional
- Varredura de reles (intervalo configurado em `RELAY_INTERVAL`).
- Varredura de inversores (intervalo configurado em `INVERTER_INTERVAL`).
- Heartbeat em horarios definidos por `HEARTBEAT_TIMES`.
- Persistencia de state para retomada segura.

## 3. Estrutura do projeto
- `main.py`: entrypoint, configuracao e runtime.
- `logs/`: logs rotativos por dominio.
- `state/`: state e lock da instancia.
- `tests/`: testes atuais compativeis com `main.py`.
- `deletar/`: conteudo legado/QA (ignorado pelo pytest).

## 4. Fluxo de execucao (alto nivel)
1) Inicio: valida configuracao, cria lock e carrega state.
2) Threads: loop de varredura (rele/inversor) e loop de heartbeat.
3) Varreduras: consolida alertas, aplica dedupe e envia Teams.
4) Encerramento: salva state e libera lock ao receber SIGINT/SIGTERM.

## 5. Requisitos
- Python 3.12+ (ou compativel).
- Dependencias: `pip install -r requirements.txt`.

## 6. Configuracao
Edite a secao `CONFIGURACAO (EDITAR AQUI)` no topo de `main.py`:
- `PVOP_BASE_URL`
- `PVOP_EMAIL`
- `PVOP_PASSWORD`
- `TEAMS_WEBHOOK_URL`
- `TEAMS_ENABLED`

Se algum valor estiver vazio ou como `COLE_AQUI`, o processo encerra com erro explicito.

## 7. SSL/CA (ambiente)
Se necessario, configure:
- `SSL_CERT_FILE` ou `REQUESTS_CA_BUNDLE`

Essas variaveis apontam para o bundle de CA valido no servidor.

## 8. Operacao
### 8.1 Execucao
- Comando unico: `python main.py`
- Execucao continua ate interrupcao manual (Ctrl+C/SIGTERM).

### 8.2 Encerramento seguro
- SIGINT/SIGTERM: salva state, libera lock e encerra com log.
- Lock de instancia unica: `state/.monitor_lock`.

## 9. Observabilidade
- Logs:
  - `logs/rele/rele.log`
  - `logs/inversor/inversor.log`
- Rotacao diaria com historico limitado (`backupCount=7`).
- State: `state/monitor_state.json` (gravacao atomica via arquivo temporario).

## 10. Testes
- `pytest -q`
- O pytest esta configurado para rodar apenas `tests/` e ignorar `deletar/`.

## 11. Validacao
- Relatorio consolidado: `VALIDATION_REPORT.md`.

## 12. Observacoes e limitacoes
- Webhook comum do Teams nao permite atualizar um card existente; para isso, use Flow/Graph.
- Conteudo legado permanece em `deletar/` e nao participa da execucao ou testes.
