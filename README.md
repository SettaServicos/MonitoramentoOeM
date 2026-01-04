# Monitoramento OeM (Runtime)

## Requisitos
- Python 3.12 (ou compativel)
- Instalar dependencias: `pip install -r requirements.txt`

## Configuracao (editar no topo do main.py)
Edite a secao `CONFIGURACAO (EDITAR AQUI)` e substitua os placeholders:
- `PVOP_BASE_URL`
- `PVOP_EMAIL`
- `PVOP_PASSWORD`
- `TEAMS_WEBHOOK_URL`
- `TEAMS_ENABLED`

Se algum valor estiver vazio ou como `COLE_AQUI`, o script falha cedo com mensagem clara.

## Execucao
- Comando unico: `python main.py`
- Execucao continua ate interrupcao manual (Ctrl+C/SIGTERM).

## Encerramento
- Ctrl+C no terminal ou envio de SIGTERM.
- O processo salva state, libera lock e encerra com log.

## Logs e state
- Logs: `logs/rele` e `logs/inversor`
- State: `state/monitor_state.json`
- Lock: `state/.monitor_lock`

## Observacoes
- `monitor_daemon.py` e arquivos legados foram movidos para `deletar/legacy`.
- Nao existem flags de teste/auditoria; apenas runtime de producao.
- Webhook comum do Teams nao permite atualizar card original; para isso, use Flow/Graph.
