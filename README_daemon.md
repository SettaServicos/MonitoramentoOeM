# Monitor de Relés/Inversores – Daemon Único

Monitor headless que verifica relés e inversores via API PVOperation e envia alertas para Microsoft Teams. Estruturado para rodar como serviço/daemon (sem cron), com lock de instância única e estado persistido em disco.

## Requisitos
- Python 3.9+
- Dependências listadas em `requirements.txt`
- Acesso à API PVOperation
- Webhook do Microsoft Teams para receber alertas

## Configuração obrigatória (variáveis de ambiente)
- `MONITOR_EMAIL`: usuário da API (ex.: `monitoramento@empresa.com`)
- `MONITOR_PASSWORD`: senha da API (ex.: `senha-super-secreta`)
- `TEAMS_WEBHOOK_URL`: URL do Webhook do Teams

O script encerra se qualquer uma estiver com valor de exemplo/placeholder.

## SSL (opcional)
- `SSL_CERT_FILE` ou `REQUESTS_CA_BUNDLE`: caminho para o bundle de certificados CA (ex.: `/etc/ssl/certs/ca-bundle.crt` ou `C:\certs\ca.pem`). Se não definir, usa verificação padrão do `requests`.

## Como rodar localmente (teste rápido)
```bash
export MONITOR_EMAIL="seu_email@empresa.com"
export MONITOR_PASSWORD="sua_senha"
export TEAMS_WEBHOOK_URL="https://seu-webhook.office.com/..."
python monitor_daemon.py
```
Interrompa com `Ctrl+C`; o monitor salvará estado e liberará o lock.

## Rodando como serviço/daemon
- **Linux (systemd/supervisor)**: crie um serviço apontando para `python monitor_daemon.py` com as variáveis definidas. Evite cron.
- **Windows (NSSM/Task Scheduler)**: configure a tarefa/serviço chamando `python monitor_daemon.py` e defina as variáveis.
- Apenas uma instância por lock (`.monitor_lock`). Se precisar mais de uma (não recomendado), altere `LOCK_FILE`.

## O que o monitor faz
- Duas threads internas:
  - Relé: varre a cada 10 minutos, busca alertas em relés e envia para Teams.
  - Inversor: varre a cada 15 minutos, detecta falhas (3 leituras seguidas de potência zero entre 06:30–17:30) e envia alerta.
- Normalização de inversor: se estava em falha e surgirem 3 leituras consecutivas com potência acima de zero, envia aviso de “normalizado” e limpa o alerta.
- Estado persistido em `monitor_state.json` (últimas varreduras e alertas ativos), na mesma pasta do script.
- Lock de instância (`.monitor_lock`) para evitar múltiplas cópias concorrentes.
- Logs detalhados com horários e severidade.

## Arquivos relevantes
- `monitor_daemon.py`: daemon único com toda a lógica de detecção e notificação.
- `main.py`: versão headless equivalente.
- `requirements.txt`: dependências do projeto.

## Notas rápidas
- Não use cron: o daemon roda contínuo e se autogerencia.
- Garanta rede de saída para a API PVOperation e para o webhook do Teams.
- Certifique-se de que as credenciais e o webhook reais estejam setados antes de produção.
