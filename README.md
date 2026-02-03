# Monitor de Usinas Fotovoltaicas (FV) - Headless

## 1. Visão Geral e Objetivo

Este projeto consiste em um monitor Python headless, projetado para operar 24 horas por dia, 7 dias por semana, em um ambiente de servidor. Seu objetivo principal é monitorar o status de relés e inversores em usinas fotovoltaicas, consultando a API PVOperation, e enviar alertas e mensagens de heartbeat para o Microsoft Teams via Incoming Webhook. O monitor visa garantir a detecção proativa de falhas e a comunicação eficiente do status operacional das usinas.

## 2. Funcionalidades

*   **Monitoramento de Relés:** Varredura periódica para identificar alertas em relés das usinas.
*   **Monitoramento de Inversores:** Varredura periódica para detectar falhas (potência zero) e normalizações em inversores.
*   **Notificações no Microsoft Teams:** Envio de alertas de falha, normalização e mensagens de heartbeat para um canal configurado no Teams.
*   **Persistência de Estado:** Mantém o estado do monitor (últimas varreduras, alertas ativos, notificações pendentes) em disco para resiliência a reinícios.
*   **Deduplicação de Alertas:** Evita o envio de notificações repetidas para o mesmo evento ativo.
*   **Heartbeat:** Envio de mensagens periódicas para o Teams, indicando que o monitor está ativo e funcionando.
*   **Resiliência:** Mecanismos de retry com backoff para chamadas de API e envio de notificações para o Teams.
*   **Instância Única:** Garante que apenas uma instância do monitor esteja em execução por vez.

## 3. Como Funciona (Arquitetura)

O monitor opera com uma arquitetura baseada em threads e persistência de estado:

*   **Inicialização:** Ao iniciar, o script valida as configurações, realiza o login na API PVOperation e carrega o estado persistido do arquivo `monitor_state.json`.
*   **Threads de Execução:** Duas threads principais são iniciadas:
    *   `_loop_scans`: Responsável por agendar e executar as varreduras de relés e inversores em intervalos definidos.
    *   `_loop_heartbeat`: Envia mensagens de heartbeat para o Teams em horários fixos.
*   **Varredura de Relés:** A cada 10 minutos, consulta a API PVOperation para dados de relés. Identifica novos alertas e normalizações, atualiza o estado interno e envia notificações para o Teams.
*   **Varredura de Inversores:** A cada 15 minutos, consulta a API PVOperation para dados de inversores. Detecta falhas (3 leituras consecutivas com Pac=0) e normalizações (3 leituras consecutivas com Pac>0) dentro de uma janela de geração (06:30-17:30). Se houver um relé ativo em uma usina, a varredura do inversor para essa usina é pulada para evitar alertas redundantes.
*   **Estado e Locks:** O estado do monitor é salvo atomicamente em `monitor_state.json`. Locks (`_state_lock`, `_scan_lock`) são usados para garantir a consistência dos dados entre as threads e durante o salvamento do estado. Um lock de arquivo (`.monitor_lock`) garante que apenas uma instância do monitor esteja ativa.
*   **Shutdown:** Em caso de interrupção (Ctrl+C ou sinais de sistema), o monitor tenta encerrar suas threads graciosamente, salva o estado final e libera o lock de instância.

## 4. Requisitos

*   **Python:** Versão 3.x
*   **Bibliotecas Python:**
    *   `requests`
    *   `pathlib` (nativo do Python 3.4+)
    *   `logging` (nativo)
    *   `threading` (nativo)
    *   `datetime` (nativo)
    *   `email.utils` (nativo)
    *   `socket` (nativo)
    *   `signal` (nativo)
    *   `statistics` (nativo)
    *   `fcntl` (para sistemas Unix-like) ou `msvcrt` (para Windows) para lock de arquivo.
*   **Sistema Operacional:** Linux (preferencialmente) ou Windows.

## 5. Instalação

1.  **Clone o repositório:**
    ```bash
    git clone <URL_DO_REPOSITORIO>
    cd <DIRETORIO_DO_PROJETO>
    ```
2.  **Crie e ative um ambiente virtual (recomendado):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # No Windows: .\venv\Scripts\activate
    ```
3.  **Instale as dependências:**
    ```bash
    pip install requests
    ```
    *(Nota: `pytest` não é uma dependência de runtime, mas é recomendado para testes.)*

## 6. Configuração

As configurações principais estão hardcoded no topo do arquivo `main.py`. **Para ambientes de produção, é altamente recomendado o uso de variáveis de ambiente para credenciais sensíveis.**

Edite a seção `CONFIGURACAO` no `main.py`:

```python
# =========================
# CONFIGURACAO (EDITAR AQUI)
# =========================
PVOP_BASE_URL = "https://apipv.pvoperation.com.br/api/v1"  # URL base da API PVOperation
PVOP_EMAIL = "<SEU_EMAIL_PVOPERATION>"                     # Seu email de login na PVOperation
PVOP_PASSWORD = "<SUA_SENHA_PVOPERATION>"                   # Sua senha da PVOperation
TEAMS_WEBHOOK_URL = "<SUA_URL_WEBHOOK_TEAMS>"               # URL do Incoming Webhook do Microsoft Teams
TEAMS_ENABLED = True                                        # Define se as notificações do Teams estão ativas (True/False)
# =========================
```

**Substitua os placeholders (`<SEU_EMAIL_PVOPERATION>`, `<SUA_SENHA_PVOPERATION>`, `<SUA_URL_WEBHOOK_TEAMS>`) pelos valores reais.**

**Variáveis de Ambiente (Recomendado para Produção):**
Em vez de editar o `main.py` diretamente, você pode definir as seguintes variáveis de ambiente:

*   `PVOP_BASE_URL`
*   `PVOP_EMAIL`
*   `PVOP_PASSWORD`
*   `TEAMS_WEBHOOK_URL`
*   `TEAMS_ENABLED` (pode ser `"True"` ou `"False"`)

O script tentará ler essas variáveis de ambiente primeiro, se existirem.

## 7. Execução Local

Para executar o monitor localmente:

```bash
python3 main.py
```

Para sair, pressione `Ctrl+C`.

**Testes (se `pytest` estiver instalado):**

```bash
pytest -q
```

**Verificação de sintaxe:**

```bash
python3 -m compileall main.py
```

## 8. Execução em Servidor

Para execução em um servidor de produção 24/7, é recomendado configurar o monitor como um serviço do sistema (ex: `systemd` no Linux). Isso garante que o monitor inicie automaticamente com o sistema e seja reiniciado em caso de falha.

**Exemplo de arquivo `systemd` (ex: `/etc/systemd/system/pvmonitor.service`):**

```ini
[Unit]
Description=PVOperation Monitor Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/pvmonitor
ExecStart=/opt/pvmonitor/venv/bin/python3 /opt/pvmonitor/main.py
Restart=always
Environment="PVOP_EMAIL=seu_email" "PVOP_PASSWORD=sua_senha" "TEAMS_WEBHOOK_URL=sua_webhook_url"

[Install]
WantedBy=multi-user.target
```

**Ajuste `User`, `WorkingDirectory`, `ExecStart` e as variáveis `Environment` conforme seu ambiente.**

Após criar o arquivo de serviço:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pvmonitor.service
sudo systemctl start pvmonitor.service
sudo systemctl status pvmonitor.service
```

## 9. Logs

Os logs são rotacionados diariamente e armazenados nos seguintes diretórios:

*   **Logs Gerais:** `logs/rele/rele.log`
*   **Logs de Relés:** `logs/rele/rele.log`
*   **Logs de Inversores:** `logs/inversor/inversor.log`

**Exemplos de logs para procurar:**

*   `[HEARTBEAT]`: Mensagens de pulsação do monitor.
*   `[RELE] Falha`: Alertas de falha de relé.
*   `[RELE] Normalizacao`: Normalização de relé.
*   `[ALERTA INVERSOR]`: Alertas de falha de inversor.
*   `[RECUPERACAO INVERSOR]`: Normalização de inversor.
*   `[PVOP] Falha ao logar`: Problemas de autenticação na API PVOperation.
*   `[TEAMS] Falha ao enviar webhook`: Problemas no envio de notificações para o Teams.

## 10. State

O estado do monitor é persistido no arquivo `state/monitor_state.json`. Este arquivo armazena informações cruciais para a operação contínua, como:

*   `ultima_varredura_rele`: Timestamp da última varredura geral de relés.
*   `ultima_varredura_inversor`: Timestamp da última varredura geral de inversores.
*   `ultima_varredura_rele_por_usina`: Última varredura por usina para relés.
*   `ultima_varredura_inversor_por_usina`: Última varredura por usina para inversores.
*   `rele_alertas_ativos`: Conjunto de alertas de relé atualmente ativos.
*   `estado_inversores`: Estado de falha/normalização dos inversores.
*   `pending_notifications`: Notificações do Teams que não puderam ser enviadas e estão aguardando retry.

**Cuidados:**

*   Não edite este arquivo manualmente enquanto o monitor estiver em execução.
*   Em caso de corrupção do arquivo, o monitor tentará fazer um backup (`.corrupt.TIMESTAMP`) e iniciará com um estado limpo.

## 11. Regras de Alertas

### Relés

*   **Detecção:** Baseada em parâmetros específicos (`PARAMETROS_RELE`) que indicam um estado ativo (falha).
*   **Classificação:** Alertas são classificados em tipos (ex: SOBRETENSÃO, TÉRMICO, BLOQUEIO) com base nos parâmetros ativos.

### Inversores

*   **Janela de Operação:** Apenas leituras entre 06:30 e 17:30 são consideradas.
*   **Falha:** Detectada quando a potência (`Pac`) é igual a 0 em 3 leituras sequenciais.
*   **Normalização:** Detectada quando a potência (`Pac`) é maior que 0 em 3 leituras sequenciais, após um estado de falha.

### Prioridade Relé → Inversor

*   Se houver um alerta de relé ativo em uma usina, a varredura de inversores para essa usina é **pulada**. Isso evita alertas redundantes e foca na causa raiz do problema.

## 12. Troubleshooting

*   **Teams 429 (Too Many Requests):** O monitor implementa retry com backoff exponencial e respeita o cabeçalho `Retry-After`. Se o problema persistir, verifique os limites de taxa do Teams para Incoming Webhooks.
*   **PVOperation Indisponível:** O monitor tentará reautenticar e fazer retry em caso de erros de conexão ou `401 Unauthorized`. Se a API estiver persistentemente indisponível, verifique a conectividade de rede e o status do serviço PVOperation.
*   **Lock Ativo:** Se o monitor não iniciar com a mensagem "Outra instância rodando", verifique se há um processo `main.py` já ativo ou se o arquivo `state/.monitor_lock` não foi liberado corretamente após um encerramento abrupto. Remova o arquivo `.monitor_lock` manualmente se tiver certeza de que nenhuma outra instância está rodando.
*   **State Corrompido:** Se o arquivo `state/monitor_state.json` estiver corrompido, o monitor fará um backup (`.corrupt.TIMESTAMP`) e iniciará com um estado limpo. Isso pode levar a reenvio de alertas ativos.

## 13. Segurança

*   **Credenciais Hardcoded:** As credenciais da API PVOperation e a URL do webhook do Teams estão atualmente hardcoded no `main.py`. **É fortemente recomendado migrar essas credenciais para variáveis de ambiente ou um sistema de gerenciamento de segredos (ex: Azure Key Vault, HashiCorp Vault) em ambientes de produção.**
*   **Rotação de Segredos:** Implemente uma política de rotação regular para as senhas da PVOperation e, se possível, para a URL do webhook do Teams.

## 14. Checklist de Deploy

### Antes do `git push`

*   [ ] **Remover Credenciais Hardcoded:** Certifique-se de que `PVOP_EMAIL`, `PVOP_PASSWORD` e `TEAMS_WEBHOOK_URL` não contenham valores reais no código que será versionado. Use placeholders ou garanta que serão definidos via variáveis de ambiente no servidor.
*   [ ] **Revisar Configurações:** Verifique se `RELAY_INTERVAL`, `INVERTER_INTERVAL`, `HEARTBEAT_TIMES` e outros parâmetros estão adequados para o ambiente de produção.

### No Servidor

*   [ ] **Instalar Dependências:** Garanta que todas as bibliotecas Python necessárias estejam instaladas no ambiente do servidor.
*   [ ] **Configurar Variáveis de Ambiente:** Defina as variáveis de ambiente para as credenciais (`PVOP_EMAIL`, `PVOP_PASSWORD`, `TEAMS_WEBHOOK_URL`) e `TEAMS_ENABLED`.
*   [ ] **Configurar Serviço:** Crie e habilite o serviço `systemd` (ou equivalente) para garantir a execução 24/7 e o reinício automático.
*   [ ] **Verificar Permissões:** Certifique-se de que o usuário sob o qual o serviço será executado tenha permissões de leitura/escrita nos diretórios `state/` e `logs/`.
*   [ ] **Configurar SSL:** Verifique se `VERIFY_CA` aponta para o bundle de CA correto no servidor, se aplicável.

### Como Validar Antes do Deploy

*   [ ] **Execução Local com Variáveis de Ambiente:** Teste o monitor localmente definindo as variáveis de ambiente (em vez de hardcoded) para simular o ambiente de produção.
*   [ ] **Testes de Conectividade:** Verifique se o servidor tem acesso à API PVOperation e ao endpoint do Teams Webhook.
*   [ ] **Teste de Alerta:** Force um cenário de alerta (se possível em ambiente de homologação) para confirmar que as notificações chegam ao Teams.
*   [ ] **Teste de Heartbeat:** Verifique se as mensagens de heartbeat são enviadas nos horários configurados.
*   [ ] **Teste de Reinício:** Inicie o monitor, force um encerramento abrupto (ex: `kill -9 <PID>`) e reinicie para verificar se o estado é recuperado corretamente.
*   [ ] **Monitoramento de Logs:** Acompanhe os logs iniciais para garantir que não há erros de configuração ou inicialização.
