# Separação dos canais Teams — RELÉS, INVERSORES e HEARTBEAT

**Data:** 2026-09-01
**Arquivo afetado:** `main.py` (processo de produção). `monitor_daemon.py` está fora de escopo (código legado, não listado nos arquivos principais do README).

---

## Problema

Hoje todas as notificações do monitor vão para um único canal do Teams
(`ALERTAS DE MONITORAMENTO`, no time `MONITORAMENTO`), através de uma única
constante `TEAMS_WEBHOOK_URL` (`main.py:47`) consumida por `_teams_post_card`
(`main.py:285`).

Isso mistura, no mesmo canal:

- Falhas / normalizações de **relé**
- Falhas / normalizações de **inversor**
- **Heartbeat** operacional (status combinado de relé + inversor)
- **Erros do sistema** (falha ao salvar estado, falha no relatório semanal)

O objetivo é separar por natureza do alerta, em três canais.

---

## Objetivo

| Canal Teams | Conteúdo | Origem no código |
|---|---|---|
| `HEARTBEAT` (renomeação do canal atual `ALERTAS DE MONITORAMENTO`) | Heartbeat + erros de sistema | `_enviar_heartbeat` (`main.py:3470`), falha ao salvar estado (`main.py:2125`), falhas do relatório semanal (`main.py:2696`, `main.py:2714`) |
| `RELÉS` (novo) | Falha e normalização de relé | `_notificar_rele_agrupado` (`main.py:3504`, `main.py:3531`) |
| `INVERSORES` (novo) | Falha e normalização de inversor | `_notificar_inversor` (`main.py:3561`), `_notificar_inversor_recuperado` (`main.py:3576`) |

**Não-objetivos:**

- Nenhuma mudança no formato do payload (`MessageCard`). Os três webhooks são
  fluxos Power Automate idênticos, mudando só o canal de destino.
- Nenhuma mudança na lógica de detecção, retry, cooldown ou heartbeat.
- Nenhuma mudança em `monitor_daemon.py`.

---

## Infraestrutura (fora do código, já concluída pelo operador)

1. Canal `ALERTAS DE MONITORAMENTO` renomeado para `HEARTBEAT`. O fluxo Power
   Automate existente continua funcionando: ele posta pelo ID do canal, não pelo
   nome. A URL não muda.
2. Criados os canais `RELÉS` e `INVERSORES` no time `MONITORAMENTO`.
3. Criado um fluxo Power Automate para cada canal novo (cópia do fluxo atual via
   "Salvar como", trocando só o canal de destino). Cada fluxo gera sua própria
   URL de gatilho.
4. As três URLs serão colocadas no `.env` local e no `.env` de produção no EC2
   (`/home/ubuntu/Repositories/MonitoramentoOeM/.env`), seguido de
   `sudo systemctl restart monitoramento_oem`.

Observação: a assinatura (`sig=`) na URL do Power Automate é permanente enquanto
o fluxo existir — não há expiração a tratar.

---

## Desenho da mudança de código (Abordagem A: parâmetro `webhook_url`)

### 1. Constantes de ambiente (`main.py`, junto da linha 47)

```python
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_WEBHOOK_URL_RELE = os.environ.get("TEAMS_WEBHOOK_URL_RELE", "").strip() or TEAMS_WEBHOOK_URL
TEAMS_WEBHOOK_URL_INVERSOR = os.environ.get("TEAMS_WEBHOOK_URL_INVERSOR", "").strip() or TEAMS_WEBHOOK_URL
TEAMS_ENABLED = bool(TEAMS_WEBHOOK_URL)
```

- `TEAMS_WEBHOOK_URL` continua sendo a variável-mãe (canal `HEARTBEAT` / geral).
- Se `TEAMS_WEBHOOK_URL_RELE` ou `TEAMS_WEBHOOK_URL_INVERSOR` vier vazia, cai
  para `TEAMS_WEBHOOK_URL` — permite implantação incremental e nunca perde
  alerta. As duas variáveis novas são **opcionais**.
- `TEAMS_ENABLED` segue amarrado só a `TEAMS_WEBHOOK_URL`.

### 2. `_teams_post_card` (`main.py:285`)

Assinatura ganha um parâmetro opcional no fim:

```python
def _teams_post_card(
    title: str,
    text: str,
    severity: SeverityLevel = "info",
    facts: list[tuple[str, str]] | None = None,
    max_tentativas: int = 3,
    webhook_url: str | None = None,
) -> bool:
```

No corpo:

- O guard `if not TEAMS_ENABLED: return False` **permanece igual** — é o
  interruptor global da integração Teams. Não trocar por `if not url:` (isso
  quebraria ~5 testes existentes que fazem `monkeypatch.setattr(main,
  "TEAMS_ENABLED", True)` sem setar `TEAMS_WEBHOOK_URL`).
- Logo após o guard, resolver a URL:
  `url = webhook_url or TEAMS_WEBHOOK_URL`
- Usar `url` no lugar de `TEAMS_WEBHOOK_URL` na chamada
  `_teams_session.post(...)` (`main.py:318`).
- Logs de debug (`RELE_DEBUG`) e de warning continuam exatamente como estão. A
  URL do webhook **não** entra em log (contém a assinatura `sig=`). Nenhum
  rótulo de canal novo é adicionado aos logs nesta mudança.

### 3. Roteamento nos call sites

| Função | Linha(s) | Mudança |
|---|---|---|
| `_notificar_rele_agrupado` | `main.py:3504`, `main.py:3531` | `_teams_post_card(**card, webhook_url=TEAMS_WEBHOOK_URL_RELE)` |
| `_notificar_inversor` | `main.py:3561` | acrescentar `webhook_url=TEAMS_WEBHOOK_URL_INVERSOR` |
| `_notificar_inversor_recuperado` | `main.py:3576` | acrescentar `webhook_url=TEAMS_WEBHOOK_URL_INVERSOR` |
| `_enviar_heartbeat` | `main.py:3470` | sem mudança (usa default → `HEARTBEAT`) |
| Falha ao salvar estado | `main.py:2125` | sem mudança |
| Falhas do relatório semanal | `main.py:2696`, `main.py:2714` | sem mudança |

### 4. `validate_config()` (`main.py:246`)

Sem mudança. Continua exigindo apenas `TEAMS_WEBHOOK_URL`. As variáveis novas são
opcionais por design (fallback garante entrega).

### 5. Documentação

- `.env.example`: adicionar as duas variáveis novas com comentário explicando o
  fallback.
- `README.md`:
  - Tabela "Variáveis opcionais" (linha ~117): incluir
    `TEAMS_WEBHOOK_URL_RELE` e `TEAMS_WEBHOOK_URL_INVERSOR`.
  - Seção "Notificações Teams": explicar o roteamento por canal e o fallback.

---

## Testes

Arquivo novo: `tests/test_canais_teams.py` (segue o padrão de `tests/test_hardening.py`:
mock de `main._teams_session.post` capturando a URL, `monkeypatch` em
`main.TEAMS_ENABLED` / constantes de canal).

1. **`_teams_post_card` respeita `webhook_url` explícito.** Chamar com
   `webhook_url="https://canal-x"` e afirmar que `_teams_session.post` recebeu
   essa URL.
2. **`_teams_post_card` sem `webhook_url` usa `TEAMS_WEBHOOK_URL`.** Protege o
   roteamento de heartbeat e erros de sistema, que não passam o parâmetro.
3. **Roteamento de relé.** `_notificar_rele_agrupado` com pacote de falha +
   normalização posta as duas mensagens em `TEAMS_WEBHOOK_URL_RELE`.
4. **Roteamento de inversor.** `_notificar_inversor` e
   `_notificar_inversor_recuperado` postam em `TEAMS_WEBHOOK_URL_INVERSOR`.
5. **Fallback.** Com `main.TEAMS_WEBHOOK_URL_RELE` igual a
   `main.TEAMS_WEBHOOK_URL` (situação de variável não definida no `.env`), o
   alerta de relé é entregue na URL geral.

Os testes existentes de heartbeat / save-state / relatório semanal
(`test_heartbeat_indica_scan_atrasado`, `test_save_state_envia_teams_apos_falhas_consecutivas`,
`test_relatorio_xlsx_falha_notifica_teams`) continuam válidos sem alteração —
eles mockam `_teams_post_card` por inteiro.

Verificação geral: `python -m py_compile main.py` e `python -m pytest -q`
(toda a suíte deve continuar passando — o parâmetro `webhook_url` é aditivo e
opcional, então os ~30 testes que já mockam `_teams_post_card` não quebram).

---

## Riscos e mitigação

| Risco | Mitigação |
|---|---|
| Constante resolvida no import: se a env var for setada depois do import, o fallback "congela". | Comportamento idêntico ao `TEAMS_WEBHOOK_URL` atual, que já é lido no import. Testes que sobrescrevem devem usar `monkeypatch.setattr(main, "TEAMS_WEBHOOK_URL_RELE", ...)`, não `setenv`. |
| Esquecer de atualizar o `.env` de produção → alertas de relé/inversor caem no canal `HEARTBEAT`. | Fallback é seguro (nada é perdido). Checklist de deploy no README. |
| Renomear o canal quebrar o fluxo Power Automate. | Não quebra — fluxo referencia o canal por ID. Já validado na etapa de infra. |
