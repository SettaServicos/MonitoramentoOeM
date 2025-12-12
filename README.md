# GUIA – MONITOR DE RELÉS E INVERSORES (HEADLESS)

## 📋 Objetivo

O serviço foi desenvolvido para monitorar automaticamente os **relés** e **inversores** das usinas em modo *headless*.  
Ele consulta a **API PVOperation**, detecta alertas de relé e falhas de inversor e envia notificações no **Microsoft Teams**.

Não há interface gráfica: toda a visibilidade ocorre por meio de **logs** e **mensagens no Teams**.

---

## ⚙️ Como o Programa Funciona

### 1. Primeira varredura

Ao iniciar o serviço:

- Analisa os dados desde o início do dia (**00:00**) até o momento atual.

### 2. Próximas varreduras

As varreduras seguintes usam uma janela **incremental**:

- Sempre do **último horário varrido** até “agora”.
- Evitam reprocessar o dia inteiro.

Intervalos padrão:

- **Relés:** a cada **10 minutos**.  
- **Inversores:** a cada **15 minutos**.

### 🎯 3. Prioridade entre relé e inversor

- Se houver **alerta de relé** em uma usina no ciclo:
  - Os **inversores dessa usina** são ignorados naquele ciclo (para evitar ruído de informação).
  - Os **estados de falha dos inversores** dessa usina são **zerados** sempre que há alerta de relé no ciclo.

### 🎯 4. Regras específicas para inversores

- São analisados apenas no período de **06:30** até **17:30**.
- Uma falha de inversor é registrada quando:
  - `Pac == 0` em **3 leituras consecutivas**  
  - Não é obrigatório ter exatamente 5 minutos entre cada leitura; basta que sejam leituras sequenciais.
- A falha desaparece automaticamente quando o inversor volta a gerar:
  - `Pac > 0` limpa a condição de falha.

### 🔄 5. Timeouts / sem dados de inversor

- Quando não há retorno de dados ou ocorre **timeout** da API para os inversores, o programa:
  - Registra um **aviso nos logs**.
  - Marca a usina/inversor internamente com o motivo:
    - `TIMEOUT`; ou  
    - `SEM_DADOS`.
- Não há qualquer interface gráfica para esse tipo de ocorrência, apenas logs.

### 🔔 6. Deduplicação de alertas

#### Relé

- Um alerta é enviado na **primeira detecção** de uma combinação:

  > `usina : relé : tipo`

- Enquanto o alerta permanecer **ativo** (a condição não mudou):
  - O programa **não repete** o mesmo alerta.
- Se a condição **desaparecer** e depois **voltar a ocorrer**:
  - Um **novo alerta** é enviado normalmente.

#### Inversor

- A falha de `Pac == 0` gera um **alerta uma única vez**, quando confirmada.
- Ao **normalizar** (`Pac > 0`):
  - O alerta é removido internamente.
- Se a falha voltar a ocorrer após a normalização:
  - Um **novo alerta** pode ser enviado.

---

## O que você verá (logs e Teams)

Como o serviço é **headless**, não há janelas ou abas na tela.  
A observação do sistema acontece por dois canais principais:

### Logs

- Registram **início** e **fim** de cada varredura.
- Registram **alertas de relé** e **falhas de inversor** em nível `WARNING` (ou equivalente).
- Registram também avisos de:
  - `TIMEOUT`
  - `SEM_DADOS`

### Microsoft Teams

- Cada novo alerta de relé ou falha de inversor gera uma **mensagem** no canal configurado.
- As mensagens trazem as principais informações:
  - **Usina**
  - **Relé/Inversor**
  - **Horário**
  - **Tipo/detalhes** da ocorrência
  - **Capacidade** da usina/equipamento

---

## Como são apresentados os alertas

Sempre que surge um **novo alerta** (*não duplicado*), o serviço envia uma mensagem para o Teams usando o webhook configurado.

Conteúdo típico da mensagem:

- Nome da **usina**
- Identificação do **relé** ou **inversor**
- **Horário** da detecção
- **Tipo de alerta ou falha**, com detalhes relevantes (por exemplo: `Pac == 0`, subtensão, etc.)
- **Capacidade** da usina/equipamento e outros dados complementares definidos na mensagem

### Nível de severidade

- **Relés:** classificados como **perigo** ou **aviso**, de acordo com o tipo de atuação.  
- **Inversores:** tratados como alerta de **perigo** quando confirmada falha de geração (`Pac == 0` nas condições definidas).

Paralelamente, o mesmo evento é registrado nos **logs** do aplicativo em nível `WARNING`.

---

## Configuração de SSL (servidor)

O cliente HTTP (`requests`) utiliza uma `Session` com o atributo `verify`.

Por padrão:

```python
VERIFY_CA = (
    os.environ.get("SSL_CERT_FILE")
    or os.environ.get("REQUESTS_CA_BUNDLE")
    or True
)

---

*Sistema de monitoramento contínuo para garantir a operação eficiente das usinas*