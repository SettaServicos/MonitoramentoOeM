# GUIA – MONITOR DE RELÉS E INVERSORES

## 📋 Objetivo
O aplicativo foi desenvolvido para monitorar automaticamente os relés e inversores das usinas. Ele busca dados na plataforma PVOperation e mostra alertas em tempo real na tela e, se configurado, também envia notificações no Microsoft Teams.

## ⚙️ Como o Programa Funciona

### 🔄 Ciclo de Operação
1. **Primeira varredura**: Ao abrir o programa, ele analisa todos os relés e inversores desde o início do dia até o momento atual
2. **Varreduras subsequentes**: Ocorrem automaticamente a cada **20 minutos**

### 🎯 Prioridades e Regras
- **Prioridade de alertas**: Se houver alerta de Relé em uma usina, os inversores dessa usina são ignorados naquele ciclo (para evitar ruído de informação)
- **Inversores**:
  - São analisados apenas no período **06:30 até 17:30**
  - Uma falha é registrada quando o **Pac = 0 em 3 leituras seguidas** com intervalo de 5 minutos
  - A falha desaparece automaticamente quando o inversor volta a gerar (Pac > 0)
- **Sem Dados**: Aplica-se apenas para inversores (não se aplica a relés)

## 🖥️ Interface do Usuário

O programa abre uma janela com várias abas organizadas:

### 📊 Abas Disponíveis
- **Alertas Relés**: Lista de usinas e relés que tiveram atuação, com cores diferentes para cada tipo (sobretensão, subtensão, frequência, etc.)
- **Alertas Inversores**: Mostra os inversores em falha segundo as regras estabelecidas
- **Estatísticas**: Gráficos simples com a contagem de alertas de relé e de falhas de inversores
- **Sem Dados**: Usinas que não retornaram leituras de inversores no período

### 🔔 Sistema de Notificações
- **Popup sonoro**: Sempre que surge um novo alerta, abre um popup com som na tela
- **Informações do alerta**: Usina, equipamento, horário, tipo de alerta e parâmetros envolvidos
- **Integração Teams**: Se configurado, o mesmo alerta é enviado para o Microsoft Teams via webhook

## 👨‍💻 Instruções para o Operador

### 📝 Ações Recomendadas
- Acompanhar continuamente a tela de alertas
- Verificar a ocorrência quando aparecer um alerta (popup e lista)
- Consultar as abas de Estatísticas e Sem Dados para ter visão geral
- Usar o botão **"Limpar"** quando quiser reiniciar as listas de exibição (os dados novos serão carregados na próxima varredura)

### 📍 Barra de Status Inferior
- Contador regressivo para a próxima varredura
- Número de alertas ativos
- Status atual do sistema

## 🎯 Resumo das Características

- **✅ Automático**: O programa busca dados e atualiza sozinho a cada 20 min
- **✅ Crítico**: Sempre que um relé atua, você será avisado com som e popup
- **✅ Confiável**: Falhas de inversores só aparecem quando confirmadas por sequência de leituras
- **✅ Organizado**: Tudo fica separado por abas e cores, facilitando a visualização

---

*Sistema de monitoramento contínuo para garantir a operação eficiente das usinas*