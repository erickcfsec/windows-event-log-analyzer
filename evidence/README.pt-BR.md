# 📸 Evidências do Projeto

[🇺🇸 English](README.md) | [🇧🇷 Português (Brasil)](README.pt-BR.md)

Este diretório contém capturas de tela que documentam a execução, as funcionalidades e os testes do projeto **Windows Event Log Analyzer**.

As evidências demonstram as principais capacidades da ferramenta, incluindo coleta de eventos do Windows Security, detecção de força bruta, testes automatizados, geração de alertas e utilização da interface de linha de comando.

---

## 📂 Visão Geral das Evidências

### 🖥️ 01 — Coleta de Eventos em Tempo Real

**Arquivo:** `01-live-event-collection.png`

**Objetivo:** Demonstrar a coleta de eventos reais do Windows Security no ambiente local.

**O que demonstra:**
- Conexão com o log Windows Security.
- Coleta de eventos de autenticação.
- Processamento e interpretação dos eventos.
- Quantidade de eventos coletados e processados corretamente.

**Classificação dos dados:** Eventos reais coletados do ambiente Windows local.

---

### 🚨 02 — Detecção de Força Bruta

**Arquivo:** `02-bruteforce-detection.png`

**Objetivo:** Demonstrar a detecção de múltiplas tentativas de autenticação malsucedidas.

**O que demonstra:**
- Registros simulados do Windows Event ID 4625.
- Múltiplas falhas de logon originadas do mesmo endereço IP.
- Acionamento da regra de detecção `WIN-AUTH-001`.
- Geração de alerta com severidade alta.

**Cenário de detecção:**
- Event ID: `4625`
- IP de origem: `192.0.2.10`
- Tentativas malsucedidas: `5`
- Janela de detecção: `5 minutos`

**Classificação dos dados:** Dados sintéticos de teste.

---

### 🧪 03 — Testes Automatizados

**Arquivo:** `03-automated-tests.png`

**Objetivo:** Demonstrar a execução dos testes automatizados e a validação do projeto.

**O que demonstra:**
- Execução do Pytest.
- Resultados da suíte de testes.
- Validação bem-sucedida dos componentes do projeto.

**Resultado dos testes:** 62 testes aprovados na execução validada.

---

### 📄 04 — Alerta de Detecção Simulada

**Arquivo:** `04-synthetic-detection-alert.png`

**Objetivo:** Demonstrar a estrutura e a persistência de um alerta de segurança gerado pela ferramenta.

**O que demonstra:**
- Regra de detecção: `WIN-AUTH-001`.
- Severidade: `High`.
- Event ID: `4625`.
- IP de origem: `192.0.2.10`.
- Cinco tentativas de autenticação malsucedidas.
- Horários da primeira e da última ocorrência.
- Usuários associados e IDs dos registros dos eventos.
- Identificador único do alerta.

**Classificação dos dados:** Dados sintéticos de teste.

O endereço IP `192.0.2.10` é reservado para documentação e exemplos. Este cenário não representa um incidente de segurança real.

---

### 💻 05 — Interface de Linha de Comando

**Arquivo:** `05-cli-interface.png`

**Objetivo:** Demonstrar a interface de linha de comando e suas opções de configuração.

**O que demonstra:**
- Exibição da ajuda da CLI.
- Argumentos disponíveis.
- Parâmetros personalizados de execução.
- Configuração do limite de detecção e da janela de tempo.

**Exemplos de comandos:**

```powershell
python -m event_analyzer --help
```

```powershell
python -m event_analyzer --threshold 10 --window-minutes 10
```

---

## 🔍 Observações sobre as Evidências

- As evidências de coleta em tempo real utilizam eventos do ambiente Windows local.
- A detecção de força bruta utiliza eventos sintéticos controlados.
- Os cenários sintéticos são destinados a testes seguros e fins educacionais.
- As capturas documentam as funcionalidades atuais e os resultados dos testes do projeto.
- Essas demonstrações não representam uma solução de monitoramento de segurança pronta para produção.

---

## 🎯 Objetivo do Projeto

As evidências reforçam os objetivos educacionais deste projeto:

- Análise de logs de segurança do Windows.
- Monitoramento de falhas de autenticação.
- Detecção básica de ataques de força bruta.
- Geração e persistência de alertas de segurança.
- Desenvolvimento com Python e testes automatizados.

**Projeto:** Windows Event Log Analyzer
**Foco:** Blue Team | SOC | Monitoramento de Segurança Windows