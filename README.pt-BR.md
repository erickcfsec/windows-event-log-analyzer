# 🛡️ Windows Event Log Analyzer

[🇺🇸 English](README.md) | [🇧🇷 Português (Brasil)](README.pt-BR.md)

Uma ferramenta desenvolvida em Python para analisar os logs de eventos de segurança do Windows, identificar atividades suspeitas de autenticação, detectar possíveis padrões de ataques de força bruta (*Brute Force*) e gerar alertas de segurança estruturados.

Este projeto faz parte de um portfólio prático de cibersegurança, com foco em operações Blue Team, monitoramento de segurança e análise de atividades relacionadas a um SOC (Security Operations Center).

## 🎯 Visão Geral

O Windows Event Log Analyzer coleta eventos de segurança do Windows, processa suas representações XML, identifica tentativas repetidas de falha de autenticação e armazena os alertas gerados em um arquivo JSON.

A lógica de detecção atual concentra-se no evento de segurança do Windows **Event ID 4625** — Falha na tentativa de logon de uma conta.

O principal objetivo é demonstrar um fluxo prático de monitoramento de segurança utilizando Python e os logs nativos de eventos do Windows.

## ⚙️ Funcionalidades

- Coleta de logs de eventos de segurança do Windows.
- Processamento de eventos XML brutos.
- Normalização dos campos relevantes dos eventos.
- Detecção de tentativas repetidas de falha de autenticação provenientes do mesmo endereço IP.
- Configuração de limite de tentativas e janela de tempo.
- Geração de alertas de segurança estruturados.
- Armazenamento de alertas no formato JSON.
- Prevenção de registros duplicados de alertas.
- Execução da análise por meio de uma interface de linha de comando (CLI).
- Execução de testes automatizados utilizando pytest.

## 🚨 Regra de Detecção

| Atributo | Valor |
|---|---|
| ID da regra | `WIN-AUTH-001` |
| Event ID | `4625` |
| Descrição | Múltiplas tentativas de falha de logon do Windows provenientes do mesmo endereço IP |
| Limite padrão | 5 tentativas |
| Janela de tempo padrão | 5 minutos |
| Severidade | Alta (High) |

A regra agrupa eventos válidos de falha de autenticação pelo endereço IP de origem e verifica se o limite configurado é atingido dentro da janela de tempo definida.

Um alerta é gerado quando esse limite é alcançado.

**Importante:** essa regra identifica um padrão suspeito de autenticação. Isoladamente, ela não comprova que ocorreu um ataque de força bruta.

Consulte [Regras de Detecção](docs/detection_rules.md) para obter mais detalhes.

## 🏗️ Arquitetura

A aplicação utiliza uma arquitetura modular organizada em um fluxo de processamento (*pipeline*):

1. **Collector (Coletor):** recupera os registros brutos do Windows Security Event Log.
2. **Parser (Analisador):** converte o XML dos eventos em dicionários normalizados.
3. **Detector (Detector):** analisa os eventos processados e identifica padrões suspeitos de autenticação.
4. **Alert Manager (Gerenciador de Alertas):** armazena novos alertas e evita registros duplicados.
5. **CLI (Interface de Linha de Comando):** permite executar a ferramenta e visualizar os resultados da análise.

Consulte [Arquitetura](docs/architecture.md).

## 💻 Tecnologias Utilizadas

- Python
- Windows Event Log API
- pywin32
- Processamento de XML
- JSON
- pytest
- PowerShell

## 📋 Requisitos

- Sistema operacional Windows.
- Python 3.10 ou superior.
- Acesso ao Windows Security Event Log.
- Permissões adequadas para leitura do log de segurança.

O projeto utiliza a biblioteca `pywin32` para interagir com a API de eventos do Windows.

## 📦 Instalação

Clone o repositório:

```powershell
git clone https://github.com/erickcfsec/windows-event-log-analyzer.git
cd windows-event-log-analyzer
```

Crie um ambiente virtual:

```powershell
python -m venv .venv
```

Ative o ambiente virtual:

```powershell
.\.venv\Scripts\Activate.ps1
```

Instale as dependências:

```powershell
python -m pip install -e ".[dev]"
```

## 🖥️ Utilização

Execute o analisador:

```powershell
python -m event_analyzer
```

A configuração padrão é:

- Event ID: `4625`
- Número máximo de eventos: `100`
- Limite de detecção: `5`
- Janela de detecção: `5` minutos
- Canal de eventos: `Security`
- Armazenamento dos alertas: `data/alerts.json`

Para visualizar as opções disponíveis:

```powershell
python -m event_analyzer --help
```

### 🔧 Execução Personalizada

Exemplo utilizando um limite de 10 tentativas de falha de autenticação dentro de uma janela de 10 minutos:

```powershell
python -m event_analyzer --event-id 4625 --max-events 200 --threshold 10 --window-minutes 10
```

Para especificar um caminho diferente para o armazenamento dos alertas:

```powershell
python -m event_analyzer --storage data/custom_alerts.json
```

A leitura do Windows Security Event Log pode exigir a execução do PowerShell com privilégios elevados e permissões adequadas no Windows.

## 🔍 Exemplo de Cenário de Detecção

O cenário abaixo é ilustrativo e não representa um incidente real:

- Cinco eventos de falha de autenticação (Event ID 4625).
- Todos os eventos