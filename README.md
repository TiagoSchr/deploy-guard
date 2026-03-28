<div align="center">

# 🛡️ Deploy Guard

**Scanner de segurança pré-deploy com conformidade LGPD**

Detecta segredos, dados pessoais (PII) e configurações inseguras antes que cheguem à produção.

[![CI](https://github.com/TiagoSchr/deploy-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/TiagoSchr/deploy-guard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![LGPD](https://img.shields.io/badge/compliance-LGPD-purple.svg)](#regras-lgpd)
[![SARIF](https://img.shields.io/badge/output-SARIF%20v2.1-orange.svg)](#formatos-de-saída)

</div>

> **Setup:** Antes de publicar, substitua `TiagoSchr` pelo seu username do GitHub em todos os arquivos do projeto:
> ```bash
> # Linux/Mac
> grep -rl "TiagoSchr" . --include="*.py" --include="*.toml" --include="*.yml" --include="*.md" | xargs sed -i 's/TiagoSchr/SEU-USERNAME/g'
> # Windows (PowerShell)
> Get-ChildItem -Recurse -Include *.py,*.toml,*.yml,*.md | ForEach-Object { (Get-Content $_) -replace 'TiagoSchr','SEU-USERNAME' | Set-Content $_ }
> ```

---

## Por que o Deploy Guard?

Você está prestes a fazer deploy. Mas verificou se há:

- 🔑 **Chaves de API hardcoded** (AWS, Stripe, OpenAI, SendGrid, GitHub, Slack)
- 📄 **Dumps de banco de dados de produção** commitados por acidente
- 🇧🇷 **Dados pessoais brasileiros** (CPF, CNPJ, telefones) violando a LGPD
- 💳 **Números de cartão de crédito** que quebram conformidade PCI-DSS
- ⚙️ **Configurações inseguras** (DEBUG=true, CORS *, bancos de dados acessíveis publicamente)
- 🌐 **Vazamentos no frontend** (variáveis NEXT_PUBLIC_/VITE_ expondo segredos)
- 🏥 **Dados de saúde** (LGPD Art. 5, II — categoria especial)
- 🔐 **Chaves privadas e certificados** no repositório

O Deploy Guard detecta tudo isso em **um único scan**, localmente ou no CI/CD.

---

## Início Rápido

### Instalação

```bash
pip install deploy-guard
```

### Escaneamento

```bash
# Escanear diretório atual
deploy-guard .

# Escanear com modo LGPD estrito
deploy-guard . --strict-lgpd

# Escanear build do frontend
deploy-guard ./dist --target frontend

# Escanear código de infraestrutura
deploy-guard ./infra --target iac
```

### Exemplo de Saída

```
   ___           _               ___                     _
  |   \ ___ _ __| |___ _  _     / __|_  _ __ _ _ _ __ __| |
  | |) / -_) '_ \ / _ \ || |   | (_ | || / _` | '_/ _` |_|
  |___/\___| .__/_\___/\_, |    \___|\_,_\__,_|_| \__,_(_)
            |_|        |__/     v1.0.0

  ⛔ DEPLOY GUARD — Relatório de Segurança
  ════════════════════════════════════════════════════════════
  Alvo:    ./dist
  Issues:  12
  ● Crítico: 5  ● Alto: 4  ● Médio: 2  ● Baixo: 1
  Decisão: ⛔ BLOQUEADO
  ════════════════════════════════════════════════════════════

  📄 dist/bundle.js
    ⛔ [CRÍTICO] CREDENCIAL — Stripe Secret Key (live)
      Linha: L42
      Issue: Stripe Secret Key (live) detectado hardcoded na linha 42.
      Fix:   Usar variáveis de ambiente ou secret manager.
      ⚡ AÇÃO: Revogar esta credencial imediatamente

    ⛔ [CRÍTICO] DADOS PESSOAIS — CPF (LGPD Art. 5, I)
      Linha: L108
      Issue: CPF válido detectado: 123.***.***-**
      Fix:   Remover dado real. Em testes, usar CPF fictício.
      📋 LGPD: Notificar o DPO. Avaliar notificação à ANPD (Art. 48)
```

---

## Funcionalidades

### 🔍 O que Detecta

| Categoria | Exemplos | Nível de Risco |
|-----------|----------|----------------|
| **Segredos** | Chaves AWS, chaves Stripe, tokens OpenAI, SendGrid, GitHub PATs, webhooks Slack, chaves privadas, strings de conexão | Crítico |
| **PII (LGPD)** | CPF, CNPJ, e-mails, telefones, nomes brasileiros | Crítico/Alto |
| **Financeiro** | Números de cartão de crédito (validação Luhn), códigos CVV | Crítico |
| **Dados de Saúde** | Prontuários médicos, códigos CID-10, prescrições | Crítico |
| **Configuração Insegura** | DEBUG=true, CORS *, IAM wildcards, bancos públicos | Crítico/Alto |
| **Vazamentos no Frontend** | NEXT_PUBLIC_/VITE_ com segredos, chaves de API em bundles | Crítico |
| **Artefatos** | Dumps .sql, arquivos .env, chaves .pem, CSVs com PII | Crítico/Alto |
| **Análise JWT** | Tokens com PII no payload (CPF, e-mail, etc.) | Crítico |

### 🧮 Validação Inteligente

- **CPF/CNPJ**: Valida usando o algoritmo oficial de módulo-11 — somente números reais geram alertas
- **Cartões de Crédito**: Validação pelo algoritmo de Luhn — reconhece cartões de teste Stripe/Visa/Amex
- **E-mails**: Filtra placeholders (example.com, noreply@) para reduzir falsos positivos
- **Sensível ao Contexto**: Eleva a severidade quando PII é encontrado em dumps SQL vs. código regular

### 📊 Formatos de Saída

| Formato | Flag | Caso de Uso |
|---------|------|-------------|
| **Terminal** | `--format terminal` (padrão) | Desenvolvimento local, saída colorida |
| **JSON** | `--format json` | Pipelines CI/CD, automação |
| **SARIF** | `--format sarif` | Aba Security do GitHub, VS Code |
| **HTML** | `--format html` | Relatórios, documentação, demonstrações |

---

## Integração CI/CD

### GitHub Actions

Copie `hooks/github-action.yml` para `.github/workflows/deploy-guard.yml`:

```yaml
name: Deploy Guard Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - run: pip install deploy-guard

      - name: Run Deploy Guard
        run: |
          deploy-guard . --format sarif -o results.sarif --exit-zero
          deploy-guard . --format json -o report.json

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Verificar decisão
        run: |
          DECISION=$(python -c "import json; print(json.load(open('report.json'))['summary']['decision'])")
          if [ "$DECISION" = "block" ]; then exit 1; fi
```

### Hook Git Pre-Push

```bash
cp hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

### Docker

```bash
# Build
docker build -t deploy-guard .

# Escanear um diretório
docker run --rm -v $(pwd):/scan deploy-guard . --target any
```

---

## Configuração

Crie um `.deploy-guard.yml` na raiz do seu projeto:

```yaml
# Tipo de alvo do deploy
target: any

# Habilitar regras LGPD estritas
strict_lgpd: true

# Domínios de e-mail seguros customizados
# safe_email_domains:
#   - "minhaempresa.com.br"
```

---

## Regras LGPD

O Deploy Guard implementa regras de detecção baseadas na **Lei Geral de Proteção de Dados (Lei 13.709/2018)**:

| Artigo | Categoria | O que Detectamos |
|--------|-----------|------------------|
| **Art. 5, I** | Dados Pessoais | CPF, CNPJ, e-mail, telefone, nomes |
| **Art. 5, II** | Dados Sensíveis | Prontuários de saúde, dados biométricos |
| **Art. 11** | Tratamento de Dados Sensíveis | Diagnósticos médicos, códigos CID-10 |
| **Art. 46** | Medidas de Segurança | Credenciais expostas, configurações fracas |
| **Art. 48** | Comunicação de Incidentes | Sinaliza quando notificação ao DPO é necessária |

O conjunto completo de regras está documentado em [rules/lgpd.yml](rules/lgpd.yml) com casos de teste em [rules/lgpd-tests.yml](rules/lgpd-tests.yml).

---

## Estrutura do Projeto

```
deploy-guard/
├── src/deploy_guard/          # Pacote principal
│   ├── __init__.py            # Versão e metadados
│   ├── __main__.py            # python -m deploy_guard
│   ├── cli.py                 # Ponto de entrada CLI
│   ├── config.py              # Suporte a .deploy-guard.yml
│   ├── scanner.py             # Motor de escaneamento
│   ├── models.py              # Dataclass Issue e helpers
│   ├── validators.py          # Algoritmos CPF, CNPJ, Luhn
│   ├── known_safe.py          # Filtros de falso positivo
│   ├── patterns.py            # Padrões regex de detecção
│   ├── git_scanner.py         # Análise de histórico Git
│   ├── pdf_scanner.py         # Extração de texto de PDF
│   └── formatters/
│       ├── terminal.py        # Saída colorida no terminal
│       ├── json_fmt.py        # Relatório JSON
│       ├── sarif.py           # SARIF v2.1.0
│       └── html.py            # Relatório HTML standalone
├── tests/                     # Suite de testes automatizados
│   ├── test_validators.py     # Testes de algoritmos
│   ├── test_secrets.py        # Testes de detecção de segredos
│   ├── test_lgpd_rules.py     # Testes de conformidade LGPD
│   ├── test_scenarios.py      # 7 cenários reais
│   ├── test_formatters.py     # Testes de formatos de saída
│   └── test_cli.py            # Testes da interface CLI
├── rules/                     # Definições de regras (YAML)
├── hooks/                     # Integração CI/CD
├── pyproject.toml             # Configuração do pacote
├── Dockerfile                 # Suporte a container
├── LICENSE                    # Licença MIT
└── README.md                  # Este arquivo
```

---

## Desenvolvimento

```bash
# Clonar
git clone https://github.com/TiagoSchr/deploy-guard.git
cd deploy-guard

# Instalar em modo de desenvolvimento
pip install -e ".[dev]"

# Rodar testes
pytest

# Rodar testes com cobertura
pytest --cov=deploy_guard --cov-report=html

# Executar o scanner
python -m deploy_guard tests/ --strict-lgpd
```

---

## Referência CLI

```
uso: deploy-guard [-h] [-V] [--target {frontend,backend,iac,any}]
                  [--strict-lgpd] [--format {terminal,json,sarif,html}]
                  [-o ARQUIVO] [--json] [--history N] [--pdf]
                  [--no-banner] [--config ARQUIVO] [--exit-zero]
                  caminho

Opções:
  caminho                 Arquivo ou diretório para escanear
  -V, --version           Mostrar versão
  --target                Tipo de alvo do deploy (padrão: any)
  --strict-lgpd           Habilitar regras LGPD mais estritas
  --format                Formato de saída: terminal, json, sarif, html
  -o, --output ARQUIVO    Escrever relatório em arquivo
  --json                  Atalho para --format json
  --history N             Escanear últimos N commits do Git
  --pdf                   Habilitar escaneamento de PDF (requer pdfplumber)
  --no-banner             Suprimir banner ASCII
  --config ARQUIVO        Caminho para arquivo de configuração customizado
  --exit-zero             Sempre retornar exit 0 (modo somente relatório)
```

---

## Códigos de Saída

| Código | Significado |
|--------|-------------|
| `0` | Nenhum problema bloqueante encontrado (ALLOW ou WARN) |
| `1` | Problemas bloqueantes encontrados (BLOCK) — deploy não deve prosseguir |
| `2` | Erro (caminho não encontrado, argumentos inválidos) |

---

## Contribuindo

1. Faça um fork do repositório
2. Crie uma branch de feature (`git checkout -b feature/nova-regra`)
3. Adicione testes para suas alterações
4. Execute a suite de testes (`pytest`)
5. Envie um Pull Request

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

<div align="center">

**Feito com 🛡️ para a comunidade brasileira de desenvolvedores**

*Protegendo deploys, respeitando a privacidade de dados.*

</div>
