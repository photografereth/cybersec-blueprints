# Nmap Automation Toolkit

![Docker](https://img.shields.io/badge/Docker-Ready-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Nmap](https://img.shields.io/badge/Nmap-7.90%2B-orange)

Um conjunto abrangente de ferramentas para automatizar varreduras de segurança com Nmap, processar resultados e integrar com outros sistemas. Este módulo faz parte do projeto CyberSec Blueprints.

## 📋 Visão Geral

O toolkit Nmap Automation fornece:

- **Scripts de automação** para executar varreduras Nmap programadas
- **Parser XML para JSON/CSV** para facilitar análise e integração
- **Detecção de portas críticas e vulnerabilidades comuns**
- **Integração com sistemas de alerta** (e-mail, Discord, Slack, etc.)
- **Containerização com Docker** para facilitar a implantação

## 🔧 Componentes

| Arquivo | Descrição |
|---------|-----------|
| `nmap-auto-scan.sh` | Script Bash para automação de varreduras Nmap |
| `nmap-report-parser.py` | Conversor Python de XML para JSON estruturado |
| `config.yaml` | Configurações gerais para o parser e critérios de alerta |
| `requirements.txt` | Dependências Python para o projeto |
| `Dockerfile` | Configuração para criar container Docker |
| `docker-compose.yml` | Configuração para orquestrar serviços Docker |

## 🔧 Pré-requisitos

### Para execução local:
- Python 3.8+
- Nmap 7.90+
- Bibliotecas Python listadas em `requirements.txt`

### Com Docker:
- Docker Engine
- Docker Compose (opcional)

## 📦 Instalação

### Método 1: Instalação Local

```bash
# Clone o repositório
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/nmap-automation

# Instale as dependências Python
pip install -r requirements.txt

# Certifique-se de que o Nmap está instalado
command -v nmap >/dev/null 2>&1 || { echo "É necessário instalar o Nmap. Abortando."; exit 1; }

# Torne os scripts executáveis
chmod +x nmap-auto-scan.sh
```

### Método 2: Usando Docker

```bash
# Clone o repositório
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/nmap-automation

# Construa a imagem Docker
docker build -t nmap-toolkit .

# Ou use Docker Compose
docker-compose up -d
```

## 🚀 Como Usar

### Execução de Varreduras Automatizadas

```bash
# Uso básico
./nmap-auto-scan.sh 192.168.1.0/24 /tmp/nmap-scans

# Com parâmetros personalizados
./nmap-auto-scan.sh -t 192.168.1.0/24 -o /tmp/nmap-scans -p "22,80,443,3389" -s "-sS -sV -O"
```

### Parsing de Relatórios XML

```bash
# Converter relatório XML do Nmap para JSON
python nmap-report-parser.py /tmp/nmap-scans/scan-20250513-123456.xml

# Converter e detectar portas críticas abertas
python nmap-report-parser.py --detect-critical /tmp/nmap-scans/scan-20250513-123456.xml

# Converter, detectar e enviar alertas
python nmap-report-parser.py --detect-critical --alert /tmp/nmap-scans/scan-20250513-123456.xml
```

### Execução com Docker

```bash
# Executar uma varredura em um alvo específico
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  ./nmap-auto-scan.sh 192.168.1.0/24 /output

# Parser de relatório
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  python nmap-report-parser.py /output/scan-latest.xml
```

## 📝 Configurações

As configurações principais estão no arquivo `config.yaml`:

```yaml
# Configurações para nmap-auto-scan.sh
nmap:
  # Argumentos padrão do Nmap
  default_args: "-sS -sV -O --script=default,vuln"
  # Portas padrão a verificar
  default_ports: "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
  # Tempo máximo de execução (em segundos)
  timeout: 3600

# Configurações para nmap-report-parser.py
parser:
  # Portas consideradas críticas (geram alertas)
  critical_ports:
    - { port: 21, service: "ftp", reason: "FTP não criptografado" }
    - { port: 23, service: "telnet", reason: "Telnet não criptografado" }
    - { port: 3389, service: "rdp", reason: "RDP potencialmente exposto" }
  # Critérios para gerar alertas
  alert_criteria:
    - os_match: "Windows.*2003"
    - service_match: "apache.*2.2"

# Configurações de alerta
alerts:
  # Alertas por email
  email:
    enabled: true
    smtp_server: "smtp.example.com"
    smtp_port: 587
    sender: "security@example.com"
    recipients: 
      - "admin@example.com"
      - "security-team@example.com"
  
  # Alertas Discord
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/your-webhook-id/your-token"
```

## 🔍 Exemplos de Uso

### Cenário 1: Monitoramento de Segurança Periódico

```bash
# Adicione ao crontab para execução diária às 01:00
0 1 * * * /path/to/nmap-auto-scan.sh -t 192.168.0.0/24 -o /var/log/nmap-scans -a "-sS -sV"
```

### Cenário 2: Detecção de Novos Hosts

```bash
# Script para detectar novos hosts na rede e alertar
./nmap-auto-scan.sh -t 10.0.0.0/24 -o /tmp/nmap-latest -n
python nmap-report-parser.py --compare-previous=/tmp/nmap-previous.json --alert /tmp/nmap-latest/scan.xml
```

### Cenário 3: Integração com Dashboard Splunk

```bash
# Gerar JSON para ingestão no Splunk
python nmap-report-parser.py --output-format=splunk /tmp/nmap-latest/scan.xml > /opt/splunk/var/log/nmap/latest.json
```

## 📑 Saída do Parser

O parser gera um JSON estruturado como este:

```json
{
  "scan_info": {
    "timestamp": "2025-05-13T10:15:30",
    "args": "nmap -sS -sV -O 192.168.1.0/24",
    "version": "7.93"
  },
  "hosts": [
    {
      "ip": "192.168.1.10",
      "status": "up",
      "hostname": "server.local",
      "os": {
        "name": "Linux 5.10",
        "accuracy": "96"
      },
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "version": "OpenSSH 8.4",
          "critical": false
        },
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "Apache httpd 2.4.52",
          "critical": false
        }
      ]
    }
  ],
  "summary": {
    "total_hosts": 256,
    "up_hosts": 12,
    "down_hosts": 244,
    "critical_issues": 0
  }
}
```

## 🔄 Integração com Outros Sistemas

O toolkit foi projetado para fácil integração com:

- **Splunk:** Fornece JSON formatado para dashboards de segurança
- **Sistemas de Ticket:** Pode gerar tickets via API quando problemas críticos são encontrados
- **Alertas de Email/Discord/Slack:** Notifica equipes de segurança sobre problemas
- **Relatórios Automáticos:** Gera relatórios PDF/HTML para revisão

## 🧪 Testes

```bash
# Testar script de varredura com alvo local
./nmap-auto-scan.sh -t 127.0.0.1 -o /tmp/test-scan -v

# Testar parser com um arquivo XML de exemplo
python nmap-report-parser.py --test examples/sample-scan.xml
```

## 📋 To-Do / Roadmap

- [ ] Adicionar detecção de vulnerabilidades baseada em CVE
- [ ] Implementar comparação com linha de base para detecção de alterações
- [ ] Melhorar a integração com SIEMs adicionais
- [ ] Adicionar suporte para verificação de certificados TLS
- [ ] Visualização web para resultados de varredura

## 🤝 Contribuição

Contribuições são bem-vindas! Veja o [CONTRIBUTING.md](../CONTRIBUTING.md) para diretrizes.

## 📜 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](../LICENSE) para detalhes.

---

⚠️ **Aviso Legal:** Este toolkit deve ser usado apenas em redes e sistemas que você tem permissão para escanear. Varreduras não autorizadas podem ser ilegais em muitas jurisdições.