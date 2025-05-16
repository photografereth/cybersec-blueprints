# Tutorial: Automação de Varreduras Nmap para Monitoramento Contínuo

Este tutorial explica como configurar e utilizar o módulo nmap-automation para estabelecer um processo de monitoramento contínuo de segurança em sua infraestrutura.

## Objetivos

Ao final deste tutorial, você será capaz de:

1. Configurar varreduras Nmap automatizadas e recorrentes
2. Processar os resultados para identificar vulnerabilidades potenciais
3. Integrar com sistemas de alerta para notificação de problemas
4. Visualizar os resultados em dashboards Splunk

## Pré-requisitos

- Sistema Linux/macOS com acesso à linha de comando
- Python 3.8+ instalado
- Docker (opcional, mas recomendado)
- Acesso administrativo à sua rede (ou permissão para executar varreduras)
- Splunk instalado (opcional, para dashboards)

## Passo 1: Configuração Inicial

### 1.1 Clone o Repositório

```bash
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/nmap-automation
```

### 1.2 Instale as Dependências

```bash
# Método 1: Instalação direta
pip install -r requirements.txt

# Método 2: Usando Docker
docker build -t nmap-toolkit .
```

### 1.3 Configure o Arquivo config.yaml

Edite o arquivo `config.yaml` para personalizar as configurações:

```yaml
# Configurações para nmap-auto-scan.sh
nmap:
  # Modificar para incluir as portas relevantes para seu ambiente
  default_ports: "21,22,23,25,80,443,3389,8080,8443"
  # Ajuste os argumentos conforme sua necessidade
  default_args: "-sS -sV -O --script=default,vuln"
  # Configure o timeout apropriado
  timeout: 3600

# Configurações para nmap-report-parser.py
parser:
  # Defina quais portas são consideradas críticas para seu ambiente
  critical_ports:
    - { port: 21, service: "ftp", reason: "FTP não criptografado" }
    - { port: 3389, service: "rdp", reason: "RDP potencialmente exposto" }
    - { port: 1433, service: "mssql", reason: "SQL Server exposto" }
  
  # Serviços obsoletos que geram alertas
  alert_criteria:
    - os_match: "Windows.*2003|Windows.*XP"
    - service_match: "apache.*2.2|OpenSSH.*(5|6)."

# Configure suas opções de alerta
alerts:
  email:
    enabled: true
    smtp_server: "smtp.suaempresa.com"
    smtp_port: 587
    sender: "security@suaempresa.com"
    recipients: 
      - "admin@suaempresa.com"
      - "security-team@suaempresa.com"
```

## Passo 2: Executando uma Varredura Inicial

### 2.1 Varredura Básica

```bash
# Se instalado localmente
./nmap-auto-scan.sh 192.168.1.0/24 /tmp/nmap-scans

# Se usando Docker
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  ./nmap-auto-scan.sh 192.168.1.0/24 /output
```

### 2.2 Varredura com Parâmetros Personalizados

```bash
# Se instalado localmente
./nmap-auto-scan.sh -t 10.0.0.0/24 -o /tmp/nmap-scans -p "80,443,8080" -s "-sS -sV"

# Se usando Docker
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  ./nmap-auto-scan.sh -t 10.0.0.0/24 -o /output -p "80,443,8080" -s "-sS -sV"
```

## Passo 3: Processando os Resultados

### 3.1 Converta o Relatório XML para JSON

```bash
# Se instalado localmente
python nmap-report-parser.py /tmp/nmap-scans/scan-$(date +%Y%m%d)-*.xml

# Se usando Docker
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  python nmap-report-parser.py /output/scan-latest.xml
```

### 3.2 Detecte Portas Críticas e Envie Alertas

```bash
# Se instalado localmente
python nmap-report-parser.py --detect-critical --alert /tmp/nmap-scans/scan-latest.xml

# Se usando Docker
docker run -it --rm \
  -v $(pwd)/output:/output \
  nmap-toolkit \
  python nmap-report-parser.py --detect-critical --alert /output/scan-latest.xml
```

## Passo 4: Automatize com Agendamentos

### 4.1 Configure um Cron Job para Varreduras Regulares

Edite o crontab para programar varreduras automáticas:

```bash
crontab -e
```

Adicione a seguinte linha para executar uma varredura diária às 01:00:

```
0 1 * * * /caminho/para/nmap-auto-scan.sh -t 192.168.1.0/24 -o /var/log/nmap-scans
```

### 4.2 Configure um Segundo Job para Processar os Resultados

```
30 1 * * * /usr/bin/python3 /caminho/para/nmap-report-parser.py --detect-critical --alert /var/log/nmap-scans/scan-$(date +\%Y\%m\%d)*.xml
```

## Passo 5: Integração com Splunk

### 5.1 Configure a Ingestão dos Resultados JSON no Splunk

Configure um monitor no Splunk para observar o diretório de saída:

1. Acesse Splunk Web (e.g., http://splunk-server:8000)
2. Vá para "Configurações" > "Entradas de Dados"
3. Clique em "Arquivos e Diretórios"
4. Adicione o diretório onde os arquivos JSON são armazenados
5. Configure a fonte de dados como "nmap" e o sourcetype como "json"

### 5.2 Importe o Dashboard Nmap para Splunk

1. No Splunk, vá para "Configurações" > "Objetos de Visualização de Dados"
2. Clique em "Importar Dashboard"
3. Selecione o arquivo `cybersec-blueprints/splunk-dashboards/dashboards/nmap_alerts.xml`
4. Salve o dashboard

## Passo 6: Estabeleça um Processo de Revisão

### 6.1 Revisão de Resultados

Estabeleça um processo regular para revisar os resultados:

1. Revise os alertas gerados pelo sistema
2. Examine o dashboard Splunk para novas descobertas
3. Compare com a linha de base para identificar alterações

### 6.2 Documentação e Ação

Para cada vulnerabilidade ou problema identificado:

1. Documente em seu sistema de tickets
2. Atribua responsabilidade para correção
3. Estabeleça prazos baseados na gravidade
4. Verifique novamente após a correção

## Solução de Problemas Comuns

### Problemas de Permissão

Se encontrar problemas de permissão ao executar as varreduras:

```bash
# Certifique-se de que os scripts são executáveis
chmod +x nmap-auto-scan.sh

# Verifique se o usuário tem permissão para capturar pacotes
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

### Varreduras Lentas

Para acelerar varreduras em redes grandes:

```bash
# Use a flag -T para especificar a velocidade (1-5)
./nmap-auto-scan.sh -t 192.168.0.0/16 -o /tmp/scans -s "-T4 -sS --top-ports 100"
```

### Falsos Positivos

Se estiver recebendo muitos falsos positivos:

1. Ajuste o arquivo `config.yaml` para refinar as definições de portas críticas
2. Crie uma lista de exclusão para hosts específicos:

```bash
./nmap-auto-scan.sh -t 192.168.1.0/24 -o /tmp/scans -e "192.168.1.5,192.168.1.10"
```

## Exemplo de Fluxo de Trabalho Completo

Aqui está um exemplo de um fluxo de trabalho completo para monitoramento contínuo:

```bash
#\!/bin/bash
# Script para monitoramento contínuo de segurança com Nmap

# Diretório de saída
OUTPUT_DIR="/var/log/security/nmap-scans"
mkdir -p "$OUTPUT_DIR"

# Data de hoje para nomeação de arquivos
TODAY=$(date +%Y%m%d)

# Execute a varredura
/path/to/nmap-auto-scan.sh -t 10.0.0.0/24,192.168.1.0/24 -o "$OUTPUT_DIR" -p "21,22,23,25,80,443,1433,3306,3389,8080" -s "-sS -sV --script=default,vuln"

# Processe os resultados
/path/to/nmap-report-parser.py --detect-critical --alert "$OUTPUT_DIR/scan-$TODAY"*.xml

# Gere saída para Splunk
/path/to/nmap-report-parser.py --output-format=splunk "$OUTPUT_DIR/scan-$TODAY"*.xml > "/opt/splunk/var/log/nmap/scan-$TODAY.json"

# Compare com varreduras anteriores
PREV_SCAN=$(find "$OUTPUT_DIR" -name "scan-*.json" -not -name "scan-$TODAY*" | sort -r | head -n1)
if [ -n "$PREV_SCAN" ]; then
  /path/to/nmap-report-parser.py --compare-previous="$PREV_SCAN" --alert "$OUTPUT_DIR/scan-$TODAY"*.xml
fi

echo "Nmap security monitoring completed for $TODAY"
```

## Conclusão

Você agora tem um sistema de monitoramento de segurança automatizado e contínuo usando Nmap. Este sistema:

1. Executa varreduras regulares de segurança
2. Identifica automaticamente portas críticas e vulnerabilidades potenciais
3. Alerta a equipe de segurança sobre problemas
4. Fornece visualização através de dashboards Splunk
5. Mantém um registro histórico para análise de tendências

Continue refinando suas configurações para se adequar ao seu ambiente específico. Considere expandir as varreduras para incluir outros tipos de verificações de segurança e integrar com seu processo de gerenciamento de vulnerabilidades.

---

**Segurança Primeiro:** Certifique-se de que você tem permissão para executar varreduras em sua rede. Varreduras não autorizadas podem ser ilegais ou contra as políticas da sua organização.
EOF < /dev/null