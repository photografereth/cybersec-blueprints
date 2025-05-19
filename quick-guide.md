# Guia Rápido de Ferramentas de Segurança Cibernética

Este guia oferece instruções básicas para usar as ferramentas e começar a testar cada componente deste projeto.

## Índice
- [Ansible Hardening](#ansible-hardening)
- [Nmap Automation](#nmap-automation)
- [Splunk Dashboards](#splunk-dashboards)
- [Threat Hunting](#threat-hunting)
- [Red vs Blue Labs](#red-vs-blue-labs)

## Ansible Hardening

### O que é?
Ansible é uma ferramenta de automação que permite configurar sistemas remotos de forma consistente. Nossos playbooks de hardening aplicam configurações de segurança para Linux.

### Pré-requisitos
- Ansible instalado: `pip install ansible`
- Acesso SSH aos servidores de destino
- Privilégios de sudo

### Como usar
1. Configure seus servidores no arquivo de inventário:
   ```
   cd ansible-hardening
   nano inventory/hosts.ini
   ```

2. Execute o playbook:
   ```
   ansible-playbook -i inventory/hosts.ini playbooks/hardening-linux.yml
   ```

3. Para testar módulos específicos:
   ```
   ansible-playbook -i inventory/hosts.ini playbooks/hardening-linux.yml --tags "ssh,auditd"
   ```

> **⚠️ AVISO**: Aplique primeiro em um ambiente de teste. Algumas configurações podem interromper serviços existentes.

## Nmap Automation

### O que é?
Esta ferramenta automatiza escaneamentos de rede com Nmap e analisa os resultados.

### Pré-requisitos
- Docker e Docker Compose
- Python 3.x (para o parser)

### Como usar
1. Construa a imagem Docker:
   ```
   cd nmap-automation
   docker build -t nmap-toolkit .
   ```

2. Execute o contêiner:
   ```
   docker run -it --rm nmap-toolkit
   ```

3. Para personalizar escaneamentos, edite `config.yaml`

4. Para analisar relatórios XML:
   ```
   python3 nmap-report-parser.py scan-results.xml
   ```

> **⚠️ AVISO**: Realize escaneamentos apenas em redes e sistemas que você tem permissão para analisar. Escaneamentos não autorizados podem ser ilegais.

## Splunk Dashboards

### O que é?
Dashboards e alertas para monitoramento de segurança no Splunk.

### Pré-requisitos
- Instância Splunk funcionando
- Dados sendo enviados ao Splunk

### Como usar
1. Importe os dashboards:
   ```
   cd splunk-dashboards
   ```
   
2. No Splunk Web, navegue até Configurações > Importações
   - Importe os arquivos .xml da pasta dashboards

3. Configure alertas:
   ```
   # No Splunk, crie alertas usando os arquivos de configuração em:
   splunk-dashboards/alerts/
   ```

4. Para testar, execute as consultas manualmente antes de configurar alertas automáticos.

## Threat Hunting

### O que é?
Consultas e playbooks para detecção proativa de ameaças.

### Pré-requisitos
- Splunk ou outra plataforma SIEM
- Logs adequados configurados

### Como usar
1. Veja as consultas disponíveis:
   ```
   cd threat-hunting/detection-queries
   ```

2. Execute uma consulta no seu SIEM:
   ```
   # Exemplo para Splunk:
   cat linux-persistence.spl
   # Copie e cole a consulta no console de busca do Splunk
   ```

3. Siga os playbooks de hunting:
   ```
   cat hunting-playbooks.md
   ```

## Red vs Blue Labs

### O que é?
Cenários para praticar ataque e defesa de sistemas.

### Pré-requisitos
- Ambiente de laboratório isolado
- Ferramentas de segurança básicas

### Como usar
1. Leia a documentação:
   ```
   cd red-vs-blue-labs
   cat README.md
   ```

2. Para exercícios de ataque:
   ```
   cat attacker-notes.md
   ```

3. Para respostas de defesa:
   ```
   cat defender-responses.md
   ```

> **⚠️ AVISO IMPORTANTE**: Todas as técnicas deste laboratório devem ser praticadas apenas em ambientes dedicados e isolados. Nunca utilize técnicas de ataque em sistemas reais sem permissão explícita.

## Começando do Zero

Para iniciantes completos, recomendamos esta sequência:

1. Configure um ambiente de laboratório virtual (VirtualBox + VMs Linux)
2. Comece pelo Ansible Hardening para aprender sobre configurações seguras
3. Passe para o Nmap Automation para entender escaneamento de rede
4. Configure o Splunk para aprender sobre monitoramento
5. Pratique os cenários Red vs Blue

Lembre-se: a segurança cibernética exige aprendizado contínuo. Documente seus resultados e aprenda com cada ferramenta gradualmente.