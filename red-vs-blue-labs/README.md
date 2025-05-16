# Red vs Blue Labs

![Labs](https://img.shields.io/badge/Environment-Labs-blue)
![Red Team](https://img.shields.io/badge/Red%20Team-Offensive-red)
![Blue Team](https://img.shields.io/badge/Blue%20Team-Defensive-blue)

Laboratórios práticos para simulação de ataques e defesas, proporcionando ambiente controlado para treinamento de equipes de segurança.

## Visão Geral

O módulo Red vs Blue Labs fornece cenários realistas de ataque-defesa para:

- Treinar equipes defensivas (Blue Team) em detecção e resposta
- Praticar técnicas de ataque controladas (Red Team)
- Documentar Indicadores de Compromisso (IoCs)
- Desenvolver e testar playbooks de resposta a incidentes
- Simular técnicas do MITRE ATT&CK em ambiente seguro

## Componentes

```
red-vs-blue-labs/
README.md                 # Esta documentação
attacker-notes.md         # Passo-a-passo e notas para Red Team
defender-responses.md     # Guias de detecção e resposta para Blue Team
scenarios/                # Cenários de ataque organizados
ransomware/               # Simulação de ransomware
lateral-movement/         # Simulação de movimento lateral
data-exfiltration/        # Simulação de exfiltração de dados
iocs/                     # Indicadores de Compromisso dos cenários
hashes.txt                # Hashes de arquivos maliciosos
domains.txt               # Domínios maliciosos simulados
ip-addresses.txt          # Endereços IP maliciosos simulados
setup/                    # Scripts para configuração de ambientes
vagrant/                  # Configurações Vagrant
docker-compose.yml        # Ambiente baseado em Docker
aws-terraform/            # Configuração para ambiente AWS
```

## Conceito

Em cada cenário de laboratório:

1. **Red Team** segue um plano de ataque documentado
2. **Blue Team** tenta detectar e responder às atividades
3. **Ambas as equipes** documentam suas ações e observações
4. **Retrospectiva** analisa o que funcionou e o que poderia melhorar

Os laboratórios são projetados para serem seguros, isolados e facilitar o aprendizado prático.

## Cenários Disponíveis

### 1. Ransomware Simulation

Um cenário que simula um ataque de ransomware, desde a infecção inicial até a criptografia de arquivos:

- **Vetor de Ataque**: Phishing com documento malicioso
- **Técnicas**: Execução de PowerShell ofuscado, persistência via tarefa agendada
- **Objetivos Red Team**: Obter acesso, persistir, criptografar arquivos de teste
- **Objetivos Blue Team**: Detectar, conter e analisar a infecção

### 2. Lateral Movement

Cenário focado em movimento lateral após o comprometimento inicial:

- **Vetor de Ataque**: Comprometimento de credenciais
- **Técnicas**: Pass-the-Hash, WMI para execução remota, criação de usuário
- **Objetivos Red Team**: Espalhar por múltiplos sistemas, obter acesso privilegiado
- **Objetivos Blue Team**: Detectar movimento, mapear propagação, conter o incidente

### 3. Data Exfiltration

Simulação de roubo de dados sensíveis de uma organização:

- **Vetor de Ataque**: Comprometimento via aplicação web
- **Técnicas**: Enumeração de rede, descoberta de dados, exfiltração via DNS/HTTPS
- **Objetivos Red Team**: Localizar e exfiltrar dados "sensíveis" sem ser detectado
- **Objetivos Blue Team**: Detectar acesso indevido a dados, identificar canais de C2

## Ambiente de Laboratório

### Opção 1: Ambiente Local com Vagrant

Ambiente portátil que pode ser executado em qualquer máquina com Vagrant e VirtualBox.

```bash
# Clone o repositório
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/red-vs-blue-labs/setup/vagrant

# Inicie o ambiente
vagrant up

# Acesse as máquinas
vagrant ssh victim
vagrant ssh attacker
```

### Opção 2: Ambiente em Containers Docker

Versão mais leve usando containers Docker para simular redes e sistemas.

```bash
# Clone o repositório
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/red-vs-blue-labs/setup

# Inicie o ambiente
docker-compose up -d

# Acesse os containers
docker exec -it victim-windows bash
docker exec -it attacker-kali bash
```

### Opção 3: Implantação em AWS com Terraform

Para ambiente de treinamento em equipe usando infraestrutura AWS.

```bash
# Clone o repositório
git clone https://github.com/photografereth/cybersec-blueprints.git
cd cybersec-blueprints/red-vs-blue-labs/setup/aws-terraform

# Inicialize e aplique a configuração Terraform
terraform init
terraform apply

# Ao finalizar, destrua os recursos para evitar custos
terraform destroy
```

## Tecnologias em Cada Ambiente

### Ambiente de Infraestrutura
- Windows Server 2019 (Active Directory)
- Windows 10 Workstations
- Linux Servers (Ubuntu, CentOS)
- SIEM (Wazuh open-source)
- Firewall (pfSense)

### Ferramentas Red Team
- Kali Linux
- Metasploit Framework
- PowerShell Empire
- Impacket
- Mimikatz
- Ferramentas de reconhecimento

### Ferramentas Blue Team
- Splunk SIEM
- Sysmon
- Auditd
- Suricata IDS
- OSSEC/Wazuh
- ELK Stack

## Como Utilizar

### Para Instrutores

1. Escolha um cenário alinhado aos objetivos de aprendizado
2. Configure o ambiente seguindo as instruções em `setup/`
3. Divida os participantes em equipes Red e Blue
4. Forneça as instruções iniciais e contexto do cenário
5. Facilite a retrospectiva ao final do exercício

### Para Equipes Red

1. Estude o cenário em `attacker-notes.md`
2. Planeje a abordagem e ferramentas necessárias
3. Execute os ataques conforme documentado
4. Documente achados e mudanças na abordagem
5. Participe da retrospectiva

### Para Equipes Blue

1. Revise as boas práticas em `defender-responses.md`
2. Configure as ferramentas de monitoramento
3. Detecte e responda às atividades da equipe Red
4. Documente IoCs e timeline do ataque
5. Desenvolva melhorias nos controles de segurança

## Lições e Aprendizados

Cada laboratório inclui seções para documentar lições aprendidas:

- **Gaps de Detecções**: Atividades maliciosas não detectadas
- **Falsos Positivos**: Alertas incorretos
- **Pontos de Melhoria**: Controles de segurança a implementar
- **Eficácia de Ferramentas**: Quais ferramentas funcionaram melhor
- **Recomendações**: Sugestões para melhorar a segurança em produção

## Recursos Educacionais

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Incident Response Playbooks](https://www.sans.org/score/incident-response-playbooks/)
- [Atomic Red Team](https://atomicredteam.io/)
- [NIST SP 800-61 Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

## Extensões e Personalizações

Os laboratórios podem ser expandidos com:

- Novas técnicas de ataque do MITRE ATT&CK
- Infraestruturas de rede mais complexas
- Integração com ferramentas comerciais de segurança
- Ataques em infraestruturas cloud (AWS, Azure)
- Simulações específicas para seu ambiente organizacional

## To-Do / Roadmap

- [ ] Adicionar cenãrio de APT com movimento lento
- [ ] Implementar lab de segurança de aplicações web
- [ ] Desenvolver cenário de ataque em containers/Kubernetes
- [ ] Criar ambiente automatizado para competições CTF
- [ ] Adicionar cenários para ameaças específicas por setor

## Contribuição

Contribuições são bem-vindas! Veja o [CONTRIBUTING.md](../CONTRIBUTING.md) para diretrizes.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](../LICENSE) para detalhes.

---

**Atenção**: Estas ferramentas e técnicas devem ser usadas apenas em ambientes de laboratório controlados. Nunca use essas técnicas em sistemas sem autorização explícita.