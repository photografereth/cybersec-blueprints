# Ansible Hardening Toolkit

Este módulo contém playbooks e roles Ansible para automação de hardening de servidores Linux, seguindo recomendações de segurança e benchmarks CIS (Center for Internet Security).

![Ansible Version](https://img.shields.io/badge/Ansible-2.12%2B-blue)
![Python Version](https://img.shields.io/badge/Python-3.x-green)

## 📋 Visão Geral

O toolkit fornece uma abordagem modular para aplicar configurações de segurança em servidores Linux, com foco em:

- Implementação de controles técnicos baseados em benchmarks de segurança
- Automação e padronização das configurações de segurança
- Redução da superfície de ataque dos servidores
- Conformidade com padrões de segurança comuns

## 🧩 Componentes

O módulo está organizado em roles independentes, cada um responsável por um aspecto específico do hardening:

| Role | Descrição |
|------|-----------|
| `common` | Configurações básicas, pacotes essenciais, NTP e atualizações |
| `ssh_hardening` | Fortalecimento do SSH (protocolos, autenticação, algoritmos) |
| `auditd` | Instalação e configuração de auditoria do sistema |
| `sysctl` | Ajustes de parâmetros de kernel para segurança de rede |

## 🔧 Pré-requisitos

- Python 3.x
- Ansible 2.12+
- Acesso SSH com privilégios sudo aos hosts-alvo
- Sistemas suportados:
  - Ubuntu 20.04 LTS+
  - Debian 11+
  - CentOS/RHEL 8+ (em desenvolvimento)

## 📁 Estrutura de Diretórios

```
ansible-hardening/
├── README.md                  # Esta documentação
├── inventory/                 # Definição de hosts e grupos
│   └── hosts.ini             # Arquivo de inventário
├── playbooks/                 # Playbooks agregadores
│   └── hardening-linux.yml   # Playbook principal
├── roles/                     # Roles individuais
│   ├── common/               # Configurações básicas
│   │   ├── tasks/           # Tarefas da role
│   │   │   └── main.yml    # Tarefas principais
│   │   └── handlers/        # Handlers para serviços
│   │       └── main.yml    # Handlers principais
│   ├── ssh_hardening/        # Hardening de SSH
│   │   └── tasks/
│   │       └── main.yml
│   ├── auditd/               # Configuração de auditoria
│   │   └── tasks/
│   │       └── main.yml
│   └── sysctl/               # Parâmetros de kernel
│       └── tasks/
│           └── main.yml
└── group_vars/                # Variáveis para grupos de hosts
    └── all.yml               # Variáveis aplicáveis a todos hosts
```

## 🚀 Como Usar

### 1. Configure o Arquivo de Inventário

Edite o arquivo `inventory/hosts.ini` para definir seus hosts-alvo:

```ini
[web_servers]
web1.example.com
web2.example.com

[database_servers]
db1.example.com
db2.example.com

[all:vars]
ansible_user=admin
ansible_become=yes
ansible_become_method=sudo
```

### 2. Personalize as Variáveis (Opcional)

Ajuste o arquivo `group_vars/all.yml` para customizar as configurações padrão:

```yaml
# Ajuste conforme necessário para seu ambiente
ssh_permit_root_login: "no"
ssh_max_auth_tries: 3
password_min_length: 12
```

### 3. Execute o Playbook

```bash
ansible-playbook -i inventory/hosts.ini playbooks/hardening-linux.yml
```

Para realizar uma verificação sem aplicar mudanças:

```bash
ansible-playbook -i inventory/hosts.ini playbooks/hardening-linux.yml --check
```

Para aplicar apenas um conjunto específico de configurações:

```bash
ansible-playbook -i inventory/hosts.ini playbooks/hardening-linux.yml --tags ssh
```

## 🧪 Testes Automatizados

Utilizamos Molecule para testes de integração das roles:

### Pré-requisitos para Testes

```bash
pip install molecule[docker] ansible yamllint flake8
```

### Executando Testes

Dentro do diretório de cada role:

```bash
cd roles/common
molecule test
```

O processo de teste inclui:
1. Criação de container Docker para testes
2. Preparação do ambiente (prepare.yml)
3. Aplicação da role (converge.yml)
4. Verificação das configurações (verify.yml)
5. Destruição do ambiente de teste

## 📝 Controles de Segurança Implementados

### SSH
- Desativação de login como root
- Desativação de autenticação por senha
- Uso de protocolos e algoritmos fortes
- Timeouts de sessão
- Banner de conexão personalizado

### Auditd
- Monitoramento de chamadas de sistema críticas
- Registro de alterações em arquivos de configuração
- Registro de acessos privilegiados
- Audit rules específicas por subsistema

### Sysctl
- Proteção contra ataques ICMP e SYN flood
- Desativação de encaminhamento de pacotes
- Restrições para protocolos de rede inseguros
- Parâmetros de kernel para proteção de memória

### Common
- Atualizações automáticas de segurança
- Configuração de NTP
- Gerenciamento seguro de senhas
- Restrições de permissões em arquivos críticos

## 🔄 CI/CD e Integração

Para integrar este módulo em pipelines CI/CD, considere:

- Executar `molecule test` durante integração contínua
- Configurar ansible-lint no pipeline
- Aplicar gradualmente em ambientes (dev → staging → produção)
- Integrar com ferramentas de avaliação de vulnerabilidades (como OpenSCAP)

## 📚 Documentação Adicional

- [Ansible Hardening Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final)

## 🛣️ Roadmap

- Adicionar suporte completo para sistemas RedHat/CentOS
- Implementar role para configuração de firewall (iptables/nftables/firewalld)
- Expandir testes automatizados
- Integrar com ferramentas de avaliação como Lynis

## 🤝 Contribuição

Contribuições são bem-vindas! Veja o [CONTRIBUTING.md](../CONTRIBUTING.md) para diretrizes.

---

📣 **Nota:** Este módulo implementa controles básicos de segurança. Ajuste as configurações para seu ambiente específico e requisitos de segurança.