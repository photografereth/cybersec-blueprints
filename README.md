# CyberSec Blueprints

**Repositório prático para profissionais e entusiastas de cibersegurança defensiva (blue team).**  
Inclui automações com Nmap, playbooks Ansible para hardening, dashboards Splunk e estratégias de hunting em ambientes reais.

---

## Objetivos

- Servir como base de conhecimento técnico para minha atuação profissional em cibersegurança.
- Compartilhar práticas e ferramentas reais aplicadas em ambientes corporativos.
- Ajudar outros profissionais a aprender, colaborar e aplicar segurança de forma objetiva.

---

## Estrutura do Repositório

```bash
cybersec-blueprints/
│
├── nmap-automation/         # Scripts e wrappers para varredura e parsing automatizado
├── ansible-hardening/       # Playbooks para hardening de servidores Linux
├── splunk-dashboards/       # Dashboards e alertas customizados para SIEM
├── threat-hunting/          # Queries, playbooks e táticas de hunting com base no MITRE ATT&CK
├── red-vs-blue-labs/        # Ambientes simulados com visão ofensiva e defensiva
└── docs/                    # Documentação, tutoriais e referências

Conteúdo por Módulo

nmap-automation/

Scripts Shell e Python para:
	•	Scans agendados com output estruturado
	•	Parsing e exportação para CSV/JSON
	•	Classificação de vulnerabilidades por severidade

ansible-hardening/

Playbooks baseados em benchmarks CIS e práticas de hardening como:
	•	Desativação de serviços desnecessários
	•	Políticas de senha e auditoria
	•	Configurações de firewall e SSH

splunk-dashboards/

Dashboards e alertas para:
	•	Detecção de movimentos laterais
	•	Análise de tráfego suspeito e brute force
	•	Tentativas de persistência em endpoints

threat-hunting/

Táticas baseadas no MITRE ATTACK:
	•	Queries para Windows/Linux/M365
	•	Checklists de análise e indicadores
	•	Playbooks de hunting manual e automatizado

red-vs-blue-labs/

Ambientes de simulação:
	•	Scripts de ataque com Metasploit/Nmap
	•	Resposta defensiva documentada (logs, alertas)
	•	Lições aprendidas e estratégias de contenção


	•	Requisitos por pasta estão em cada README.md interno.
	•	Scripts podem ser testados em laboratórios locais ou ambientes virtualizados (VirtualBox, Proxmox, AWS Free Tier).

COMO USAR
```bash
git clone https://github.com/seuusuario/cybersec-blueprints.git
cd cybersec-blueprints

⸻

Contribuição

Este repositório é vivo! Contribuições são bem-vindas via pull requests, issues ou sugestões no GitHub Discussions.

⸻

Licença

MIT License — fique à vontade para usar, adaptar e contribuir, com atribuição.

⸻

Contato

Criado por: [Felipe Miranda]
LinkedIn: [felipe-miranda-399462353]
GitHub: [photografereth]
