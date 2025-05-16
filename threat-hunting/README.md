# Threat Hunting Toolkit

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![SPL](https://img.shields.io/badge/SPL-Queries-orange)
![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Cloud-blue)

Recursos para threat hunting proativo baseado no framework MITRE ATT&CK, incluindo queries de detecção, playbooks para investigação, e metodologias de hunting.

## Visão Geral

O Threat Hunting Toolkit fornece recursos para equipes de segurança realizarem busca proativa de ameaças em suas redes e sistemas. Diferente da detecção reativa tradicional, o hunting foca em identificar adversários antes que eles completem seus objetivos.

O toolkit é organizado pelos principais táticas do MITRE ATT&CK:

- **Persistência**: Detecção de técnicas de permanência em sistemas
- **Escalação de Privilégios**: Identificação de tentativas de ganhar privilégios elevados
- **Evasão de Defesa**: Detecção de técnicas para evitar controles de segurança
- **Acesso a Credenciais**: Localização de tentativas de extração de credenciais
- **Movimento Lateral**: Detecção de propagação entre sistemas
- **Exfiltração**: Identificação de tentativas de roubo de dados

## Componentes

```
threat-hunting/
README.md                      # Esta documentação
detection-queries/             # Queries para detecção
linux-persistence.spl          # Detecção de persistência em Linux
windows-lateral-movement.spl   # Detecção de movimento lateral em Windows
hunting-playbooks.md           # Playbooks e procedimentos para hunting manual
```

## Queries de Detecção

As queries são principalmente desenvolvidas para Splunk (SPL), mas os conceitos podem ser adaptados para outros SIEMs e ferramentas de análise.

### Persistência em Linux (linux-persistence.spl)

Queries para detectar métodos comuns de persistência em ambientes Linux:

- Cron jobs suspeitos
- Services/Systemd modificados
- Arquivos .bashrc/.profile alterados
- SSH authorized_keys modificados
- Módulos de kernel carregados
- Arquivos startup incomuns

### Movimento Lateral em Windows (windows-lateral-movement.spl)

Queries para detectar técnicas de movimento lateral em ambientes Windows:

- Uso de WMI para execução remota
- PsExec e ferramentas semelhantes
- Conexões RDP incomuns
- Uso de Pass-the-Hash/Pass-the-Ticket
- DCOM para execução remota
- Uso de ferramentas administrativas comuns em padrões incomuns

## Playbooks de Hunting

Os playbooks detalhados podem ser encontrados em `hunting-playbooks.md` e incluem:

1. **Preparação**
   - Definição do escopo e objetivos
   - Coleta de dados necessários
   - Estabelecimento de linha de base

2. **Hunting por Tática**
   - Hipótese inicial
   - Queries e técnicas de análise
   - Pivoteamento com base em achados
   - Documentação dos resultados

3. **Resposta a Achados**
   - Escalação e comunicação
   - Contenção imediata
   - Investigação aprofundada
   - Remediação completa

## Metodologia de Hunting

Nossa abordagem de hunting segue um ciclo de quatro fases:

1. **Formular Hipóteses**: Usar inteligência de ameaças e conhecimento de adversários para criar hipóteses de teste
2. **Investigar via Ferramentas**: Usar as queries e técnicas para identificar indicadores de atividade suspeita
3. **Descobrir Novas Técnicas**: Documentar técnicas identificadas durante o hunting
4. **Informar e Aprimorar**: Melhorar detecções e processos com base nas descobertas

## Casos de Uso Principais

### Caso 1: Hunting de Persistência Incomum

Objetivo: Identificar mecanismos de persistência que tenham evadido detecções tradicionais.

Abordagem:
1. Analisar alterações recentes em serviços, tarefas agendadas e chaves de registro
2. Buscar padrões incomuns de execução de processos
3. Verificar binários em locais de inicialização não padrão

Queries relevantes:
```spl
index=windows EventCode=7045 OR (EventCode=4698)
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, Service_File_Name, Service_Name
| lookup whitelist Service_File_Name
| where isnull(is_whitelisted)
| sort - count
```

### Caso 2: Detecção de Movimento Lateral

Objetivo: Identificar tentativas de movimento lateral usando credenciais roubadas.

Abordagem:
1. Analisar padrões de logon em múltiplos sistemas
2. Buscar horários incomuns ou sequências suspeitas
3. Correlacionar com comandos executados logo após logon

Queries relevantes:
```spl
index=windows (EventCode=4624 OR EventCode=4625) LogonType=3
| bucket _time span=5m
| stats count as auth_attempts, dc(ComputerName) as unique_targets, values(ComputerName) as targets by SourceIP, _time
| where auth_attempts > 5 AND unique_targets > 3
| sort - auth_attempts
```

### Caso 3: Hunting de Comportamentos Suspeitos em Linha de Comando

Objetivo: Identificar comandos suspeitos que podem indicar atividade maliciosa.

Abordagem:
1. Analisar comandos PowerShell/Bash com codificação ou obfuscação
2. Detectar tentativas de dump de memória ou credenciais
3. Identificar conexões de rede iniciadas por processos suspeitos

Queries relevantes:
```spl
index=linux sourcetype=bash_history OR sourcetype=auditd
| regex command="(?i)(wget|curl).*(\-O|\-output|>).*(/tmp|/dev/shm)"
| stats count min(_time) as firstTime max(_time) as lastTime by host, user, command
| sort - count
```

## TTP Mapeadas para MITRE ATT&CK

| Tática | Técnica | ID | Detecção |
|--------|---------|-------|----------|
| Persistência | Create Account | T1136 | linux-persistence.spl |
| Persistência | Cron Jobs | T1053.003 | linux-persistence.spl |
| Persistência | Registry Run Keys | T1547.001 | windows-persistence.spl |
| Acesso a Credenciais | OS Credential Dumping | T1003 | windows-credential-access.spl |
| Movimento Lateral | Remote Services | T1021 | windows-lateral-movement.spl |
| Movimento Lateral | Pass the Hash | T1550.002 | windows-lateral-movement.spl |
| Execução | Command and Scripting Interpreter | T1059 | linux-execution.spl, windows-execution.spl |
| Exfiltração | Exfiltration Over Web Service | T1567 | data-exfiltration.spl |

## Integração com Outras Ferramentas

Este toolkit foi projetado para trabalhar em conjunto com:

- **SIEM** (Splunk, ELK, QRadar)
- **EDR** (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
- **NDR** (Darktrace, Vectra, Corelight)
- **Ferramentas de Forense** (Velociraptor, OSQuery, KAPE)

## Recursos de Aprendizado

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Threat Hunting](https://www.sans.org/blog/-effective-threat-hunting-techniques/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)

## Testes e Validação

Para validar as técnicas de hunting, considere:

1. **Simulações de Adversários**: Execute ferramentas como Atomic Red Team para testar detecções
2. **Revisão de Falsos Positivos**: Refine continuamente as queries para reduzir falsos positivos
3. **Purple Team Exercises**: Colabore com equipes Red Team para validar técnicas de detecção

## To-Do / Roadmap

- [ ] Expandir queries para Azure e AWS
- [ ] Desenvolver queries para detecção de exfiltração de dados
- [ ] Criar playbooks específicos para ameaças emergentes
- [ ] Implementar automação para hunting contínuo
- [ ] Adicionar visualizações para análise de resultados

## Contribuição

Contribuições são bem-vindas! Veja o [CONTRIBUTING.md](../CONTRIBUTING.md) para diretrizes.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](../LICENSE) para detalhes.

---

**Lembre-se**: Threat Hunting é um processo iterativo que melhora com o tempo. Documente seus achados, refine suas técnicas, e compartilhe conhecimento com a comunidade.