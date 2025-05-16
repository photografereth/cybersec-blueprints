# Playbooks de Threat Hunting

Este documento contém playbooks estruturados para caça a ameaças (threat hunting) em ambientes corporativos. Cada playbook foca em uma tática específica do MITRE ATT&CK e fornece uma abordagem metodológica para identificar atividades suspeitas ou maliciosas.

## Índice

1. [Metodologia de Hunting](#metodologia-de-hunting)
2. [Playbook: Persistência em Linux](#playbook-persistência-em-linux)
3. [Playbook: Movimento Lateral em Windows](#playbook-movimento-lateral-em-windows)
4. [Playbook: Exfiltração de Dados](#playbook-exfiltração-de-dados)
5. [Playbook: Acesso Inicial via Phishing](#playbook-acesso-inicial-via-phishing)
6. [Documentação de Resultados](#documentação-de-resultados)

---

## Metodologia de Hunting

### Abordagem Baseada em Hipóteses

Nossa metodologia segue um ciclo de hunting de quatro fases:

1. **Formular Hipóteses**: Desenvolver hipóteses baseadas em:
   - Inteligência de ameaças recentes
   - Táticas, técnicas e procedimentos (TTPs) conhecidos
   - Vulnerabilidades específicas do ambiente
   - Eventos históricos ou resultados de hunting anteriores

2. **Investigar via Ferramentas**: Usar técnicas de análise para investigar:
   - Consultas específicas em logs e eventos
   - Análise de anomalias comportamentais
   - Correlação de eventos aparentemente não relacionados
   - Verificação de indicadores de comprometimento (IoCs)

3. **Descobrir Novas Técnicas**: Documentar novas descobertas:
   - Variações de TTPs conhecidas
   - Técnicas inovadoras não documentadas anteriormente
   - Comportamentos anômalos específicos do ambiente

4. **Informar e Aprimorar**: Usar resultados para melhorar a segurança:
   - Documentar e compartilhar descobertas
   - Implementar detecções para novos padrões
   - Refinar hipóteses futuras
   - Atualizar playbooks com novos insights

### Preparação para Hunting

Antes de iniciar qualquer sessão de hunting, assegure:

1. **Acesso a Dados**:
   - Confirme acesso a logs relevantes (SIEM, EDR, etc.)
   - Verifique se o período de dados é adequado (geralmente 30-90 dias)
   - Confirme que a cobertura de dados inclui sistemas-alvo

2. **Ferramentas Necessárias**:
   - SIEM (Splunk, ELK, QRadar, etc.)
   - Ferramentas de EDR
   - Analisadores de logs
   - Ferramentas de visualização de dados

3. **Estabelecimento de Baseline**:
   - Compreenda o comportamento normal do ambiente
   - Identifique padrões sazonais ou cíclicos
   - Documente atividades administrativas legítimas que podem parecer maliciosas

4. **Equipe e Comunicação**:
   - Defina papéis para a sessão de hunting
   - Estabeleça canais de comunicação
   - Prepare processo de escalação para descobertas críticas

---

## Playbook: Persistência em Linux

### Objetivo

Identificar mecanismos de persistência não autorizados em sistemas Linux que poderiam permitir a um adversário manter acesso após reinicialização do sistema ou credenciais alteradas.

### Hipóteses

1. Adversários podem ter estabelecido persistência via cron jobs
2. Podem existir serviços ou unidades systemd maliciosas
3. Arquivos de perfil de shell (.bashrc, .profile) podem ter sido modificados
4. Possíveis módulos de kernel maliciosos carregados
5. Chaves SSH não autorizadas podem ter sido adicionadas

### Fontes de Dados

- Logs do Auditd
- Syslogs
- Eventos de autenticação
- Histórico de comandos
- Inventário de arquivos e pacotes

### Procedimento de Hunting

#### Fase 1: Análise de Cron Jobs

1. **Execute as seguintes consultas**:
   ```splunk
   index=linux (sourcetype=syslog OR sourcetype="linux_secure") ("CRON" OR "/etc/cron") 
   | rex field=_raw "(?<user>\w+).*?(?<action>ADD|LIST|REPLACE|REMOVE).*?(?<cron_target>crontab for|cron\.daily|cron\.hourly|cron\.monthly|cron\.weekly)"
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, action, cron_target
   ```

2. **Comandos para análise direta**:
   ```bash
   # Verificar cron jobs de todos os usuários
   for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null; done
   
   # Verificar cron jobs do sistema
   ls -la /etc/cron*
   cat /etc/crontab
   ```

3. **Análise**:
   - Compare com linha de base conhecida
   - Identifique jobs que executam scripts em locais não padrão (/tmp, /dev/shm)
   - Procure comandos de conexão de rede (curl, wget)
   - Observe quaisquer comandos codificados (base64, hex)

#### Fase 2: Serviços e Daemons

1. **Execute as seguintes consultas**:
   ```splunk
   index=linux sourcetype=auditd path IN ("/etc/systemd/system/*", "/usr/lib/systemd/system/*", "/lib/systemd/system/*") 
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, path, process
   ```

2. **Comandos para análise direta**:
   ```bash
   # Listar todos os serviços habilitados
   systemctl list-unit-files --state=enabled
   
   # Examinar serviços recém-criados
   find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -30
   
   # Verificar services que escutam em portas
   ss -tulpn
   ```

3. **Análise**:
   - Procure serviços recentemente adicionados ou modificados
   - Observe serviços com nomes similares a serviços legítimos (typosquatting)
   - Analise serviços que usam caminhos não padrão para executáveis
   - Identifique serviços configurados para reiniciar persistentemente

#### Fase 3: Arquivos de Perfil Shell

1. **Execute as seguintes consultas**:
   ```splunk
   index=linux sourcetype=auditd path IN ("*.bashrc", "*.bash_profile", "*.profile", "*.zshrc", "/etc/profile", "/etc/bash.bashrc") 
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, path, process
   ```

2. **Comandos para análise direta**:
   ```bash
   # Encontrar arquivos .bashrc e similares modificados recentemente
   find /home -name ".*rc" -o -name ".*profile" -mtime -30
   
   # Verificar conteúdo de arquivos suspeitos
   for file in $(find /home -name ".bashrc" -mtime -7); do echo "=== $file ==="; cat $file; echo; done
   ```

3. **Análise**:
   - Procure por comandos adicionados que iniciam processos em segundo plano
   - Identifique aliases que podem mascarar comandos legítimos
   - Procure scripts que são baixados e executados automaticamente
   - Observe exportações de variáveis de ambiente incomuns

#### Fase 4: Módulos do Kernel

1. **Execute as seguintes consultas**:
   ```splunk
   index=linux (sourcetype=syslog OR sourcetype=messages) ("insmod" OR "modprobe" OR "kernel: module" OR "lsmod") 
   | rex field=_raw "(?<module_name>\w+)\.ko"
   | stats count min(_time) as firstTime max(_time) as lastTime by host, source, module_name, user
   ```

2. **Comandos para análise direta**:
   ```bash
   # Listar módulos carregados
   lsmod
   
   # Verificar módulos incomuns
   modinfo $(lsmod | awk '{print $1}' | grep -v "^Module$")
   
   # Verificar módulos carregados na inicialização
   cat /etc/modules
   ls /etc/modules-load.d/
   ```

3. **Análise**:
   - Compare com linha de base de módulos conhecidos
   - Procure módulos sem informações ou documentação
   - Identifique módulos assinados incorretamente
   - Observe módulos que ocultam processos ou arquivos

#### Fase 5: Chaves SSH

1. **Execute as seguintes consultas**:
   ```splunk
   index=linux sourcetype=auditd path="*/.ssh/authorized_keys" 
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, path, process
   ```

2. **Comandos para análise direta**:
   ```bash
   # Encontrar arquivos authorized_keys modificados recentemente
   find /home -name "authorized_keys" -mtime -30
   
   # Verificar conteúdo de authorized_keys
   for file in $(find /home -name "authorized_keys"); do echo "=== $file ==="; cat $file; echo; done
   ```

3. **Análise**:
   - Compare com um inventário aprovado de chaves SSH
   - Identifique chaves sem comentários descritivos
   - Procure chaves adicionadas fora do processo normal
   - Observe chaves com opções incomuns (como force-command)

### Indicadores de Comprometimento

- Cron jobs que executam scripts em locais temporários ou via URLs
- Serviços systemd recém-criados com nomes suspeitos
- Modificações em arquivos .bashrc com comandos obfuscados
- Módulos de kernel sem informações claras de origem
- Chaves SSH não reconhecidas em arquivos authorized_keys

### Próximos Passos e Resposta

1. **Para cada achado potencial**:
   - Documente detalhadamente (data, hora, sistema, usuário, evidências)
   - Preserve evidências forenses
   - Correlacione com outros eventos no mesmo sistema

2. **Para confirmação de comprometimento**:
   - Isole o sistema afetado
   - Inicie procedimentos de resposta a incidentes
   - Capture memória e imagem forense se necessário
   - Escale para equipe de resposta a incidentes

3. **Para remediação**:
   - Remova mecanismos de persistência não autorizados
   - Implemente monitoramento adicional
   - Conduza análise de causa raiz
   - Atualize detecções baseadas nos achados

---

## Playbook: Movimento Lateral em Windows

### Objetivo

Identificar atividades de movimento lateral em ambiente Windows onde adversários podem estar se movendo entre sistemas após o comprometimento inicial, utilizando técnicas como Pass-the-Hash, WMI, PowerShell Remoting ou PsExec.

### Hipóteses

1. Adversários podem estar utilizando PsExec ou similares para movimentação
2. Credenciais podem estar sendo reutilizadas entre sistemas (Pass-the-Hash)
3. PowerShell Remoting pode estar sendo abusado para execução em múltiplos hosts
4. WMI pode estar sendo utilizado para execução de comandos remota
5. Compartilhamentos administrativos podem estar sendo explorados

### Fontes de Dados

- Windows Event Logs (Security, System, PowerShell)
- EDR/XDR logs
- Dados de autenticação
- Logs de firewall/proxy
- Tráfego de rede

### Procedimento de Hunting

#### Fase 1: Detecção de PsExec e Similares

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) (Process_Name="*psexec.exe" OR Process_Name="*psexesvc.exe" OR OriginalFileName="psexec.exe") 
   | rex field=CommandLine "(?i).*\s+\\\\(?<target_host>[^\\\s]+).*\s+-[suepn]{1,5}\s+(?<command_args>.+)"
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, user, target_host, CommandLine
   ```

   ```splunk
   index=windows EventCode=7045 Service_Name="PSEXESVC" OR Service_File_Name="*PSEXESVC.exe"
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, Service_Name, Service_File_Name
   ```

2. **Análise**:
   - Identifique sistemas de origem e destino de conexões PsExec
   - Observe o contexto de usuário utilizando a ferramenta
   - Analise os comandos executados remotamente
   - Correlacione com atividades administrativas legítimas conhecidas

#### Fase 2: Análise de Pass-the-Hash e Reutilização de Credenciais

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetUserName, IpAddress
   | join type=left TargetUserName [
       search index=windows EventCode=4624 LogonType=2 
       | stats count as interactive_logons by TargetUserName
       | eval has_interactive=if(interactive_logons>0, "yes", "no")
       | fields TargetUserName, has_interactive
   ]
   | where has_interactive="yes"
   | stats count values(Computer) as targets by TargetUserName, IpAddress
   | where count > 2
   ```

   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) 
   | search (Process_Name="*lsass.exe" AND ParentProcessName\!="*wininit.exe") OR 
            CommandLine="*sekurlsa*" OR 
            CommandLine="*kerberos*" OR 
            CommandLine="*mimikatz*" OR
            CommandLine="*privilege::debug*"
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, user, Process_Name, CommandLine
   ```

2. **Análise**:
   - Identifique contas que fazem logon em múltiplos sistemas em um período curto
   - Observe padrões atípicos de autenticação NTLM
   - Procure autenticações de contas administrativas fora do padrão normal
   - Correlacione com potencial extração de credenciais (Mimikatz, etc)

#### Fase 3: PowerShell Remoting

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) Process_Name="*powershell.exe" 
   (CommandLine="*-ComputerName*" OR CommandLine="*Invoke-Command*" OR CommandLine="*Enter-PSSession*" OR CommandLine="*New-PSSession*")
   | rex field=CommandLine "(?i).*(?:ComputerName|\-ComputerName|\-Cn)\s+(?:[\"'])?(?<target_host>[^,\"'\s]+)(?:[\"'])?.*"
   | search target_host=*
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, user, target_host, CommandLine
   ```

   ```splunk
   index=windows EventCode IN (800, 4103, 4104) 
   | search "*-ComputerName*" OR "*Invoke-Command*" OR "*Enter-PSSession*" OR "*New-PSSession*"
   | rex field=Message "(?i).*(?:ComputerName|\-ComputerName|\-Cn)\s+(?:[\"'])?(?<target_host>[^,\"'\s]+)(?:[\"'])?.*"
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, UserID, target_host
   ```

2. **Análise**:
   - Identifique execução de PowerShell em múltiplos hosts
   - Observe scripts sendo executados remotamente
   - Procure por técnicas de ofuscação dentro dos comandos
   - Analise contexto de execução (usuário, horário, origem)

#### Fase 4: WMI para Execução Remota

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) (Process_Name="*wmic.exe" OR OriginalFileName="wmic.exe")
   | rex field=CommandLine "(?i).*\s+/node:(?:[\"'])?(?<target_host>[^\"'\s]+)(?:[\"'])?\s+.*process\s+(?:call\s+create|exec|start)\s+(?:[\"'])?(?<command_run>[^\"']+)(?:[\"'])?"
   | search target_host=* command_run=*
   | stats count min(_time) as firstTime max(_time) as lastTime by Computer, user, target_host, command_run
   ```

   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) (Process_Name="*WmiPrvSE.exe" OR Process_Name="*WmiApSrv.exe") host=*
   | stats count values(Process_Name) min(_time) as firstTime max(_time) as lastTime by Computer, ParentProcessId
   | join ParentProcessId [search index=windows (EventCode=4688 OR EventCode=1) | rename ProcessId as ParentProcessId | fields ParentProcessId, Process_Name, CommandLine]
   ```

2. **Análise**:
   - Identifique padrões de uso do WMI para execução remota
   - Observe os comandos executados em sistemas remotos
   - Analise padrões de atividade WmiPrvSE nos hosts de destino
   - Correlacione com outras atividades de movimento lateral

#### Fase 5: Uso de Compartilhamentos Administrativos

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows EventCode=5140 ShareName IN ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$") ObjectType=File
   | stats count min(_time) as firstTime max(_time) as lastTime values(ShareName) as shares by Computer, SubjectUserName, IpAddress
   ```

   ```splunk
   index=windows EventCode=5145 ShareName IN ("\\\\*\\C$", "\\\\*\\ADMIN$") AccessMask="0x2" OR AccessMask="0x100"
   | rex field=RelativeTargetName "(?<file_name>[^\\]+)$"
   | stats count min(_time) as firstTime max(_time) as lastTime values(file_name) as created_files by Computer, SubjectUserName, IpAddress, ShareName
   ```

2. **Análise**:
   - Identifique acessos a compartilhamentos administrativos (C$, ADMIN$)
   - Observe criação ou modificação de arquivos nesses compartilhamentos
   - Procure por cópias de ferramentas potencialmente maliciosas
   - Analise padrões de uso por contas administrativas fora do normal

#### Fase 6: Correlação e Análise de Padrões

1. **Execute a seguinte consulta para identificar sistemas com múltiplos indicadores**:
   ```splunk
   index=windows 
   | eval lateral_movement_type=case(
       (EventCode=4624 AND LogonType=3), "Network Logon",
       (EventCode=4624 AND LogonType=10), "RDP",
       (EventCode=5140 AND match(ShareName, "\\\\.*\\(C|ADMIN)\$")), "Admin Share",
       (Process_Name="*psexec.exe" OR Process_Name="*psexesvc.exe"), "PsExec",
       (Process_Name="*wmic.exe" AND match(CommandLine, ".*node.*process")), "WMI",
       (Process_Name="*powershell.exe" AND (match(CommandLine, ".*Enter-PSSession.*") OR match(CommandLine, ".*Invoke-Command.*"))), "PowerShell Remoting",
       1=1, NULL()
   )
   | search lateral_movement_type=*
   | stats count values(lateral_movement_type) as techniques by Computer
   | where mvcount(techniques) > 1
   ```

2. **Análise**:
   - Identifique sistemas que apresentam múltiplas técnicas de movimento lateral
   - Reconstrua a timeline de eventos entre sistemas relacionados
   - Estabeleça o caminho de movimento (de onde para onde)
   - Determine o contexto e possível impacto

### Indicadores de Comprometimento

- Uso de PsExec fora de janelas de manutenção ou por usuários não autorizados
- Autenticações NTLM de uma única conta em múltiplos sistemas em curto período
- Comandos PowerShell Remoting executando scripts suspeitos ou ofuscados
- Execução de WMI para criar processos remotos com comandos suspeitos
- Transferência de arquivos executáveis para compartilhamentos administrativos

### Próximos Passos e Resposta

1. **Para cada achado potencial**:
   - Documente detalhadamente os indicadores
   - Mapeie todos os sistemas envolvidos no movimento lateral
   - Preserve logs e evidências relevantes

2. **Para confirmação de comprometimento**:
   - Isole os sistemas afetados
   - Execute análise forense de memória
   - Inicie procedimentos de resposta a incidentes
   - Identifique ponto de comprometimento inicial

3. **Para remediação**:
   - Implementar monitoramento adicional
   - Rever políticas de acesso administrativo
   - Considerar implementação de PAM (Privileged Access Management)
   - Atualizar detecções com base nos TTPs observados

---

## Playbook: Exfiltração de Dados

### Objetivo

Identificar possíveis exfiltrações de dados, onde adversários podem estar tentando extrair informações sensíveis do ambiente corporativo usando vários canais como DNS, HTTPS, ou transferências de arquivo não autorizadas.

### Hipóteses

1. Adversários podem estar usando DNS para exfiltração lenta
2. HTTPS pode estar sendo usado para enviar dados para sites externos não categorizados
3. Volumes anômalos de upload podem indicar exfiltração em massa
4. Transferências para serviços de armazenamento em nuvem não aprovados podem ocorrer
5. Exfiltração através de canais criptografados ou ofuscados pode estar em andamento

### Fontes de Dados

- Logs de Proxy/Firewall
- Logs de DNS
- Netflow/dados de volume de tráfego
- Logs de DLP (Data Loss Prevention)
- EDR/Endpoint logs

### Procedimento de Hunting

#### Fase 1: Análise de Exfiltração via DNS

1. **Execute as seguintes consultas**:
   ```splunk
   index=dns sourcetype=*dns* 
   | stats count sum(bytes_out) as total_bytes_out values(query_type) as query_types by src_ip, query, dest_ip
   | eval domain_segments=mvcount(split(query, "."))
   | search domain_segments > 5
   | sort - total_bytes_out
   ```

   ```splunk
   index=dns sourcetype=*dns* query_type="TXT"
   | stats count sum(bytes_out) as total_bytes_out by src_ip, query
   | sort - total_bytes_out
   ```

2. **Análise**:
   - Identifique consultas DNS com subdomínios excessivamente longos
   - Procure padrões de consultas TXT incomuns ou repetitivas
   - Analise volume de consultas para domínios específicos
   - Observe padrões de codificação (base64, hex) em subdominios

#### Fase 2: HTTPS e Tráfego Web Suspeito

1. **Execute as seguintes consultas**:
   ```splunk
   index=proxy OR index=firewall action=allowed dest_port=443
   | stats sum(bytes_out) as upload_volume avg(bytes_out) as avg_upload count by src_ip, dest_ip, dest_host
   | eval upload_mb=round(upload_volume/1024/1024,2)
   | search upload_mb > 50
   | sort - upload_mb
   ```

   ```splunk
   index=proxy OR index=firewall action=allowed NOT (dest_category=*business* OR dest_category=*software* OR dest_category="approved storage") dest_port=443
   | stats sum(bytes_out) as upload_volume by src_ip, user, dest_host, category
   | eval upload_mb=round(upload_volume/1024/1024,2)
   | where upload_mb > 10
   | sort - upload_mb
   ```

2. **Análise**:
   - Identifique uploads de volume anormalmente alto para destinos externos
   - Procure transferências para domínios não categorizados ou recém-registrados
   - Observe tráfego para países geograficamente incomuns ou suspeitos
   - Analise ratio de upload/download que pode indicar exfiltração

#### Fase 3: Serviços de Armazenamento em Nuvem Não Aprovados

1. **Execute as seguintes consultas**:
   ```splunk
   index=proxy OR index=firewall (dest_host="*dropbox*" OR dest_host="*box.com*" OR dest_host="*onedrive*" OR dest_host="*drive.google*" OR dest_host="*mega.nz*" OR dest_host="*mediafire*" OR dest_host="*sendspace*")
   | lookup approved_storage_services.csv domain as dest_host OUTPUT approved
   | search approved\!="yes"
   | stats sum(bytes_out) as upload_volume by src_ip, user, dest_host
   | eval upload_mb=round(upload_volume/1024/1024,2)
   | sort - upload_mb
   ```

   ```splunk
   index=endpoint sourcetype=process_creation (process_name="*rclone*" OR process_name="*azcopy*" OR process_name="*gsutil*" OR process_name="*aws*" CommandLine="*s3*") 
   | stats count by host, user, process_name, CommandLine
   | sort - count
   ```

2. **Análise**:
   - Identifique uso de serviços de armazenamento em nuvem não aprovados
   - Observe padrões de upload em horários incomuns
   - Analise o uso de ferramentas de sincronização de nuvem
   - Correlacione com eventos de autenticação ou VPN

#### Fase 4: Análise de Tráfego em Protocolos Incomuns

1. **Execute as seguintes consultas**:
   ```splunk
   index=firewall action=allowed NOT (dest_port=80 OR dest_port=443 OR dest_port=53 OR dest_port=25)
   | stats sum(bytes_out) as upload_volume by src_ip, dest_ip, dest_port, protocol
   | eval upload_mb=round(upload_volume/1024/1024,2)
   | search upload_mb > 5
   | sort - upload_mb
   ```

   ```splunk
   index=firewall action=allowed dest_port IN (21, 22, 23, 3389, 5900, 5800)
   | stats sum(bytes_out) as upload_volume by src_ip, dest_ip, dest_port, protocol
   | eval upload_mb=round(upload_volume/1024/1024,2)
   | sort - upload_mb
   ```

2. **Análise**:
   - Identifique tráfego em portas não convencionais com altos volumes
   - Observe transferências por protocolos menos utilizados (ICMP, FTP)
   - Analise conexões outbound para serviços que normalmente são internos
   - Procure padrões de tunelamento dentro de outros protocolos

#### Fase 5: Identificação de Exfiltração por Compressão ou Criptografia

1. **Execute as seguintes consultas**:
   ```splunk
   index=endpoint sourcetype=process_creation (process_name="*zip*" OR process_name="*rar*" OR process_name="*7z*" OR process_name="*tar*" OR process_name="*gzip*")
   | search CommandLine="*password*" OR CommandLine="*-p*" OR CommandLine="*-e*"
   | stats count by host, user, process_name, CommandLine
   | sort - count
   ```

   ```splunk
   index=endpoint sourcetype=file_creation file_name="*.pgp" OR file_name="*.gpg" OR file_name="*.enc" OR file_name="*.aes"
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, file_name, file_path
   | sort - count
   ```

2. **Análise**:
   - Identifique uso de ferramentas de compressão com senha
   - Observe criação de arquivos criptografados antes de transferências
   - Analise processo de criação/modificação de grandes quantidades de dados
   - Correlacione com subsequentes transferências de rede

### Indicadores de Comprometimento

- Consultas DNS anômalas com subdomínios longos ou codificados
- Grandes volumes de dados enviados para domínios externos não categorizados
- Uso de serviços de armazenamento em nuvem não aprovados
- Tráfego em portas ou protocolos incomuns
- Compressão e criptografia de dados antes de transferências

### Próximos Passos e Resposta

1. **Para cada achado potencial**:
   - Documente detalhadamente (sistemas, usuários, volumes, destinos)
   - Quantifique o potencial impacto (volume de dados, sensibilidade)
   - Estabeleça uma linha do tempo do evento

2. **Para confirmação de exfiltração**:
   - Inicie procedimentos de resposta a incidentes
   - Bloqueie destinos identificados (firewall, proxy)
   - Isole sistemas comprometidos
   - Execute análise forense para determinar dados comprometidos

3. **Para remediação**:
   - Implemente bloqueios adicionais para destinos não categorizados
   - Reforce políticas de DLP
   - Considere ferramentas adicionais de monitoramento de saída de dados
   - Realize treinamento de conscientização de segurança

---

## Playbook: Acesso Inicial via Phishing

### Objetivo

Identificar comprometimentos resultantes de campanhas de phishing, onde adversários podem ter conseguido acesso inicial ao ambiente através de emails maliciosos, anexos ou links.

### Hipóteses

1. Usuários podem ter recebido e interagido com emails de phishing
2. Anexos maliciosos podem ter sido abertos resultando em execução de código
3. Links em emails podem ter levado a sites de phishing ou downloads maliciosos
4. Macros de Office podem ter sido ativadas e executado código malicioso
5. Atividades pós-comprometimento podem estar ocorrendo após sucesso do phishing

### Fontes de Dados

- Logs de email (gateway, servidor)
- Logs de endpoint/EDR
- Logs de proxy/firewall
- Logs de segurança do Windows
- Logs de autenticação

### Procedimento de Hunting

#### Fase 1: Identificação de Emails Suspeitos

1. **Execute as seguintes consultas**:
   ```splunk
   index=email (sourcetype=ms_o365_email OR sourcetype=exchange)
   | regex subject="(?i).*\b(urgent|immediate|attention|required|action|verify|confirm|password|account|suspended|unusual|activity|security|access)\b.*"
   | stats count by sender, sender_domain, subject, recipient
   | where NOT match(sender_domain, "^(company\.com|partner1\.com|partner2\.com)$")
   | sort - count
   ```

   ```splunk
   index=email (sourcetype=ms_o365_email OR sourcetype=exchange)
   | regex attachment="(?i).*(\.zip|\.rar|\.7z|\.js|\.vbs|\.hta|\.exe|\.scr|\.bat|\.cmd|\.lnk)$"
   | stats count by sender, sender_domain, subject, recipient, attachment
   | sort - count
   ```

2. **Análise**:
   - Identifique domínios de remetente similares a domínios legítimos (typosquatting)
   - Procure por anexos com extensões de alto risco
   - Observe assuntos que criam senso de urgência
   - Analise remetentes com histórico de envio curto

#### Fase 2: Detecção de Interação com Anexos e Links Maliciosos

1. **Execute as seguintes consultas**:
   ```splunk
   index=endpoint sourcetype=process_creation (parent_process="*outlook*" OR parent_process="*chrome*" OR parent_process="*firefox*" OR parent_process="*edge*")
   | stats count min(_time) as firstTime max(_time) as lastTime by host, user, process_name, process_path, CommandLine
   | sort - count
   ```

   ```splunk
   index=proxy OR index=web
   | regex url="(?i).*\.(zip|exe|rar|7z|js|vbs|hta|ps1|bat|cmd|msi)$"
   | stats count by src_ip, user, url, dest_host
   | sort - count
   ```

2. **Análise**:
   - Identifique downloads de arquivos potencialmente maliciosos
   - Observe processos iniciados a partir de clientes de email
   - Correlacione downloads com emails recebidos
   - Analise URLs visitados para padrões de phishing

#### Fase 3: Detecção de Execução de Código de Anexos Office

1. **Execute as seguintes consultas**:
   ```splunk
   index=endpoint sourcetype=process_creation parent_process IN ("*excel.exe", "*word.exe", "*powerpoint.exe", "*outlook.exe")
   | stats count by host, user, process_name, CommandLine
   | search process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe")
   | sort - count
   ```

   ```splunk
   index=endpoint sourcetype=process_creation process_name IN ("*excel.exe", "*word.exe", "*powerpoint.exe")
   | regex CommandLine="(?i).*\/e:.*|\-e|\-enc|\-encodedcommand|iex|invoke-expression|webclient|downloadstring|bypass"
   | stats count by host, user, process_name, CommandLine
   | sort - count
   ```

2. **Análise**:
   - Identifique processos suspeitos lançados por aplicativos Office
   - Observe o uso de macros ou DDE para execução de código
   - Procure comandos PowerShell codificados ou ofuscados
   - Analise tentativas de baixar conteúdo adicional

#### Fase 4: Detecção de Atividades Pós-Comprometimento

1. **Execute as seguintes consultas**:
   ```splunk
   index=endpoint sourcetype=process_creation 
   | search [
       search index=endpoint sourcetype=process_creation 
       parent_process IN ("*excel.exe", "*word.exe", "*powerpoint.exe", "*outlook.exe")
       | rename host as comp
       | fields comp
   ]
   | stats count by host, user, process_name, CommandLine
   | search process_name IN ("*reg.exe", "*net.exe", "*netsh.exe", "*sc.exe", "*schtasks.exe", "*certutil.exe", "*bitsadmin.exe")
   | sort - count
   ```

   ```splunk
   index=windows (EventCode=4688 OR EventCode=1) host IN (
       search index=endpoint sourcetype=process_creation 
       parent_process IN ("*excel.exe", "*word.exe", "*powerpoint.exe", "*outlook.exe")
       | rename host as comp
       | fields comp)
   | stats count by host, user, Process_Name, CommandLine
   | search Process_Name IN ("powershell.exe", "cmd.exe", "wmic.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe")
   | sort - count
   ```

2. **Análise**:
   - Identifique atividades de persistência após execução de anexos
   - Observe conexões de rede iniciadas após abertura de documentos
   - Procure por alterações no registro ou agendamento de tarefas
   - Analise comportamentos de reconhecimento ou movimentação

#### Fase 5: Analise de Comportamento de Usuário e Padrões

1. **Execute as seguintes consultas**:
   ```splunk
   index=windows (EventCode=4624 OR EventCode=4625)
   | stats count values(LogonType) as logon_types by user, ComputerName, SourceIP
   | search [
       search index=email (sourcetype=ms_o365_email OR sourcetype=exchange)
       | regex attachment="(?i).*(\.zip|\.rar|\.7z|\.js|\.vbs|\.hta|\.exe|\.doc|\docm|\xlsm|\pdf)$"
       | rename recipient as user
       | fields user
   ]
   | sort - count
   ```

   ```splunk
   index=windows (EventCode=4624 OR EventCode=4625) earliest=-24h
   | stats count min(_time) as firstTime max(_time) as lastTime by SourceIP, user, LogonType
   | where LogonType=10 OR LogonType=3
   | join user [
       search index=endpoint sourcetype=process_creation 
       parent_process IN ("*excel.exe", "*word.exe", "*powerpoint.exe", "*outlook.exe")
       process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
       | fields user
   ]
   | sort - count
   ```

2. **Análise**:
   - Identifique padrões de autenticação incomuns após recebimento de emails
   - Observe tentativas de login remoto após execução de anexos
   - Correlacione eventos de abertura de anexo com atividades subsequentes
   - Analise a timeline completa de eventos por usuário

### Indicadores de Comprometimento

- Emails com domínios similares a legítimos ou recém-registrados
- Anexos com extensões potencialmente perigosas ou raramente usadas
- Processos cmd/PowerShell sendo lançados por aplicativos Office
- Downloads de arquivos por links em emails
- Comportamento de persistência após interação com emails

### Próximos Passos e Resposta

1. **Para cada achado potencial**:
   - Documente detalhadamente o fluxo desde o email até atividades pós-execução
   - Preserve o email original e anexos para análise forense
   - Identifique todos os sistemas e usuários potencialmente afetados

2. **Para confirmação de comprometimento**:
   - Inicie procedimentos de resposta a incidentes
   - Isole sistemas afetados
   - Bloqueie indicadores identificados nos sistemas de segurança
   - Execute varredura completa em sistemas potencialmente comprometidos

3. **Para remediação**:
   - Aplique medidas de contenção (bloqueio de domínios, hashes)
   - Reforçe configurações de segurança de email
   - Conduza treinamento adicional para usuários
   - Implemente regras de detecção baseadas nos TTPs observados

---

## Documentação de Resultados

### Modelo de Documentação

Para cada sessão de hunting, documente os resultados usando o seguinte modelo:

```markdown
# Relatório de Threat Hunting: [Nome do Playbook]

## Resumo Executivo
- Data da sessão de hunting: [Data]
- Participantes: [Nomes]
- Hipóteses testadas: [Lista de hipóteses]
- Resultados chave: [Breve resumo dos achados]

## Metodologia
- Fontes de dados utilizadas: [Lista]
- Período de dados analisados: [Intervalo de datas]
- Escopo: [Sistemas/redes analisados]
- Ferramentas utilizadas: [Lista]

## Achados Detalhados
1. [Achado #1]
   - Hipótese relacionada: [Hipótese]
   - Descrição: [Detalhes]
   - Sistemas afetados: [Lista]
   - Evidências: [Consultas, logs, screenshots]
   - Severidade: [Alta/Média/Baixa]
   - Confiança: [Alta/Média/Baixa]

2. [Achado #2]
   ...

## Falsos Positivos Encontrados
- [Lista de falsos positivos e razão]

## Recomendações
1. [Recomendação #1]
   - Prioridade: [Alta/Média/Baixa]
   - Implementação sugerida: [Detalhes]

2. [Recomendação #2]
   ...

## Melhorias para Futuros Huntings
- [Sugestões para melhorar visibilidade]
- [Novas hipóteses para testar]
- [Ajustes necessários em consultas/ferramentas]

## Anexos
- [Consultas SPL utilizadas]
- [Dados adicionais]
```

### Melhores Práticas para Documentação

1. **Seja específico**: Inclua detalhes técnicos suficientes para reproduzir os achados.
2. **Use evidências**: Inclua capturas de tela, logs e consultas específicas.
3. **Avalie a confiança**: Indique seu nível de confiança em cada achado e explique por quê.
4. **Documente também o negativo**: Registre hipóteses que foram testadas mas não confirmadas.
5. **Forneça contexto**: Explique o impacto potencial de cada achado no ambiente.
6. **Sugira melhorias**: Ofereça recomendações específicas para fortalecer as defesas.

---

*Estes playbooks são documentos vivos que devem ser regularmente atualizados com base em novas táticas, técnicas e procedimentos (TTPs) de adversários, bem como melhorias nas capacidades de detecção.*
EOF < /dev/null