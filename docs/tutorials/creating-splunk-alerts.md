# Tutorial: Criando Alertas no Splunk para Detecção de Ameaças

Este tutorial explica como configurar alertas no Splunk usando os dashboards e queries do CyberSec Blueprints para melhorar sua capacidade de detecção de ameaças.

## Objetivos

Ao final deste tutorial, você será capaz de:

1. Configurar alertas no Splunk para detecção de atividades suspeitas
2. Personalizar alertas para seu ambiente específico
3. Implementar um processo de triagem de alertas
4. Integrar alertas com sistemas de notificação e resposta

## Pré-requisitos

- Acesso a um ambiente Splunk Enterprise ou Splunk Cloud
- Dados relevantes já sendo indexados no Splunk, incluindo:
  - Logs de Windows (Event Logs, Sysmon)
  - Logs de segurança de Linux (auth.log, syslog)
  - Logs de firewall e aplicações web
  - Resultados de varreduras Nmap (via nmap-automation)
- Permissões para criar/editar dashboards e alertas no Splunk

## Passo 1: Preparação do Ambiente Splunk

### 1.1 Verifique seus Índices e Dados

Antes de configurar alertas, verifique se os dados necessários estão sendo indexados:

1. Acesse seu ambiente Splunk
2. Execute estas consultas básicas para verificar a disponibilidade de dados:

```splunk
index=* sourcetype=* | stats count by index sourcetype
```

```splunk
index=windows EventCode=4625 OR EventCode=4624 
| stats count by _time span=1d
```

```splunk
index=linux sourcetype=auth* OR sourcetype=syslog 
| stats count by host
```

### 1.2 Importe os Dashboards

Importe os dashboards do CyberSec Blueprints para o Splunk:

1. Vá para "Configurações" > "Objetos de Visualização de Dados"
2. Clique em "Importar"
3. Selecione os arquivos XML da pasta `splunk-dashboards/dashboards/`

## Passo 2: Criando um Alerta para Detecção de Logins Suspeitos

### 2.1 Defina a Consulta de Busca

1. Navegue até "Pesquisar" no Splunk
2. Cole a seguinte consulta SPL para identificar tentativas de login suspeitosas:

```splunk
index=windows (EventCode=4625 OR EventCode=4624) 
| eval loginStatus=case(EventCode=4624,"success",EventCode=4625,"failure") 
| stats count(eval(loginStatus="failure")) as failures, 
  count(eval(loginStatus="success")) as successes, 
  values(user) as users, 
  values(src_ip) as source_ips, 
  values(dest) as target_hosts 
  by user, src_ip span=1h 
| where failures > 5 
| eval suspicious=case(failures > 10 AND successes > 0, "Successful login after multiple failures", 
                      failures > 20, "Brute Force Attempt", 
                      1=1, "Suspicious Auth Activity") 
| sort - failures
```

3. Ajuste o threshold (atualmente definido como 5 falhas) conforme o ambiente
4. Teste a consulta para verificar se ela está retornando resultados esperados

### 2.2 Crie o Alerta

1. Clique em "Salvar Como" > "Alerta"
2. Configure os seguintes parâmetros:
   - **Título**: "Alerta de Tentativas de Login Suspeitas"
   - **Descrição**: "Detecta múltiplas falhas de login seguidas por um login bem-sucedido"
   - **Acesso de Compartilhamento**: App ou Global, conforme sua preferência
   - **Cronograma**: A cada hora (ajuste conforme necessário)
   - **Tipo de Alerta**: Em tempo real ou agendado (recomendado: agendado)
   - **Condição de Disparo**: Quando o número de resultados for > 0
   - **Expiração**: 24 horas (ajuste conforme necessário)

3. Em "Ações de Alerta", configure uma ou mais ações, como:
   - Email
   - Webhook para Microsoft Teams ou Slack
   - Script (para integração com sistemas de tickets)

## Passo 3: Alerta para Detecção de Portas Críticas (Nmap)

### 3.1 Defina a Consulta de Busca

1. Navegue até "Pesquisar" no Splunk
2. Cole a seguinte consulta para detectar hosts com portas críticas expostas:

```splunk
index=security source=nmap
| spath input=_raw path=hosts{}.ip output=ip
| spath input=_raw path=hosts{}.hostname output=hostname
| spath input=_raw path=hosts{}.ports{}.port output=port
| spath input=_raw path=hosts{}.ports{}.state output=state
| spath input=_raw path=hosts{}.ports{}.service output=service
| spath input=_raw path=hosts{}.ports{}.critical output=critical
| search state="open" critical="true"
| table _time ip hostname port service
| sort -_time
```

3. Salve a consulta para uso posterior

### 3.2 Crie o Alerta

1. Clique em "Salvar Como" > "Alerta"
2. Configure da seguinte forma:
   - **Título**: "Portas Críticas Expostas Detectadas"
   - **Descrição**: "Alerta quando portas sensíveis são detectadas abertas no perímetro"
   - **Acesso de Compartilhamento**: App ou Global
   - **Cronograma**: Diariamente após o horário de suas varreduras Nmap
   - **Tipo de Alerta**: Agendado
   - **Condição de Disparo**: Quando o número de resultados for > 0
   - **Expiração**: 7 dias

3. Configure as ações de alerta, incluindo:
   - Notificação por email
   - Criação de tickets no sistema de gerenciamento de incidentes

## Passo 4: Alerta para Detecção de Movimentos Laterais

### 4.1 Defina a Consulta de Busca

1. Crie uma consulta para detectar possíveis movimentos laterais:

```splunk
index=windows EventCode=4624 Logon_Type=3 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer,Account,Source_Network_Address,Logon_Type 
| where Source_Network_Address\!="::1" AND Source_Network_Address\!="127.0.0.1" 
| join Account [
    search index=windows EventCode=4688
    | rex field=Process_Command_Line "(?<cmd>.{1,10})"
    | stats count as cmd_count values(cmd) as commands by Account 
    | where cmd_count > 3
]
| rename Source_Network_Address as src_ip, Computer as dest_host
| table Account, firstTime, lastTime, src_ip, dest_host, count, commands
| sort - count
```

2. Teste e refine a consulta para reduzir falsos positivos

### 4.2 Crie o Alerta

1. Salve a consulta como alerta
2. Configure com os seguintes parâmetros:
   - **Título**: "Possível Movimento Lateral Detectado"
   - **Descrição**: "Detecta logons de rede seguidos por atividade de comando suspeita"
   - **Cronograma**: A cada 4 horas
   - **Condição de Disparo**: Personalizada - `if 'count' > 5 AND 'commands' contains "powershell" OR 'commands' contains "cmd" OR 'commands' contains "wmic"`
   - **Prioridade**: Alta

3. Configure ações de alerta com notificações mais urgentes, potencialmente incluindo SMS ou chamadas para a equipe de resposta a incidentes

## Passo 5: Criação de Alertas Baseados em MITRE ATT&CK

### 5.1 Alerta para Execução Suspeita de PowerShell

```splunk
index=windows EventCode=4688 
| regex Process_Command_Line="(?i)(powershell\.exe.*(-|/)(enc|encode|encodedcommand|e|ec)|powershell.*-nop|-windowstyle hidden|iex|invoke-expression|webclient|downloadstring|bypass)"
| stats count min(_time) as firstTime max(_time) as lastTime by Computer,Account,Process_Command_Line
| eval technique="PowerShell Execution", mitre_id="T1059.001"
| sort -count
```

### 5.2 Alerta para Persistência via Scheduled Tasks

```splunk
index=windows (EventCode=4698 OR (EventCode=4688 (Process_Name="*schtasks.exe" OR Process_Name="*at.exe"))) 
| regex Process_Command_Line=".*/create.*|.*/sc.*"
| stats count min(_time) as firstTime max(_time) as lastTime by Computer,Account,Process_Command_Line,Task_Name
| eval technique="Scheduled Task", mitre_id="T1053.005"
| sort -count
```

## Passo 6: Personalização dos Alertas para seu Ambiente

### 6.1 Ajuste de Thresholds

Para cada alerta criado, analise os resultados durante um período de "aprendizado" (1-2 semanas):

1. Execute as consultas regularmente e analise os resultados
2. Ajuste os limiares (thresholds) com base no volume normal de eventos
3. Adicione exclusões para atividades legítimas conhecidas

### 6.2 Implementação de Context Enrichment

Melhore seus alertas com informações contextuais:

```splunk
| lookup asset_lookup dest_host OUTPUT criticality, owner, department
| eval alert_priority=case(
    criticality="critical", "P1",
    criticality="high", "P2",
    criticality="medium", "P3",
    1=1, "P4")
```

## Passo 7: Criação de Processo de Triagem

### 7.1 Crie um Dashboard de Triagem

1. Crie um dashboard personalizado combinando todos os seus alertas
2. Inclua:
   - Status atual dos alertas (novos, em andamento, resolvidos)
   - Tendências ao longo do tempo
   - Distribuição por tipo de alerta, host e usuário

```splunk
| savedsearch "Alerta de Tentativas de Login Suspeitas" 
| append [| savedsearch "Portas Críticas Expostas Detectadas"] 
| append [| savedsearch "Possível Movimento Lateral Detectado"] 
| stats count by alert_name, severity
| sort - severity
```

### 7.2 Defina um Processo de Resposta

Documente um processo claro para cada tipo de alerta:

1. Quem é responsável pela triagem
2. Tempo de resposta esperado baseado na severidade
3. Passos iniciais de investigação
4. Procedimentos de escalação
5. Documentação de resolução

## Passo 8: Integração com Sistemas de Resposta

### 8.1 Integração com SOAR

Se você tiver uma plataforma SOAR (Security Orchestration, Automation and Response):

1. Configure webhooks do Splunk para sua plataforma SOAR
2. Mapeie campos de alerta para os campos da plataforma
3. Configure playbooks de automação para resposta inicial

### 8.2 Integração com Sistema de Tickets

Configure a integração com sistemas como JIRA, ServiceNow ou similar:

```
# Exemplo de configuração de webhook para JIRA
curl -X POST -H "Content-Type: application/json" -u username:password \
  -d '{"fields": {"project": {"key": "SEC"}, "summary": "Alerta Splunk: $result.alert_name$", "description": "$result.description$\n\nDetalhes: $result.raw$", "issuetype": {"name": "Security Incident"}}}' \
  https://jira.example.com/rest/api/2/issue/
```

## Passo 9: Teste e Validação

### 9.1 Teste de Alertas

Para cada alerta configurado:

1. Crie um ambiente de teste seguro
2. Execute atividades que deveriam disparar o alerta
3. Verifique se o alerta é disparado como esperado
4. Valide se as ações de alerta funcionam corretamente

### 9.2 Validação de Falsos Positivos

Para reduzir falsos positivos:

1. Mantenha um registro de falsos positivos identificados
2. Atualize regularmente as consultas para excluir padrões de falsos positivos
3. Crie listas de exclusão para atividades administrativas conhecidas

## Passo 10: Manutenção Contínua

### 10.1 Revisão Regular

Estabeleça um processo de revisão regular:

1. Mensalmente: Revise a eficácia dos alertas e ajuste conforme necessário
2. Trimestralmente: Avalie novas técnicas de ataque e crie alertas correspondentes
3. Anualmente: Revise completamente a estratégia de alertas e detecção

### 10.2 Atualização com Base em Inteligência de Ameaças

Atualize os alertas com base em novas ameaças:

1. Acompanhe boletins de segurança e relatórios de ameaças
2. Implemente novas detecções com base em técnicas emergentes
3. Integre feeds de inteligência de ameaças para detecção baseada em IoCs

## Conclusão

Agora você tem um conjunto abrangente de alertas configurados no Splunk para detecção de ameaças em seu ambiente. Este sistema:

1. Monitora continuamente atividades suspeitas
2. Alerta rapidamente sobre possíveis incidentes
3. Fornece contexto para investigação eficiente
4. Se integra com seu processo de resposta a incidentes

Continue refinando e ajustando seus alertas com base em falsos positivos, mudanças no ambiente e evolução das ameaças.

---

**Dica Pro:** Lembre-se que os melhores alertas são aqueles que equilibram detecção eficaz com um número gerenciável de falsos positivos. Um sistema de alerta que gera muito ruído eventualmente será ignorado.
EOF < /dev/null