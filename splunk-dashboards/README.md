# Splunk Dashboards para Segurança

![Splunk](https://img.shields.io/badge/Splunk-8.x%2B-green)
![SPL](https://img.shields.io/badge/SPL-Queries-orange)

Coleção de dashboards, alertas e consultas para monitoramento de segurança usando Splunk, focada em detecção de ameaças e visualização de dados de segurança.

## Visão Geral

Este módulo oferece dashboards e alertas Splunk pré-configurados para:

- Detecção de ameaças em endpoints
- Monitoramento de anomalias de rede
- Visualização de resultados de varreduras Nmap
- Alertas de segurança configuráveis
- Detecção precoce de comprometimentos

## Componentes

```
splunk-dashboards/
README.md                      # Esta documentação
dashboards/                    # Arquivos de dashboard XML
  endpoint-threats.xml         # Dashboard para eventos em endpoints
  network-anomalies.xml        # Dashboard para anomalias de rede
  nmap_alerts.xml              # Dashboard para resultados de Nmap
  security-command-center.xml  # Dashboard unificado (central de comando)
alerts/                        # Configurações de alertas
  suspicious-logins.json       # Alerta para logins suspeitos
```

## Pré-requisitos

- Splunk Enterprise ou Splunk Cloud 8.x+
- Forwarders configurados em endpoints para coleta de dados
- Fontes de dados apropriadas configuradas:
  - Windows Event Logs (Sysmon recomendado)
  - Linux Syslog/Auditd
  - NetFlow ou dados de tráfego de rede
  - Resultados de varreduras Nmap (via nmap-automation)

## Instalação

### Método 1: Importação Manual no Splunk

1. Acesse o Splunk Web (http://splunk-server:8000)
2. Navegue até Configurações > Conhecimento > Objetos de Visualização de Dados
3. Clique em "Importar Dashboard"
4. Selecione o arquivo XML desejado

### Método 2: Usando Splunk CLI

```bash
# Copie os arquivos para o diretório de aplicativos do Splunk
cp -r dashboards/* "$SPLUNK_HOME/etc/apps/search/local/data/ui/views/"
cp -r alerts/* "$SPLUNK_HOME/etc/apps/search/local/savedsearches/"

# Reinicie o Splunk
$SPLUNK_HOME/bin/splunk restart
```

### Método 3: Integração com Splunk App

Se você estiver usando um aplicativo Splunk personalizado:

```bash
# Substitua app-name pelo nome do seu aplicativo
cp -r dashboards/* "$SPLUNK_HOME/etc/apps/app-name/local/data/ui/views/"
cp -r alerts/* "$SPLUNK_HOME/etc/apps/app-name/local/savedsearches/"
```

## Dashboards Disponíveis

### 1. Central de Comando de Segurança (security-command-center.xml)

![Security Command Center](https://via.placeholder.com/800x400?text=Security+Command+Center)

Dashboard unificado que integra todos os aspectos de segurança em uma única interface:

- Visão geral consolidada do status de segurança
- Indicadores de status em tempo real
- Distribuição de alertas por tipo de ameaça
- Mapa global de ameaças
- Lista de hosts em maior risco
- Navegação integrada para dashboards especializados
- Timeline de eventos recentes de segurança

#### Fontes de Dados Necessárias:
- Todas as fontes abaixo combinadas
- Integração com os três dashboards especializados

### 2. Endpoint Threats Dashboard (endpoint-threats.xml)

![Endpoint Threats](https://via.placeholder.com/800x400?text=Endpoint+Threats+Dashboard)

Dashboard focado em detecção de ameaças em endpoints, com painéis para:

- Processos suspeitos por host
- Conexões de rede não comuns
- Modificações em arquivos críticos
- Execução de PowerShell suspeita
- Logins com falha e bem-sucedidos
- Timeline de atividades por criticidade
- Processos executados com privilégios elevados

#### Fontes de Dados Necessárias:
- Windows Event Logs
- Sysmon
- Linux Syslog/Auditd

### 3. Network Anomalies Dashboard (network-anomalies.xml)

![Network Anomalies](https://via.placeholder.com/800x400?text=Network+Anomalies+Dashboard)

Dashboard para detecção de comportamentos anômalos na rede:

- Tráfego por país e geolocalização
- Comunicações para domínios/IPs mal-intencionados conhecidos
- Indicadores de exfiltração de dados
- Padrões de comunicação incomuns
- Detecção de varreduras e força bruta
- Acessos a serviços críticos
- Anomalias temporais baseadas em modelos preditivos

#### Fontes de Dados Necessárias:
- NetFlow
- Firewall logs
- IDS/IPS logs
- Proxy logs

### 4. Nmap Security Scan Dashboard (nmap_alerts.xml)

![Nmap Alerts](https://via.placeholder.com/800x400?text=Nmap+Alerts+Dashboard)

Dashboard completo para visualizar resultados de varreduras Nmap:

- Status geral de segurança com indicadores visuais
- Mapa de hosts com portas críticas abertas
- Timeline de detecções de portas críticas
- Lista de hosts mais vulneráveis
- Detalhes de portas/serviços por host
- Comparação com linha de base
- Estatísticas de vulnerabilidades por serviço
- Ranking de hosts com mais portas abertas

#### Fontes de Dados Necessárias:
- Resultados JSON do nmap-report-parser.py (do módulo nmap-automation)

## Alertas Configuráveis

### Suspicious Logins Alert (suspicious-logins.json)

Alerta para detecção de login em horários incomuns ou de localizações não usuais:

- Configurado para verificar logins fora do horário comercial
- Detecção de logins de endereços IP incomuns
- Alertas para logins após vários fracassos
- Notificações para contas privilegiadas
- Correlação entre múltiplos hosts

```
Consulta SPL:
| tstats count from datamodel=Authentication where Authentication.action=success 
  by Authentication.src_ip Authentication.user Authentication.app Authentication.dest 
  _time span=1h
| join type=left Authentication.src_ip
  [| tstats count from datamodel=Authentication where Authentication.action=success 
     by Authentication.src_ip Authentication.user span=7d
   | stats dc(Authentication.user) as user_count values(Authentication.user) as users by Authentication.src_ip
   | where user_count > 20]
| where isnull(user_count)
| lookup previously_seen_auth_sources Authentication.src_ip as src_ip
| lookup previously_seen_auth_users Authentication.user as user
| lookup previously_seen_auth_dest Authentication.dest as dest
| where ( (isnull(src_ip_previously_seen) AND NOT cidrmatch("10.0.0.0/8", Authentication.src_ip))
       OR isnull(user_previously_seen)
       OR isnull(dest_previously_seen) )
```

## Personalização

Todos os dashboards e alertas podem ser personalizados para seu ambiente específico:

### Ajustes de Dashboards

1. Importe o dashboard para o Splunk
2. Clique em "Editar" no canto superior direito
3. Modifique as consultas SPL conforme necessário para corresponder às suas fontes de dados
4. Salve as alterações

### Ajustes de Alertas

1. Navegue até Configurações > Buscas, relatórios e alertas
2. Encontre o alerta que deseja modificar
3. Ajuste a consulta, o cronograma e as ações de alerta
4. Salve as alterações

## Exemplos de Uso

### Detecção de Movimento Lateral

```spl
index=windows EventCode=4624 LogonType=3
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, Account, IpAddress
| where count > 5
| lookup hostname_lu Computer OUTPUT department
| lookup username_lu Account OUTPUT department as user_dept
| where department != user_dept
| sort - count
```

### Detecção de Processos Suspeitos

```spl
index=windows EventCode=4688 OR sourcetype=xmlwineventlog
| regex CommandLine="(?i)(powershell\s+.*(hidden|encode|webclient|downloadstring|bypass))"
| table _time Computer Account CommandLine ParentProcessName
| sort - _time
```

### Análise de Resultados Nmap

```spl
index=security source=nmap
| spath "hosts{}.ip"
| spath "hosts{}.ports{}.port"
| spath "hosts{}.ports{}.state"
| spath "hosts{}.ports{}.critical"
| where hosts{}.ports{}.state="open" AND hosts{}.ports{}.critical="true"
| table _time hosts{}.ip hosts{}.hostname hosts{}.ports{}.port hosts{}.ports{}.service
| rename hosts{}.* as *
```

## Integração com Outros Módulos

Este módulo foi projetado para integrar-se perfeitamente com outros componentes do CyberSec Blueprints:

- **nmap-automation**: Visualiza os resultados das varreduras automatizadas
- **ansible-hardening**: Monitora alterações pós-hardening
- **threat-hunting**: Implementa alertas baseados nas consultas de hunting

## Recursos de Aprendizado

- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## To-Do / Roadmap

- [x] Concluir dashboards endpoint-threats.xml e network-anomalies.xml
- [x] Melhorar o dashboard nmap_alerts.xml com mais visualizações
- [x] Criar dashboard unificado (security-command-center.xml)
- [ ] Adicionar dashboard específico para eventos de autenticação
- [ ] Implementar visualizações para detecção de ameaças baseadas em MITRE ATT&CK
- [ ] Criar mais alertas para detecção de atividades maliciosas comuns
- [ ] Adicionar suporte para dados de EDR e SIEM
- [ ] Melhorar a internacionalização das buscas
- [ ] Desenvolver app Splunk dedicado (com navegação personalizada)
- [ ] Implementar mecabismos de exportação de relatórios
- [ ] Adicionar análise avançada com Machine Learning
- [ ] Integrar com outros módulos do CyberSec Blueprints

## Contribuição

Contribuições são bem-vindas! Veja o [CONTRIBUTING.md](../CONTRIBUTING.md) para diretrizes.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](../LICENSE) para detalhes.

---

**Nota:** Estes dashboards e alertas devem ser testados e ajustados para seu ambiente específico antes do uso em produção.