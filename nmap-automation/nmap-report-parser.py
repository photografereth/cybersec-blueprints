#\!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nmap-report-parser.py - Converte XML do Nmap para JSON, CSV ou outros formatos

Este script processa os resultados de varreduras Nmap em formato XML e os converte
para formatos mais utilizáveis como JSON ou CSV. Também pode detectar portas críticas
abertas e enviar alertas por email ou Discord.

Autor: Felipe Miranda
Data: 2025-05-13
Versão: 1.0
"""

import argparse
import datetime
import json
import os
import re
import smtplib
import sys
import xml.etree.ElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Any, Tuple

try:
    import yaml
    import xmltodict
    import requests
    from rich.console import Console
    from rich.table import Table
except ImportError as e:
    print(f"Erro: Biblioteca necessária não encontrada: {e}")
    print("Por favor, instale as dependências com: pip install -r requirements.txt")
    sys.exit(1)

# Configuração do console Rich para saída formatada
console = Console()

class NmapReportParser:
    """
    Processador de relatórios XML do Nmap que converte para outros formatos
    e pode detectar problemas de segurança.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Inicializa o parser com as configurações fornecidas.
        
        Args:
            config_path: Caminho para o arquivo de configuração YAML
        """
        self.config = self._load_config(config_path)
        self.critical_ports = self.config.get("parser", {}).get("critical_ports", [])
        self.alert_criteria = self.config.get("parser", {}).get("alert_criteria", [])
        self.alerts_config = self.config.get("alerts", {})

    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """
        Carrega configurações do arquivo YAML ou usa padrões.
        
        Args:
            config_path: Caminho para o arquivo de configuração
            
        Returns:
            Dicionário com as configurações
        """
        default_config = {
            "parser": {
                "critical_ports": [
                    {"port": 21, "service": "ftp", "reason": "FTP não criptografado"},
                    {"port": 23, "service": "telnet", "reason": "Telnet não criptografado"},
                    {"port": 3389, "service": "ms-wbt-server", "reason": "RDP exposto"}
                ],
                "alert_criteria": [
                    {"os_match": "Windows.*2003|Windows.*XP"},
                    {"service_match": "apache.*2.2|OpenSSH.*(5|6)."}
                ]
            },
            "alerts": {
                "email": {"enabled": False},
                "discord": {"enabled": False}
            },
            "output": {
                "default_format": "json"
            }
        }
        
        if not config_path:
            # Buscar no diretório padrão
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(script_dir, "config.yaml")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as config_file:
                    loaded_config = yaml.safe_load(config_file)
                    console.print(f"[green]Configurações carregadas de:[/green] {config_path}")
                    # Mesclar configurações, mantendo padrões para valores não especificados
                    merged_config = default_config.copy()
                    for key, value in loaded_config.items():
                        if key in merged_config and isinstance(merged_config[key], dict):
                            merged_config[key].update(value)
                        else:
                            merged_config[key] = value
                    return merged_config
            except Exception as e:
                console.print(f"[yellow]Erro ao carregar configurações:[/yellow] {e}")
                console.print("[yellow]Usando configurações padrão.[/yellow]")
        else:
            console.print(f"[yellow]Arquivo de configuração não encontrado:[/yellow] {config_path}")
            console.print("[yellow]Usando configurações padrão.[/yellow]")
            
        return default_config
    
    def parse_xml(self, xml_file: str) -> Dict:
        """
        Converte arquivo XML do Nmap em dicionário Python.
        
        Args:
            xml_file: Caminho para o arquivo XML do Nmap
            
        Returns:
            Dicionário contendo os dados estruturados do relatório
            
        Raises:
            FileNotFoundError: Se o arquivo XML não for encontrado
        """
        try:
            console.print(f"[green]Processando arquivo XML:[/green] {xml_file}")
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            # Converter XML para dicionário Python
            raw_data = xmltodict.parse(xml_content)
            
            # Processar e estruturar os dados
            return self._process_nmap_data(raw_data)
        except FileNotFoundError:
            console.print(f"[red]Arquivo não encontrado:[/red] {xml_file}")
            raise
        except Exception as e:
            console.print(f"[red]Erro ao processar XML:[/red] {e}")
            raise
    
    def _process_nmap_data(self, raw_data: Dict) -> Dict:
        """
        Processa o dicionário bruto do XML e o converte em um formato estruturado.
        
        Args:
            raw_data: Dicionário bruto parseado do XML
            
        Returns:
            Dicionário estruturado com os dados processados
        """
        nmap_run = raw_data.get('nmaprun', {})
        scan_info = {
            'timestamp': nmap_run.get('@startstr', datetime.datetime.now().isoformat()),
            'args': nmap_run.get('@args', ''),
            'version': nmap_run.get('@version', '')
        }
        
        # Extrair informações dos hosts
        hosts_data = []
        
        # Garantir que temos uma lista de hosts, mesmo se for apenas um
        hosts_list = nmap_run.get('host', [])
        if not isinstance(hosts_list, list):
            hosts_list = [hosts_list]
        
        for host in hosts_list:
            # Verificar se o host está up
            status = host.get('status', {}).get('@state', '')
            if status != 'up':
                continue
            
            # Informações básicas do host
            ip = None
            for addr in host.get('address', []):
                if not isinstance(addr, dict):
                    continue
                if addr.get('@addrtype') == 'ipv4':
                    ip = addr.get('@addr')
                    break
            
            if not ip:
                continue
            
            # Nome do host
            hostname = ''
            hostnames = host.get('hostnames', {}).get('hostname', [])
            if hostnames:
                if not isinstance(hostnames, list):
                    hostnames = [hostnames]
                for hn in hostnames:
                    if hn.get('@type') == 'PTR':
                        hostname = hn.get('@name', '')
                        break
            
            # Informações de SO
            os_info = {'name': 'Unknown', 'accuracy': '0'}
            if 'os' in host and 'osmatch' in host['os']:
                os_matches = host['os']['osmatch']
                if not isinstance(os_matches, list):
                    os_matches = [os_matches]
                
                if os_matches:
                    best_match = os_matches[0]
                    os_info = {
                        'name': best_match.get('@name', 'Unknown'),
                        'accuracy': best_match.get('@accuracy', '0')
                    }
            
            # Extrair portas
            ports_data = []
            if 'ports' in host and 'port' in host['ports']:
                ports = host['ports']['port']
                if not isinstance(ports, list):
                    ports = [ports]
                
                for port in ports:
                    port_number = int(port.get('@portid', 0))
                    protocol = port.get('@protocol', '')
                    state = port.get('state', {}).get('@state', '')
                    
                    service_info = port.get('service', {})
                    service = service_info.get('@name', '')
                    version = service_info.get('@product', '')
                    if service_info.get('@version'):
                        version += f" {service_info.get('@version')}"
                    
                    # Verificar scripts
                    scripts = []
                    if 'script' in port:
                        script_entries = port['script']
                        if not isinstance(script_entries, list):
                            script_entries = [script_entries]
                        
                        for script in script_entries:
                            script_data = {
                                'id': script.get('@id', ''),
                                'output': script.get('@output', '')
                            }
                            scripts.append(script_data)
                    
                    # Determinar se esta porta é crítica
                    is_critical = self._is_critical_port(port_number, service, version, scripts)
                    
                    port_data = {
                        'port': port_number,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version,
                        'scripts': scripts,
                        'critical': is_critical
                    }
                    ports_data.append(port_data)
            
            # Montar o objeto de host
            host_data = {
                'ip': ip,
                'status': status,
                'hostname': hostname,
                'os': os_info,
                'ports': sorted(ports_data, key=lambda x: x['port'])
            }
            hosts_data.append(host_data)
        
        # Computar estatísticas de resumo
        total_hosts = len(hosts_list)
        up_hosts = len(hosts_data)
        critical_issues = sum(1 for host in hosts_data for port in host['ports'] 
                           if port['critical'] and port['state'] == 'open')
        
        return {
            'scan_info': scan_info,
            'hosts': hosts_data,
            'summary': {
                'total_hosts': total_hosts,
                'up_hosts': up_hosts,
                'down_hosts': total_hosts - up_hosts,
                'critical_issues': critical_issues
            }
        }
    
    def _is_critical_port(self, port: int, service: str, version: str, scripts: List[Dict]) -> bool:
        """
        Determina se uma porta é considerada crítica com base nas configurações.
        
        Args:
            port: Número da porta
            service: Nome do serviço
            version: String de versão do serviço
            scripts: Lista de resultados de scripts Nmap
            
        Returns:
            True se a porta for considerada crítica, False caso contrário
        """
        # Verificar se a porta está na lista de portas críticas
        for critical_port in self.critical_ports:
            if critical_port['port'] == port and service.lower() == critical_port['service'].lower():
                return True
        
        # Verificar critérios baseados em versão
        for criteria in self.alert_criteria:
            if 'service_match' in criteria:
                pattern = criteria['service_match']
                if re.search(pattern, version, re.IGNORECASE):
                    return True
        
        # Verificar critérios baseados em saída de scripts
        for criteria in self.alert_criteria:
            if 'script_match' in criteria:
                pattern = criteria['script_match']
                for script in scripts:
                    if re.search(pattern, script['output'], re.IGNORECASE):
                        return True
        
        return False
    
    def convert_to_format(self, data: Dict, output_format: str = 'json') -> str:
        """
        Converte os dados processados para o formato de saída especificado.
        
        Args:
            data: Dados processados da varredura
            output_format: Formato de saída desejado (json, csv, etc.)
            
        Returns:
            String formatada no formato especificado
        """
        if output_format == 'json':
            return json.dumps(data, indent=2)
        elif output_format == 'csv':
            # Implementar conversão para CSV
            csv_output = "IP,Hostname,Port,Protocol,State,Service,Version,Critical\n"
            for host in data['hosts']:
                for port in host['ports']:
                    if port['state'] == 'open':  # Incluir apenas portas abertas
                        csv_output += f"{host['ip']},{host['hostname']},{port['port']},"
                        csv_output += f"{port['protocol']},{port['state']},{port['service']},"
                        csv_output += f"{port['version']},{port['critical']}\n"
            return csv_output
        elif output_format == 'splunk':
            # Formato específico para ingestão no Splunk
            events = []
            for host in data['hosts']:
                for port in host['ports']:
                    if port['state'] == 'open':  # Incluir apenas portas abertas
                        event = {
                            'time': data['scan_info']['timestamp'],
                            'source': 'nmap',
                            'host': host['ip'],
                            'hostname': host['hostname'],
                            'os_name': host['os']['name'],
                            'port': port['port'],
                            'protocol': port['protocol'],
                            'service': port['service'],
                            'version': port['version'],
                            'critical': port['critical']
                        }
                        events.append(json.dumps(event))
            return '\n'.join(events)
        else:
            console.print(f"[yellow]Formato de saída não suportado:[/yellow] {output_format}")
            console.print("[yellow]Usando formato JSON como fallback.[/yellow]")
            return json.dumps(data, indent=2)
    
    def save_to_file(self, content: str, output_file: str) -> None:
        """
        Salva o conteúdo formatado em um arquivo.
        
        Args:
            content: Conteúdo formatado para salvar
            output_file: Caminho do arquivo de saída
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            console.print(f"[green]Arquivo salvo com sucesso:[/green] {output_file}")
        except Exception as e:
            console.print(f"[red]Erro ao salvar arquivo:[/red] {e}")
    
    def detect_critical_issues(self, data: Dict) -> List[Dict]:
        """
        Detecta problemas críticos nos dados da varredura.
        
        Args:
            data: Dados processados da varredura
            
        Returns:
            Lista de problemas críticos detectados
        """
        issues = []
        
        for host in data['hosts']:
            host_issues = []
            
            # Verificar OS crítico
            for criteria in self.alert_criteria:
                if 'os_match' in criteria and host['os']['name'] != 'Unknown':
                    pattern = criteria['os_match']
                    if re.search(pattern, host['os']['name'], re.IGNORECASE):
                        host_issues.append({
                            'type': 'os',
                            'issue': f"Sistema operacional potencialmente vulnerável: {host['os']['name']}",
                            'severity': 'high'
                        })
            
            # Verificar portas críticas
            for port in host['ports']:
                if port['critical'] and port['state'] == 'open':
                    # Encontrar a razão para esta porta ser crítica
                    reason = "Porta crítica"
                    for critical_port in self.critical_ports:
                        if critical_port['port'] == port['port'] and critical_port['service'].lower() == port['service'].lower():
                            reason = critical_port['reason']
                            break
                    
                    host_issues.append({
                        'type': 'port',
                        'port': port['port'],
                        'service': port['service'],
                        'version': port['version'],
                        'issue': f"Porta {port['port']} ({port['service']}): {reason}",
                        'severity': 'medium'
                    })
                    
                    # Verificar se a versão do serviço é vulnerável
                    for criteria in self.alert_criteria:
                        if 'service_match' in criteria:
                            pattern = criteria['service_match']
                            if re.search(pattern, port['version'], re.IGNORECASE):
                                host_issues.append({
                                    'type': 'version',
                                    'port': port['port'],
                                    'service': port['service'],
                                    'version': port['version'],
                                    'issue': f"Versão potencialmente vulnerável de {port['service']}: {port['version']}",
                                    'severity': 'high'
                                })
            
            if host_issues:
                issues.append({
                    'ip': host['ip'],
                    'hostname': host['hostname'],
                    'issues': host_issues
                })
        
        return issues
    
    def send_alerts(self, issues: List[Dict], data: Dict) -> bool:
        """
        Envia alertas por email e/ou Discord para problemas críticos.
        
        Args:
            issues: Lista de problemas críticos detectados
            data: Dados completos da varredura
            
        Returns:
            True se os alertas foram enviados com sucesso, False caso contrário
        """
        if not issues:
            console.print("[green]Nenhum problema crítico detectado, não enviando alertas.[/green]")
            return True
        
        console.print(f"[yellow]Encontrados {len(issues)} hosts com problemas.[/yellow]")
        
        success = True
        
        # Enviar alerta por email
        if self.alerts_config.get('email', {}).get('enabled', False):
            email_success = self._send_email_alert(issues, data)
            success = success and email_success
        
        # Enviar alerta para Discord
        if self.alerts_config.get('discord', {}).get('enabled', False):
            discord_success = self._send_discord_alert(issues, data)
            success = success and discord_success
        
        return success
    
    def _send_email_alert(self, issues: List[Dict], data: Dict) -> bool:
        """
        Envia alertas por email.
        
        Args:
            issues: Lista de problemas críticos detectados
            data: Dados completos da varredura
            
        Returns:
            True se o email foi enviado com sucesso, False caso contrário
        """
        try:
            email_config = self.alerts_config.get('email', {})
            
            sender = email_config.get('sender', 'security@example.com')
            recipients = email_config.get('recipients', ['admin@example.com'])
            smtp_server = email_config.get('smtp_server', 'localhost')
            smtp_port = email_config.get('smtp_port', 25)
            use_tls = email_config.get('use_tls', False)
            
            # Montar assunto do email
            subject_prefix = email_config.get('subject_prefix', '[SECURITY] Nmap Scan Alert - ')
            critical_count = sum(len(host['issues']) for host in issues)
            subject = f"{subject_prefix}{critical_count} issues found in {len(issues)} hosts"
            
            # Construir corpo do email em HTML
            body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    h1, h2 {{ color: #333; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    .high {{ color: #d9534f; font-weight: bold; }}
                    .medium {{ color: #f0ad4e; }}
                    .low {{ color: #5bc0de; }}
                </style>
            </head>
            <body>
                <h1>Nmap Security Scan Report</h1>
                <p>Scan completed at: {data['scan_info']['timestamp']}</p>
                <p>Command: {data['scan_info']['args']}</p>
                
                <h2>Summary</h2>
                <ul>
                    <li>Total hosts scanned: {data['summary']['total_hosts']}</li>
                    <li>Hosts up: {data['summary']['up_hosts']}</li>
                    <li>Hosts with critical issues: {len(issues)}</li>
                    <li>Total critical issues: {critical_count}</li>
                </ul>
                
                <h2>Critical Issues</h2>
            """
            
            # Adicionar tabela para cada host com problemas
            for host in issues:
                body += f"""
                <h3>Host: {host['ip']}{f" ({host['hostname']})" if host['hostname'] else ""}</h3>
                <table>
                    <tr>
                        <th>Issue Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                """
                
                for issue in host['issues']:
                    severity_class = issue['severity']
                    body += f"""
                    <tr>
                        <td>{issue['type'].upper()}</td>
                        <td class="{severity_class}">{issue['severity'].upper()}</td>
                        <td>{issue['issue']}</td>
                    </tr>
                    """
                
                body += """
                </table>
                <br>
                """
            
            body += """
            </body>
            </html>
            """
            
            # Criar mensagem de email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            
            # Adicionar versão HTML
            msg.attach(MIMEText(body, 'html'))
            
            # Conectar ao servidor SMTP e enviar
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                
                # Se houver usuário e senha, autenticar
                if 'username' in email_config and 'password' in email_config:
                    server.login(email_config['username'], email_config['password'])
                
                server.sendmail(sender, recipients, msg.as_string())
            
            console.print(f"[green]Alerta de email enviado para:[/green] {', '.join(recipients)}")
            return True
        
        except Exception as e:
            console.print(f"[red]Erro ao enviar alerta por email:[/red] {e}")
            return False
    
    def _send_discord_alert(self, issues: List[Dict], data: Dict) -> bool:
        """
        Envia alertas para Discord via webhook.
        
        Args:
            issues: Lista de problemas críticos detectados
            data: Dados completos da varredura
            
        Returns:
            True se o alerta foi enviado com sucesso, False caso contrário
        """
        try:
            discord_config = self.alerts_config.get('discord', {})
            webhook_url = discord_config.get('webhook_url', '')
            
            if not webhook_url:
                console.print("[yellow]URL do webhook do Discord não configurada.[/yellow]")
                return False
            
            # Configurações adicionais
            username = discord_config.get('username', 'Security Scanner')
            avatar_url = discord_config.get('avatar_url', '')
            
            # Cores para níveis de severidade (decimal)
            colors = discord_config.get('severity_colors', {
                'high': 16711680,    # Vermelho
                'medium': 16737095,  # Laranja
                'low': 65280         # Verde
            })
            
            # Montar mensagem principal
            critical_count = sum(len(host['issues']) for host in issues)
            message = {
                'username': username,
                'avatar_url': avatar_url,
                'content': f'**Alerta de Segurança:** {critical_count} problemas encontrados em {len(issues)} hosts',
                'embeds': []
            }
            
            # Adicionar resumo da varredura
            message['embeds'].append({
                'title': 'Resumo da Varredura',
                'color': 3447003,  # Azul
                'fields': [
                    {'name': 'Data da Varredura', 'value': data['scan_info']['timestamp'], 'inline': True},
                    {'name': 'Hosts Escaneados', 'value': str(data['summary']['total_hosts']), 'inline': True},
                    {'name': 'Hosts Online', 'value': str(data['summary']['up_hosts']), 'inline': True},
                    {'name': 'Comando', 'value': data['scan_info']['args'], 'inline': False}
                ]
            })
            
            # Adicionar embed para cada host (limite Discord: 10 embeds por mensagem)
            for i, host in enumerate(issues[:9]):  # Limite de 9 hosts + o resumo
                host_issues = host['issues']
                highest_severity = max([{'high': 3, 'medium': 2, 'low': 1}[issue['severity']] for issue in host_issues])
                severity_color = colors['high'] if highest_severity == 3 else colors['medium'] if highest_severity == 2 else colors['low']
                
                fields = []
                for issue in host_issues[:10]:  # Limite de 10 problemas por host
                    fields.append({
                        'name': f"{issue['type'].upper()} - {issue['severity'].upper()}",
                        'value': issue['issue'],
                        'inline': False
                    })
                
                message['embeds'].append({
                    'title': f"Host: {host['ip']}{f' ({host['hostname']})' if host['hostname'] else ''}",
                    'color': severity_color,
                    'fields': fields
                })
            
            # Se houver mais hosts do que podemos mostrar
            if len(issues) > 9:
                remaining = len(issues) - 9
                message['embeds'].append({
                    'title': f"E mais {remaining} hosts com problemas",
                    'color': 16777215,  # Branco
                    'description': "Devido a limitações do Discord, nem todos os hosts podem ser mostrados aqui."
                })
            
            # Enviar para o webhook
            response = requests.post(webhook_url, json=message)
            
            if response.status_code == 204:
                console.print("[green]Alerta enviado com sucesso para o Discord.[/green]")
                return True
            else:
                console.print(f"[red]Erro ao enviar alerta para o Discord:[/red] {response.status_code} {response.text}")
                return False
        
        except Exception as e:
            console.print(f"[red]Erro ao enviar alerta para o Discord:[/red] {e}")
            return False
    
    def display_report_summary(self, data: Dict, issues: Optional[List[Dict]] = None) -> None:
        """
        Exibe um resumo formatado do relatório no console.
        
        Args:
            data: Dados processados da varredura
            issues: Lista opcional de problemas críticos detectados
        """
        console.print("\n[bold green]===== RELATÓRIO DE SEGURANÇA NMAP =====[/bold green]")
        
        # Informações da varredura
        console.print(f"\n[bold]Informações da Varredura:[/bold]")
        console.print(f"  Data: {data['scan_info']['timestamp']}")
        console.print(f"  Comando: {data['scan_info']['args']}")
        console.print(f"  Versão do Nmap: {data['scan_info']['version']}")
        
        # Resumo
        console.print(f"\n[bold]Resumo:[/bold]")
        console.print(f"  Total de hosts escaneados: {data['summary']['total_hosts']}")
        console.print(f"  Hosts online: {data['summary']['up_hosts']}")
        console.print(f"  Hosts offline: {data['summary']['down_hosts']}")
        
        # Tabela de hosts com portas abertas
        console.print(f"\n[bold]Hosts com Portas Abertas:[/bold]")
        table = Table(title="Inventário de Hosts")
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("Sistema Operacional", style="yellow")
        table.add_column("Portas Abertas", style="red")
        table.add_column("Portas Críticas", style="red bold")
        
        for host in data['hosts']:
            open_ports = [port for port in host['ports'] if port['state'] == 'open']
            critical_ports = [port for port in open_ports if port['critical']]
            
            open_ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in open_ports[:5]])
            if len(open_ports) > 5:
                open_ports_str += f"... +{len(open_ports) - 5} mais"
                
            critical_ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in critical_ports])
            if not critical_ports_str:
                critical_ports_str = "-"
            
            hostname = host['hostname'] if host['hostname'] else "-"
            os_name = host['os']['name'] if host['os']['name'] != 'Unknown' else "-"
            
            table.add_row(
                host['ip'],
                hostname,
                os_name,
                open_ports_str,
                critical_ports_str
            )
        
        console.print(table)
        
        # Mostrar problemas críticos se fornecidos
        if issues:
            console.print(f"\n[bold red]Problemas Críticos Detectados:[/bold red]")
            
            for host in issues:
                console.print(f"\n[bold]Host:[/bold] {host['ip']}{f' ({host['hostname']})' if host['hostname'] else ''}")
                
                issues_table = Table()
                issues_table.add_column("Tipo", style="cyan")
                issues_table.add_column("Severidade", style="yellow")
                issues_table.add_column("Descrição", style="white")
                
                for issue in host['issues']:
                    severity_style = "red bold" if issue['severity'] == 'high' else "yellow" if issue['severity'] == 'medium' else "cyan"
                    issues_table.add_row(
                        issue['type'].upper(),
                        issue['severity'].upper(),
                        issue['issue']
                    )
                
                console.print(issues_table)
        
        console.print("\n[bold green]=====================================[/bold green]")

def main():
    """
    Função principal que processa os argumentos de linha de comando e executa o parser.
    """
    parser = argparse.ArgumentParser(
        description="Converte relatórios XML do Nmap para outros formatos e detecta problemas de segurança"
    )
    parser.add_argument(
        "xml_file", 
        help="Arquivo XML do Nmap para processar"
    )
    parser.add_argument(
        "--output-file", "-o",
        help="Arquivo de saída para salvar o resultado (opcional)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "splunk"],
        default="json",
        help="Formato de saída (padrão: json)"
    )
    parser.add_argument(
        "--config", "-c",
        help="Caminho para o arquivo de configuração YAML"
    )
    parser.add_argument(
        "--detect-critical", "-d",
        action="store_true",
        help="Detectar e relatar problemas críticos"
    )
    parser.add_argument(
        "--alert", "-a",
        action="store_true",
        help="Enviar alertas para problemas críticos"
    )
    parser.add_argument(
        "--compare-previous", "-p",
        help="Comparar com varredura anterior (caminho para JSON)"
    )
    parser.add_argument(
        "--silent", "-s",
        action="store_true",
        help="Modo silencioso (sem saída em console)"
    )
    
    args = parser.parse_args()
    
    # Inicializar parser
    nmap_parser = NmapReportParser(args.config)
    
    try:
        # Processar arquivo XML
        data = nmap_parser.parse_xml(args.xml_file)
        
        # Detectar problemas críticos se solicitado
        issues = []
        if args.detect_critical or args.alert:
            issues = nmap_parser.detect_critical_issues(data)
        
        # Enviar alertas se solicitado
        if args.alert and issues:
            nmap_parser.send_alerts(issues, data)
        
        # Converter para o formato solicitado
        output = nmap_parser.convert_to_format(data, args.format)
        
        # Salvar para arquivo se caminho fornecido
        if args.output_file:
            nmap_parser.save_to_file(output, args.output_file)
        elif not args.silent:
            # Caso contrário, exibir no console
            # Se for JSON ou CSV, exibir os primeiros 1000 caracteres para não sobrecarregar o terminal
            if args.format in ["json", "csv"]:
                preview = output[:1000] + ("..." if len(output) > 1000 else "")
                console.print(f"[dim]{preview}[/dim]")
                console.print(f"\n[yellow]Saída completa não exibida ({len(output)} bytes). Use --output-file para salvar.[/yellow]")
        
        # Exibir resumo formatado para o usuário
        if not args.silent:
            nmap_parser.display_report_summary(data, issues if args.detect_critical else None)
        
        return 0
    
    except Exception as e:
        console.print(f"[bold red]Erro:[/bold red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return 1

if __name__ == "__main__":
    sys.exit(main())