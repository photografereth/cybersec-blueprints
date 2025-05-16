# Guia de Contribuição

Agradecemos seu interesse em contribuir com o projeto CyberSec Blueprints! Este documento fornece diretrizes para contribuir com o repositório de maneira eficaz.

## Índice

- [Código de Conduta](#código-de-conduta)
- [Como Contribuir](#como-contribuir)
  - [Reportando Bugs](#reportando-bugs)
  - [Sugerindo Melhorias](#sugerindo-melhorias)
  - [Pull Requests](#pull-requests)
- [Padrões de Codificação](#padrões-de-codificação)
  - [Python](#python)
  - [Ansible/YAML](#ansibleyaml)
  - [Bash](#bash)
  - [Splunk SPL](#splunk-spl)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Processo de Revisão](#processo-de-revisão)
- [Recursos Adicionais](#recursos-adicionais)

## Código de Conduta

Este projeto adota um código de conduta que esperamos que todos os participantes sigam. Por favor, seja respeitoso com outros contribuidores, mantenha discussões técnicas construtivas e foque em melhorar o projeto.

## Como Contribuir

### Reportando Bugs

Bugs podem ser reportados através das Issues do GitHub. Ao reportar um bug, inclua:

- Título claro e descritivo
- Passos detalhados para reproduzir o problema
- Comportamento esperado vs. comportamento observado
- Screenshots, logs ou mensagens de erro relevantes
- Informações sobre ambiente (SO, versões de ferramentas, etc.)

### Sugerindo Melhorias

Ideias para novas funcionalidades são bem-vindas! Para sugerir melhorias:

1. Verifique se a sugestão já não foi proposta nas Issues existentes
2. Crie uma nova Issue com detalhes da funcionalidade sugerida
3. Descreva o problema que sua sugestão resolverá
4. Explique como a implementação beneficiará o projeto

### Pull Requests

Para contribuir com código ou documentação:

1. Fork o repositório
2. Crie um branch para sua feature (`git checkout -b feature/nome-da-feature`)
3. Faça commit das suas alterações (`git commit -m 'Adiciona nova feature'`)
4. Push para o branch (`git push origin feature/nome-da-feature`)
5. Abra um Pull Request

Certifique-se de que seu PR inclui:
- Descrição clara do que foi implementado/alterado
- Links para Issues relacionadas
- Testes, quando aplicável
- Documentação atualizada

## Padrões de Codificação

### Python

- Siga a PEP 8 para estilo de código
- Use snake_case para nomes de funções e variáveis
- Inclua docstrings com descrições claras (formato Google ou NumPy)
- Organize imports na seguinte ordem:
  1. Bibliotecas padrão
  2. Bibliotecas de terceiros
  3. Imports locais
- Utilize tipagem quando apropriado (Python 3.6+)
- Trate exceções de forma específica (evite `except Exception:`)

Exemplo:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para processamento de relatórios do Nmap.

Este módulo converte relatórios XML do Nmap em formatos mais utilizáveis
como JSON ou CSV, facilitando a análise e integração com outras ferramentas.
"""

import json
import os
import sys
from typing import Dict, List, Optional

import requests
import xmltodict

from .utils import format_output


def parse_nmap_xml(file_path: str) -> Dict:
    """
    Converte arquivo XML do Nmap em dicionário Python.
    
    Args:
        file_path: Caminho para o arquivo XML do Nmap
        
    Returns:
        Dicionário contendo os dados estruturados do relatório
        
    Raises:
        FileNotFoundError: Se o arquivo XML não for encontrado
    """
    try:
        with open(file_path, 'r') as xml_file:
            xml_content = xml_file.read()
        return xmltodict.parse(xml_content)
    except FileNotFoundError:
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
```

### Ansible/YAML

- Use indentação de 2 espaços
- Nomeie as tasks de forma descritiva e em português
- Organize roles e playbooks de forma modular
- Use handlers para ações que dependem de mudanças
- Prefira usar módulos nativos do Ansible em vez de comandos shell

Exemplo:
```yaml
---
- name: Configurar política de senhas seguras
  lineinfile:
    path: /etc/security/pwquality.conf
    regexp: "^{{ item.param }}"
    line: "{{ item.param }} = {{ item.value }}"
    state: present
  with_items:
    - { param: "minlen", value: "12" }
    - { param: "minclass", value: "4" }
    - { param: "dcredit", value: "-1" }
    - { param: "ucredit", value: "-1" }
  notify: Reiniciar serviço PAM
  tags:
    - security
    - password_policy
```

### Bash

- Use indentação de 2 espaços
- Inclua cabeçalho com descrição, uso e autor
- Declare variáveis em MAIÚSCULAS
- Adicione tratamento de erros com trap e códigos de saída
- Implemente validação de entrada para todos os scripts
- Use [[ ]] para testes condicionais (mais robusto que [ ])

Exemplo:
```bash
#!/bin/bash
#
# nmap-auto-scan.sh - Automatiza varreduras Nmap em redes específicas
#
# Autor: Seu Nome <seu.email@exemplo.com>
# Data: YYYY-MM-DD
#
# Uso: ./nmap-auto-scan.sh [target] [output_dir]
# Exemplo: ./nmap-auto-scan.sh 192.168.1.0/24 /tmp/scans

# Definição de variáveis
TARGET="${1:-"192.168.1.0/24"}"
OUTPUT_DIR="${2:-"/tmp/nmap-scans"}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOGFILE="${OUTPUT_DIR}/nmap-scan-${TIMESTAMP}.log"
XML_OUTPUT="${OUTPUT_DIR}/nmap-scan-${TIMESTAMP}.xml"

# Tratamento de erros
set -e
trap 'echo "Erro na linha $LINENO. Saindo..."; exit 1' ERR

# Verifica se Nmap está instalado
if ! command -v nmap &> /dev/null; then
  echo "Erro: Nmap não está instalado. Por favor instale-o primeiro."
  exit 1
fi

# Cria diretório de saída se não existir
mkdir -p "$OUTPUT_DIR" || {
  echo "Erro: Não foi possível criar o diretório $OUTPUT_DIR"
  exit 1
}

# Função para execução da varredura
function run_scan() {
  local target="$1"
  local output="$2"
  
  echo "Iniciando varredura em $target em $(date)"
  nmap -sS -sV -O --script=default,vuln -oX "$output" "$target"
  return $?
}

# Executa a varredura
echo "Iniciando varredura em $TARGET" | tee -a "$LOGFILE"
if run_scan "$TARGET" "$XML_OUTPUT"; then
  echo "Varredura concluída com sucesso. Resultados salvos em $XML_OUTPUT" | tee -a "$LOGFILE"
  exit 0
else
  echo "Erro durante a varredura. Verifique $LOGFILE para detalhes" | tee -a "$LOGFILE"
  exit 1
fi
```
### Splunk SPL

- Organize queries com comentários descritivos
- Use indentação para comandos em pipeline
- Documente filtros, campos e condições importantes
- Nomeie campos processados de forma descritiva

Exemplo:
```spl
/* 
 * Detecção de lateral movement via wmi/psexec
 * Autor: Seu Nome
 * Data: YYYY-MM-DD
 * Descrição: Esta query detecta possíveis movimentos laterais usando WMI ou PsExec
 */

index=windows sourcetype=WinEventLog:Security EventCode=4688
| where OriginalFileName IN ("wmic.exe", "psexec.exe", "wmiexec.py") 
| eval technique="Lateral Movement" 
| eval mitre_id="T1021.002, T1021.006" 
| eval severity=case(
    match(CommandLine, "-accepteula"), "high",
    match(CommandLine, "process call create"), "high",
    1=1, "medium")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, 
    User, OriginalFileName, technique, mitre_id, severity
| rename Computer as target_host, User as actor
| sort - severity
```

## Estrutura do Projeto

Mantenha a estrutura de diretórios consistente e adicione novos componentes nos locais apropriados:

- Cada módulo principal tem seu próprio diretório
- Cada módulo tem seu próprio README.md com instruções detalhadas
- Documentação em `/docs`
- Diretórios seguem a convenção kebab-case (ex: `ansible-hardening`)

## Processo de Revisão

- Todos os Pull Requests serão revisados pelos mantenedores
- Comentários e sugestões devem ser implementados antes da aprovação
- Código deve passar em testes (quando implementados)
- O estilo de código deve seguir as diretrizes acima

## Recursos Adicionais

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Nmap Documentation](https://nmap.org/docs.html)

---

# Contribua
Agradecemos suas contribuições ao projeto CyberSec Blueprints!
