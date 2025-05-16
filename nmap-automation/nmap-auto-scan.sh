#\!/bin/bash
#
# nmap-auto-scan.sh - Script para automação de varreduras Nmap e geração de relatórios
#
# Autor: Felipe Miranda
# Data: 2025-05-13
# Versão: 1.0
#
# Descrição:
#   Este script automatiza varreduras Nmap em redes específicas, gerando relatórios XML, JSON
#   e outros formatos personalizáveis. É parte do conjunto de ferramentas CyberSec Blueprints.
#
# Uso: ./nmap-auto-scan.sh [opções] [alvo] [diretório-saída]
# Exemplos:
#   ./nmap-auto-scan.sh 192.168.1.0/24 /tmp/nmap-scans
#   ./nmap-auto-scan.sh -t 10.0.0.0/24 -o /tmp/scans -p "80,443,8080" -s "-sS -sV"
#
# Opções:
#   -t, --target        Rede ou host alvo (ex: 192.168.1.0/24)
#   -o, --output-dir    Diretório para salvar os resultados
#   -p, --ports         Lista de portas para verificar (padrão: portas comuns)
#   -s, --scan-args     Argumentos personalizados para o Nmap
#   -n, --name          Nome personalizado para o arquivo de saída
#   -e, --exclude       IPs ou redes para excluir da varredura
#   -v, --verbose       Saída detalhada
#   -h, --help          Exibe esta ajuda

# Definição de cores para saída
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Definição de variáveis
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DEFAULT_OUTPUT_DIR="/tmp/nmap-scans"
DEFAULT_TARGET="127.0.0.1"
VERBOSE=false

# Função para exibir mensagens de erro e sair
error_exit() {
    echo -e "${RED}ERRO: $1${NC}" >&2
    exit 1
}

# Função para exibir mensagens de log
log() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[AVISO]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERRO]${NC} $message"
            ;;
        "DEBUG")
            if $VERBOSE; then
                echo -e "${BLUE}[DEBUG]${NC} $message"
            fi
            ;;
        *)
            echo -e "$message"
            ;;
    esac
}

# Função para exibir ajuda
show_help() {
    echo "Uso: $0 [opções] [alvo] [diretório-saída]"
    echo
    echo "Opções:"
    echo "  -t, --target        Rede ou host alvo (ex: 192.168.1.0/24)"
    echo "  -o, --output-dir    Diretório para salvar os resultados"
    echo "  -p, --ports         Lista de portas para verificar (padrão: portas comuns)"
    echo "  -s, --scan-args     Argumentos personalizados para o Nmap"
    echo "  -n, --name          Nome personalizado para o arquivo de saída"
    echo "  -e, --exclude       IPs ou redes para excluir da varredura"
    echo "  -v, --verbose       Saída detalhada"
    echo "  -h, --help          Exibe esta ajuda"
    echo
    echo "Exemplos:"
    echo "  $0 192.168.1.0/24 /tmp/nmap-scans"
    echo "  $0 -t 10.0.0.0/24 -o /tmp/scans -p \"80,443,8080\" -s \"-sS -sV\""
    exit 0
}

# Verifica se o Nmap está instalado
check_requirements() {
    if \! command -v nmap &> /dev/null; then
        error_exit "Nmap não está instalado. Por favor, instale-o primeiro."
    fi
    
    # Tentar ler configurações do arquivo config.yaml se existir
    if [ -f "$CONFIG_FILE" ] && command -v python3 &> /dev/null; then
        log "DEBUG" "Lendo configurações de $CONFIG_FILE"
        if \! DEFAULT_PORTS=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['nmap']['default_ports'])"); then
            log "WARN" "Não foi possível ler 'default_ports' do arquivo de configuração."
            DEFAULT_PORTS="21,22,23,25,80,443,3389,8080"
        fi
        
        if \! DEFAULT_ARGS=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['nmap']['default_args'])"); then
            log "WARN" "Não foi possível ler 'default_args' do arquivo de configuração."
            DEFAULT_ARGS="-sS -sV -O"
        fi
    else
        log "DEBUG" "Usando configurações padrão"
        DEFAULT_PORTS="21,22,23,25,80,443,3389,8080"
        DEFAULT_ARGS="-sS -sV -O"
    fi
}

# Processar argumentos
parse_arguments() {
    TARGET="$DEFAULT_TARGET"
    OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
    PORTS="$DEFAULT_PORTS"
    SCAN_ARGS="$DEFAULT_ARGS"
    SCAN_NAME=""
    EXCLUDE_TARGETS=""
    
    # Verificar se temos argumentos posicionais (compatibilidade com versões anteriores)
    if [ $# -ge 1 ] && [[ \! "$1" =~ ^- ]]; then
        TARGET="$1"
        shift
        
        if [ $# -ge 1 ] && [[ \! "$1" =~ ^- ]]; then
            OUTPUT_DIR="$1"
            shift
        fi
    fi
    
    # Processar argumentos nomeados
    while [ $# -gt 0 ]; do
        case "$1" in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -p|--ports)
                PORTS="$2"
                shift 2
                ;;
            -s|--scan-args)
                SCAN_ARGS="$2"
                shift 2
                ;;
            -n|--name)
                SCAN_NAME="$2"
                shift 2
                ;;
            -e|--exclude)
                EXCLUDE_TARGETS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                error_exit "Opção desconhecida: $1"
                ;;
        esac
    done
    
    # Verificar argumentos obrigatórios
    if [ -z "$TARGET" ]; then
        error_exit "Alvo não especificado. Use -t para definir o alvo da varredura."
    fi
    
    # Definir nome do arquivo de saída
    if [ -z "$SCAN_NAME" ]; then
        # Substituir caracteres não permitidos em nomes de arquivo
        TARGET_SAFE=$(echo "$TARGET" | tr '/' '_' | tr ':' '-')
        FILE_PREFIX="scan-${TIMESTAMP}-${TARGET_SAFE}"
    else
        FILE_PREFIX="$SCAN_NAME"
    fi
    
    XML_OUTPUT="${OUTPUT_DIR}/${FILE_PREFIX}.xml"
    
    log "DEBUG" "Alvo: $TARGET"
    log "DEBUG" "Diretório de saída: $OUTPUT_DIR"
    log "DEBUG" "Portas: $PORTS"
    log "DEBUG" "Argumentos de varredura: $SCAN_ARGS"
    log "DEBUG" "Arquivo XML de saída: $XML_OUTPUT"
    
    if [ -n "$EXCLUDE_TARGETS" ]; then
        log "DEBUG" "Alvos excluídos: $EXCLUDE_TARGETS"
    fi
}

# Função para criar o diretório de saída
create_output_dir() {
    if [ \! -d "$OUTPUT_DIR" ]; then
        log "INFO" "Criando diretório de saída: $OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR" || error_exit "Não foi possível criar o diretório: $OUTPUT_DIR"
    fi
}

# Função para executar o Nmap
run_nmap() {
    local nmap_cmd="nmap $SCAN_ARGS -p $PORTS -oX $XML_OUTPUT"
    
    if [ -n "$EXCLUDE_TARGETS" ]; then
        nmap_cmd="$nmap_cmd --exclude $EXCLUDE_TARGETS"
    fi
    
    nmap_cmd="$nmap_cmd $TARGET"
    
    log "INFO" "Iniciando varredura Nmap em $TARGET..."
    log "DEBUG" "Executando comando: $nmap_cmd"
    
    if $VERBOSE; then
        eval "$nmap_cmd"
    else
        eval "$nmap_cmd" > /dev/null
    fi
    
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "A varredura Nmap falhou com código de saída $exit_code"
        return $exit_code
    fi
    
    log "INFO" "Varredura concluída. Resultados salvos em: $XML_OUTPUT"
    return 0
}

# Função para verificar se temos o parser Python
check_parser() {
    PARSER_PATH="${SCRIPT_DIR}/nmap-report-parser.py"
    
    if [ -f "$PARSER_PATH" ] && command -v python3 &> /dev/null; then
        log "INFO" "Parser de relatório Nmap encontrado: $PARSER_PATH"
        return 0
    else
        log "WARN" "Parser de relatório Nmap não encontrado em: $PARSER_PATH"
        return 1
    fi
}

# Função para executar o parser de relatório
run_parser() {
    if check_parser; then
        log "INFO" "Processando relatório XML com parser..."
        
        local parser_cmd="python3 $PARSER_PATH $XML_OUTPUT"
        log "DEBUG" "Executando comando: $parser_cmd"
        
        eval "$parser_cmd"
        local exit_code=$?
        
        if [ $exit_code -ne 0 ]; then
            log "WARN" "O processamento do relatório falhou com código de saída $exit_code"
            return $exit_code
        fi
        
        log "INFO" "Processamento do relatório concluído"
        return 0
    fi
    
    return 1
}

# Função principal
main() {
    # Verificar requisitos
    check_requirements
    
    # Processar argumentos
    parse_arguments "$@"
    
    # Criar diretório de saída
    create_output_dir
    
    # Executar varredura Nmap
    run_nmap
    
    # Processar resultados
    run_parser
    
    log "INFO" "Todas as operações concluídas com sucesso"
    
    # Criar link simbólico para a varredura mais recente
    ln -sf "$XML_OUTPUT" "${OUTPUT_DIR}/scan-latest.xml" || log "WARN" "Não foi possível criar link simbólico para a varredura mais recente"
}

# Execução do script
main "$@"
EOF < /dev/null