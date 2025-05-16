#Dockerfile para nmap-automation
FROM python:3.11-bullseye-slim

# Instala Nmap e dependências de sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Copia o código Python para o container
COPY . .

# Instala libs Python
RUN pip install --no-cache-dir -r requirements.txt

# Entrada padrão: ajuda
ENTRYPOINT [ "bash", "-c", "echo 'Use nmap-auto-scan.sh e nmap-parser.py conforme README.md.' && bash]
