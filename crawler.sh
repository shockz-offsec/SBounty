#!/bin/bash

# Configuración
. config.ini  # Para variables como otx_api_key, urlscan_api_key

# Colores de terminal
byellow='\033[1;33m'
bgreen='\033[0;32m'
bred='\033[0;31m'
reset='\033[0m'

# Función banner
function banner() {
    printf "\n${bgreen}[*] Starting URL fetcher!${reset}\n"
}

# Validar argumento
if [ -z "$1" ]; then
    echo "Usage: $0 <subdomain>"
    exit 1
fi

subdomain="$1"

# Normalizar subdominio
dominio_temp=$(echo "$subdomain" | sed -E 's/https?:\/\/(www\.)?([a-zA-Z0-9.-]+)(\/.*)?/\2/')
dominio=$(echo "$dominio_temp" | tr -d -c '[:alnum:]')
results_path="results/$dominio"
urls_output_path="$results_path/urls.txt"
urls_filtered_path="$results_path/urls_filtered.txt"

# Verificar root
if [[ $(id -u) -ne 0 ]]; then
    printf "${bred} Please run as root or with user added to sudoers ${reset}\n\n"
    exit
fi

banner

# Crear carpeta de resultados
mkdir -p "$results_path"

# Función de crawling y agregando URLs de APIs
fetch_urls() {
    if [ -f "$urls_output_path" ]; then
        printf "${byellow}[*]${reset} URLs file already exists, skipping crawling.\n"
    else
        {
            gau "$subdomain" --threads 10 2>/dev/null
            waybackurls "$subdomain" 2>/dev/null
            katana -u "$subdomain" -silent -jc -d 3 2>/dev/null
            echo "$subdomain" | hakrawler -d 3 -insecure 2>/dev/null
        } | uro | sort -u \
          | grep -E "^https?://([a-z0-9.-]*\.)?$subdomain" \
          > "$urls_output_path"

        # Añadir URLs vía APIs
        echo "[*] Fetching URLs via APIs..."
        {
            if [ -n "$otx_api_key" ]; then
                curl -s -H "X-OTX-API-KEY: $otx_api_key" \
                    "https://otx.alienvault.com/api/v1/indicators/domain/$subdomain/url_list?limit=100&page=1" \
                | jq -r '.url_list[].url' 2>/dev/null
            fi

            if [ -n "$urlscan_api_key" ]; then
                curl -s -H "API-Key: $urlscan_api_key" \
                    "https://urlscan.io/api/v1/search/?q=domain:$subdomain" \
                | jq -r '.results[].page.url' 2>/dev/null
            fi
        } | uro | sort -u \
          | grep -E "^https?://([a-z0-9.-]*\.)?$subdomain" \
          >> "$urls_output_path"
    fi
}

# Ejecutar crawling
fetch_urls
echo "[*] URLs saved in $urls_output_path"

# Script Python para filtrar URLs duplicadas por parámetros
python3 - <<EOF
import sys
from urllib.parse import urlparse, parse_qsl

input_file = "${urls_output_path}"
output_file = "${urls_filtered_path}"

seen_params = set()
unique_urls = []

with open(input_file, 'r') as f:
    for line in f:
        url = line.strip()
        if not url:
            continue
        parsed = urlparse(url)
        query_params = tuple(sorted(parse_qsl(parsed.query)))
        if query_params not in seen_params:
            seen_params.add(query_params)
            unique_urls.append(url)

with open(output_file, 'w') as f:
    for url in unique_urls:
        f.write(url + '\n')
EOF

echo "[*] Filtered URLs saved in $urls_filtered_path"
