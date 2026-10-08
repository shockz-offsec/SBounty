# MANTENIMIENTO — SBounty

Guía por casos para tocar SBounty sin romperlo. Contexto y reglas duras en `CLAUDE.md`; uso en `README.md`.

## Ficheros
```
sbounty.sh    todo el código (un solo bash)
config.ini    flags de clases + waf_check + blind_xss_url
README.md     uso (publicado, en inglés)       CLAUDE.md / MANTENIMIENTO.md  (mantenedor, español)
results/<host>/   salida por objetivo (gitignored)
```
No hay más: `crawler.sh`/`xss_payloads.txt`/`sources.ini` se eliminaron en el refactor; no volver a crearlos.

## Añadir una clase de vulnerabilidad / motor
1. Escribe una función `foo_scan()` que lea `$urls_output_path` y escriba `results/<host>/foo.txt`
   (una línea por hallazgo). Usa `have <tool> || { skip "foo"; : > "$out"; return; }` para degradar.
2. Usa los arrays de cabecera que correspondan: `curl_hdr`/`httpx_hdr`/`nuclei_hdr`/`dalfox_hdr` y, para
   sqlmap, `sqlmap_hdr` + `sqlmap_host`. NO leas `$headers` directo (rompe el bypass de WAF).
3. Regístrala en `run_engines`: añade `test "$foo" = "true" && specs+=("foo:foo_scan")`.
4. Añade su flag a `config.ini` (`foo=true|false`) — el script lo lee como `$foo`.
5. Si el nombre del `.txt` es nuevo, añádelo a DOS sitios: el bucle de `summarize` Y el de `_cleanup`
   (lista `nuclei-dast dalfox sqlmap stored-xss secrets cors`), y dale su rama en `show_findings`.
6. Si necesita una tool nueva, mete su instalador en el `declare -A INSTALL` de `install()`.

> **Decisión de diseño:** la cobertura ANCHA la da `nuclei -dast`. Antes de añadir un motor nuevo,
> comprueba que aporta algo que nuclei-dast no cubre (como dalfox en XSS o sqlmap en explotación SQLi).
> Si no, mejor una plantilla de nuclei.

## Adquisición: saneo y dedup (lo que recorta el corpus)
- `probe_target` (al inicio de `scan_target`, antes de `waf_detect`): chequeo LIGHT (1 request) de que
  el objetivo resuelve y responde; prueba `https` y `http` y fija `seed_url` al esquema VIVO (un host
  http-only ya no se escanea por el https muerto, y wafw00f deja de perder ~23s ahí). Si no responde por
  ninguno → aborta el objetivo (no se gasta crawl/arjun/liveness). El `seed_url` corregido se propaga:
  `build_corpus "$seed_url"` (katana/hakrawler crawlean el esquema bueno).
- `sanitize_urls` (tras `scope_filter`): tira artefactos del crawl/wayback mirando **solo la RUTA**
  (antes del `?`): 2º `http://` concatenado en la ruta, whitespace/control, caracteres crudos
  `'"<>\`{}*\\`. **NO filtra por el VALOR**: la basura del valor la neutraliza el dedup, y filtrar por
  un carácter del valor mataría endpoints reales (open-redirect `?r=http://...`, `?name=<script>`).
- `dedup_by_params`: 1 URL por `(scheme, host, path, claves)`. **Normaliza el puerto por defecto**
  (`host:80`==`host`, evita doble escaneo) y **canonicaliza valores**: un payload archivado
  (union/`<script>`/comillas/largo>40/espacios) se pone a `1` (`clean()` + `JUNK`). Así colapsan las
  variantes del mismo endpoint y sqlmap/dalfox reciben valores limpios.
- `target_responsive` (antes de los motores, en `scan_target`): sondea 4 URLs del corpus FINAL con
  `curl -w %{http_code}`; si **todas** dan `000` (conexión rechazada), pone `TARGET_DOWN=1`, **omite los
  motores** y lo avisa (evita el escaneo fantasma que daba "58 hits" sobre un host que rechazaba todo).
- sqlmap fail-fast: `--timeout 10 --retries 1` (`SB_SQLI_TIMEOUT`/`SB_SQLI_RETRIES`); el defecto 30s×3
  gastaba ~65s por URL muerta.
- `no_static` (feed de dalfox y sqlmap): excluye ficheros ESTATICOS (`.txt/.html/.jpg/.css/.js/fuente/
  media`) mirando **solo la RUTA** (`^https?://[^?]*\.ext(\?|$)`, no el valor: `Templatize.asp?item=x.html`
  NO se descarta). Un estatico no procesa params → es 0% inyectable; en testasp sqlmap quemaba 1200s en
  `/t/fit.txt`. nuclei (rapido) sigue viendo el corpus COMPLETO, solo se recorta el feed de los caros.
- **"capped != clean":** cada motor que toca el cap (`timeout` rc 124, o el deadline de cors) deja
  `results/<host>/.cap.<motor>`. `summarize` lo lee: 0 hits + capped → "sin hallazgos (INCONCLUSO)" en
  amarillo, NUNCA "clean"; con hits, "(PARCIAL)". `show_findings` avisa si algun motor quedo incompleto.
  Se borran al empezar `scan_target`. Un "clean" solo es valido si el motor TERMINO.

## -no-caps (quitar todos los topes)
Flag `-no-caps`/`--no-caps`: se filtra ANTES de getopt (es multi-caracter) y pone `SB_ENGINE_CAP`,
`SB_CRAWL_CAP`, `SB_ARJUN_CAP`, `SB_CORS_MAX`, `SB_SECRETS_MAX`, `SB_SX_MAX` a valores enormes (30 días /
1e8) → crawl/arjun/motores corren hasta terminar, corpus sin truncar. **Los timeouts POR PETICIÓN
(`SB_REQ_TIMEOUT`/`SB_SQLI_TIMEOUT`/`SB_CORS_TIMEOUT`) se mantienen** (evitan colgarse en una petición
muerta). Para añadir un cap nuevo, anúlalo también en el bloque `if [ "$NO_CAPS" = 1 ]`.

## Afinar (sin tocar código)
- **Clases:** `config.ini` (`dast/xss_deep/sqli_deep/cors/param_mining/waf_check`).
- **Ajustes finos por env** (ver tabla del README): `SB_CRAWL_CAP`, `SB_MAX_URLS`, `SB_SQLI_LEVEL/RISK/
  TAMPER/THREADS`, `SB_NUCLEI_RL/C`. Defaults sensatos; súbelos/bájalos según ruido/objetivo.
- **sqlmap es ADAPTATIVO a la latencia** (medida en el probe, `TARGET_LAT_MS`): rápido (<800 ms/req) →
  `level 3/risk 2`; lento (≥800 ms) → `level 2/risk 1` (menos peticiones = scan COMPLETO en vez de uno
  profundo cortado por el cap). `--timeout` sale de `SB_REQ_TIMEOUT` (6–30 s según latencia). Forzar con
  `SB_SQLI_LEVEL=5 SB_SQLI_RISK=3 SB_SQLI_TIMEOUT=30 ./sbounty.sh ...`. Siempre `--flush-session
  --tamper=between,randomcase,space2comment --dbs` (sin `--level 5`: cabeceras las cubre nuclei-dast).

## Tools (toolset)
- En SBounty: el mapa `INSTALL` de `install()` valida e instala lo que falte (go→PATH, pipx, apt).
- En **Shockz-MKE** (para pre-hornearlas): fila en `registry/tools.tsv` + `run_step` en `arsenal/<cat>.sh`
  (dalfox/arjun/wafw00f viven en `web`), y actualizar recuentos en CLAUDE/BUILD-STATUS/README + `tools.conf`.
  Tras tocar el registry: `bash provision.sh --self-check` debe quedar en verde.

## sqlmap: GET + forms (POST)
- **Presupuesto COMPARTIDO:** GET y forms comparten `SB_ENGINE_CAP` (total sqlmap ≤ cap, como el resto de
  motores, ya no 2×). El GET corre con tope `cap`; el forms con lo que SOBRA (`cap - gasto_GET`, y si
  quedan <30 s se omite con aviso). Con la profundidad adaptativa, en un objetivo lento el GET termina
  antes y deja presupuesto para los formularios.
- **GET:** `gf sqli` (o fallback: todo param-url) → `no_static` → `sqlmap -m`. Encuentra SQLi en query.
- **POST/forms:** NO usa `--crawl` (re-descubria el sitio y capaba antes del login). Construye la lista de
  **paginas dinamicas ya crawleadas** (`.asp/.aspx/.php/.jsp/.do/.cfm/.cgi/.pl` + el seed, sin query,
  dedup) y lanza `sqlmap -m form_pages --forms`: fetch de cada pagina, parseo de su `<form>` y prueba del
  POST (asi llega al bypass de auth de un login). `SB_SQLI_FORMS=0` lo desactiva.
- **Ceiling conocido (NO lo cubre ningun motor):** XSS ALMACENADO (requiere postear y volver a leer) y la
  superficie AUTENTICADA (endpoints que exigen login). Son limites de alcance, no bugs.

## Motores de cobertura ampliada
- **stored_xss_scan** (`stored_xss`): planta un canary único por GET (qsreplace) y por formulario
  (extrae `name="..."`, resuelve la `action`, POST con `--data-urlencode`), luego RE-PIDE las páginas del
  corpus y marca solo si el breakout aparece **CRUDO** (`grep -qF 'token"><svg'`). Escapado = no cuenta
  (precisión). **ESCRIBE en el objetivo** → por eso es clase propia conmutable. `SB_SX_MAX` acota.
- **secrets_scan** (`secrets`): fetch de `.js/.json/.map` del corpus y `grep -oE` de patrones de ALTA
  confianza (prefijos distintivos: AKIA/AIza/ghp_/glpat-/xox/sk_live/SG./PRIVATE KEY). Read-only.
  NO añadir patrones genéricos (api_key, password): disparan FP. `SB_SECRETS_MAX` acota.
- **Modo autenticado:** `-H "Cookie: ..."` (`$headers`) se cablea al crawl ACTIVO (`katana -H`,
  `hakrawler -h`), a `arjun --headers` y a httpx/motores (ya vía `build_headers`). gau/wayback son
  pasivos, no la usan. Así se descubre y prueba la superficie tras login.

## Fiabilidad / caveats (lo que está PROBADO y lo que NO)
- **Probado en vivo (testasp):** núcleo crawl→dedup→motores→display, caps honestos, nuclei/dalfox/sqlmap
  (LFI/XSS/SQLi+dbs). Verificado estáticamente + lógica unit-tested: adaptativo (latencia→timeout/depth),
  dedup (puerto/valor), `no_static`, `count_hits`, `fmt_time`, strip de color en `_log`, presupuesto
  compartido. Guardas de runtime presentes (fallbacks de `TARGET_LAT_MS`/`SB_REQ_TIMEOUT`, `left<30`,
  `have curl/qsreplace`) → no revienta.
- **Ejecuta pero detección positiva NO confirmada aún:** `stored_xss_scan` y `secrets_scan` corrieron
  limpios en testasp, pero testasp no tiene stored-XSS anónimo ni secretos en JS → falta validarlos
  contra un objetivo que SÍ los tenga (para stored-XSS anónimo-no-alcanzable, pasar cookie con `-H`).
- **stored_xss es BEST-EFFORT:** parsea `name="..."` solo con comillas dobles, NO gestiona tokens CSRF
  (un form protegido rechazará el POST → posible falso negativo), y **ESCRIBE** en el objetivo. Precisión
  alta (solo cuenta el breakout CRUDO), recall limitado.
- **Riesgo conocido `hakrawler -h`:** según versión, `-h` puede ser "headers" o "help". Si fuese help,
  en modo auth hakrawler no crawlea (imprime ayuda y sale) pero **degrada con gracia**: katana `-H` sigue
  siendo el crawler autenticado primario. No bloquea el run.

## -s (host) vs -url (URL enfocada)
- **`-s host`**: flujo COMPLETO, crawl del host entero (gau/wayback del dominio + katana/hakrawler
  depth 3). Es para host/subdominio. (Si le pasas una URL, la trata como host igualmente.)
- **`-url URL`**: flujo ENFOCADO = esa URL + sus llamadas DIRECTAS. Pone `CRAWL_FOCUS=1`, que en
  `crawl_source` OMITE gau/waybackurls (son host-wide) y baja katana/hakrawler a depth 1 (`SB_FOCUS_DEPTH`)
  desde la URL; y en `mine_params` salta arjun (host-wide). El resto del pipeline (dedup/liveness/motores)
  es igual. `-url` se filtra ANTES de getopt (multi-carácter, lleva valor); cuenta como 1 de los 4 objetivos
  exclusivos (-s/-url/-l/-f). Un modo nuevo que toque el crawl debe gatearse por `CRAWL_FOCUS`.

## -f (URLs crudas): también se PROCESAN
`-f` NO crawlea ni mina (las URLs las da el usuario), pero sí: `sanitize_urls` (quita basura
estructural) → `dedup_by_params` (firma de params, normaliza puerto/valor) → `liveness_filter` (httpx
descarta muertas). Lleva `build_headers ""` para que `-H` llegue a httpx/motores. Graba `.t.prep` y
`.t.liveness`. Así no se atacan URLs rotas, duplicadas ni caídas. El fichero de entrada no se toca.

## sqlmap: comando por finding
`show_findings` saca, bajo cada punto de inyección, el comando para reproducirlo: asocia cada
`Parameter: X (METHOD)` con el último `GET/POST http://` que sqlmap tecleó antes (awk). GET →
`sqlmap -u "<url>" -p X --batch --dbs`; POST → `--forms` (así lo halló la pasada de formularios, sin
pegar el `__VIEWSTATE`). Si cambias el formato de salida de sqlmap, revisa ese awk.

## WAF / origen (cómo funciona, por si falla)
- `waf_detect`: `wafw00f` (comportamiento) + `cdncheck` (rango IP). Aviso en rojo si detecta.
- `origin_discover`: `uncover -q "$host"` → IPs candidatas → descarta las de CDN (`cdncheck`) → **verifica**
  con `curl -H "Host: $host" http://IP/` (el body menciona el dominio) → `ORIGIN_IP`.
- `scan_target`: si `ORIGIN_IP`, reescribe el corpus con `sed -E 's#^(https?://)[^/]+#\1IP#'`, pone
  `Host:` en todos los motores (`build_headers "$host"`; sqlmap usa `--host`), y los curl van con `-k`.
- **Si no encuentra origen:** necesita claves Shodan/Censys/Fofa en `uncover` (config de Shockz-MKE). Sin
  ellas la detección de WAF sí funciona y el scan sigue a través del WAF. Es best-effort a propósito.
- Trampa conocida: la reescritura descarta `:puerto` no estándar (asume 80/443).

## Observabilidad (lo que verás, y sus ficheros)
- Progreso: marcadores `[n/4]` en adquisición, `crawl_monitor` (conteo por fuente), `monitor_engines`
  (heartbeat por motor). Nunca debe parecer colgado; si lo parece, revisa que esos monitores corran.
- Tiempos: `results/<host>/.t.{waf,crawl,prep,liveness,<motor>}` + `.n.acquire`; los lee `summarize`.
  `.start.<motor>` lo usa el heartbeat (se borra al acabar el motor).
- Log: `results/<host>/sbounty.log` (stderr de las tools va ahí). `-D` añade traza de comando+rc (`dbg`).
- **Hits reales, no líneas:** `count_hits <motor> <fichero>` cuenta hallazgos de verdad (sqlmap =
  `^Parameter:`, dalfox = `[POC]`, nuclei/cors = línea). NUNCA `grep -cvE '^\s*$'` sobre el stdout
  crudo: el banner/errores de sqlmap inflaban el conteo (un run dio "58 hits" con 0 vulns reales).
- **Evidencia en pantalla:** `show_findings [parcial]` pinta el bloque VULNERABILIDADES tras el resumen:
  caja de inyección de sqlmap (`sed -n '/^---$/,/^---$/p'`) + `--dbs` (awk acotado a `available
  databases`, NO cuela `[*] starting`), POCs de dalfox, líneas de nuclei/cors. Si añades un motor con
  evidencia propia, dale su rama en `show_findings` y su caso en `count_hits`.

## Estructura del fichero (wrap anti-corrupción)
TODO el cuerpo de `sbounty.sh` va dentro de un grupo `{ ... }` (`{` tras el shebang, `}` en la ÚLTIMA
línea) para que bash lo lea ENTERO antes de ejecutar → editar el fichero (o un `git pull`) a mitad de
una corrida ya no la corrompe. **No añadir NADA debajo del `}` final**, y al editar mantener el balance
de llaves (`bash -n` lo valida). Es transparente: no es subshell, funciones/traps/`exit` igual.

## Ctrl-C
`trap _cleanup INT TERM` + `_killtree` (TERM→KILL del árbol vía `pgrep -P`). Los motores van por
`run_engine &` con PIDs en `MON_PIDS`; el crawl en `CRAWL_PIDS`. **Si añades procesos en segundo plano,
regístralos** en una de esas listas o Ctrl-C los dejará huérfanos.

## Probar
- Estático: `bash -n sbounty.sh` · `./sbounty.sh -h`.
- Real (solo Kali, objetivo autorizado): `rm -rf results/ && ./sbounty.sh -s testphp.vulnweb.com -D`
  (tiene SQLi+XSS conocidos). Revisa fases/tiempos, hits de los motores, y el `sbounty.log`.
- Correr SIEMPRE la copia de `Tools_custom/SBounty` (la nueva), no una copia vieja en otra carpeta.
