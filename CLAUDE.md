# CLAUDE.md — SBounty

Punto de entrada para quien **mantiene o retoma** SBounty (Claude u otra persona). Fija lo que no se
puede romper y dónde vive cada cosa. El **uso** está en `README.md`; el **cómo tocarlo** en `MANTENIMIENTO.md`.

## Qué es
Escáner de **inyección activa (DAST)** sobre UN objetivo ya elegido. Un solo script bash (`sbounty.sh`):
adquiere un corpus de URLs+parámetros y lo fuzzea con los mejores motores por clase, en paralelo.
Repo propio `shockz-offsec/SBounty`; se **copia** dentro de Shockz-MKE en `Tools_custom/SBounty`.

## Reparto de roles (NO romper)
- **recon-sub** hace el recon: subdominios, liveness, tech, puertos, **subdomain takeover**, nuclei de CVEs.
- **SBounty** NO hace recon ni enumeración de subdominios ni takeover. Toma un objetivo y **fuzzea sus
  parámetros**. No reintroducir nada de recon aquí.

## Flujo (orden real)
```
args -> install (valida/instala toolset) -> por cada objetivo:
  build_headers "" -> waf_detect -> build_corpus -> [si ORIGIN_IP: reescribe corpus a la IP + build_headers "$host"]
  -> run_engines (paralelo) -> summarize
```
- **Adquisición** (`build_corpus`): `crawl_source` (katana/gau/waybackurls/hakrawler en paralelo, con
  `crawl_monitor` y tope `SB_CRAWL_CAP`) → normaliza (uro+scope) → `mine_params` (arjun) →
  `dedup_by_params` (firma = netloc+path+claves de params) → `liveness_filter` (httpx). Graba tiempos
  por fase en `results/<host>/.t.{crawl,prep,liveness}` y el nº en `.n.acquire`.
- **WAF** (`waf_detect` + `origin_discover`): wafw00f + cdncheck; si hay WAF/CDN, `uncover` busca el
  origen por cert, descarta IPs de CDN y **verifica** con `Host:`; si lo verifica, `scan_target`
  reescribe el corpus a esa IP y fuerza `Host:` en todos los motores (sqlmap vía `--host`).
- **Motores** (`run_engines` → `run_engine` wrapper + `monitor_engines`): `broad_scan` (nuclei -dast, o
  `native_fallback` si falta nuclei), `xss_deep` (dalfox: reflejado/DOM), `sqli_deep` (sqlmap: GET +
  forms POST), `stored_xss_scan` (XSS almacenado: planta canary y lo busca crudo), `secrets_scan`
  (secretos en JS/JSON), `cors_scan`. Cada uno escribe `results/<host>/<nombre>.txt` y su tiempo en
  `.t.<nombre>`; si toca el cap deja `.cap.<nombre>` (resumen → "INCONCLUSO", no "clean").
- **Cobertura:** XSS reflejado/DOM (dalfox) + almacenado (stored_xss) + broad (nuclei); SQLi GET+POST
  (sqlmap); LFI/SSTI/SSRF/CRLF/cmdi/open-redirect (nuclei-dast); CORS; secretos (JS). **Modo
  autenticado:** `-H "Cookie:"` fluye a crawl+arjun+httpx+motores. **Ceiling conocido:** no hay motor
  de XSS almacenado que requiera multi-paso complejo ni de superficie que exija auto-login.

## Reglas duras (no romper)
1. **nuclei -dast es el núcleo ancho**; dalfox y sqlmap son PROFUNDIDAD; los checks nativos
   (`native_fallback`) son SOLO fallback cuando falta nuclei. No reconvertir los nativos en primarios.
2. **Config-driven:** `config.ini` enciende/apaga clases (`dast/xss_deep/sqli_deep/cors/param_mining/
   waf_check/blind_xss_url`); los ajustes finos van por env `SB_*` (ver README). No hardcodear.
3. **Degradación con gracia:** toda tool externa se comprueba con `have()`; si falta, se salta con aviso,
   nunca peta.
4. **Sin secretos en el repo.** No se guardan claves API: `gau` usa su `~/.gau.toml`, `uncover` su config.
   No reintroducir `sources.ini` ni claves committeadas.
5. **Eficiencia = recortar el corpus, no saltar params:** dedup por firma + param-filter (dalfox/sqlmap
   solo URLs con `?x=`) + liveness + CORS por ruta única. sqlmap SIN `--smart` a propósito (corpus ya recortado).
6. **Globals por objetivo:** `host host_re results_path urls_output_path seed_url ORIGIN_IP` y los arrays
   de cabecera (`curl_hdr httpx_hdr sqlmap_hdr nuclei_hdr dalfox_hdr sqlmap_host`) se reconstruyen por
   objetivo con `build_headers` (para que `-l` no acumule).
7. **Ctrl-C limpio:** `trap _cleanup INT TERM` + `_killtree` matan el árbol (dalfox/nuclei/sqlmap/crawl).
   No lanzar motores fuera de `run_engines`/`run_engine` sin registrarlos en `MON_PIDS`/`CRAWL_PIDS`.

## Verificar sin objetivo (Windows/Git Bash o Kali)
- `bash -n sbounty.sh` (sintaxis).
- `./sbounty.sh -h` (ayuda; sale antes de `install`).
- Reproducir lógica pura: `is_url`, `extract_host`, `dedup_by_params`, el filtro de alcance, el
  param-filter (`grep -E '\?[^#[:space:]]*='`), la reescritura host→IP (`sed -E 's#^(https?://)[^/]+#\1IP#'`).
- La detección/explotación reales SOLO se validan con una **corrida en Kali** contra objetivo autorizado.

## Entradas (4 objetivos EXCLUSIVOS)
`-s host` (host/subdominio: crawl del host ENTERO + flujo completo) · `-url URL` (URL concreta:
ENFOCADO, esa URL + sus llamadas directas; `CRAWL_FOCUS=1` omite gau/wayback host-wide y arjun, crawl
depth 1) · `-l` (fichero de host/URLs mezclados, con tiempos) · `-f` (URLs crudas: sanea + dedup +
liveness, sin crawl/mining). Opciones: `-H` cabecera (fluye a crawl/arjun/httpx/motores) · `-p`
secuencial · `-D` debug · `-no-caps` (sin topes de tiempo/recuento). **`-url` y `-no-caps` se filtran
ANTES de getopt** (multi-carácter). **`-s` ya NO es para URL enfocada: eso es `-url`.**

## Integración con Shockz-MKE
SBounty se **copia** a `$HOME/SBounty` al instalar (no se clona: repo privado). Sus tools (nuclei,
dalfox, sqlmap, katana, gau, waybackurls, hakrawler, httpx, qsreplace, gf, arjun, uro, wafw00f,
cdncheck, uncover, dnsx) las provee Shockz-MKE; si falta alguna, el propio `install()` de SBounty la
pone. **Añadir una tool nueva = tocar el `install()` de aquí Y (opcional) `arsenal/*.sh`+`registry` de
Shockz-MKE.** Ver `MANTENIMIENTO.md`.
