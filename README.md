<div align="center">
  <h1>SBounty</h1>
  <p><i>Active-injection (DAST) scanner for a single authorized target.</i></p>
</div>

SBounty takes a target you already chose, **acquires a high-quality corpus** (crawl + historical URLs
+ hidden-parameter mining, deduplicated by parameter signature and filtered to live endpoints), and
feeds it to **best-in-class injection engines running in parallel**. It detects a WAF/CDN up front and,
if it finds the real origin behind it, **attacks the origin directly** to bypass the WAF.

> **Role split.** [`recon-sub`](../Recon-Sub) owns surface discovery (subdomains, liveness, tech,
> ports, subdomain takeover, known-CVE nuclei). SBounty takes one chosen target and **fuzzes its
> parameters**. It does **not** do subdomain enumeration or takeover — that is recon-sub's job.

> [!IMPORTANT]
> For targets you are **authorized** to test only (bug bounty scope / your own assets). The scan sends
> real attack traffic.

---

## How it works

```
target ─▶ probe ─▶ WAF/CDN check ─▶ acquire corpus ─▶ engines (parallel) ─▶ summary
        alive?       │ (if WAF)          │ crawl+history+arjun            │ nuclei-dast
        scheme?      └ find+verify       │ dedup+liveness                 │ dalfox
                       origin IP ────────┘ (rewrite to origin, Host hdr)  │ sqlmap  [+ cors]
```

| Stage | What it does | Tools |
|---|---|---|
| **WAF / CDN** | Fingerprints perimeter protection; if present, finds+verifies the **real origin IP** and rewrites the scan to hit it (bypassing the WAF) | `wafw00f` `cdncheck` `uncover` `dnsx` |
| **Acquire** | Crawl the host/route + historical URLs + mine hidden params; **sanitize** crawl artifacts; dedup by parameter signature (default-port + value normalized); keep only live endpoints | `katana` `gau` `waybackurls` `hakrawler` `arjun` `httpx` `uro` |
| **Broad core** | One fast, concurrent DAST pass: XSS/SQLi/SSTI/LFI/open-redirect/SSRF/CRLF/cmdi across **query, path, headers, cookie**; automatic **out-of-band** (interactsh) | `nuclei -dast` |
| **XSS depth** | Reflected/**DOM**, context-aware, optional **blind** | `dalfox` |
| **SQLi depth** | GET exploitation + **POST/forms** — tests the `<form>`s on the already-crawled dynamic pages (login auth-bypass, register, search), no wasteful re-crawl; tuned (`--flush-session`, tamper chain, balanced level/risk, threaded) | `sqlmap` |
| **Stored XSS** | Plants a unique canary in params + forms, re-fetches and flags the **RAW (unescaped)** breakout — persistence = executable (submits data) | native + `qsreplace` |
| **Secrets** | High-confidence secrets (AWS/Google/GitHub/GitLab/Slack/Stripe/SendGrid keys, private keys) in **JS/JSON/map** bodies | native |
| **CORS** (opt) | Arbitrary/null origin, suffix bypass, credentials reflection (one probe per unique path) | native |

**Request positions covered:** query params (all engines) · **Host / Referer / User-Agent / Cookie**
(nuclei `-dast`) · **URL path** (nuclei) · **POST body/forms** (sqlmap `--forms`, stored-XSS). Engines run
**in parallel** with conservative rate limits (`-p` for sequential). Every tool is optional: a missing
one is skipped gracefully; if `nuclei` is absent a lightweight native LFI/SSTI/open-redirect check fills in.

**Authenticated scanning:** pass a session cookie with `-H "Cookie: ..."` and it flows through the whole
pipeline — the **active crawl** (katana/hakrawler), param mining (arjun), liveness and every engine — so
the surface behind a login is discovered and tested, not just the anonymous one.

---

## Key features

- **WAF detection + origin bypass.** Checks for a WAF/CDN at the start (red warning). If found, it tries
  to discover the real origin IP (via `uncover`: Shodan/Censys/Fofa by certificate), **verifies** it
  serves your site with a `Host:` header, and **rewrites the whole corpus to that IP** while forcing
  `Host: <domain>` on every engine — so the scan hits the origin and skips the WAF.
- **Smart & efficient** (fewer, sharper requests): corpus sanitation (drops concatenated/whitespace
  crawl+wayback artifacts), parameter-signature dedup with **default-port normalization** (no
  `host:80` vs `host` twins) and **value canonicalization** (archived payloads in the URL collapse to
  a clean `=1`, so sqlmap/dalfox get clean inputs), **param-only + static-file-excluded feeding for
  dalfox/sqlmap** (a `.txt`/`.css`/`.jpg?param` never processes params, so it is dropped from the
  expensive engines — nuclei still sees the full corpus), CORS probed once per unique path, dead
  endpoints dropped (`httpx` liveness), optional corpus/time caps.
- **No wasted runs / no phantom results.** A **light up-front probe** confirms the target resolves and
  responds, and picks the live **scheme** (http vs https) so an http-only host is not scanned over a
  dead https (and `wafw00f` does not stall on it); a dead/mistyped target is skipped immediately. Later,
  a responsiveness gate re-probes the (post-bypass) target before the engines: if it refuses every
  connection, the engines are **skipped** instead of reporting fake "clean"/hits. Finding counts are
  real evidence (sqlmap injection points, dalfox PoCs), never raw output lines. An engine that hits its
  time cap is labelled **PARCIAL / inconcluso**, never "clean" — a capped engine did not finish, so its
  "no findings" is not a verdict.
- **Full observability** (never looks hung): per-phase progress markers, live crawl/engine heartbeats,
  per-phase + per-engine + total timing in the summary, a run log, and `-D` debug (command + rc tracing).
- **Clean Ctrl-C:** stops every engine and its tool children (dalfox/nuclei/sqlmap) and exits.
- **Self-provisioning:** validates the toolset and installs what is missing (Go tools land in the PATH).

---

## Install

```bash
git clone https://github.com/shockz-offsec/SBounty.git
cd SBounty && chmod +x sbounty.sh
./sbounty.sh -h
```

On first run SBounty **validates the toolset in your PATH and installs whatever is missing** (Go tools
via `go install` to the PATH; `arjun`/`uro`/`wafw00f` via `pipx`; `sqlmap` via apt; nuclei templates
fetched once). No root required; `sudo` is used only where a package install needs it.

**Toolset:** `nuclei` · `dalfox` · `sqlmap` · `katana` · `gau` · `waybackurls` · `hakrawler` · `httpx`
· `qsreplace` · `gf` · `arjun` · `uro` · `wafw00f` · `cdncheck` · `uncover` · `dnsx`.
*(Blind SSRF/XSS use nuclei's own built-in interactsh — no extra OOB binary.)*

---

## Usage

```
Usage: ./sbounty.sh [-s host | -url URL | -l file | -f urls_file] [-H "Header: value"] [-p] [-D] [-no-caps] [-h]

TARGET (choose exactly one)
  -s host       A host/subdomain (tesla.com): crawls the WHOLE host + full flow
  -url URL      A concrete URL (https://x.com/app/login): that URL + its DIRECT calls only (shallow
                crawl from the URL, no host-wide gau/wayback, no arjun) — focused, not the whole host
  -l file       File of targets, one per line: hosts and/or URLs mixed (per-target + batch total time)
  -f urls_file  File of raw URLs to test (no crawl/mining; still sanitized, deduped by parameter
                signature, and liveness-checked so dead/duplicate URLs are dropped before scanning)

OPTIONS
  -H "N: v"     Custom HTTP header sent on probes (e.g. a session cookie)
  -p            Run engines sequentially (default: parallel, rate-limited)
  -D            Debug: trace each tool's command + rc (and send stderr to the log)
  -no-caps      Remove ALL time/count caps (crawl, arjun, per-engine, corpus) — engines run to
                completion. Per-request timeouts stay (no infinite hangs). For a no-rush deep scan.
  -h            Help
```

```bash
./sbounty.sh -s tesla.com                               # whole host
./sbounty.sh -s https://shop.tesla.com/app/login        # one route (its calls)
./sbounty.sh -l targets.txt -H "Cookie: session=abc"    # list, with a session header
./sbounty.sh -f urls.txt -D                             # raw URLs, with debug
```

---

## Configuration (`config.ini`)

A class set to `false` simply does not run; a missing tool is skipped.

```ini
dast=true         # nuclei -dast broad core (recommended; covers most classes + automatic OOB)
xss_deep=true     # dalfox (XSS depth: reflected/DOM)
sqli_deep=true    # sqlmap (SQLi depth + POST/forms on crawled pages)
stored_xss=true   # stored/persistent XSS (plants a canary, re-checks; NOTE: submits data)
secrets=true      # high-confidence secrets in JS/JSON/map (read-only)
cors=true         # improved CORS
param_mining=true # arjun (hidden params)
waf_check=true    # WAF/CDN detection + origin bypass at the start of each host
blind_xss_url=""  # optional dalfox blind-XSS callback (nuclei runs its own OOB regardless)
```

**No API keys required** for the core. URL discovery already covers OTX AlienVault and urlscan.io via
`gau`; *origin discovery* (behind a WAF) uses `uncover`, which needs Shodan/Censys/Fofa keys — without
them, WAF detection still works and the scan continues normally (through the WAF).

### Tuning (environment variables)

| Variable | Default | Effect |
|---|---|---|
| `SB_CRAWL_CAP` | `180` | Max seconds for the crawl phase (katana/hakrawler/gau/wayback) |
| `SB_ARJUN_CAP` | `120` | Max seconds for arjun param mining (bounds the prep phase on slow targets) |
| `SB_PROBE_CTO` | `4` | Probe connect-timeout (fail fast on a closed port before falling back to the other scheme) |
| `SB_ENGINE_CAP` | `600` | Max seconds **per engine**; kills it and keeps partial results. For sqlmap this is a **shared budget** across its GET + forms passes (total ≤ cap, not 2×). |
| `SB_MAX_URLS` | `0` (off) | Cap the corpus to N URLs after dedup (huge targets) |
| `SB_CORS_MAX` | `200` | Max unique paths probed for CORS |
| `SB_CORS_TIMEOUT` | `8` | Per-request max seconds for CORS probes (also capped overall by `SB_ENGINE_CAP`) |
| `SB_SQLI_TECH` | `BEU` | sqlmap techniques (fast: boolean/error/union). Full incl. time-based: `BEUSTQ` |
| `SB_SQLI_LEVEL` / `SB_SQLI_RISK` | adaptive | sqlmap depth, **auto by target latency**: `3`/`2` if fast, `2`/`1` if slow (≥800 ms/req) so a slow target gets a *complete* shallow scan instead of a capped deep one. Set to force. |
| `SB_SQLI_TAMPER` | `between,randomcase,space2comment` | sqlmap tamper chain |
| `SB_SQLI_THREADS` | `10` | sqlmap threads |
| `SB_SQLI_TIMEOUT` / `SB_SQLI_RETRIES` | adaptive / `1` | sqlmap per-request timeout (**auto from measured latency**, 6–30 s) / retries (fail-fast on dead hosts). Set to force. |
| `SB_SQLI_FORMS` | `1` | run the sqlmap forms/POST pass (`0` to skip — it is a second full pass, the slowest) |
| `SB_DALFOX_WORKER` | `100` | dalfox concurrency (runs with `--skip-mining-all --skip-bav`) |
| `SB_NUCLEI_RL` / `SB_NUCLEI_C` | `60` / `25` | nuclei rate limit / concurrency |
| `SB_SX_MAX` | `60` | stored-XSS: max URLs/pages to plant+harvest |
| `SB_SECRETS_MAX` | `80` | secrets: max JS/JSON files to fetch |

---

## Output

```
results/<host>/
  urls.txt         the final test corpus
  nuclei-dast.txt dalfox.txt sqlmap.txt stored-xss.txt secrets.txt cors.txt   findings per engine
  sbounty.log      timestamped run log (commands/errors; full trace with -D)
```

The end-of-run **summary** shows per-phase times (WAF/CDN · crawl · prep · liveness), corpus size,
per-engine hits + time, and the total; `-l` adds a per-target + batch-total time table. Hit counts are
**real findings**, not raw output lines (sqlmap = vulnerable parameters, dalfox = PoCs, nuclei/cors = one
per line) — a tool's banner/errors never inflate the count.

Below the summary a **VULNERABILIDADES** block prints the actual evidence on screen:
- **SQLi** — sqlmap's native injection box (`Parameter` / `Type` / `Title` / `Payload`), the target
  **fingerprint** (web-server OS / web-app technology / back-end DBMS — shown even on a partial result),
  a **ready reproduction command per finding** (`sqlmap -u "<url>" -p <param> --batch --dbs`, or
  `--forms` for a POST/login finding), **plus the `--dbs` database list** when exploitation finishes.
- **XSS** — each dalfox PoC (the injected URL + payload).
- **nuclei / CORS** — each finding line.

A Ctrl-C prints the same block with whatever was confirmed up to the interruption (`· parcial`).

---

## Disclaimer

For legal use only, on systems you own or are explicitly authorized to test. Any other use is illegal
and at your own risk. Licensed under **GPL-3.0**.
