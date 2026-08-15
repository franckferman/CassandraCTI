<div id="top" align="center">

[![CI][ci-shield]](https://github.com/franckferman/CassandraCTI/actions/workflows/ci.yml)
[![Contributors][contributors-shield]](https://github.com/franckferman/CassandraCTI/graphs/contributors)
[![Forks][forks-shield]](https://github.com/franckferman/CassandraCTI/network/members)
[![Stars][stars-shield]](https://github.com/franckferman/CassandraCTI/stargazers)
[![Issues][issues-shield]](https://github.com/franckferman/CassandraCTI/issues)
[![License][license-shield]](https://github.com/franckferman/CassandraCTI/blob/stable/LICENSE)

<a href="https://github.com/franckferman/CassandraCTI">
  <img src="https://raw.githubusercontent.com/franckferman/CassandraCTI/stable/docs/github/graphical_resources/Logo-CassandraCTI.png" alt="CassandraCTI" width="auto" height="auto">
</a>

<h2 align="center">CassandraCTI</h2>

<p align="center">
  <strong>Modular Cyber Threat Intelligence Aggregator.</strong><br>
  Collect threat intel from RSS feeds, ransomware trackers, malicious domains, CISA KEV & abuse.ch —<br>
  then route it to Teams, Discord, Telegram, Email, or a live web dashboard.
</p>

<p align="center">
  <a href="#about">About</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="examples/">Examples</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#sources">Sources</a> ·
  <a href="#transports">Transports</a> ·
  <a href="#briefings">Briefings</a> ·
  <a href="#cli-reference">CLI Reference</a> ·
  <a href="#docker">Docker</a> ·
  <a href="#templates">Templates</a> ·
  <a href="#security--tls">Security</a>
</p>

</div>

---

## About

**CassandraCTI** — named after the Trojan prophetess condemned to warn of future dangers without being believed — is a modular, asynchronous CTI pipeline that does the opposite: it makes sure your threat intel actually reaches the people who need it.

Originally built as a private internal tool, it is now open-source, designed to be composable and adaptable to any security team's workflow.

**What it does:**

- Polls threat intel sources on a schedule (RSS feeds, ransomware trackers, malicious domain lists, CISA KEV vulnerabilities, abuse.ch IOCs)
- Deduplicates events using SHA1-based fingerprinting with a local SQLite store
- Routes events through configurable rules (by source, tag, or regex) — every matching route fires
- Renders messages from Jinja2 templates and pushes them to Teams, Discord, Telegram, or Email (SMTP)
- Verifies TLS on every fetch and caps response sizes by default
- Exposes Prometheus metrics for observability

---

## Features

| Capability | Details |
|---|---|
| **Modular sources** | RSS/Atom feeds · the **ransomware.live** family (victims — free; plus Cyber Press, SEC 8-K & Stats on its PRO tier) · Red Flag Domains · **CISA KEV** vulnerabilities · **abuse.ch** IOCs (Feodo/ThreatFox/URLhaus/MalwareBazaar) |
| **Live web dashboard** | Dependency-free SOC command center — real-time SSE feed, per-category tabs, filters, export, optional AI briefs |
| **LLM briefings** | Optional periodic recap per category — prioritised, with links, sent after the alerts (local Ollama or a cloud key) |
| **Resilient ransomware feed** | Multi-backend fallback chain: API PRO → API v2 → legacy `posts.json` |
| **Modular transports** | Microsoft Teams, Discord, Telegram, Email (SMTP), Signal, live web dashboard — extensible |
| **Smart deduplication** | SHA1 event fingerprint + SQLite delivery tracking |
| **Flexible routing** | Match by source prefix, tag, or regex — every matching route fires |
| **Jinja2 templates** | Full control over message formatting |
| **Batching & throttling** | Group events, respect rate limits |
| **Env var substitution** | `${VAR_NAME}` in YAML — no secrets in files |
| **TLS-verified fetches** | Certificates checked by default, response bodies size-capped |
| **Dry-run mode** | Validate pipelines without sending anything |
| **Backfill** | Replay past events to a transport |
| **Prometheus metrics** | `cassandra_cti_events_sent`, `cassandra_cti_fetch_total` (binds `127.0.0.1` by default) |
| **Docker-ready** | Minimal image, config via mounted volume |

---

## Getting Started

### Prerequisites

- Python 3.10 or later
- pip

### Installation

```bash
git clone https://github.com/franckferman/CassandraCTI.git
cd CassandraCTI
pip install -r requirements.txt
```

Or install as a package (provides the `cassandra` CLI entry point):

```bash
pip install .
```

### Initialization

Create default configuration files (`config.yaml` + `connectors.yaml`) in the standard config directory:

- **Linux / macOS:** `~/.config/cassandra-cti/`
- **Windows:** `%APPDATA%\cassandra-cti\`

```bash
python -m cassandra_cti.cli init
```

This creates:

```
~/.config/cassandra-cti/
├── config.yaml         ← sources, routes, filters, store, logging, metrics
├── connectors.yaml     ← transport definitions (Teams / Discord / Telegram / Email / Web)
└── templates/          ← custom Jinja2 templates (optional)
```

### Fastest start

One command scaffolds the config files (if missing) and opens the live dashboard — no editing required to see it working:

```bash
cassandra quickstart              # sets up config + opens http://127.0.0.1:8080
cassandra quickstart --no-web     # just create the config files
```

The shipped `config.example.yaml` already enables RSS, ransomware.live, Red Flag Domains, CISA KEV and abuse.ch, so the dashboard fills up on the first pass. To also push alerts to Teams/Discord/Telegram/Email, wire a connector and a route as below.

> **Prefer a worked example?** The [`examples/`](examples/) directory has ready-to-run `config.yaml` + `connectors.yaml` pairs — one per scenario (Discord quickstart, multi-channel Teams SOC, Telegram channel, email digest, vulnerability/IOC watch, dashboard-only). Copy the closest folder, set its env vars, and run. See [`examples/README.md`](examples/README.md).

### Quick Start

**1. Add a connector:**

```bash
# Microsoft Teams / Discord (incoming webhook)
cassandra add-connector --id "teams-soc" --type teams   --webhook-url "https://your-tenant.webhook.office.com/..."
cassandra add-connector --id "discord"   --type discord --webhook-url "https://discord.com/api/webhooks/..."

# Telegram (bot token + chat id)
cassandra add-connector --id "tg-soc" --type telegram --bot-token "$TELEGRAM_BOT_TOKEN" --chat-id "@my_channel"

# Email (SMTP)
cassandra add-connector --id "mail" --type smtp --host smtp.gmail.com --from-addr you@example.com --to-addrs soc@example.com
```

**2. Add threat intel sources:**

```bash
# RSS feed
cassandra add-source rss \
  --name "CERT-FR Alertes" \
  --url "https://cert.ssi.gouv.fr/alerte/feed/" \
  --tags "cert,fr"

cassandra add-source ransomware_live      # ransomware tracker
cassandra add-source redflag              # malicious domain list
cassandra add-source kev                  # CISA Known Exploited Vulnerabilities
cassandra add-source abusech --feeds "feodo,urlhaus"   # abuse.ch IOCs (add --api-key for threatfox/malwarebazaar)
```

**3. Validate your setup:**

```bash
cassandra doctor config
cassandra doctor connector --id teams-soc
```

**4. Run:**

```bash
# One-shot
cassandra run

# Loop every 5 minutes
cassandra run --loop --interval 300

# Dry run (no messages sent)
cassandra run --dry-run
```

---

## Configuration

CassandraCTI uses two YAML files:

| File | Purpose |
|---|---|
| `config.yaml` | Sources, routes, filters, store, logging, metrics |
| `connectors.yaml` | Transport definitions (webhook URLs, formatting) |

### config.yaml

```yaml
schema_version: 1

scheduler:
  mode: oneshot          # "oneshot" or "loop"
  interval_seconds: 300

sources:
  rss:
    enabled: true
    feeds:
      - name: "CERT-FR Alertes"
        url: "https://cert.ssi.gouv.fr/alerte/feed/"
        tags: ["cert", "fr"]
      - name: "BleepingComputer"
        url: "https://www.bleepingcomputer.com/feed/"
        tags: ["news"]

  ransomware_live:
    enabled: true
    lookback_days: 30
    api_key: ${RANSOMWARE_API_KEY}   # optional — enables API PRO; else v2 → posts.json
    url: "https://data.ransomware.live/posts.json"   # optional legacy dump override

  # --- PRO-only feeds (require api_key; skipped with a warning if absent) ---
  ransomware_press:                  # Cyber-press news (/press/recent)
    enabled: false
    api_key: ${RANSOMWARE_API_KEY}
    # country: US                    # optional ISO-2 filter

  ransomware_8k:                     # SEC 8-K cyber-incident filings (/8k)
    enabled: false
    api_key: ${RANSOMWARE_API_KEY}

  ransomware_stats:                  # One daily tracker digest (/stats)
    enabled: false
    api_key: ${RANSOMWARE_API_KEY}

  red_flag_domains:
    enabled: true
    base_url: "https://dl.red.flag.domains/daily/"  # optional

filters:
  title_regex_deny:                  # Drop matching events
    - "(?i)sponsored"
    - "(?i)webinar"
  title_regex_allow: []              # If non-empty, ONLY allow these
  max_items_per_source: 50           # Cap per source per run

transports:
  use: ["teams-soc", "discord-alert"]  # Reference connectors by ID

routes:
  - name: "ransomware"
    include_sources: ["ransomware.live"]
    transports: ["teams-soc"]
    template: "templates/ransomware_card.j2"

  - name: "cert-alerts"
    include_tags: ["cert"]
    transports: ["teams-soc", "discord-alert"]

  - name: "vendor-news"
    include_tags: ["vendor", "microsoft"]
    transports: ["teams-soc"]

  - name: "catch-all"
    include_sources: ["rss:"]          # Matches any RSS source
    transports: ["discord-alert"]

store:
  sqlite_path: ".cassandra_cti.db"
  seen_ttl_days: 90

logging:
  level: "INFO"                        # DEBUG | INFO | WARNING | ERROR

metrics:
  enabled: true
  host: "127.0.0.1"                    # localhost by default; set 0.0.0.0 to expose
  port: 9108
```

> The bundled `config.example.yaml` ships 30+ RSS feeds, the multi-backend `ransomware_live` source, and its three **ransomware.live PRO** feeds (`ransomware_press`, `ransomware_8k`, `ransomware_stats`) pre-wired but disabled — enable them and supply a `RANSOMWARE_API_KEY` to use them.

### connectors.yaml

Connectors are defined separately from `config.yaml` so they can be secrets-managed independently. Environment variables are substituted using `${VAR_NAME}` syntax before schema validation.

```yaml
connectors:
  - id: "teams-soc"
    type: "teams"
    params:
      webhook_url: ${MSTEAMS_WEBHOOK_SOC}
      theme_color: "0078D7"        # Blue border
      emojis: true
      throttle_ms: 1000
      batching:
        enabled: true
        max_items: 5

  - id: "discord-alert"
    type: "discord"
    params:
      webhook_url: ${DISCORD_WEBHOOK_URL}
      username: "CassandraCTI"
      avatar_url: "https://..."
      emojis: true
      throttle_ms: 500
```

The bundled `connectors.example.yaml` includes ready-to-edit `teams`, `discord`, `telegram`, and `smtp` connectors — see the [Transports](#transports) section for the full parameter set of each.

---

## Sources

### RSS

Fetches and parses RSS/Atom feeds. Each feed is identified as `rss:{name}`.

```yaml
sources:
  rss:
    enabled: true
    feeds:
      - name: "Krebs on Security"
        url: "https://krebsonsecurity.com/feed/"
        tags: ["news"]
```

**30+ pre-configured feeds are available in `config.example.yaml`**, organized by category:

| Category | Examples |
|---|---|
| CERTs | CERT-FR Alertes, CERT-FR Avis |
| Microsoft | Microsoft Security, Sentinel Blog, MSRC |
| Vendors | Cisco, Trend Micro, Proofpoint, CrowdStrike, Kaspersky, Recorded Future, Google TAG, Palo Alto |
| News | Krebs on Security, BleepingComputer, Dark Reading, Hacker News, Threatpost, SANS ISC |
| Technical | Adam Chester (XPN), Modexp, James Forshaw |

---

### Ransomware Live

Tracks ransomware group activity from [ransomware.live](https://ransomware.live). Source ID: `ransomware.live`.

This source is **resilient by design** — it walks a multi-backend fallback chain and the first backend to return events wins. Any failure (network, auth, empty payload) falls through to the next:

| Order | Backend | Endpoint | Auth |
|---|---|---|---|
| 1 | **API PRO** | `api-pro.ransomware.live/victims/recent` | `X-API-KEY` header — used only when `api_key` is set |
| 2 | **API v2** | `api.ransomware.live/v2/recentvictims` | none (free) |
| 3 | **posts.json** | `data.ransomware.live/posts.json` | none (legacy dump) |

```yaml
sources:
  ransomware_live:
    enabled: true
    lookback_days: 30
    api_key: ${RANSOMWARE_API_KEY}   # optional; enables the API PRO backend
```

| Config key | Default | Description |
|---|---|---|
| `enabled` | `false` | Turn the source on |
| `lookback_days` | `30` | Drop events older than N days (`0` = no limit) |
| `api_key` | — | Optional PRO key; without it the chain starts at API v2 |

Regardless of the backend that served the data, every event is normalized to the same canonical `raw` fields so templates behave identically:

- **Title:** `{Victim} by {Group}`
- **Tags:** `["ransomware"]`
- **Raw fields:** `victim`, `group_name`, `country`, `country_display`, `country_flag`, `activity`, `website`, `discovered`, `attackdate`, `description`, `infostealer`, `infostealer_summary`, `infostealer_stealers`, `data_size`, `leak_url`, `backend`
- **Country enrichment:** `country_display` = `"France (FR)"` and `country_flag` = 🇫🇷, derived from the ISO-2 `country` code via `cassandra_cti/countries.py` (full ISO-3166 name map + computed regional-indicator flag).
- **Infostealer enrichment:** ransomware.live's `infostealer` object is summarized into `infostealer_summary` (e.g. `"886 users, 32 employees, 251 third-parties"` — empty when all counts are zero, so no false positive) and `infostealer_stealers` (top stealer families from `infostealer_stats`, e.g. `"Lumma (137), RedLine (132)"`).
- **Leak link:** `leak_url` is the group's onion leak site when the backend provides it; the cards link both it and the stable ransomware.live permalink.
- **Emoji:** Auto-detects victim country flag (🇫🇷 🇬🇧 🇩🇪 🇺🇸 ...)

The `backend` field records which source (`pro` / `v2` / `posts`) produced the event. The stable ransomware.live permalink is used as the event URL so deduplication identity does not shift when a fallback occurs.

> **Same provider, more feeds.** ransomware.live's **PRO tier** also powers the three feeds below — Cyber Press, SEC 8-K and Tracker Stats — all from `api-pro.ransomware.live` and authenticated with the same `RANSOMWARE_API_KEY`. (Red Flag Domains, further down, is an unrelated provider — malicious domains, not ransomware.)

---

### Ransomware Press (PRO)

Recent cyber-press news from ransomware.live PRO (`/press/recent`). Source ID: `ransomware.press`.

> **PRO-only:** there is no free fallback. Without a valid `api_key` the source degrades gracefully — it logs a warning and yields nothing (other sources are unaffected). `cassandra doctor config` warns upfront when a PRO source is enabled without a key.

```yaml
sources:
  ransomware_press:
    enabled: true
    api_key: ${RANSOMWARE_API_KEY}
    # country: US        # optional ISO-2 filter
```

- **Title:** victim name
- **URL:** none — `/press/recent` items carry no article link (only a `domain`), so dedup is per `(source, victim)`
- **Tags:** `["press", "news"]`
- **Raw fields:** `date`, `victim`, `domain`, `country`, `summary`

---

### Ransomware 8-K (PRO)

SEC 8-K cyber-incident filings from US public companies (`/8k`). Source ID: `ransomware.8k`.

> **PRO-only** (same graceful-skip behaviour as above).

```yaml
sources:
  ransomware_8k:
    enabled: true
    api_key: ${RANSOMWARE_API_KEY}
```

- **Title:** `{Company} ({Ticker})`
- **URL:** the real SEC/EDGAR filing link (also the dedup key)
- **Summary:** filing form + disclosed items (`Item 1.05 Material Cybersecurity Incident`, `Item 8.01 Other Events`)
- **Tags:** `["sec", "8k", "disclosure"]`
- **Raw fields:** `company`, `stockticker`, `file_date`, `link`, `item105`, `item801` (among others)

---

### Ransomware Stats (PRO)

One daily digest summarising the ransomware.live tracker (`/stats`). Source ID: `ransomware.stats`.

> **PRO-only** (same graceful-skip behaviour as above).

```yaml
sources:
  ransomware_stats:
    enabled: true
    api_key: ${RANSOMWARE_API_KEY}
```

- **Title:** `Ransomware tracker - {YYYY-MM-DD}`
- **Summary:** `Victims tracked: … | Groups: … | Press articles: …`
- **Tags:** `["stats", "digest"]`
- **Raw fields:** `stats` (`victims` / `groups` / `press` counts), `last_update`, `day`
- Emits exactly **one event per day** (dedup identity includes the day).

---

### Red Flag Domains

Fetches daily malicious domain lists from [red.flag.domains](https://red.flag.domains).

```yaml
sources:
  red_flag_domains:
    enabled: true
```

Each run generates one event with:
- **Title:** `Red Flag Domains – {YYYY-MM-DD}`
- **Summary:** Full domain list (newline-separated)
- **Tags:** `["domains"]`
- **Raw fields:** `file`, `count`, `date`

### CISA KEV

Fetches the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog — CVEs actively exploited in the wild. **A single public JSON feed, no API key.** Source ID: `cisa.kev`.

```yaml
sources:
  cisa_kev:
    enabled: true
    lookback_days: 365   # keep CVEs added within this window
    max_items: 80
```

Each CVE becomes an event with `raw` fields `cve`, `vendor`, `product`, `due_date`, `ransomware_use`, `required_action`, `date_added`. Tags: `["vulnerability", "kev"]` (plus `"ransomware"` when the CVE is used in ransomware campaigns). The dashboard's *Vulnerabilities* tab filters by vendor and the ransomware-linked flag.

### abuse.ch IOCs

One source (`abuse.ch`) that aggregates several [abuse.ch](https://abuse.ch) feeds into the *IOCs* tab:

| Feed | IOC type | API key |
|---|---|---|
| `feodo` | botnet C2 IPs | none (public) |
| `urlhaus` | malware distribution URLs | none (public CSV) |
| `threatfox` | IP / domain / URL / hash + malware family | **free Auth-Key** |
| `malwarebazaar` | sample hashes (SHA-256) + family | **free Auth-Key** |

```yaml
sources:
  abusech:
    enabled: true
    feeds: ["feodo", "threatfox", "urlhaus", "malwarebazaar"]
    api_key: ${ABUSECH_API_KEY}   # optional; unlocks threatfox + malwarebazaar
    max_items: 60
```

A **single free Auth-Key** ([auth.abuse.ch](https://auth.abuse.ch)) unlocks ThreatFox and MalwareBazaar; without it, only the public feeds (Feodo, URLhaus) run. Set it via the `ABUSECH_API_KEY` environment variable. Each event carries `raw` fields `ioc`, `ioc_type`, `malware`, `status`, `feed`; tags start with `["ioc", …]`.

---

## Transports

### Microsoft Teams

Sends Adaptive Cards (MessageCard format) to an incoming webhook.

```yaml
connectors:
  - id: "teams-cert"
    type: "teams"
    params:
      webhook_url: ${MSTEAMS_WEBHOOK_CERT}
      theme_color: "0078D7"      # Hex without #
      emojis: true
      throttle_ms: 1000          # Minimum: 1000ms
      batching:
        enabled: false
        max_items: 10
```

**Theme color suggestions:**

| Color | Hex | Use Case |
|---|---|---|
| Blue | `0078D7` | General / Microsoft |
| Purple | `8E44AD` | Vendor news |
| Orange | `D83B01` | General news |
| Green | `107C10` | Ransomware (green for money) |
| Red | `C0392B` | Malicious domains |

---

### Discord

Sends rich Embeds to a Discord webhook.

```yaml
connectors:
  - id: "discord-alert"
    type: "discord"
    params:
      webhook_url: ${DISCORD_WEBHOOK_URL}
      username: "CassandraCTI"
      avatar_url: "https://..."
      emojis: true
      throttle_ms: 500
      batching:
        enabled: true
        max_items: 5
```

**Limits enforced automatically:**
- Title: 256 characters (truncated)
- Description: 4000 characters (truncated with notice)

---

### Telegram

Sends messages to a chat/channel via the Bot API (`sendMessage`). Unlike Teams/Discord there is **no incoming-webhook URL** — you need a **bot token** and a **chat_id**.

```yaml
connectors:
  - id: "telegram-soc"
    type: "telegram"
    params:
      bot_token: ${TELEGRAM_BOT_TOKEN}
      chat_id: ${TELEGRAM_CHAT_ID}     # "@publicchannel" or -100123456789 (private)
      parse_mode: "HTML"               # default; auto-falls back to plain text on parse errors
      throttle_ms: 1000
      emojis: true
```

**Setup:**
1. Create a bot with [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token.
2. Add the bot to your channel/group **as an administrator**.
3. Get the `chat_id`: use the public `@channelusername`, or send any message to the chat and read `result[].message.chat.id` from `https://api.telegram.org/bot<TOKEN>/getUpdates`.
4. Test it live: `cassandra doctor connector --id telegram-soc`.

Messages render as HTML (4096-char limit, auto-truncated). Assign `templates/telegram_default.j2` to Telegram routes — Discord/Teams Markdown templates won't render as rich text on Telegram. For `ransomware.live` routes use `templates/telegram_ransomware.j2`, a structured HTML card that reads the raw fields (group / country / sector / victim / date) and skips empty ones.

---

### Email (SMTP)

Sends HTML emails through any SMTP server (Gmail, SendGrid, corporate relay…). Uses the standard library — no extra dependency.

```yaml
connectors:
  - id: "email-soc"
    type: "smtp"
    params:
      host: ${SMTP_HOST}            # e.g. smtp.gmail.com
      port: 587
      security: "starttls"          # starttls (587) | ssl (465) | none (25)
      username: ${SMTP_USERNAME}
      password: ${SMTP_PASSWORD}    # app password / API key
      from_addr: ${SMTP_FROM}       # defaults to username
      to_addrs: ${SMTP_TO}          # "a@x.com,b@y.com" or a YAML list
      subject_prefix: "[CTI]"
      batching: { enabled: true, max_items: 20 }   # optional digest emails
```

The event/source name becomes the **Subject** (`subject_prefix` + title); the body is a `multipart/alternative` (plain + HTML). Assign `templates/smtp_default.j2` to SMTP routes. Batching is recommended so you get one digest email instead of one per event.

**Gmail example:** host `smtp.gmail.com`, port `587`, security `starttls`, username = your address, password = a [Google App Password](https://support.google.com/accounts/answer/185833) (not your login password).

### Signal

Sends to Signal via a **self-hosted bridge** — Signal has no hosted webhook/bot API. Run [`bbernhard/signal-cli-rest-api`](https://github.com/bbernhard/signal-cli-rest-api) and register a dedicated number once; CassandraCTI then `POST`s to its `/v2/send`.

```yaml
connectors:
  - id: "signal-soc"
    type: "signal"
    params:
      api_url: "http://localhost:8090"     # your signal-cli-rest-api endpoint
      number: ${SIGNAL_NUMBER}             # the registered sender, e.g. +33600000000
      recipients: ["+33611111111", "group.AbCdEf123="]
      throttle_ms: 500
      # text_mode: styled                  # optional: basic *bold* / _italic_
```

**`recipients` is a plain list — send to a number, a group, or both:**

| Target | `recipients` |
|---|---|
| A number only | `["+33611111111"]` |
| A group only | `["group.AbCdEf123="]` |
| Both at once | `["+33611111111", "group.AbCdEf123="]` |

**Setup (one-time):**

1. **Run the bridge** — device linking needs `json-rpc` mode and outbound network:
   ```bash
   docker run -d --name signal-api -p 8090:8080 --dns 9.9.9.9 \
     -v $HOME/.local/share/signal-api:/home/.local/share/signal-cli \
     -e MODE=json-rpc bbernhard/signal-cli-rest-api
   ```
   If linking later fails with *"Connection closed"*, the container has no internet — check DNS/egress (`docker exec signal-api getent hosts chat.signal.org`). A common cause is a host firewall dropping the Docker bridge's forwarded traffic.

2. **Link it to your Signal account** (as a secondary device — your phone stays primary, no number takeover):
   ```bash
   curl -s -o signal-qr.png "http://localhost:8090/v1/qrcodelink?device_name=cassandra-cti"
   xdg-open signal-qr.png          # then on your phone: Signal → Settings →
                                   # Linked devices → + → scan (QR expires in minutes)
   ```

3. **Confirm** the link, then send a test:
   ```bash
   curl -s http://localhost:8090/v1/accounts        # should list your number
   cassandra doctor connector --id signal-soc
   ```

> Alternatively, register a **dedicated** number as a new primary (`POST /v1/register/{number}` + SMS/captcha verify) — never do this with your personal number, it would deregister Signal on your phone.

Messages are **plain text** (URLs auto-link), so leave Signal routes template-less or use a plain-text template.

> **Supply-chain:** the transport is a thin HTTP client — it imports no Signal library and vendors no bridge code, so there's no code-level dependency on the bridge (it's an external process behind `api_url`). To harden the bridge, pin the image by digest (`…@sha256:…` instead of `:latest`) or self-build from a reviewed fork — the transport works unchanged against any of them.

### Web Dashboard

A live, read-only dashboard for a CTI/Blue team: think RSS reader meets alerting console. Events appear in real time (SSE) as they are routed, with history served from the local SQLite store. Zero extra dependency (aiohttp is already required), self-contained page (no CDN — works on isolated networks).

Fastest way — no configuration at all:

```bash
cassandra run --loop --web                 # http://127.0.0.1:8080
cassandra run --loop --web --web-port 9000 --web-host 0.0.0.0
```

`--web` injects a temporary catch-all route to a built-in `web` connector (nothing is written to your YAML files) and implies `--loop` so the process stays alive.

You can also declare it like any other connector to control exactly which events it receives:

```yaml
# connectors.yaml
connectors:
  - id: "web-soc"
    type: "web"
    params:
      host: "127.0.0.1"   # bind address — keep localhost unless you know why
      port: 8080
      # token: ${CTI_WEB_TOKEN}   # optional: require Bearer token / ?token=
```

```yaml
# config.yaml
routes:
  - name: "dashboard-ransomware"
    include_sources: ["ransomware.live"]
    transports: ["web-soc"]
```

**UI — a dense, terminal-grade SOC command center** (light/dark, monospace data, self-contained, no CDN):

- **Tabbed** — *Overview*, *Live feed*, and one tab per category: *Ransomware*, *RSS*, *Red flags*, *Vulnerabilities* (CISA KEV), *IOCs* (abuse.ch).
- **Overview** — a live clock and a stat strip (total, new over 24h/7d/30d with a delta vs the previous period, critical count, active sources, alerts sent, live clients), an interactive activity chart, a top-sources and by-category breakdown, a most-active ransomware-groups table, source health (last event per source), and a latest-critical list.
- **Feed tabs** — a log-style table (time · source · event) with per-category filters (group/country/sector, vendor + ransomware-linked, malware/IOC-type, feed/tag…), a date-range and sort (newest / oldest / criticality), a result count, and per-row actions: **copy** the IOC/CVE, an **AI brief**, and a **details** view.
- **Details** — a modal per event with all fields, links (open source · NVD · VirusTotal · leak site) and copy.
- **Actionable** — copy indicators, **export the current view to CSV or JSON**, deep-link the tab + filters + search in the URL, keyboard shortcuts (`1`–`7` tabs, `/` search, `e` export, `Esc` close), and optional sound alerts on critical events.
- **Inventory** (opt-in) — filter/highlight only events that concern your stack (see the `inventory` config section).
- **AI brief** (opt-in) — a SOC-oriented summary per event via the optional `llm` layer (local Ollama or a cloud key).

The server binds to `127.0.0.1` by default — set a `token` before exposing it on the network.

### Inventory & AI briefs (optional)

Both features are **off by default** and live in `config.yaml`. They only affect the web dashboard.

**Inventory** — a list of names you care about: vendors/products/OS in your stack, **or company/entity names you watch** (e.g. `Credit Agricole`, `Gouvernement`). The dashboard's **INV** toggle then applies `match_mode` to those terms. (For *alerting* on the same names rather than dashboard filtering, use a route's [`include_terms`](#match-by-entity--company-name-include_terms).)

```yaml
inventory:
  enabled: true
  match_mode: highlight        # highlight = show all, emphasize matches · filter = show only matches
  terms: ["Fortinet", "Cisco", "VMware", "Microsoft", "Ivanti", "Citrix"]
```

The dashboard's **INV** toggle then applies `match_mode`: `highlight` keeps every event but emphasizes the ones touching your stack; `filter` shows only those.

**AI briefs** — a per-event, SOC-oriented summary generated on demand from the *AI brief* row action. Provider-agnostic and private-first: `auto` prefers a reachable local **Ollama** (free, offline), otherwise the first cloud key found in the environment (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `DEEPSEEK_API_KEY`).

```yaml
llm:
  enabled: true
  provider: auto               # auto | ollama | anthropic | openai | deepseek
  model: ""                    # optional override (else a sensible per-provider default)
  ollama_base_url: http://localhost:11434
  ollama_model: ""             # optional; else the first pulled model
  max_tokens: 300
```

No key and no local Ollama ⇒ the AI-brief button simply stays hidden; every other feature works unchanged.

---

## Routing

Routes match incoming events and send them to one or more transports. **Every** matching route fires — a single event can fan out to several routes (e.g. a "firehose" route alongside a topic route). Per-transport deduplication guarantees the same event is never delivered twice to the same transport.

### How it fits together

Configuration is split across **two files** so secrets never touch the routing logic:

| File | Holds | Example |
|---|---|---|
| `config.yaml` | sources, filters, **routes**, and `transports.use` (a list of connector **IDs**) | `transports: { use: ["discord-general", "telegram-main"] }` |
| `connectors.yaml` | the **connectors** — the real endpoints (webhook URLs, tokens, options), keyed by `id` | `- id: discord-general` → `type: discord` → `params: {webhook_url: ...}` |

A route references a connector by its `id`; the connector file holds the secret. Every run flows through five stages:

```
SOURCES ─▶ EVENTS (title, url, tags, raw) ─▶ FILTERS (deny/allow, max per source)
        ─▶ ROUTES (all-match) ─▶ TRANSPORTS (render the route's template, POST to each connector)
```

A **route** is the glue: it *selects* events (`include_sources` / `include_tags` / `include_regex`), *names* one or more transports (connector IDs), and *picks* a template. Because **every** matching route fires, one event can hit several routes; per-transport dedup then delivers it to each connector at most once.

### Pattern: one source → several channels

To send the *same* events to *different* connectors, add **one route per connector** — each matches the same source and carries the template that fits its transport. This is exactly how a single feed lands in a Discord channel **and** a Telegram channel, each rendered correctly:

```yaml
transports:
  use: ["discord-general", "telegram-main"]

routes:
  - name: rss-discord               # RSS → Discord (Markdown embed)
    include_sources: ["rss:"]
    transports: ["discord-general"]
    template: "templates/discord_default.j2"

  - name: rss-telegram              # the SAME RSS → Telegram (HTML message)
    include_sources: ["rss:"]
    transports: ["telegram-main"]
    template: "templates/telegram_default.j2"
```

> **Templates are transport-flavoured.** A route sends its *one* template to *all* of its transports, so never mix a Markdown transport (Discord/Teams) and an HTML transport (Telegram/SMTP) in the same route — split them into two routes as above. The card/embed title (and email subject) is the **source name**; the template renders the article body via `{{ title }}`, `{{ summary }}`, `{{ url }}`, `{{ raw }}`. See [Templates](#templates) for the built-in set.

### Match by source prefix

```yaml
routes:
  - name: "all-rss"
    include_sources: ["rss:"]        # Matches rss:CERT-FR, rss:Krebs, etc.
    transports: ["discord-alert"]
```

### Match by exact source

```yaml
routes:
  - name: "ransomware"
    include_sources: ["ransomware.live"]
    transports: ["teams-soc"]
```

### Match by tag

```yaml
routes:
  - name: "cert-only"
    include_tags: ["cert"]
    transports: ["teams-cert", "discord-alert"]
```

### Match by regex (title or source)

```yaml
routes:
  - name: "critical"
    include_regex: "(?i)(critical|zero.day|0-day|CVE)"
    transports: ["teams-soc", "discord-alert"]
```

### Match by entity / company name (`include_terms`)

A plain list of names — **accent- and case-insensitive** — matched against the
**title, summary, source, tags and meta** of every event. Unlike `include_regex`
(title/source only), it catches a company named only in the body or in a
ransomware victim field. This is how you get "alert me when *X* shows up anywhere":

```yaml
routes:
  - name: "entity-watch"
    include_terms: ["Credit Agricole", "BNP Paribas", "Gouvernement", "Airbus"]
    transports: ["signal-soc", "discord-alert"]
```

`include_terms` also works on **[briefings](#briefings)**. It's pure config, so
entity alerting is fully CLI-portable — not tied to the dashboard. To *visually*
filter/highlight the same names in the web UI, put them in
[`inventory.terms`](#inventory--ai-briefs-optional) (the INV toggle). The
[`entity-watch`](examples/entity-watch/) example wires both from one list.

---

## Briefings

Routes deliver **each** event. A **briefing** does the opposite: it periodically
recaps a *batch* of events — an LLM writes a short, **prioritised** summary with
links, sent through a normal transport **after** the individual alerts. Think of
it as a shift hand-over: "here's what came in since last time, and what matters."

It reuses the optional [LLM layer](#inventory--ai-briefs-optional) (local Ollama
or a cloud key) and is **off unless you configure `briefings:`**.

```yaml
briefings:
  - name: vuln-daily
    include_sources: ["cisa.kev"]     # same selectors as routes (source / tag / regex)
    include_tags: ["cert"]            #   — OR across them; omit all = recap everything
    transports: ["discord-brief"]     # a connector id (its own #briefings channel is nice)
    schedule: "24h"                   # cadence: 24h | 6h | 30m | 2d
    min_items: 1                      # skip the brief if fewer than N new items
    max_items: 40                     # cap how many items the LLM sees
    template: "templates/briefing_default.j2"   # Markdown; Telegram -> briefing_telegram.j2
```

| Key | Default | Meaning |
|---|---|---|
| `include_sources` / `include_tags` / `include_regex` | — | select events, exactly like a route (OR across them; none = all) |
| `transports` | — | connector id(s) that receive the brief (must be in `transports.use`) |
| `schedule` | `24h` | how often it may fire (`24h`, `6h`, `30m`, `2d`) |
| `min_items` | `1` | don't send a brief with fewer than N new items (accumulates instead) |
| `max_items` | `40` | cap on items fed to the LLM |
| `top_n` | `0` | `0` = a short 2-4 highlight narrative; `N` = a ranked, numbered **Top N** digest (e.g. "Top 10 CVEs of the week") |
| `template` | `briefing_default.j2` | Markdown for Discord/Teams; `briefing_telegram.j2` for Telegram |

**How it works** — every collection cycle, after delivery, each briefing checks
whether its `schedule` has elapsed. If so it gathers the events **ingested since
its last run** that match its selectors, asks the LLM to prioritise them (KEV /
ransomware-linked / high-confidence IOCs first) and narrate them with links, then
sends one message and records the timestamp. In `--loop` mode this happens on its
own; the window is keyed on *when CassandraCTI saw* each item, so a brief reflects
"what's new," not original publish dates.

**Per-category digests in separate channels** — briefings compose: define one per
topic, each scoped to its sources and pointed at its own channel, with its own
cadence and `top_n`. For example a **6h Top 10 news** recap, a **daily Top 10
ransomware** victims recap, and a **daily + weekly Top 10 CVE** recap — each in a
different Discord/Signal channel. The [`category-digests`](examples/category-digests/)
example wires exactly that. (Ranking is the LLM's judgment — exploited/critical
first — not CVSS; there's no NVD/CVSS source.)

For a single **cross-category overview**, add a briefing with **no selectors** — a
catch-all over the whole event pool — pointed at a dedicated channel:

```yaml
briefings:
  - name: general-debrief          # no include_* = every category, one channel
    transports: ["discord-debrief"]
    schedule: "24h"
    top_n: 15
```

**Trigger it manually** (testing, or an on-demand recap):

```bash
cassandra briefing-run --all            # force every briefing now
cassandra briefing-run --name vuln-daily
cassandra briefing-run --all --dry-run  # prints [DRYRUN:BRIEFING], calls no LLM
```

> Briefings need the `llm:` layer to resolve a provider. With no Ollama and no
> cloud key they're skipped silently (a warning is logged) — everything else runs.

---

## CLI Reference

### `cassandra quickstart`

Scaffold the config files (if missing) and open the live dashboard — the fastest way to a running instance.

```
Options:
  --web / --no-web    Open the dashboard after setup (default: --web)
  --web-host TEXT     Dashboard bind address (default: 127.0.0.1)
  --web-port INT      Dashboard port (default: 8080)
  --config PATH       Path to config.yaml
  --connectors PATH   Path to connectors.yaml
```

---

### `cassandra init`

Initialize default configuration files (`config.yaml`, `connectors.yaml`, `templates/`).

```
Options:
  --config PATH       Path to config.yaml
  --connectors PATH   Path to connectors.yaml
```

---

### `cassandra run`

Execute the aggregation cycle.

```
Options:
  --config PATH       Path to config.yaml
  --connectors PATH   Path to connectors.yaml
  --loop              Run in loop mode
  --interval INT      Loop interval in seconds (default: 300)
  --sources TEXT      Comma-separated source filter (e.g. "rss:,ransomware.live")
  --dry-run           Log only, do not send
  --verbose           Set log level to DEBUG
  --since TEXT        Only process events after this date (ISO8601 or YYYY-MM-DD)
  --no-dedupe         Skip deduplication check
  --web               Serve the live web dashboard (implies --loop)
  --web-host TEXT     Dashboard bind address (default: 127.0.0.1)
  --web-port INT      Dashboard port (default: 8080)
```

**Examples:**

```bash
# Standard run
cassandra run

# Loop every 10 minutes, verbose
cassandra run --loop --interval 600 --verbose

# Only fetch ransomware and CERT feeds
cassandra run --sources "ransomware.live,rss:CERT-FR Alertes"

# Backfill events from the past week, no dedup
cassandra run --since 2025-03-12 --no-dedupe

# Dry run to test a new config
cassandra run --dry-run --verbose

# Live web dashboard on http://127.0.0.1:8080 (implies --loop)
cassandra run --web
```

---

### `cassandra add-source`

Add a source to config.yaml. Kinds: `rss`, `ransomware_live`, `redflag`, `kev` (CISA KEV), `abusech`.

```bash
cassandra add-source rss \
  --name "CERT-FR Alertes" \
  --url "https://cert.ssi.gouv.fr/alerte/feed/" \
  --tags "cert,fr"

cassandra add-source ransomware_live
cassandra add-source redflag
cassandra add-source kev
cassandra add-source abusech --feeds "feodo,threatfox,urlhaus,malwarebazaar" --api-key "$ABUSECH_API_KEY"
```

---

### `cassandra remove-source`

Remove an RSS feed (by `--name` or `--url`), or disable another source. Pair with
`cassandra list` to see what's configured.

```bash
cassandra remove-source rss --name "CERT-FR Alertes"
cassandra remove-source rss --url "https://cert.ssi.gouv.fr/alerte/feed/"
cassandra remove-source kev            # disables the source (enabled: false)
```

---

### `cassandra import-feeds`

Bulk import RSS feeds from a CSV file.

```
Format: Name,URL,Tags
Tags are pipe-separated: "cert|fr|alerts"
```

```bash
cassandra import-feeds feeds.csv
```

---

### `cassandra add-connector`

Add a connector to connectors.yaml. `--type` selects the transport (`teams` default, `discord`, `telegram`, `smtp`, `web`, `signal`); required parameters are validated per type.

```bash
# Teams / Discord — incoming webhook
cassandra add-connector --id "teams-soc" --type teams   --webhook-url "https://..." --theme-color "0078D7"
cassandra add-connector --id "discord"   --type discord --webhook-url "https://..." --username "CassandraCTI"

# Telegram — bot token + chat id
cassandra add-connector --id "tg-soc" --type telegram --bot-token "$TELEGRAM_BOT_TOKEN" --chat-id "@my_channel"

# Email — SMTP
cassandra add-connector --id "mail" --type smtp \
  --host smtp.gmail.com --from-addr you@example.com --to-addrs "soc@example.com" --security starttls

# Signal — via a self-hosted signal-cli-rest-api bridge (number and/or group)
cassandra add-connector --id "signal-soc" --type signal \
  --api-url "http://localhost:8090" --number "$SIGNAL_NUMBER" \
  --recipients "+33611111111,group.AbCdEf123="
```

---

### `cassandra routes-add`

Add or update a route. **Auto-activation:** the referenced `--transports` are
added to `transports.use` automatically, so a connector goes live as soon as a
route (or briefing) uses it — no manual `transports.use` editing.

```bash
cassandra routes-add \
  --name "cert-alerts" \
  --include-tag "cert" \
  --transports "teams-cert,discord-alert"
```

---

### Removing things — `remove-connector` / `routes-remove` / `briefing-remove`

Symmetric with the `add-*` commands (pair with `cassandra list`):

```bash
cassandra remove-connector --id "teams-cert"   # also drops it from transports.use
cassandra routes-remove --name "cert-alerts"
cassandra briefing-remove --name "vuln-daily"
```

---

### `cassandra briefing-add`

Add or update a periodic LLM briefing (see [Briefings](#briefings)).

```bash
cassandra briefing-add \
  --name "vuln-daily" \
  --include "cisa.kev" \
  --transports "discord-brief" \
  --schedule "24h" --min-items 1
```

---

### `cassandra briefing-run`

Send briefings now — no flag runs the ones that are due; `--name`/`--all` force.

```bash
cassandra briefing-run --all              # force every briefing
cassandra briefing-run --name vuln-daily  # force just this one
cassandra briefing-run --all --dry-run    # [DRYRUN:BRIEFING], no LLM call
```

---

### `cassandra doctor`

Validate configuration and test connectivity.

```bash
# Validate YAML and schema
cassandra doctor config

# Send a test message through a connector
cassandra doctor connector --id teams-soc
```

---

### `cassandra list`

Display current sources, routes, and connectors.

```bash
cassandra list
```

---

### `cassandra backfill`

Replay past events to a specific transport.

```bash
cassandra backfill --to teams-soc --since 2025-03-01
```

---

### `cassandra db-reset`

Delete the local SQLite database (clears all dedup history).

```bash
cassandra db-reset          # prompts for confirmation
cassandra db-reset --force  # skip confirmation
```

---

### `cassandra seen-clear`

Selectively clear dedup history without resetting the whole database.

```bash
# Clear all events from a specific feed
cassandra seen-clear --source-prefix "rss:BleepingComputer"

# Clear events seen before a date
cassandra seen-clear --before 2025-01-01

# Clear events from a source after a date
cassandra seen-clear --source-prefix "ransomware.live" --since 2025-03-01
```

---

## Templates

Messages are rendered with Jinja2. Custom templates can be assigned per route.

### Available context variables

| Variable | Type | Description |
|---|---|---|
| `title` | `str` | Event title |
| `source` | `str` | Source ID (e.g. `rss:CERT-FR`) |
| `summary` | `str` | Body text |
| `url` | `str` or `None` | Event URL |
| `emoji` | `str` | Computed emoji for this source |
| `events` | `list[Event]` | All events in current chunk (batching) |
| `raw` | `dict` | Raw data from source (fields vary by source) |

### Built-in templates

| Template | Use Case |
|---|---|
| `templates/rss_default.j2` | Standard RSS event |
| `templates/discord_default.j2` | Discord-optimized layout |
| `templates/ransomware_card.j2` | Ransomware events (group, country, activity) |
| `templates/vuln_card.j2` | CISA KEV vulnerability card (Discord/Teams) |
| `templates/ioc_card.j2` | abuse.ch IOC card (Discord/Teams) |
| `templates/domains_list.j2` | Malicious domain list with preview |
| `templates/batch_default.j2` | Batched multi-event messages |
| `templates/telegram_default.j2` | Telegram HTML layout (assign to Telegram routes) |
| `templates/telegram_ransomware.j2` | Telegram structured card for `ransomware.live` |
| `templates/telegram_vuln.j2` | Telegram card for CISA KEV (`cisa.kev`) |
| `templates/telegram_ioc.j2` | Telegram card for abuse.ch IOCs (`abuse.ch`) |
| `templates/telegram_domains.j2` | Telegram layout for Red Flag Domains |
| `templates/telegram_press.j2` | Telegram layout for `ransomware.press` |
| `templates/telegram_8k.j2` | Telegram layout for `ransomware.8k` filings |
| `templates/telegram_stats.j2` | Telegram layout for `ransomware.stats` digest |
| `templates/smtp_default.j2` | HTML email body (assign to SMTP routes) |
| `templates/briefing_default.j2` | LLM briefing body (Markdown — Discord/Teams) |
| `templates/briefing_telegram.j2` | LLM briefing body (Telegram HTML) |

> Telegram and SMTP render as HTML — assign a matching `telegram_*` / `smtp_*` template to those routes; Discord/Teams Markdown templates won't render as rich text there.
>
> **See [`templates/README.md`](templates/README.md)** for the full pool: which template to pick per source kind × transport flavor, the context variables, and the `raw` fields each source emits.

### Example: custom template

```jinja2
{# templates/my_cert_card.j2 #}
🚨 **{{ title }}**

| Field | Value |
|---|---|
| **Source** | {{ source }} |
| **Date** | {{ raw.published if raw.published else "—" }} |

{{ summary | truncate(300) }}

[Read more]({{ url }})
```

Assign it in a route:

```yaml
routes:
  - name: "cert-alerts"
    include_tags: ["cert"]
    transports: ["teams-cert"]
    template: "templates/my_cert_card.j2"
```

---

## Running continuously

The single most important thing to understand: **deduplication is what makes "only send new items" work — not a flag.** Every run reloads the config, fetches every source, and the SQLite store remembers what has already been delivered *to each transport*. So each pass sends only items that were never delivered — run the same command a hundred times and each article goes out exactly once.

```
reload config → fetch all sources → filter → DEDUP (SQLite) → route → deliver
```

The store keeps this delivery history for `store.seen_ttl_days` (default 90) before purging old entries.

### One-shot vs. loop

```bash
# One pass and exit — ideal behind cron or a systemd timer
cassandra run --config config.yaml --connectors connectors.yaml

# Stay alive and repeat every N seconds (default 300 = 5 min)
cassandra run --config config.yaml --connectors connectors.yaml --loop --interval 300
```

In `--loop` mode the process reloads `config.yaml` **at the start of every cycle**, so adding a feed or editing a route is picked up on the next pass — no restart needed. RSS and `ransomware.live` share the exact same fetch → dedup → deliver cycle.

### First run: avoid the backlog flood

On a **fresh** database the first pass sees every item currently in your feeds as "new" and would send the whole backlog at once. Seed with a date floor, then let dedup take over:

```bash
# 1) Seed: only the last 2 days, sent once
cassandra run --config config.yaml --connectors connectors.yaml --since 2026-07-05

# 2) Then run continuously — dedup prevents any repeats
cassandra run --config config.yaml --connectors connectors.yaml --loop --interval 300
```

- **dedup** (always on) — never re-sends a delivered item. Bypass for testing with `--no-dedupe`.
- **`--since YYYY-MM-DD`** — an optional date floor; most useful on the first run.
- **`filters.max_items_per_source`** (config) — caps how many items each feed emits per cycle.

### Ransomware & PRO feeds

Same model. `sources.ransomware_live.lookback_days: 2` controls how far back the source looks on each fetch; dedup guarantees each victim is delivered once. In loop mode every newly-disclosed victim goes out on the next cycle.

### As a service

**systemd** (long-running loop, auto-restart):

```ini
# /etc/systemd/system/cassandra-cti.service
[Unit]
Description=CassandraCTI aggregator
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/cassandra run --config /etc/cassandra/config.yaml --connectors /etc/cassandra/connectors.yaml --loop --interval 300
Environment=RANSOMWARE_API_KEY=xxxxxxxx
Environment=DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now cassandra-cti
journalctl -u cassandra-cti -f          # follow the logs
```

**cron / systemd timer** (one-shot each fire — dedup makes repeats harmless):

```cron
*/5 * * * * cassandra run --config ~/.config/cassandra-cti/config.yaml --connectors ~/.config/cassandra-cti/connectors.yaml
```

**Docker** — see [Docker](#docker) below; run the container with `--loop` and `restart: unless-stopped`.

### Choosing the interval

| `--interval` | Result |
|---|---|
| `300` (5 min) | near-real-time — each new post within ~5 min |
| `3600` (1 h) | hourly sweeps |
| `86400` (daily) | one pass per day |

For a **grouped digest** (one message instead of one per item) enable `batching` on the connector (see [Transports](#transports)) and combine it with a longer interval for a daily roundup.

## Docker

```dockerfile
# Dockerfile (included)
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml /app/
RUN pip install --upgrade pip && pip install .
COPY . /app
ENV CTI_CONNECTORS=/config/connectors.yaml
ENV PYTHONUNBUFFERED=1
CMD ["cassandra", "run", "--config", "/config/config.yaml"]
```

**Build and run:**

```bash
docker build -t cassandra-cti .

docker run \
  -v /path/to/your/config:/config \
  -e MSTEAMS_WEBHOOK_SOC="https://..." \
  -e DISCORD_WEBHOOK_URL="https://..." \
  cassandra-cti
```

**Loop mode in Docker:**

```bash
docker run \
  -v /path/to/your/config:/config \
  -e MSTEAMS_WEBHOOK_SOC="https://..." \
  cassandra-cti \
  cassandra run --config /config/config.yaml --loop --interval 300
```

**With Docker Compose:**

```yaml
services:
  cassandra-cti:
    build: .
    volumes:
      - ./config:/config
    environment:
      - MSTEAMS_WEBHOOK_SOC=${MSTEAMS_WEBHOOK_SOC}
      - DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL}
    command: cassandra run --config /config/config.yaml --loop --interval 300
    restart: unless-stopped
```

---

## Metrics

CassandraCTI exposes Prometheus metrics when `metrics.enabled: true`. The exporter binds `127.0.0.1` by default — set `metrics.host: 0.0.0.0` to expose it to other containers or hosts.

```
Endpoint: http://127.0.0.1:9108/metrics
```

| Metric | Type | Labels | Description |
|---|---|---|---|
| `cassandra_cti_events_sent` | Counter | `route` | Events successfully sent |
| `cassandra_cti_fetch_total` | Counter | `source`, `status` | Fetch attempts (`ok` / `err`) |

**Prometheus scrape config:**

```yaml
scrape_configs:
  - job_name: "cassandra-cti"
    static_configs:
      - targets: ["cassandra-cti:9108"]
```

---

## Security / TLS

Every outbound fetch goes through shared network helpers that are hardened by default:

- **TLS is verified** on all connections (certificate + hostname checks, SNI sent). To interoperate with an intercepting corporate proxy you can disable verification by setting the environment variable `CTI_TLS_NO_VERIFY=1`. Use this only when you trust the network path — it turns off certificate validation for all fetches.
- **Response bodies are size-capped** (25 MiB per response) so a malicious or MITM'd feed cannot exhaust memory; oversized responses are refused.
- **The metrics exporter binds `127.0.0.1` by default** (see [Metrics](#metrics)).

### Secrets

Secrets never live in the config files — they are injected via `${VAR_NAME}` environment substitution.

| Secret / env var | Used by |
|---|---|
| `RANSOMWARE_API_KEY` | Ransomware Live API PRO backend and all PRO-only feeds (`ransomware_press`, `ransomware_8k`, `ransomware_stats`) |
| `ABUSECH_API_KEY` | abuse.ch Auth-Key — unlocks the ThreatFox & MalwareBazaar feeds (Feodo/URLhaus work without it) |
| `MSTEAMS_WEBHOOK_*` / `DISCORD_WEBHOOK_URL` | Teams / Discord webhooks |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Telegram Bot API |
| `SMTP_HOST` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` | Email (SMTP) transport |
| `SIGNAL_NUMBER` | Signal sender number registered on your signal-cli-rest-api bridge |
| `CTI_WEB_TOKEN` | Optional Bearer/`?token=` auth for the web dashboard when exposed |
| `CTI_TLS_NO_VERIFY` | Disable TLS verification (opt-in, `=1`) |
| Cloud LLM keys — `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `DEEPSEEK_API_KEY` | Optional AI briefs (only if the `llm` layer is enabled with a cloud provider) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        cassandra run                    │
└──────────────────────┬──────────────────────────────────┘
                       │
         ┌─────────────▼─────────────┐
         │       Sources             │
         │  ┌──────────────────────┐ │
         │  │ RSS (feedparser)     │ │
         │  │ Ransomware Live      │ │
         │  │   (PRO → v2 → posts) │ │
         │  │ Ransomware PRO feeds │ │
         │  │   (press / 8k / stats)│ │
         │  │ Red Flag Domains     │ │
         │  │ CISA KEV (vulns)     │ │
         │  │ abuse.ch (IOCs)      │ │
         │  └──────────────────────┘ │
         └─────────────┬─────────────┘
                       │  Events
         ┌─────────────▼─────────────┐
         │    Filter & Deduplicate   │
         │  title_regex_deny / allow │
         │  max_items_per_source     │
         │  SQLite event store       │
         └─────────────┬─────────────┘
                       │  New events only
         ┌─────────────▼─────────────┐
         │         Router            │
         │  source / tag / regex     │
         │  → transport IDs          │
         └─────────────┬─────────────┘
                       │  Routed chunks
         ┌─────────────▼─────────────┐
         │       Transports          │
         │  ┌──────────────────────┐ │
         │  │ Teams (MessageCard)  │ │
         │  │ Discord (Embed)      │ │
         │  │ Telegram (Bot API)   │ │
         │  │ Email (SMTP)         │ │
         │  │ Web dashboard (SSE)  │ │
         │  └──────────────────────┘ │
         │  Jinja2 templates         │
         │  Batching + throttling    │
         │  Retry with backoff       │
         └───────────────────────────┘
```

---

## License

Licensed under the **GNU Affero General Public License v3.0**.
See [LICENSE](https://github.com/franckferman/CassandraCTI/blob/stable/LICENSE) for full terms.

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- Shields -->
[ci-shield]: https://github.com/franckferman/CassandraCTI/actions/workflows/ci.yml/badge.svg
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/CassandraCTI.svg?style=for-the-badge
[forks-shield]: https://img.shields.io/github/forks/franckferman/CassandraCTI.svg?style=for-the-badge
[stars-shield]: https://img.shields.io/github/stars/franckferman/CassandraCTI.svg?style=for-the-badge
[issues-shield]: https://img.shields.io/github/issues/franckferman/CassandraCTI.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/franckferman/CassandraCTI.svg?style=for-the-badge
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=0078D7
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=1DA1F2
