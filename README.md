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
  Collect threat intel from RSS feeds, ransomware trackers & malicious domain lists —<br>
  then route it automatically to Teams, Discord, and beyond.
</p>

<p align="center">
  <a href="#about">About</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#sources">Sources</a> ·
  <a href="#transports">Transports</a> ·
  <a href="#cli-reference">CLI Reference</a> ·
  <a href="#docker">Docker</a> ·
  <a href="#templates">Templates</a>
</p>

</div>

---

## About

**CassandraCTI** — named after the Trojan prophetess condemned to warn of future dangers without being believed — is a modular, asynchronous CTI pipeline that does the opposite: it makes sure your threat intel actually reaches the people who need it.

Originally built as a private internal tool, it is now open-source, designed to be composable and adaptable to any security team's workflow.

**What it does:**

- Polls threat intel sources on a schedule (RSS feeds, ransomware trackers, malicious domain lists)
- Deduplicates events using SHA1-based fingerprinting with a local SQLite store
- Routes events through configurable rules (by source, tag, or regex)
- Renders messages from Jinja2 templates and pushes them to Teams or Discord webhooks
- Exposes Prometheus metrics for observability

---

## Features

| Capability | Details |
|---|---|
| **Modular sources** | RSS, Ransomware Live, Red Flag Domains — more coming |
| **Modular transports** | Microsoft Teams, Discord, Telegram, Email (SMTP) — extensible |
| **Smart deduplication** | SHA1 event fingerprint + SQLite delivery tracking |
| **Flexible routing** | Match by source prefix, tag, or regex |
| **Jinja2 templates** | Full control over message formatting |
| **Batching & throttling** | Group events, respect rate limits |
| **Env var substitution** | `${VAR_NAME}` in YAML — no secrets in files |
| **Dry-run mode** | Validate pipelines without sending anything |
| **Backfill** | Replay past events to a transport |
| **Prometheus metrics** | `cassandra_cti_events_sent`, `cassandra_cti_fetch_total` |
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
├── connectors.yaml     ← transport definitions (Teams / Discord webhooks)
└── templates/          ← custom Jinja2 templates (optional)
```

### Quick Start

**1. Add a webhook connector:**

```bash
# Microsoft Teams
cassandra add-connector \
  --id "teams-soc" \
  --webhook-url "https://your-tenant.webhook.office.com/..."

# Discord
# (edit connectors.yaml manually — see Transports section)
```

**2. Add threat intel sources:**

```bash
# RSS feed
cassandra add-source rss \
  --name "CERT-FR Alertes" \
  --url "https://cert.ssi.gouv.fr/alerte/feed/" \
  --tags "cert,fr"

# Ransomware tracker
cassandra add-source ransomware_live

# Malicious domain list
cassandra add-source redflag
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
    url: "https://data.ransomware.live/posts.json"   # optional

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
  host: "0.0.0.0"
  port: 9108
```

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

Tracks ransomware group activity from [ransomware.live](https://ransomware.live).

```yaml
sources:
  ransomware_live:
    enabled: true
    lookback_days: 30
```

Each event represents a ransomware attack:
- **Title:** `{Victim} by {Group}`
- **Tags:** `["ransomware"]`
- **Raw fields:** `group_name`, `country`, `activity`, `post_url`, `description`
- **Emoji:** Auto-detects victim country flag (🇫🇷 🇬🇧 🇩🇪 🇺🇸 ...)

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

---

## Routing

Routes match incoming events and send them to one or more transports. **Every** matching route fires — a single event can fan out to several routes (e.g. a "firehose" route alongside a topic route). Per-transport deduplication guarantees the same event is never delivered twice to the same transport.

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

---

## CLI Reference

### `cassandra init`

Initialize default configuration files.

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
```

---

### `cassandra add-source`

Add a source to config.yaml.

```bash
cassandra add-source rss \
  --name "CERT-FR Alertes" \
  --url "https://cert.ssi.gouv.fr/alerte/feed/" \
  --tags "cert,fr"

cassandra add-source ransomware_live
cassandra add-source redflag
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

Add a Teams connector to connectors.yaml.

```bash
cassandra add-connector \
  --id "teams-soc" \
  --webhook-url "https://..." \
  --theme-color "0078D7" \
  --emojis
```

---

### `cassandra routes-add`

Add or update a route.

```bash
cassandra routes-add \
  --name "cert-alerts" \
  --include-tag "cert" \
  --transports "teams-cert,discord-alert"
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
| `templates/domains_list.j2` | Malicious domain list with preview |
| `templates/batch_default.j2` | Batched multi-event messages |

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

CassandraCTI exposes Prometheus metrics when `metrics.enabled: true`.

```
Endpoint: http://0.0.0.0:9108/metrics
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
         │  │ Red Flag Domains     │ │
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
