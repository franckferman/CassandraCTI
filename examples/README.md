# Example configurations

Ready-to-run `config.yaml` + `connectors.yaml` pairs, one per scenario. Copy the
folder that matches your use case, set the environment variables it needs, and
run it — no other editing required to get started.

Every command follows the same shape:

```bash
cassandra run --loop --interval 300 \
  --config      examples/<scenario>/config.yaml \
  --connectors  examples/<scenario>/connectors.yaml
```

> Secrets are read from the environment (`${VAR}` in the YAML), so nothing
> sensitive lives in these files. `cassandra doctor connector --id <id> --connectors <file>`
> sends a live test message through a connector before you commit to it.

## Scenarios

| Folder | What it does | Transport(s) | Env vars to set |
|--------|--------------|--------------|-----------------|
| [`discord-quickstart`](discord-quickstart/) | A few news feeds + ransomware.live → one Discord channel. Simplest real setup. | Discord | `DISCORD_WEBHOOK_URL` |
| [`teams-soc-multichannel`](teams-soc-multichannel/) | Route by topic to separate Teams channels (CERT / vendor / news / ransomware / domains). | Teams ×5 | `MSTEAMS_WEBHOOK_CERT`, `…_VENDOR`, `…_NEWS`, `…_RANSOMWARE`, `…_DOMAINS` |
| [`telegram-channel`](telegram-channel/) | News + ransomware → a Telegram channel, with the HTML `telegram_*` cards. | Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| [`email-digest`](email-digest/) | Batched roundup email instead of one message per item. | SMTP | `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` |
| [`vuln-ioc-watch`](vuln-ioc-watch/) | CISA KEV + abuse.ch only → Discord, with the `vuln_card` / `ioc_card` layouts. | Discord | `DISCORD_WEBHOOK_URL` (opt. `ABUSECH_API_KEY`) |
| [`web-dashboard-only`](web-dashboard-only/) | Collect a broad set, send nothing out — just the local live dashboard. | Web | *(none)* |
| [`discord-telegram-fanout`](discord-telegram-fanout/) | The **same** sources to Discord **and** Telegram (one route per flavour). | Discord + Telegram | `DISCORD_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| [`soc-multi-transport`](soc-multi-transport/) | Severity-driven fan-out: critical → Teams+Discord+Telegram, advisories → Teams, news → email digest. | Teams + Discord + Telegram + SMTP | `MSTEAMS_WEBHOOK_SOC`, `DISCORD_WEBHOOK_CRITICAL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SMTP_*` |
| [`threat-intel`](threat-intel/) | IOCs + KEV + ransomware + research feeds → Discord, mirrored in the dashboard. | Discord + Web | `DISCORD_WEBHOOK_URL` (opt. `ABUSECH_API_KEY`) |
| [`cve-watch`](cve-watch/) | Exploited CVEs (CISA KEV) → a KEV channel; vuln advisories → a news channel. | Discord ×2 | `DISCORD_WEBHOOK_KEV`, `DISCORD_WEBHOOK_VULNNEWS` |
| [`ransomware-landscape`](ransomware-landscape/) | The state of the ransomware threat — ransomware.live victims (PRO feeds optional). | Discord | `DISCORD_WEBHOOK_RANSOMWARE` (opt. `RANSOMWARE_API_KEY`) |
| [`personalized-watch`](personalized-watch/) | Dashboard focused on your stack: **inventory** filtering + optional **AI briefs**. | Web | *(none; opt. Ollama or an LLM key)* |
| [`daily-cti-briefing`](daily-cti-briefing/) | Live alerts + a periodic **LLM briefing** that prioritises + links what came in. | Discord ×2 | `DISCORD_WEBHOOK_ALERTS`, `DISCORD_WEBHOOK_BRIEF` (+ Ollama or LLM key) |
| [`entity-watch`](entity-watch/) | **Alert** when a company/entity name hits any feed (`include_terms`) + **highlight** it on the dashboard (`inventory`). | Discord + Web | `DISCORD_WEBHOOK_URL` |
| [`signal-critical`](signal-critical/) | Exploited CVEs + ransomware → **Signal** (number and/or group) via a self-hosted bridge. | Signal | `SIGNAL_NUMBER` |

## How the two files relate

- **`config.yaml`** — turns on **sources**, lists which connectors to activate
  (`transports.use`), and defines **routes** (which events go to which connector,
  with which template).
- **`connectors.yaml`** — defines the connectors themselves (the real endpoints:
  webhook URLs, bot tokens, SMTP settings), keyed by `id`.

A route names a connector by its `id`; only connectors listed in
`transports.use` are activated. **Every** matching route fires, and per-transport
deduplication guarantees each event reaches a given connector at most once.

## Picking a template

Templates are transport-flavoured — a route sends its one template to all of its
transports, so don't mix Markdown (Discord/Teams) and HTML (Telegram/SMTP) in the
same route. Pick from:

| Source | Discord / Teams (Markdown) | Telegram (HTML) |
|--------|----------------------------|-----------------|
| RSS / news | `rss_default.j2`, `discord_default.j2` | `telegram_default.j2`, `telegram_press.j2` |
| Ransomware | `ransomware_card.j2` | `telegram_ransomware.j2` |
| Vulnerabilities (CISA KEV) | `vuln_card.j2` | `telegram_vuln.j2` |
| IOCs (abuse.ch) | `ioc_card.j2` | `telegram_ioc.j2` |
| Red-flag domains | `domains_list.j2` | `telegram_domains.j2` |
| Email (any) | — | `smtp_default.j2` (HTML) |

See [`../templates/README.md`](../templates/README.md) for the full pool and the
`raw` fields each source exposes.

## Mixing scenarios

These are starting points — combine them freely. To send the **same** sources to
two different channels (e.g. Discord *and* Telegram), add one route per connector,
each with the template that fits its transport:

```yaml
transports:
  use: ["discord", "telegram"]
routes:
  - { name: rss-discord,  include_sources: ["rss:"], transports: ["discord"],  template: "templates/discord_default.j2" }
  - { name: rss-telegram, include_sources: ["rss:"], transports: ["telegram"], template: "templates/telegram_default.j2" }
```

For the complete reference (all sources, all connector params, routing, the
dashboard, inventory & AI briefs), see the [main README](../README.md).
