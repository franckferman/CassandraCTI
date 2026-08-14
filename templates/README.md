# Template pool

Every route can point at a Jinja2 template that renders the body of each alert:

```yaml
routes:
  - name: vulns
    include_sources: ["cisa.kev"]
    transports: ["discord-alert"]
    template: "templates/vuln_card.j2"
```

Pick the template that matches **the source kind** and **the transport's render
flavor**. If a route has no `template`, the transport falls back to a built-in
default layout.

## Render flavors

| Transport | Flavor | Notes |
|-----------|--------|-------|
| Discord   | Markdown | `**bold**`, `[text](url)`, `` `code` `` |
| Teams     | Markdown | same Markdown subset as Discord |
| Telegram  | HTML (subset) | `<b>`, `<i>`, `<a href>`, `<code>` — escape text with `\| e` |
| SMTP      | HTML | full HTML email body |
| Web       | — | the dashboard ignores templates (renders its own UI) |

Use a Markdown template for Discord/Teams and a `telegram_*` template for
Telegram. For SMTP, use `smtp_default.j2` or your own HTML template — a Markdown
card sent to SMTP would show literal `**` and `[](…)`.

## Which template for which source

| Source kind | Discord / Teams (Markdown) | Telegram (HTML) |
|-------------|----------------------------|-----------------|
| RSS / news (`rss:*`)          | `rss_default.j2`, `discord_default.j2` | `telegram_default.j2`, `telegram_press.j2`, `telegram_8k.j2` |
| Ransomware (`ransomware.live`)| `ransomware_card.j2`       | `telegram_ransomware.j2`, `telegram_stats.j2` (digest) |
| Ransomware — **plain text** (Signal/SMS) | `ransomware_plain.j2` (normal + .onion links) | — |
| Red-flag domains (`red.flag.domains`) | `domains_list.j2`  | `telegram_domains.j2` |
| Vulnerabilities (`cisa.kev`)  | `vuln_card.j2`             | `telegram_vuln.j2` |
| IOCs (`abuse.ch`)             | `ioc_card.j2`              | `telegram_ioc.j2` |
| Any (multi-event digest)      | `batch_default.j2`         | — |
| Any (email)                   | `smtp_default.j2` (HTML)   | — |

## Variables available in every template

| Variable  | Type | Meaning |
|-----------|------|---------|
| `title`   | str  | the event's own title (e.g. `CVE-2026-1234 — …`) |
| `source`  | str  | source id (`cisa.kev`, `rss:Krebs`, …) |
| `summary` | str  | event summary (plain text; Telegram de-Markdowns it) |
| `url`     | str  | canonical link (may be empty) |
| `emoji`   | str  | emoji picked for the event |
| `events`  | list | the events in this message (usually 1; `batch_default` iterates it) |
| `raw`     | dict | source-specific structured fields (see below) |

> With a per-route `template`, the transport puts the **source name** in the card
> heading and passes the **article title** as `{{ title }}`, so a body template
> should render `{{ title }}` itself (the defaults do).

## `raw` fields by source

- **`rss:*`** — `feed` (and feed-specific extras).
- **`ransomware.live`** — `group_name`, `website`/`victim`, `country`,
  `country_display`, `country_flag`, `activity`, `discovered`, `data_size`,
  `infostealer_summary`, `infostealer_stealers`, `leak_url`.
- **`red.flag.domains`** — `count`, `date`.
- **`cisa.kev`** — `cve`, `vendor`, `product`, `due_date`,
  `ransomware_use` (bool), `required_action`, `date_added`.
- **`abuse.ch`** — `ioc`, `ioc_type`, `malware`, `country`, `status`,
  `confidence`, `feed` (`feodo` / `threatfox` / `urlhaus` / `malwarebazaar`).

Missing fields render as empty — every card guards optional lines with
`{% if raw.x %}`, so an incomplete event never crashes the template.

## Writing your own

Copy the closest card, keep the `{% if … %}` guards, and render each template
offline before wiring it to a route:

```bash
python -m pytest tests/test_templates_render.py
```
