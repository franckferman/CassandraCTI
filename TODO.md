# TODO

## Transports

- [ ] **SMS connector** — deliver critical alerts by SMS (on-call / paging). Provider-based
      (e.g. Twilio, Vonage, OVH, AWS SNS); ideally provider-agnostic behind one `send()` like
      the LLM layer. Must honour the transport contract: `send(events, title, template_text)`,
      `aclose()`, `batch_cfg`, and `CTI_DRY_RUN` → `[DRYRUN:SMS]`. Secrets via `${ENV}`.
      Notes: SMS is costly and ~160 chars, so it should be reserved for critical routes —
      ship a terse `templates/sms_default.j2` (title + short link only) and keep batching off.
      Register it in `transports/__init__.py` and add an `add-connector --type sms` path + a
      `critical-sms` example.

## Web

- [ ] **Web management UI** — extend the read-only dashboard (`cassandra run --web`) with
      configuration management from the browser: CRUD on sources (RSS feeds, ransomware.live,
      red flag domains), connectors (Teams/Discord/Telegram/SMTP/web), and routes, with
      validation via the existing Pydantic schema and safe writes to `config.yaml` /
      `connectors.yaml`. Requires authentication first (the dashboard is currently
      localhost-only / optional token).
- [ ] Optional: acknowledge/mute events in the dashboard (needs a small state table in the store).
- [ ] Optional: per-source sound alerts. _(dark/light theme toggle shipped in the dashboard redesign)_
