# TODO

## Web

- [ ] **Web management UI** — extend the read-only dashboard (`cassandra run --web`) with
      configuration management from the browser: CRUD on sources (RSS feeds, ransomware.live,
      red flag domains), connectors (Teams/Discord/Telegram/SMTP/web), and routes, with
      validation via the existing Pydantic schema and safe writes to `config.yaml` /
      `connectors.yaml`. Requires authentication first (the dashboard is currently
      localhost-only / optional token).
- [ ] Optional: acknowledge/mute events in the dashboard (needs a small state table in the store).
- [ ] Optional: per-source sound alerts. _(dark/light theme toggle shipped in the dashboard redesign)_
