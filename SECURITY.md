# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub's private channel:
**[Open a security advisory](https://github.com/YpNo/arlo-rs/security/advisories/new)**.
Do not open a public issue or pull request for a security problem.

Include what you can of: the affected version or commit, the code path,
a reproduction (a captured response shape is enough — never a live token,
password or account identifier), and the impact you see. You will get an
acknowledgement within a few days; fixes ship as a patch release with a
`CHANGELOG.md` entry that credits the reporter unless they prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| latest `0.x` minor | yes |
| older | no — upgrade |

`arlo-rs` is pre-1.0; only the latest release receives fixes.

## What the library protects, and what it does not

**In scope** — the library treats every Arlo response as untrusted input:
hosts, identifiers and stream URLs are validated before use, response
bodies are size-capped, every network wait has a deadline, TLS
verification is never disabled (the local-hub client pins the hub's leaf
certificate), the session token is sent only to the Arlo auth and API
origins, no HTTP client follows redirects, and secrets are held in
`secrecy::SecretString`, printed as `[REDACTED]` by `Debug`, and reach
error messages only as redacted, capped excerpts. The IMAP OTP fetcher
verifies the sender and bounds message size before parsing.

**Your responsibility** — the files the library reads and writes hold
credentials: `config.toml` (Arlo password, IMAP app-password) and the
session cache (`.arlo_session.json`: access token, trusted-browser
identity, cookies). Keep both out of version control (they are
gitignored) and readable by the owner only; the library writes the cache
`0600` and warns when `config.toml` is readable by other users. A stream
URL returned by `start_stream` carries a per-session egress token — log
`StreamUrl::redacted()`, not the URL.

**Out of scope** — Arlo's own services and account security, the
`browser` feature's headless-Chrome path beyond the points where this
crate touches it, and the `stealthscraper-rs` / `wreq` TLS emulation
(report those upstream).

## Dependencies

`cargo audit` and `cargo deny` run on every push and weekly; Renovate
opens vulnerability-alert PRs immediately and ordinary updates after a
three-day release age. The one accepted maintenance exception is the
`mqttbytes` MQTT codec (unmaintained upstream, bounds reviewed, frames
capped, fuzz-style test in `src/events/mqtt.rs`); see `deny.toml`.
