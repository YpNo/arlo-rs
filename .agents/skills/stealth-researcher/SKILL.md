---
name: stealth-researcher
description: High-sensitivity skill for fingerprinting evasion and network stealth.
---
# Stealth Researcher Skill

## JA4 / TLS Auditing
- When modifying the `TlsSpoofingProxy` or `BrowserProfile`:
  1. Verify the outbound JA4 signature matches the profile's expected fingerprint.
  2. Audit `ClientHello` extensions (ALPN, SNI, KeyShare) for consistency.

## CDP Stealth Injection
- When adding JavaScript hooks:
  1. Ensure the hook is injected *before* the page starts loading.
  2. Verify that the hook does not introduce detectable side-effects (e.g., `toString` modifications).
  3. Check against CreepJS and SannySoft periodically.

## Behavior Simulation
- Use Bezier curves for mouse movements to avoid linear-path detection.
- Implement variable keystroke delays based on human psychological patterns.

## Daemon browser lifetime

`arlo-rs`'s default transport (`WreqTransport`) runs no browser, so there is no
browser lifetime to manage in the daemon. The headless-Chrome MITM proxy
(`CloudScraperTransport`, crate feature `browser`, `ArloClientBuilder::browser(true)`)
is an escalation path only. If it is ever enabled in a long-lived process:

- `stealthscraper-rs` 1.0 drives Chrome over its own CDP client (no
  `headless_chrome`, no idle-timeout event loop); the proxy lives as long as the
  `CloudScraper` held by the transport, which is the client's lifetime.
- Keep it that way: never drop or rebuild the `CloudScraper` between requests —
  the `reqwest` client is routed through its per-process proxy and trusts its
  per-process CA.
- Re-evaluate whether the browser is needed at all before enabling it: Arlo's
  Cloudflare front only fingerprints TLS/HTTP2 today, which `wreq` satisfies.
