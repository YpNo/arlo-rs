---
name: protocol-specialist
description: Protocol emulation and state management for the Arlo ecosystem.
---
# Protocol Specialist Skill

## Arlo API Emulation
- When implementing new endpoints:
  1. Audit the `X-Arlo-...` headers (Telemetry, Browser version, App version).
  2. Ensure the User-Agent is consistent with the `BrowserProfile` provided by `rs-cloudscraper`.

## SSE & Event Management
- **Keep-Alives**: Implement a robust heartbeat mechanism for SSE connections.
- **Actor Isolation**: Ensure the `EventManager` uses `tokio::sync::broadcast` to prevent head-of-line blocking.
- **State Hydration**: Periodically refresh device states from the REST API to ensure SSE events haven't been missed.

## MFA Flow Orchestration
- Manage the transition from `start_auth` to `finish_auth` using a clear state machine.
- Integrate IMAP/SMS solvers as injectable adapters.
