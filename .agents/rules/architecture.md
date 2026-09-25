# Hexagonal Architecture & Core Principles
**Role**: Senior Rust Architect

## Architectural Guidelines

- **Domain Layer (Pure)**: 
    - Must be free of I/O and external transport dependencies.
    - Contains: Device state machines, Arlo error-code table, event / automation / auth models.
    
- **Application Layer (Use Cases)**: 
    - Orchestrates logic using Ports (Traits).
    - Contains: MFA challenge-response flows, Stealth navigation sequences, Re-attachment logic.
    
- **Infrastructure Layer (Adapters)**: 
    - Implementation of Output Ports using specialized crates.
    - **`arlo-rs`**: `wreq` (Chrome emulation from **`stealthscraper-rs`**) for the Cloudflare-fronted REST hosts, `tokio-tungstenite` for the MQTT / signaling WebSockets (`WsConnector`), `reqwest` + `rustls` for the LAN local-hub client, `imap-rs-*` for OTP fetching.
    - **`stealthscraper-rs`** (`browser` feature only): first-party CDP client for headless Chrome + `hyper`/BoringSSL MITM proxy.

- **Error Handling**: 
    - Use `thiserror` for all library/domain errors.
    - Use `anyhow` strictly in binaries and integration tests.

## Specialized Expertise (Agent Skills)

When working in this codebase, the following specialized skills are activated:
- **`rust-core`**: Governs hexagonal boilerplate, crate management, and instrumentation.
- **`protocol-specialist`**: Governs Arlo-specific API emulation and the MQTT event-bus actor.
- **`stealth-researcher`**: Governs JA4 auditing and CDP stealth hooks (for `stealthscraper-rs`).

## Coding Style & Safety

- **Instrumentation**: Use the `tracing` crate. Apply `#[tracing::instrument]` to all critical async paths.
- **Explicit Returns**: Prefer `impl Trait` for opaque return types.
- **Defensive Coding**: Avoid `unwrap()`. Use `.expect()` with a safety disclaimer.
