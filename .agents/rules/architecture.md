# Hexagonal Architecture & Core Principles
**Role**: Senior Rust Architect

## Architectural Guidelines

- **Domain Layer (Pure)**: 
    - Must be free of I/O and external transport dependencies.
    - Contains: Device state machines, Browser Profile definitions, SSE event enums.
    
- **Application Layer (Use Cases)**: 
    - Orchestrates logic using Ports (Traits).
    - Contains: MFA challenge-response flows, Stealth navigation sequences, Re-attachment logic.
    
- **Infrastructure Layer (Adapters)**: 
    - Implementation of Output Ports using specialized crates.
    - **`rs-arlo`**: `imap-tokio` for OTP fetching, `reqwest` for the Arlo fallback client, and **`rs-cloudscraper`** for stealth-compliant transport.
    - **`rs-cloudscraper`**: `rquest` for JA4 forging, `headless_chrome` for CDP automation, `hyper` for MITM proxy.

- **Error Handling**: 
    - Use `thiserror` for all library/domain errors.
    - Use `anyhow` strictly in binaries and integration tests.

## Specialized Expertise (Agent Skills)

When working in this codebase, the following specialized skills are activated:
- **`rust-core`**: Governs hexagonal boilerplate, crate management, and instrumentation.
- **`protocol-specialist`**: Governs Arlo-specific API emulation and SSE actor management.
- **`stealth-researcher`**: Governs JA4 auditing and CDP stealth hooks (for `rs-cloudscraper`).

## Coding Style & Safety

- **Instrumentation**: Use the `tracing` crate. Apply `#[tracing::instrument]` to all critical async paths.
- **Explicit Returns**: Prefer `impl Trait` for opaque return types.
- **Defensive Coding**: Avoid `unwrap()`. Use `.expect()` with a safety disclaimer.
