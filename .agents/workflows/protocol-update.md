# Workflow: Protocol Update Cycle
Description: Specialized workflow for reverse-engineering and implementing Arlo API changes.

## Steps

1. **Audit Phase**:
    - Analyze the provided HAR file or HTTP trace for telemetry changes.
    - Isolated modified headers (e.g., `X-Arlo-Metrics`, `X-Arlo-UserAgent`).
    
2. **Signature Analysis**:
    - Compare current implementation headers with the new trace.
    - Activate the `protocol-specialist` skill to determine if encryption or hashing schemes have changed.
    
3. **Model Hydration**:
    - Update JSON models in `src/models/` to reflect schema changes.
    - Ensure all fields are properly handled (Optional vs. Required) using `serde`.
    
4. **Event-Bus Calibration**:
    - If the update affects push events, verify that `dispatch_payload` (`src/events`) still parses the new `PUBLISH` payload shape and that `subscription_topics` covers any new topic; extend the scripted `MockWsConnector` test.
    - Run a live test to ensure the actor-based broadcast system doesn't drop the new events.
    
5. **Integration Regression**:
    - Execute a full MFA auth cycle using the revised headers.
    - Verify session caching still functions without triggering a re-auth lockout.
    
6. **Final Report**: 
    - Document the specific protocol changes discovered.
    - Confirm the client accurately mirrors the new Arlo Web Dashboard signature.
