# Evidence Pipeline Architecture

The evidence processing lifecycle follows an immutable 6-stage pipeline:

1. **Intake & Canonicalization:** Validates host path, rejects path traversal patterns, canonicalizes real path.
2. **Streaming SHA-256 Hashing:** Reads file in strict 8 MiB chunks, ensuring minimal memory footprint.
3. **Chain of Custody Registration:** Logs immutable `EVIDENCE_REGISTERED` audit record.
4. **Autonomous Planning:** Triage planner selects tool adapters and agent priority queues.
5. **Tool Execution:** Executes deterministic binaries with timeouts and `shell=False`.
6. **Verification & Correlation:** Validates findings against evidence references.
