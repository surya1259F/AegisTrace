# Security Baseline

ADFIR enforces the following non-negotiable security controls:
1. **Evidence Immutability:** Original evidence files are opened strictly in read-only mode (`rb`) and are never modified, renamed, moved, or deleted.
2. **Subprocess Isolation:** `shell=True` is prohibited across all adapters and tool runners.
3. **Cryptographic Integrity:** SHA-256 is computed using 8 MiB streaming chunks.
4. **Error Sanitization:** API exceptions return generic error envelopes and log detailed traces to secure audit files.
5. **No Dangerous HTML:** React components never use `dangerouslySetInnerHTML` for untrusted evidence strings.
