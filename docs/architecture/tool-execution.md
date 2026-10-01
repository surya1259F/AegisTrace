# Forensic Tool Execution Architecture

Tool execution is mediated by the `PlatformAwareToolRegistry`:
- Prohibits arbitrary shell command injection (`shell=False` enforced).
- Detects host tool binaries dynamically on Linux and Windows.
- Enforces strict process timeouts (default 60-120 seconds).
- Converts raw stdout/stderr output into normalized, structured JSON findings.
