# ADR-001: Native Desktop Architecture via Tauri & FastAPI

## Status: Accepted
## Context
Digital forensics applications require low memory overhead, native OS file access, local evidence immutability, and offline capability.
## Decision
We adopted Tauri (Rust) for the desktop wrapper and Python (FastAPI) for the core backend engine.
## Consequences
- Minimal RAM overhead compared to Electron.
- Full access to native forensic tool binaries and hardware capabilities.
- Retains cross-platform desktop compilation targets for Linux and Windows.
