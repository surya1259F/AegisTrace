# ADFIR System Architecture

ADFIR is an AI-Assisted Digital Forensic Investigation Platform architected as a cross-platform native desktop application.

```text
+-------------------------------------------------------------------------+
|                       TAURI DESKTOP APPLICATION                         |
|                    (React + TypeScript Strict Mode)                     |
+-------------------------------------------------------------------------+
                                    │
                         REST IPC / HTTP Localhost
                                    │
                                    ▼
+-------------------------------------------------------------------------+
|                       PYTHON CORE ENGINE (FastAPI)                      |
|                                                                         |
|  +---------------------+  +---------------------+  +-----------------+  |
|  | Integrity Service   |  | Tool Registry       |  | Security Core   |  |
|  | (8MB SHA-256 Stream)|  | (Linux / Windows)   |  | (Path Travers.) |  |
|  +---------------------+  +---------------------+  +-----------------+  |
|                                                                         |
|  +---------------------+  +---------------------+  +-----------------+  |
|  | Investigation       |  | Specialist Agents   |  | Correlation     |  |
|  | Planner             |  | (Disk, Memory, etc.)|  | & Verification  |  |
|  +---------------------+  +---------------------+  +-----------------+  |
+-------------------------------------------------------------------------+
                                    │
                       Deterministic Subprocess
                                    │
                                    ▼
+-------------------------------------------------------------------------+
|                  FORENSIC TOOLS (Ground Truth Layer)                    |
|        SleuthKit (fls) | Volatility 3 | YARA | ExifTool                 |
+-------------------------------------------------------------------------+
```

## Ground-Truth Design Principle
1. Ground truth originates exclusively from forensic tool binaries.
2. The LLM does not manipulate evidence or invent findings.
3. Every finding maintains verifiable cryptographic and provenance references.
