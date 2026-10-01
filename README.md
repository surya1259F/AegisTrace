# AegisTrace (ADFIR) — AI-Assisted Digital Forensic Investigation Platform

AegisTrace (ADFIR) is a startup-grade cross-platform desktop application designed for digital forensic investigators, incident responders, security teams, and researchers.

## Core Architectural Promise
> **Raw Evidence &rarr; Cryptographic SHA-256 & Chain of Custody &rarr; Autonomous Investigation Planner &rarr; Deterministic Forensic Tools & Specialist Agents &rarr; Correlation & Verification &rarr; LLM Reasoning &rarr; 19-Section Court-Ready Investigation Report.**

The LLM is **not the source of forensic truth**. Ground truth originates exclusively from forensic tools (`SleuthKit`, `Volatility 3`, `YARA`, `ExifTool`). The LLM acts as the reasoning and reporting layer over structured, verified facts.

## Technology Stack
- **Desktop Shell:** Tauri (Rust)
- **Frontend UI:** React + TypeScript (Strict Mode) + Vite + Tailwind CSS + Zustand + Lucide
- **Core Engine:** Python 3.12+ / FastAPI + SQLAlchemy + SQLite + Alembic
- **Forensics Layer:** The Sleuth Kit (`fls`), Volatility 3, YARA, ExifTool
- **Orchestration:** Multi-Agent Pipeline & Planning Engine

## Development Setup & Execution

### Prerequisites
- Node.js LTS (v20+)
- Rust & Cargo (v1.98+)
- Python 3.12+

### Running the Application
```bash
cd ~/ADFIR
./scripts/start_dev.sh
```

### Running the Test Suite
```bash
cd ~/ADFIR
PYTHONPATH=. backend/.venv/bin/pytest -v tests/
```

### Building Frontend
```bash
cd ~/ADFIR/frontend
npm run build
```

## Security Baseline
- **Evidence Immutability:** Original evidence is strictly read-only and never modified.
- **Path Traversal Protection:** Canonicalized path checks and `..` pattern rejection.
- **Subprocess Safety:** `shell=False` enforced across all tool executions.
- **Prompt Injection Defense:** Evidence content is treated as untrusted data blocks.

## License
Apache License 2.0
