# ADFIR — First Academic & Industrial Review Presentation

---

## Slide 1: ADFIR — Title & Project Identity
* **Product:** ADFIR (AI-Assisted Digital Forensic Investigation Platform)
* **Tagline:** Cross-Platform Desktop Platform for Autonomous Digital Forensics & Incident Response
* **Project Type:** Startup-grade engineering software prototype
* **Review Milestone:** First Academic & Engineering Evaluation (v0.1 Foundation)
* **Presenters:** ADFIR Engineering Team

> **Presenter Notes:**  
> Welcome evaluators. Today we are presenting ADFIR, a native desktop application engineered to streamline digital forensics investigations. ADFIR combines deterministic forensic tools with an isolated multi-agent reasoning layer. We emphasize that ADFIR is not an AI chatbot; it is a court-ready forensic workstation.

---

## Slide 2: Problem Statement
* **Evidence Overload:** Digital crime scenes and endpoint intrusions generate hundreds of gigabytes of disk images, memory dumps, and logs.
* **Manual Bottlenecks:** Investigators spend days manually running separate CLI tools (TSK, Volatility, YARA) and aggregating outputs.
* **Integrity Risks:** Manual evidence handling risks chain-of-custody violations and evidence tampering.
* **AI Hallucination in Forensics:** Generative LLMs applied naively to investigations hallucinate non-existent IOCs, timestamps, and attack paths.

> **Presenter Notes:**  
> Forensic investigators face a severe scalability problem. While automation is desperately needed, applying standard generative AI to forensics creates severe risks of evidence pollution and hallucinated conclusions that cannot withstand court scrutiny.

---

## Slide 3: Proposed Solution
* **Ground-Truth First Architecture:** Ground truth originates strictly from deterministic forensic tool outputs, never from LLM generation.
* **Streaming Integrity Pipeline:** Constant-memory (8 MiB chunks) SHA-256 calculation and immutable chain-of-custody tracking.
* **Autonomous Multi-Agent Triage:** Autonomous planning engine selects specialist agents and tools based on evidence categories.
* **Calibrated Verification:** Mathematical and reference-based verification checks every finding against underlying bytes/inodes.
* **Court-Ready 19-Section Reporting:** Distinguishes verified `[FACT]`, analytical `[INFERENCE]`, and flagged `[UNVERIFIED]` data.

> **Presenter Notes:**  
> ADFIR solves this by establishing a clear separation of concerns. Evidence and tools produce facts. Agents correlate facts. The verification engine validates provenance. The LLM only assists with narrative explanation and report synthesis.

---

## Slide 4: Target Users & Use Cases
* **Primary Users:**
  - Digital Forensic Investigators (Law enforcement, private consulting)
  - Incident Response Teams (SOC tier-3, threat hunters)
  - Enterprise Security & Legal Compliance Units
  - Academic Researchers & Malware Analysts
* **Primary Use Cases:**
  - Host Endpoint Compromise Analysis
  - Malware Injection & Memory Introspection
  - Unauthorized Access & Event Log Timeline Reconstruction

> **Presenter Notes:**  
> Our primary users demand precision, auditability, and speed. They operate on dedicated forensic workstations on Linux and Windows.

---

## Slide 5: System Architecture
* **Frontend Layer:** React 19 + TypeScript (Strict Mode) + Tailwind CSS + Zustand
* **Desktop Wrapper:** Tauri (Rust) native window management with low RAM overhead
* **Backend Core Engine:** FastAPI (Python 3.14) REST API service
* **Persistence Layer:** SQLite with SQLAlchemy ORM (Relational mapping for cases, evidence, custody, findings)
* **Forensics Layer:** Platform-Aware Tool Registry mediating SleuthKit, Volatility 3, YARA, ExifTool

```text
[React Desktop UI] ──(Local REST)──▶ [FastAPI Backend Engine]
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
      [Integrity / Custody]        [Multi-Agent Planner]        [Platform Tool Registry]
               │                            │                            │
               ▼                            ▼                            ▼
      [SQLite Database]            [Verification Matrix]         [TSK / Volatility / YARA]
```

> **Presenter Notes:**  
> This diagram illustrates our clean decoupled architecture. The frontend communicates with the local FastAPI backend via typed REST contracts, which manages the database and coordinates tool execution safely.

---

## Slide 6: Technology Stack & Rationales
* **Desktop Shell: Tauri (Rust)**
  - *Why:* 30MB RAM footprint vs 300MB+ in Electron; native security sandbox.
* **Frontend: React 19 + TypeScript + Vite + Zustand**
  - *Why:* Type-safe UI state, fast compilation, modular component hierarchy.
* **Backend: Python 3.14 + FastAPI**
  - *Why:* Native compatibility with top forensic libraries and high-performance async API.
* **Database: SQLite + SQLAlchemy**
  - *Why:* Zero-configuration standalone desktop database with acid compliance.

> **Presenter Notes:**  
> Every technology choice was driven by desktop performance, security, and offline operability.

---

## Slide 7: Current Implementation (What Actually Works)
* **Operational Capabilities:**
  - Full Case Lifecycle (Create, List, Switch Active Investigation)
  - Streaming 8 MiB SHA-256 Hashing and Integrity Validation
  - Immutable Chain of Custody Audit Logging
  - Platform-Aware Tool Registry with Virtualenv Autodiscovery
  - Autonomous Investigation Planner & Task Priority Generation
  - SleuthKit Filesystem Artifact Extraction (`DiskAgent`)
  - Deterministic Multi-Source Correlation Engine
  - Provenance-Based Verification Matrix
  - 19-Section Court-Ready Markdown Report Generator
  - React Desktop UI with 5 Primary Views

> **Presenter Notes:**  
> Here is what is working in code right now: our end-to-end pipeline from evidence intake to 19-section reporting is fully functional and covered by unit, security, and integration test suites.

---

## Slide 8: Evidence Integrity & Chain-of-Custody Pipeline
* **Streaming Chunking:** Hashing reads evidence in 8 MiB ($8,388,608$ bytes) chunks.
* **RAM Guarantee:** Constant $O(1)$ memory usage during ingestion of 100GB+ disk images.
* **Immutability:** Original files are opened strictly in binary read mode (`rb`); modification is prevented.
* **Custody Log:** Every registration creates an immutable timestamped event with SHA-256 snapshot.

```text
Evidence File ──▶ Path Validation ──▶ 8MB Chunks ──▶ SHA-256 ──▶ Custody DB Record
```

> **Presenter Notes:**  
> In forensics, evidence integrity is non-negotiable. Our streaming hasher prevents out-of-memory crashes while guaranteeing cryptographic provenance.

---

## Slide 9: Multi-Agent Architecture
* **Agent Base Class Contract:** `can_handle()`, `plan()`, `analyze()`, `validate()`
* **Implemented Agents:**
  - `DiskAgent`: Interfaces with SleuthKit (`fls`) for filesystem tree extraction.
  - `PlannerAgent`, `CorrelationAgent`, `VerificationAgent`, `ReportAgent`: Backed by core algorithmic services.
* **Foundation/Stub Interfaces:**
  - `MemoryAgent` (Volatility 3), `MalwareAgent` (YARA), `LogAgent` (EVTX), `BrowserAgent`, `NetworkAgent`.

> **Presenter Notes:**  
> Our agent architecture establishes strict contracts. While specialist plugin loops for memory and malware are currently in interface/foundation state, the base agent contracts and DiskAgent are fully verified.

---

## Slide 10: LLM Architecture & AI Safety
* **Provider Abstraction:** `LLMProvider` interface with `LocalLLMProvider` and `GeminiProvider`.
* **Zero-Cost Baseline:** Runs locally without paid cloud subscriptions.
* **Strict Decoupling:** The LLM cannot execute tools directly or write to database findings.
* **Prompt Injection Defense:** Evidence content is passed strictly as enclosed, untrusted literal `DATA` blocks.

> **Presenter Notes:**  
> We treat all forensic evidence as untrusted data to prevent prompt injection. The LLM is an assistant for synthesis, not the source of truth.

---

## Slide 11: Security Architecture
* **Path Traversal Defense:** Rejects `..` patterns and null bytes; resolves canonical real path.
* **Subprocess Safety:** `shell=False` strictly enforced across all tool executions.
* **Process Timeouts:** Enforces execution caps (60–120s) to prevent denial of service.
* **Error Sanitization:** Global exception middleware suppresses raw stack traces.
* **Audit Trail:** Append-only security audit log (`data/security_audit.log`).

> **Presenter Notes:**  
> Security is embedded in every layer, from input validation to subprocess execution.

---

## Slide 12: Engineering Problems & Solutions
* **Problem 1: Memory spikes on multi-GB disk files.**
  - *Solution:* 8 MiB streaming chunked reader.
* **Problem 2: Shell injection vulnerabilities in tool adapters.**
  - *Solution:* Array-based subprocess execution with `shell=False` and strict timeouts.
* **Problem 3: Potential LLM hallucination of forensic IOCs.**
  - *Solution:* Deterministic Verification Engine checking ground-truth provenance.
* **Problem 4: Sensitive stack trace leakage in API responses.**
  - *Solution:* Global FastAPI exception handler logging traces to audit files.

> **Presenter Notes:**  
> We encountered several real engineering challenges during initial implementation and resolved them through deterministic controls.

---

## Slide 13: Current Project Status
* **Realistic Completion Metric:** **~68.8%** (Engineering Prototype)
* **Fully Implemented:** Core API, Database, Integrity Pipeline, Tool Registry, Planner, Correlation, Verification, 19-Section Reporting, Frontend Desktop UI.
* **In Progress / Foundation:** Specialist parser loops (Memory, Malware, Log), native OS packaging.

> **Presenter Notes:**  
> Based on weighted technical criteria, the project is approximately 68.8% complete. The foundation and core pipeline are solid; upcoming milestones will deepen tool parser integrations.

---

## Slide 14: Testing & Validation
* **Pytest Test Suite:** 12 / 12 Tests Passed (100%)
  - `test_investigation_pipeline.py` (End-to-end lifecycle)
  - `test_security.py` (Path traversal, null bytes, immutability)
  - `test_integrity.py` (8MB chunking, hash verification)
  - `test_tool_registry.py` (Platform discovery, safe fallback)
* **Frontend Build:** `npm run build` passes in 1.18s with **0 TypeScript errors**.

> **Presenter Notes:**  
> All core workflows and security boundaries are backed by automated tests that pass consistently.

---

## Slide 15: Remaining Work & Roadmap
* **Milestone 1:** Volatility 3 Memory Agent deep parser integration.
* **Milestone 2:** YARA Malware Agent rule bank and signature scanning.
* **Milestone 3:** EVTX Windows Event Log Parser Agent.
* **Milestone 4:** Interactive graphical incident timeline in React UI.
* **Milestone 5:** Linux and Windows standalone desktop installer packaging.

> **Presenter Notes:**  
> Our roadmap focuses on systematically implementing the remaining specialist agents and delivering native installers.

---

## Slide 16: Live Demo Workflow
1. **Initialize Investigation:** Create a new workspace (`Incident Case Alpha`).
2. **Ingest Evidence:** Ingest synthetic forensic artifact with streaming SHA-256 computation.
3. **Inspect Chain of Custody:** View cryptographic metadata and immutable audit event.
4. **Generate Plan:** Execute autonomous multi-agent task planner.
5. **Review Findings:** Inspect structured findings and execute deterministic correlation.
6. **Ground-Truth Verification:** Run verification engine to validate tool provenance.
7. **Synthesize Report:** Generate and export the complete 19-section Markdown report.

> **Presenter Notes:**  
> We will now demonstrate this exact working workflow live using synthetic test evidence.

---

## Slide 17: Conclusion & Next Milestone
* **Conclusion:** ADFIR establishes a reliable, evidence-driven desktop forensic platform combining rigorous cryptographic integrity with automated triage and court-ready reporting.
* **Next Immediate Deliverable:** Deepening Volatility 3 and YARA specialist agent execution.
* **Thank You!** Questions and Feedback Welcome.

> **Presenter Notes:**  
> Thank you for your time. We look forward to your questions and technical feedback.
