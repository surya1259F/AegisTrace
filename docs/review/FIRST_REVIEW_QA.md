# ADFIR — First Review Technical Q&A Guide

**Purpose:** Comprehensive, technically rigorous answers for evaluators during the first project review.  
**Rule:** Every answer reflects the actual implementation in the repository.

---

### 1. Why is ADFIR architected as a desktop application instead of a SaaS cloud web app?
**Answer:**  
Digital forensics involves raw multi-gigabyte disk and memory dumps that cannot easily or legally be uploaded across public cloud networks due to bandwidth constraints, legal evidence boundaries, data privacy regulations (GDPR/HIPAA), and confidentiality requirements. A native desktop application operates entirely on-premise, securing evidence locally via managed forensic evidence vaults, OS-level read-only filesystem protection, cryptographic integrity verification (SHA-256 pre/post analysis gates), and immutable chain-of-custody logging with zero cloud egress.

---

### 2. Why was Tauri chosen over Electron for the desktop wrapper?
**Answer:**  
Electron bundles Chromium and Node.js with every binary, resulting in heavy RAM usage (often 300MB–1GB+) and large installer sizes (150MB+). Tauri utilizes the operating system's native webview (WebKitGTK on Linux, WebView2 on Windows) and a lightweight Rust core. This keeps ADFIR's idle memory footprint under 40MB, which is critical when running resource-intensive forensic parsers on the same workstation.

---

### 3. Why React with TypeScript in Strict Mode for the frontend?
**Answer:**  
Forensic analysis interfaces display dense, multi-faceted data (timelines, hex offsets, inode references, confidence scores). React provides a component-driven architecture for rapid updates, while TypeScript in Strict Mode eliminates runtime type coercion errors and guarantees strict contract compliance between the frontend store (`investigationStore.ts`) and backend Pydantic schemas.

---

### 4. Why FastAPI for the backend core?
**Answer:**  
FastAPI provides high-performance asynchronous request handling via Starlette and ASGI, automatic data validation through Pydantic v2, and native OpenAPI/Swagger documentation. Its lightweight architecture is ideal for running as an embedded localhost desktop backend.

---

### 5. Why SQLite for the database instead of PostgreSQL or MongoDB?
**Answer:**  
SQLite is a zero-configuration, self-contained, ACID-compliant serverless database embedded directly inside the application. Digital forensic cases must be portable and self-contained; an investigator can archive an entire ADFIR case database (`adfir.db`) alongside the forensic image for long-term legal preservation without running an external database server.

---

### 6. Why Python for the core engine?
**Answer:**  
Python is the de facto standard in the digital forensics and incident response (DFIR) ecosystem. Industry-standard tools such as Volatility 3, Plaso, and EVTX parsers are written in or expose native bindings in Python, enabling seamless integration.

---

### 7. Why use multiple specialist agents instead of a single monolithic script?
**Answer:**  
Forensic investigation requires distinct domain specializations. A disk analyst, memory analyst, network engineer, and malware reverse engineer apply entirely different heuristics and tools. The multi-agent architecture (`BaseAgent` contract) modularizes these responsibilities, allowing `DiskAgent`, `MemoryAgent`, and `MalwareAgent` to be developed, tested, and scaled independently.

---

### 8. Why use an LLM at all if forensic tools provide the findings?
**Answer:**  
Forensic tools output thousands of raw, low-level technical strings (hex offsets, inode listings, packet dumps). Investigators need high-level synthesis: attack path reconstruction, executive summaries, MITRE ATT&CK technique mapping, and court-ready explanations. The LLM acts as an analytical reasoning assistant that translates verified facts into narrative reports.

---

### 9. How is LLM hallucination prevented in ADFIR?
**Answer:**  
The LLM is strictly decoupled from the source of truth. Findings must originate from deterministic tools (`fls`, `vol`, `yara`). Before reaching the report generator, findings pass through the `VerificationEngine`, which validates that each finding is anchored in a concrete byte offset or inode reference. The LLM is only permitted to reason over verified context, and reports strictly label `[FACT]` vs `[INFERENCE]`.

---

### 10. Can the LLM modify original evidence or database findings?
**Answer:**  
**No.** The LLM has zero direct database write permissions and no filesystem write access to evidence. In ADFIR, evidence files are opened strictly in read-only binary mode (`rb`), and findings are created by specialist agent tool runs.

---

### 11. Can the LLM execute arbitrary shell commands?
**Answer:**  
**No.** Tool execution is strictly mediated by the `PlatformAwareToolRegistry`. The registry only invokes registered binary paths, passes arguments as discrete sanitised arrays, and enforces `shell=False` and timeout limits. The LLM cannot inject arbitrary shell commands.

---

### 12. How is the Chain of Custody maintained?
**Answer:**  
Upon evidence intake, an immutable record is inserted into the `chain_of_custody_events` table in SQLite. It records the UTC timestamp, user actor (`local-user`), event type (`EVIDENCE_REGISTERED`), description, source path, and the cryptographic SHA-256 hash. The audit log is append-only.

---

### 13. How is evidence integrity calculated and verified?
**Answer:**  
Integrity is calculated via `backend/app/services/integrity.py` using streaming SHA-256 in strict 8 MiB chunks ($8,388,608$ bytes). When re-verification is requested, the file is re-streamed and compared against the stored hash. If any byte differs, the state changes to `INTEGRITY_COMPROMISED`.

---

### 14. How are forensic tools executed safely?
**Answer:**  
1. All executions use `subprocess.run(cmd, shell=False, timeout=timeout_seconds)`.
2. Paths and arguments are validated before execution.
3. Subprocess execution times out automatically if the process hangs.
4. Execution results (`stdout`, `stderr`, `return_code`, `execution_time_ms`) are captured in structured `ToolExecutionResult` models.

---

### 15. How is path traversal prevented during evidence intake?
**Answer:**  
`SecurityValidator.validate_and_canonicalize_path` in `backend/app/core/security.py`:
- Rejects any path string containing `..` or null bytes (`\0`).
- Resolves the absolute canonical target using `os.path.realpath`.
- Validates that the target exists and is a regular file before proceeding.

---

### 16. What happens if an evidence file is modified on disk after ingestion?
**Answer:**  
The `verify_sha256` integrity service recalculates the streaming hash and detects the checksum mismatch immediately, returning `{"valid": False, "expected_hash": ..., "actual_hash": ...}` and logging a critical security event to `data/security_audit.log`.

---

### 17. How does the architecture support Windows?
**Answer:**  
All backend filesystem logic uses Python's standard `pathlib` and `os.sep`, avoiding Linux-only slash assumptions. The `PlatformAwareToolRegistry` detects `sys.platform` and resolves Windows binaries (`fls.exe`, `yara.exe`, `vol.exe`). The Tauri frontend uses WebView2 on Windows. Producing the Windows installer requires running cargo on a Windows runner.

---

### 18. Why is enterprise multi-user RBAC not implemented in v0.1?
**Answer:**  
ADFIR v0.1 focuses on the core forensic workstation engine: streaming cryptographic integrity, tool execution, multi-agent planning, and verification. Digital forensics workstations are traditionally dedicated single-user local systems. Multi-user enterprise RBAC and central server authentication are scheduled for Phase 17.

---

### 19. What is currently incomplete in the codebase?
**Answer:**  
1. Host deployment of binary packages (`sleuthkit`, `yara`, `exiftool`).
2. Specialist agent execution loops for `MemoryAgent`, `MalwareAgent`, `LogAgent`, `BrowserAgent`, and `NetworkAgent` are currently structured interfaces/stubs returning empty lists pending deep plugin binding.
3. Linux/Windows standalone installer CI/CD packaging.

---

### 20. What is the next immediate development milestone?
**Answer:**  
Connecting `MemoryAgent` to live Volatility 3 execution (`windows.pstree`, `windows.netscan`, `windows.malfind`) and embedding a curated YARA rule bank in `MalwareAgent` to demonstrate multi-source memory and binary triage.
