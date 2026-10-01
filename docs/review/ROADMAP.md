# ADFIR — Product & Engineering Implementation Roadmap

This roadmap defines the ordered implementation sequence for subsequent development milestones.

---

### Phase 1: Real Forensic Tool Installation & Validation
* **Objective:** Deploy and validate host-level binary packages for Linux and Windows.
* **Scope:**
  - Verify system packages: `sleuthkit`, `yara`, `exiftool`, `volatility3`.
  - Validate tool discovery in `PlatformAwareToolRegistry`.
  - Create synthetic test images for each tool parser.

---

### Phase 2: Complete DiskAgent
* **Objective:** Deepen disk filesystem parsing and deleted file carving.
* **Scope:**
  - Implement partition table reading (`mmls`) and inode extraction (`fls`).
  - Add deleted file carving (`icat`) and timeline generation (`mactime`).
  - Unit and integration tests for raw, dd, and E01 disk images.

---

### Phase 3: Complete MemoryAgent with Volatility 3
* **Objective:** Implement automated memory forensics on raw RAM dumps.
* **Scope:**
  - Execute `windows.pstree`, `windows.pslist`, and `windows.cmdline`.
  - Execute `windows.netscan` and `windows.netstat` for network sockets.
  - Execute `windows.malfind` and `windows.vadinfo` for injected code detection.
  - Parse Volatility tabular/JSON output into structured finding models with memory offsets (`offset:0x...`).

---

### Phase 4: Complete MalwareAgent with YARA
* **Objective:** Implement binary and memory signature matching.
* **Scope:**
  - Integrate curated initial YARA rule repository (CobaltStrike, webshells, ransomware strings, mimikatz).
  - Scan files, carved disk sectors, and memory regions.
  - Generate structured findings with rule tags and string offset matches.

---

### Phase 5: Complete LogAgent
* **Objective:** Parse Windows Event Logs (`.evtx`) and Linux syslog.
* **Scope:**
  - Implement `python-evtx` parser for Security (Event IDs: 4624, 4625, 4688, 7045, 1102).
  - Extract process executions, logon failures, and service installations.
  - Generate chronologically sorted finding events.

---

### Phase 6: Complete BrowserAgent
* **Objective:** Extract web navigation, search queries, and download histories.
* **Scope:**
  - Parse SQLite databases for Chrome, Edge, and Firefox (`History`, `Cookies`, `Downloads`).
  - Extract user download locations and correlate with dropped executable findings.

---

### Phase 7: Complete NetworkAgent
* **Objective:** Parse PCAP/PCAPNG network packet captures.
* **Scope:**
  - Dissect protocol hierarchies, DNS queries, and TLS server names (SNI).
  - Correlate external IP connections with memory/process findings.

---

### Phase 8: Connect Planner &rarr; Agent &rarr; Tool &rarr; Scheduler
* **Objective:** Deepen end-to-end autonomous dispatching.
* **Scope:**
  - Wire `InvestigationPlanner` output directly into `TaskScheduler` execution queue.
  - Dynamic agent dispatching based on hardware capacity slots.

---

### Phase 9: Structured Finding Pipeline Enhancements
* **Objective:** Standardize finding taxonomy across all tools.
* **Scope:**
  - Enforce common schema: `FindingType`, `Agent`, `Tool`, `Confidence`, `EvidenceReference`, `RawOutput`.
  - Support multi-reference findings (e.g. Inode + Memory Offset + IP).

---

### Phase 10: Advanced Correlation & Verification
* **Objective:** Expand causal graph clustering and truth calibration.
* **Scope:**
  - Cross-source temporal alignment ($\pm 5$ second sliding window).
  - Multi-hypothesis conflict resolution (flagging conflicting findings).

---

### Phase 11: Controlled LLM Reasoning Integration
* **Objective:** Connect local and cloud reasoning models with strict safety bounds.
* **Scope:**
  - Wire `LocalLLMProvider` to local Ollama / llama.cpp instances.
  - Structured prompt templating with verified finding matrices.

---

### Phase 12: Attack Path Reconstruction & MITRE ATT&CK Mapping
* **Objective:** Automate tactical attack progression mapping.
* **Scope:**
  - Map verified finding chains to MITRE ATT&CK Enterprise Matrix (Initial Access &rarr; Execution &rarr; Persistence &rarr; C2 &rarr; Exfiltration).

---

### Phase 13: Report Generation Refinements
* **Objective:** Enhance court-ready reporting and multi-format exports.
* **Scope:**
  - Add PDF generation with cryptographic report hashing.
  - Executive summary customization and investigator sign-off fields.

---

### Phase 14: Security Hardening & Resource Isolation
* **Objective:** Harden process execution against malicious evidence exploits.
* **Scope:**
  - Linux seccomp/AppArmor isolation for tool subprocesses.
  - Enforce cgroup memory caps and CPU quotas.

---

### Phase 15: Linux Native Packaging
* **Objective:** Build standalone Linux distribution packages.
* **Scope:**
  - Tauri `.deb` and `.AppImage` bundle generation.
  - Bundled python runtime and tool wrappers.

---

### Phase 16: Windows CI/CD & Installer
* **Objective:** Deliver native Windows desktop installer.
* **Scope:**
  - GitHub Actions Windows runner (`x86_64-pc-windows-msvc`).
  - Tauri `.msi` / `.exe` installer packaging with WebView2 bootstrapper.

---

### Phase 17: Enterprise Authentication & RBAC
* **Objective:** Multi-user enterprise support for shared forensic labs.
* **Scope:**
  - Role-Based Access Control (Admin, Lead Investigator, Analyst, Auditor).
  - SQLCipher encrypted case database at rest.
