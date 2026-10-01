# ADFIR MemoryAgent — Production Forensic Specification

**Document Version:** 1.0.0  
**Status:** Step 3 Hardened Implementation  
**Module:** `agents/memory/memory_agent.py`  
**Tool Gateway:** `forensic_tools/volatility/adapter.py` &rarr; `PlatformAwareToolRegistry`

---

## 1. Role & Responsibility

The `MemoryAgent` is the specialist agent responsible for **extracting process structures, process hierarchies, and active network sockets from volatile physical RAM dumps**.

### Responsibilities
1. Receive and validate memory evidence records (`memory_dump`, `raw_memory`, `vmem`, `dmp`).
2. Execute approved Volatility 3 plugins exclusively through `PlatformAwareToolRegistry` (`shell=False`).
3. Parse Volatility 3 stdout with dedicated parsers (`PsListParser`, `PsTreeParser`, `NetScanParser`).
4. Separate extracted raw memory objects (**Artifacts**) from security-relevant anomalies (**Candidate Findings**).
5. Attach full execution provenance (`investigation_id`, `evidence_id`, `agent`, `tool`, `plugin`, `raw_output_reference`).
6. Feed verified findings into the `CorrelationEngine` and `VerificationEngine`.

### Explicit Prohibitions
* **NO LLM Narrative Fabrication:** Does not use an LLM to invent attack conclusions or classifications.
* **NO Evidence Mutation:** Source memory images are accessed strictly in read-only binary mode (`rb`).
* **NO Arbitrary Plugin Execution:** Only plugins in `ALLOWED_PLUGINS` are executable.

---

## 2. End-to-End Execution Dataflow

```text
User / API (POST /api/investigations/{id}/analysis/memory)
   │
   ▼
Validate Investigation & Evidence (Cross-Investigation Access Rejected)
   │
   ▼
MemoryAgent.analyze(evidence_item, plugin="windows.pslist")
   │
   ▼
VolatilityAdapter.execute_plugin() ──▶ PlatformAwareToolRegistry (shell=False, Timeout Cap)
                                              │
                                              ▼
                                    Volatility 3 Binary (vol -f <image> <plugin>)
                                              │
                                              ▼
File-Backed Raw Output Storage ◀── Dedicated Parsers ◀── ToolExecutionResult
   │
   ├──▶ Artifact Records (artifacts table: memory_process, memory_network_connection)
   └──▶ Candidate Finding Records (findings table: suspicious processes, external sockets)
   │
   ▼
Database Persistence + Chain of Custody + Security Audit Log Event
```

---

## 3. Supported Evidence & Plugins

* **Supported Evidence Formats:** `memory_dump` (Raw physical memory dumps, `.raw`, `.dmp`, `.vmem`, `.bin`).
* **Volatility 3 Framework Version:** `2.28.0` (located at `/home/nandireddy/ADFIR/volatility-env/bin/vol`).
* **Approved Plugin Allowlist:**
  - `windows.pslist`: Process enumeration (PID, PPID, ImageFileName, Offset, Threads, Handles, Session, Wow64, CreateTime).
  - `windows.pstree`: Hierarchical process tree with parent-child depth markers.
  - `windows.netscan`: Active listening and established TCP/UDP network connections.
  - `windows.malfind`: Injected code and suspicious memory range identification.

---

## 4. Dedicated Parsers Architecture

| Parser | Target Plugin | Output Model | Key Fields Captured |
| :--- | :--- | :--- | :--- |
| `PsListParser` | `windows.pslist` | `ParsedPsListEntry` | `pid`, `ppid`, `image_file_name`, `offset`, `threads`, `handles`, `create_time`, `exit_time` |
| `PsTreeParser` | `windows.pstree` | `ParsedPsTreeEntry` | `depth`, `pid`, `ppid`, `image_file_name`, `offset`, `threads`, `create_time` |
| `NetScanParser` | `windows.netscan` | `ParsedNetScanEntry` | `offset`, `proto`, `local_addr`, `local_port`, `foreign_addr`, `foreign_port`, `state`, `pid`, `owner` |

---

## 5. Artifact vs. Finding Distinction

* **Artifacts (`artifacts` table):**
  - Represents every enumerated process or network socket.
  - Examples: `System (PID 4)`, `smss.exe (PID 424)`, `svchost.exe listening on 0.0.0.0:135`.
* **Findings (`findings` table):**
  - Generated only when evidence supports suspicion:
    - Suspicious process execution (e.g. `mimikatz.exe`, `nc.exe`, `psexec.exe`).
    - Established network connection to public/external IP (e.g. `198.51.100.22:443`).
  - Flagged as `verification_status: "UNVERIFIED"` for subsequent deterministic verification.

---

## 6. Security Controls

1. **Cross-Investigation Access Blocking:** The API strictly verifies `evidence.investigation_id == id`.
2. **Plugin Allowlist Enforcement:** Disallows arbitrary plugin names or script injection via `ALLOWED_PLUGINS`.
3. **Subprocess Isolation:** `shell=False` strictly enforced with argument list `[vol_path, "-f", evidence_path, plugin_name]`.
4. **Evidence Immutability:** Original RAM dump is never modified or opened for writing.
5. **File-Backed Output Isolation:** Raw Volatility output is saved to `data/investigations/<id>/tool-output/<exec_id>.stdout`.
6. **Audit Logging:** Every memory analysis execution emits structured records to `data/security_audit.log`.

---

## 7. Known Limitations

* Live kernel symbols require active internet connection or local symbol directory (`volatility-env/symbols`); when offline, Volatility 3 uses local cached symbol tables.
* Full real memory integration tests require a compatible raw Windows memory image (synthetic tests validate parser and execution pipeline).
