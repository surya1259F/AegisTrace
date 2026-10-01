# ADFIR DiskAgent — Production Forensic Specification

**Document Version:** 1.0.0  
**Status:** Step 2 Hardened Implementation  
**Module:** `agents/disk/disk_agent.py`  
**Tool Gateway:** `forensic_tools/sleuthkit/adapter.py` &rarr; `PlatformAwareToolRegistry`

---

## 1. Role & Responsibility

The `DiskAgent` is the specialist agent responsible for **extracting volume, partition, and filesystem artifacts from disk-oriented digital evidence**.

### Responsibilities
1. Receive and validate disk-oriented evidence records (`disk_image`, `file`, `filesystem_image`).
2. Execute approved Sleuth Kit operations exclusively through the `PlatformAwareToolRegistry` (`shell=False`).
3. Parse raw tool output with the dedicated `FlsParser`.
4. Separate extracted raw filesystem objects (**Artifacts**) from security-relevant anomalies (**Candidate Findings**).
5. Attach complete cryptographic and execution provenance to every record.
6. Feed verified findings into the `CorrelationEngine` and `VerificationEngine`.

### Explicit Prohibitions
* **NO LLM Narrative Invention:** The agent does not fabricate facts or generate narrative conclusions.
* **NO Evidence Mutation:** Source evidence is opened strictly in read-only binary mode (`rb`).
* **NO Arbitrary Commands:** Tool execution is mediated exclusively via registered binaries in the Tool Registry.

---

## 2. End-to-End Execution Dataflow

```text
User / API (POST /api/investigations/{id}/analysis/disk)
   │
   ▼
Validate Investigation & Evidence (Cross-Investigation Access Rejected)
   │
   ▼
DiskAgent.analyze(evidence_item)
   │
   ▼
SleuthKitAdapter.execute_fls(evidence_path, -r, -p)
   │
   ▼
PlatformAwareToolRegistry (shell=False, Timeout Cap)
   │
   ▼
Sleuth Kit Binary (fls)
   │
   ▼
ToolExecutionResult (return_code, stdout, stderr, execution_time_ms)
   │
   ▼
Save File-Backed Raw Output (data/investigations/<id>/tool-output/<exec_id>.stdout)
   │
   ▼
FlsParser.parse(stdout)
   │
   ├──▶ Artifacts (All discovered files, directories, virtual entries)
   └──▶ Candidate Findings (Deleted files, executables in unusual paths)
   │
   ▼
Database Persistence (artifacts & findings tables) + Audit Log Event
```

---

## 3. Supported Evidence Types

* `disk_image` (Raw `dd`, `img`, `raw`, `E01`)
* `filesystem_image` (Partition images: `FAT12`, `FAT16`, `FAT32`, `NTFS`, `ext2/3/4`)
* `file` (Supported filesystem container files)

*Unsupported types (e.g. `memory_dump`, `network_capture`) return `UNSUPPORTED_EVIDENCE_TYPE` without guessing.*

---

## 4. Sleuth Kit Output Parser (`FlsParser`)

The `FlsParser` parses standard Sleuth Kit `fls` formatted output lines:
```text
r/r 3:    NORMAL.TXT
r/r * 4:  _VIL.BAT
d/d 12:   Windows
v/v 32691: $MBR
```

### Extracted Attributes
* `entry_type_raw`: Raw type tag (e.g. `r/r`, `d/d`, `v/v`).
* `entry_type`: Normalized category (`file`, `directory`, `virtual`, `symlink`, `device`).
* `is_deleted`: `True` if `*` is present in the line.
* `inode`: Inode or MFT record number (e.g. `3`, `4`, `14920`).
* `file_path`: Path or filename.
* `raw_line`: Unmodified line reference.

---

## 5. Artifact vs. Finding Separation

| Concept | Database Table | Purpose | Example |
| :--- | :--- | :--- | :--- |
| **Artifact** | `artifacts` | Comprehensive inventory of every extracted filesystem object. | Allocated file `NORMAL.TXT` at inode 3. |
| **Finding** | `findings` | Security-relevant candidate anomalies flagged for investigator review. | Deleted executable `_VIL.BAT` at inode 4. |

---

## 6. Forensic Provenance & Raw Output Storage

Every extracted artifact and finding includes:
* `investigation_id` & `evidence_id`
* `agent`: `"DiskAgent"`
* `tool`: `"SleuthKit"`
* `tool_version`: `"The Sleuth Kit ver 4.12.1"`
* `source_reference`: `"inode:<number>"`
* `raw_output_reference`: File path reference `data/investigations/<id>/tool-output/<exec_id>.stdout:<inode>`

---

## 7. Security Controls

1. **Cross-Investigation Access Prohibition:** Rejects requests where `evidence.investigation_id != requested_investigation_id`.
2. **Subprocess Isolation:** `shell=False` strictly enforced; arguments passed as array `["-r", "-p"]`.
3. **Evidence Immutability:** Original disk file is never opened for writing; timestamps and file size remain unchanged.
4. **Error Sanitization:** Structured error states (`TOOL_EXECUTION_FAILED`, `TOOL_UNAVAILABLE`, `INVALID_EVIDENCE_PATH`).
5. **Audit Logging:** Every execution logs structured events to `data/security_audit.log`.

---

## 8. Test Coverage

* **Unit Tests (`tests/test_disk_agent.py`):** Parser accuracy, malformed input handling, evidence type validation, synthetic disk execution.
* **Integration Tests (`tests/test_disk_forensics_integration.py`):** Full end-to-end pipeline (Case $\rightarrow$ Evidence $\rightarrow$ Disk Analysis $\rightarrow$ Artifacts $\rightarrow$ Findings $\rightarrow$ Correlation $\rightarrow$ Verification $\rightarrow$ Report).
* **Security Tests (`tests/test_disk_security.py`):** Cross-investigation rejection, invalid path handling, immutability assertion.
