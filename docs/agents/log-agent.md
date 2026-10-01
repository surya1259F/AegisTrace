# ADFIR LogAgent — Production Forensic Specification

**Document Version:** 1.1.0  
**Status:** Step 5 Hardened Implementation  
**Module:** `agents/log/log_agent.py`  
**Parser Library:** `python-evtx` (v0.8.1) & `SecurityEventParser`  
**Parser Modules:** `agents/log/parsers/evtx_parser.py`, `agents/log/parsers/security_events.py`

---

## 1. Role & Responsibility

The `LogAgent` is the specialist agent responsible for **parsing Windows Event Logs (`.evtx`) and XML event exports to extract authentication, process execution, privilege assignment, account management, and service installation events**.

### Responsibilities
1. Receive and validate Windows event log evidence (`.evtx`, XML exports).
2. Stream binary EVTX records safely using `python-evtx` (`Evtx.Evtx`) without loading full multi-gigabyte logs into memory.
3. Parse XML records using `SecurityEventParser` to extract normalized fields (Event ID, Record ID, timestamp, user, domain, target user, target domain, group name, member name, process, IP, port, logon type).
4. Strictly separate all parsed records (**Artifacts**) from security-relevant observations (**Findings**).
5. Attach complete record-level provenance (`investigation_id`, `evidence_id`, `agent`, `tool`, `record_id`, `event_id`, `raw_output_reference`).
6. Feed verified findings into the `CorrelationEngine` and `VerificationEngine`.

### Explicit Prohibitions
* **NO LLM Interpretation or Hallucination:** Events are extracted and structured deterministically; no LLM is used to invent attacks or attacker identities.
* **NO Premature Threat Conclusions:** A failed logon (4625), account creation (4720), or process creation (4688) is an evidence-backed observation, never automatically labeled "Confirmed Attacker Compromise".
* **NO Evidence Mutation:** Source event logs are opened strictly in read-only binary mode (`rb`).

---

## 2. Supported Event IDs & Normalized Schema

| Event ID | Description | Normalized Category | Key Extracted Fields |
| :--- | :--- | :--- | :--- |
| **4624** | Successful Logon | `logon_success` | `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `IpPort` |
| **4625** | Failed Logon | `logon_failure` | `TargetUserName`, `TargetDomainName`, `Status`, `SubStatus`, `IpAddress` |
| **4672** | Special Privileges Assigned | `special_privilege_assigned` | `SubjectUserName`, `SubjectDomainName`, `PrivilegeList` |
| **4688** | Process Creation | `process_creation` | `NewProcessName`, `CommandLine`, `SubjectUserName`, `ParentProcessName`, `NewProcessId` |
| **4697** | Service Installed (Security) | `service_installed` | `ServiceName`, `ServiceFileName`, `ServiceType`, `SubjectUserName` |
| **4720** | User Account Created | `account_created` | `TargetUserName`, `TargetDomainName`, `SubjectUserName`, `SubjectDomainName` |
| **4728** | Member Added to Global Group | `global_group_member_added` | `TargetUserName` (Group), `MemberName`, `SubjectUserName` |
| **4732** | Member Added to Local Group | `local_group_member_added` | `TargetUserName` (Group), `MemberName`, `SubjectUserName` |
| **7045** | Service Installed (System) | `service_installed` | `ServiceName`, `ImagePath`, `ServiceType`, `AccountName` |

---

## 3. Artifact vs. Finding Distinction

* **Artifacts (`artifacts` table):**
  - Stored for all parsed event records.
  - Types: `windows_logon_event`, `windows_process_creation`, `windows_service_installation`, `windows_privilege_assignment`, `windows_account_change`, `windows_group_membership_change`, `windows_event`.
  - Source Reference: `record:<record_id>:eid:<event_id>`.
* **Findings (`findings` table):**
  - Generated only when an event warrants forensic observation:
    - Failed logon attempts (4625).
    - Privileged logon sessions (4672).
    - User account creation (4720).
    - Group membership changes (4728 / 4732).
    - Diagnostic/admin process executions (4688) with command lines.
    - Service installation events (4697 / 7045).
  - Status: Initialized to `verification_status: "UNVERIFIED"`.

---

## 4. Security Controls

1. **Cross-Investigation Access Blocking:** The API verifies `evidence.investigation_id == id` (HTTP 400 on mismatch).
2. **Evidence Immutability:** Event log files are opened in read-only mode (`rb`).
3. **Subprocess / Script Isolation:** Uses pure-python `python-evtx` and Python standard library `xml.etree.ElementTree`.
4. **File-Backed Output Isolation:** Raw event summaries are stored in `data/investigations/<id>/tool-output/<exec_id>.stdout`.
5. **Audit Logging:** Every log analysis execution emits structured records to `data/security_audit.log`.

---

## 5. Known Limitations

* Live Windows ETW real-time event streaming is out of scope; LogAgent operates on static `.evtx` / XML dump evidence files.
* Real binary EVTX test coverage requires local synthetic/captured EVTX fixtures; representative XML exports validate record schema processing.
