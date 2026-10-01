# ADFIR — Phase 2 / Step 4: Evidence Acquisition & Intake Subsystem Documentation

## 1. Subsystem Architecture Overview

The **Evidence Acquisition / Intake Subsystem** provides controlled, production-grade evidence intake, pre-flight safety verification, 2-phase atomic vault staging, recursive directory manifest generation, duplicate detection, and append-only hash-chained chain of custody tracking for the ADFIR platform.

```
+-----------------------------------------------------------------------------------+
|                            EVIDENCE INTAKE WORKFLOW                               |
+-----------------------------------------------------------------------------------+
|  1. Source Selection & Pre-Flight Validation                                      |
|     - Check path existence, readability, traversal rejection, null byte check     |
|     - Resource limits: File size (100GB), Dir size (500GB), File count (50000)   |
|     - Free disk space check in vault storage location                             |
|                                                                                   |
|  2. Deterministic Magic Byte Header Inspection                                   |
|     - Multi-signal header inspection (EVTX, SQLite, PE, ELF, PCAP, RAW, etc.)    |
|     - Magic byte signature reconciliation with declared evidence format            |
|                                                                                   |
|  3. Managed Vault Staging (2-Phase Atomic Copy)                                   |
|     - Stream copy to temporary part file while computing acquisition SHA-256      |
|     - Independent SHA-256 recalculation by re-reading staged vault disk copy     |
|     - Atomic move to final destination: data/evidence/vault/<case_id>/<ev_id>/    |
|     - Host OS read-only permissions applied (chmod 0o444 / FILE_ATTRIBUTE_READONLY)|
|                                                                                   |
|  4. Directory / Batch Acquisition Manifest Generation                            |
|     - Safe directory recursion with depth <= 20                                   |
|     - Generates structured manifest.json with per-file SHA-256 & relative paths  |
|     - Manifest JSON SHA-256 hash computed and sealed with read-only permissions   |
|                                                                                   |
|  5. Cryptographic Hash-Chained Chain of Custody                                  |
|     - Append-only event log with SHA-256 hash chaining                           |
|     - Events: EVIDENCE_SELECTED -> EVIDENCE_VALIDATED -> EVIDENCE_STORED ->       |
|               EVIDENCE_INTEGRITY_VERIFIED -> EVIDENCE_READY                       |
|     - Hash verification API detects any tampered block or broken link             |
+-----------------------------------------------------------------------------------+
```

---

## 2. API Specifications

### 2.1 Post Evidence Acquisition
- **Endpoint**: `POST /api/v1/evidence/cases/{case_id}/acquisitions`
- **Request Body**:
```json
{
  "source_path": "/path/to/evidence/item.evtx",
  "acquisition_type": "SINGLE_FILE", // SINGLE_FILE, DIRECTORY, DISK_IMAGE, MEMORY_DUMP, EVTX, BROWSER, PCAP
  "evidence_type": "WINDOWS_EVENT_LOG",
  "notes": "Intake note"
}
```
- **Response** (`201 Created` / `200 OK`):
Returns `EvidenceResponse` for single file, or `{ acquisition, manifest }` for directory acquisitions.

### 2.2 Get Acquisition Status
- **Endpoint**: `GET /api/v1/evidence/acquisitions/{acquisition_id}`

### 2.3 Get Directory Acquisition Manifest
- **Endpoint**: `GET /api/v1/evidence/acquisitions/{acquisition_id}/manifest`

### 2.4 Verify Chain of Custody Cryptographic Chain
- **Endpoint**: `GET /api/v1/evidence/{evidence_id}/custody/verify`
- **Response**:
```json
{
  "case_id": "...",
  "evidence_id": "...",
  "total_events": 5,
  "chain_valid": true,
  "tampered_event_id": null,
  "message": "Chain of custody verified intact across 5 events."
}
```

---

## 3. Database Schema Updates

- **Alembic Migration**: `backend/alembic/versions/003_evidence_acquisition_schema.py`
- **New Table**: `evidence_acquisitions`
- **New Foreign Key**: `evidence_items.parent_acquisition_id` -> `evidence_acquisitions.id`

---

## 4. Verification & Testing

- Comprehensive test suite: `backend/tests/test_evidence_acquisition_workflow.py`
- Full Pytest suite status: **289 / 289 tests passing**.
- Frontend build status: `npm run build` **Clean Success**.

