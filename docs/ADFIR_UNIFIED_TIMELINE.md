# ADFIR — Unified Investigation Timeline Subsystem (Phase 2 / Step 13)

## 1. Subsystem Overview & Core Principles

The **Unified Investigation Timeline Subsystem** converts timestamped normalized artifacts (`NormalizedArtifact`) from Step 12 into a chronologically ordered, tamper-evident, multi-tier provenance-backed unified UTC investigation timeline (`TimelineEvent`).

```
                    ┌────────────────────────────┐
                    │ Step 12: Normalized        │
                    │ Artifacts (Entities)       │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────┐
              │ Step 13: Unified Timeline Engine       │
              │  - Timestamp Normalization & UTC Conv. │
              │  - Timezone Preservation & Tracking    │
              │  - Temporal Windows & Precision Levels │
              │  - Deterministic Confidence Scoring    │
              │  - Deterministic Ordering Tie-Breaking │
              │  - Cryptographic Event Hashing         │
              │  - 6-Tier Forensic Lineage Chaining    │
              └───────────────────┬────────────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │ Unified Timeline Events    │
                    │ (Ordered Forensic Evidence)│
                    └────────────────────────────┘
```

### Strict Forensic Boundaries
1. **Evidence-Derived Temporal Data, NOT Conclusions**: Timeline events represent strictly observable, evidence-derived temporal records (file modifications, process creations, network socket connections, event log records). They are **NOT** conclusions, findings, or attacker storylines.
2. **NO Threat Interpretation or Attack Detection**: The timeline subsystem does **NOT**:
   - Detect attacks or breaches.
   - Infer attacker tactics, techniques, or procedures (TTPs).
   - Correlate disparate events into attack chains or execution flows.
   - Assign threat severity or maliciousness ratings.
   - Employ LLM or heuristic reasoning.
3. **No Invented Timestamps**: Artifacts without valid temporal data are **never** assigned synthetic, guessed, or current-time timestamps. If an artifact lacks timestamp information, zero timeline events are generated.
4. **Never Silently Assume a Timezone**: If a timestamp lacks timezone information, it is explicitly cataloged with `timezone_status="UNKNOWN"`, `timezone_source="MISSING_TIMEZONE"`, and its confidence score is penalized. Ambiguous timezone indicators are recorded as `timezone_status="AMBIGUOUS"`.
5. **Immutability of Prior Stages**: Underlying evidence items, execution workspaces, raw outputs, structured artifacts, and normalized entities are strictly immutable and never altered during timeline compilation.

---

## 2. Database Model & Schema Migration

### Table: `timeline_events` (Alembic Revision `012_unified_timeline_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `evidence_id` | String | Yes | Foreign key (`evidence_items.id`, SET NULL) |
| `execution_id` | String | Yes | Foreign key (`forensic_executions.id`, SET NULL) |
| `normalized_artifact_id` | String | No | Foreign key (`normalized_artifacts.id`, CASCADE) |
| `structured_artifact_id` | String | Yes | Foreign key (`structured_artifacts.id`, SET NULL) |
| `raw_output_id` | String | Yes | Foreign key (`execution_outputs.id`, SET NULL) |
| `event_type` | String | No | Canonical event classification (`PROCESS_ACTIVITY`, `NETWORK_CONNECTION`, `FILE_MODIFICATION`, etc.) |
| `event_source` | String | No | Tool/parser subsystem source identifier (`EVTX`, `PSLIST`, `NETSCAN`, `FLS`, etc.) |
| `timestamp_utc` | DateTime | No | Normalized UTC timestamp (indexed) |
| `original_timestamp` | String | No | Exact source timestamp string/repr |
| `original_timezone` | String | Yes | Captured timezone string or offset (`+05:30`, `UTC`, `EST`, etc.) |
| `timezone_offset_minutes` | Integer | Yes | Offset in minutes from UTC |
| `timezone_source` | String | No | Origin of timezone info (`EXPLICIT_OFFSET`, `INFERRED_FROM_STRING`, `ASSUMED_UTC_FALLBACK`, `MISSING_TIMEZONE`) |
| `timezone_status` | String | No | Quality status (`EXPLICIT`, `UTC`, `OFFSET_PROVIDED`, `UNKNOWN`, `AMBIGUOUS`) |
| `temporal_precision` | String | No | Granularity (`SUBSECOND`, `SECOND`, `MINUTE`, `HOUR`, `DATE_ONLY`, `WINDOW`) |
| `window_start_utc` | DateTime | Yes | Beginning of uncertainty boundary |
| `window_end_utc` | DateTime | Yes | End of uncertainty boundary |
| `confidence_score` | Float | No | Deterministic score (0.0 to 1.0) evaluating temporal certainty |
| `event_data` | JSON | No | Canonical event payload containing normalized entity fields |
| `sha256_hash` | String(64) | No | Cryptographic SHA-256 hash of canonical event representation |
| `storage_path` | String | Yes | Dedicated isolated filesystem storage path |
| `created_at` | DateTime | No | Subsystem creation timestamp |

---

## 3. Timestamp Normalization & Confidence Engine

### Supported Input Timestamp Formats
The `TimestampNormalizer` processes diverse forensic formats:
- **ISO-8601 / RFC-3339**: `2026-09-25T14:30:00Z`, `2026-09-25T19:30:00+05:00`
- **Unix Epoch Numeric**: Integer or float timestamps in seconds (`1790344800`), milliseconds (`1790344800000`), or microseconds (`1790344800000000`).
- **ExifTool Format**: `YYYY:MM:DD HH:MM:SS` (e.g. `2026:09:25 14:30:00+00:00`).
- **SleuthKit / Bodyfile**: Formatted datetime strings or integer seconds.
- **Date-Only**: `YYYY-MM-DD` expanded into 24-hour temporal window `[00:00:00Z, 23:59:59.999999Z]`.

### Deterministic Confidence Calculation
The confidence score quantifies timestamp provenance and precision without declaring maliciousness:

$$\text{Confidence} = \text{Base Precision Score} \times \text{Timezone Quality Multiplier}$$

1. **Base Precision Score**:
   - `SUBSECOND`: 1.0
   - `SECOND`: 0.95
   - `MINUTE`: 0.80
   - `HOUR`: 0.60
   - `DATE_ONLY`: 0.50
   - `WINDOW`: 0.50
2. **Timezone Quality Multiplier**:
   - `EXPLICIT`, `UTC`, `OFFSET_PROVIDED`: 1.0 (No penalty)
   - `UNKNOWN`: 0.6 (Explicit penalty for missing timezone)
   - `AMBIGUOUS`: 0.5 (Explicit penalty for non-standard timezone abbreviation)

---

## 4. Deterministic Ordering & Tie-Breaking

To eliminate non-deterministic chronological sorting across runs, databases, and platforms, events are strictly ordered by:

$$\text{ORDER BY } \texttt{timestamp\_utc ASC, confidence\_score DESC, id ASC}$$

1. **Primary**: Earliest UTC timestamp (`timestamp_utc ASC`).
2. **Secondary**: Highest temporal confidence (`confidence_score DESC`).
3. **Tertiary**: Deterministic UUID tie-breaker (`id ASC`).

---

## 5. 6-Tier Cryptographic Provenance Chaining

Every `TimelineEvent` records unbroken ancestry back to the raw physical evidence:

$$\text{EvidenceItem} \longrightarrow \text{ForensicExecution} \longrightarrow \text{ExecutionOutput} \longrightarrow \text{StructuredArtifact} \longrightarrow \text{NormalizedArtifact} \longrightarrow \text{TimelineEvent}$$

- Event SHA-256 is computed across canonicalized JSON fields:
  - `case_id`, `evidence_id`, `execution_id`, `normalized_artifact_id`
  - `event_type`, `event_source`, `timestamp_utc`, `temporal_precision`
  - `confidence_score`, `event_data`
- Tamper detection verifies current record hash against recalculation and stored filesystem artifact.

---

## 6. Storage Containment & Security

- **Path Template**:
  `data/storage/timeline/cases/{case_id}/{event_id}.json`
- **File System Permissions**:
  - Directories: `0o700` (`drwx------`)
  - Artifact files: `0o600` (`-rw-------`)
- **Evidence Vault Protection**:
  Explicit checks prevent any write into `data/evidence/vault`.
- **Multi-Tenant Case Isolation**:
  RBAC and case-scoped path resolution prevent cross-case IDOR leaks.

---

## 7. REST API Reference

All routes are nested under `/api/v1/cases/{case_id}/timeline`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/timeline/generate` | Generates timeline events for all normalized artifacts in the case. |
| `POST` | `/cases/{case_id}/executions/{execution_id}/timeline/generate` | Generates timeline events for an execution's normalized artifacts. |
| `POST` | `/cases/{case_id}/normalized-artifacts/{artifact_id}/timeline` | Generates timeline events for a single normalized artifact. |
| `GET` | `/cases/{case_id}/timeline` | Queries timeline events chronologically with filtering (`start_time`, `end_time`, `event_type`, `event_source`, `evidence_id`, `min_confidence`, pagination). |
| `GET` | `/cases/{case_id}/timeline/{event_id}` | Retrieves metadata and normalized payload for an event. |
| `GET` | `/cases/{case_id}/timeline/{event_id}/integrity` | Verifies cryptographic SHA-256 integrity and file consistency. |
| `GET` | `/cases/{case_id}/timeline/{event_id}/provenance` | Traces complete 6-tier lineage back to evidence and source tool. |
| `GET` | `/cases/{case_id}/timeline/{event_id}/download` | Downloads canonical serialized timeline event JSON artifact. |

---

## 8. Test Verification Summary

The subsystem is validated with comprehensive automated test coverage in [`backend/tests/test_unified_timeline_subsystem.py`](file:///home/nandireddy/ADFIR/backend/tests/test_unified_timeline_subsystem.py):

| Test Case | Verification Target | Status |
| :--- | :--- | :--- |
| `test_utc_conversion_and_timezone_preservation` | ISO, epoch, offset timezone conversions to UTC. | **PASSED** |
| `test_unknown_and_ambiguous_timezone_handling` | Non-assumed timezone fallback and penalty enforcement. | **PASSED** |
| `test_temporal_precision_and_windows` | Subsecond, second, minute, date-only window expansion. | **PASSED** |
| `test_no_invented_timestamps` | Artifacts without timestamps generate zero events. | **PASSED** |
| `test_chronological_ordering_and_deterministic_tie_breaking` | Strict tie-breaking by time, confidence, and ID. | **PASSED** |
| `test_event_source_and_multi_tier_provenance` | 6-tier unbroken cryptographic lineage check. | **PASSED** |
| `test_cryptographic_integrity_and_tamper_detection` | SHA-256 verification and tamper alerting. | **PASSED** |
| `test_source_immutability` | Confirmation that parent normalized artifacts remain unmodified. | **PASSED** |
| `test_storage_isolation_and_security` | Safe permissions (`0o600`/`0o700`) and vault isolation. | **PASSED** |
| `test_api_timeline_generation_and_filtering` | Generation endpoints and chronological query filters. | **PASSED** |
| `test_api_details_integrity_provenance_download` | Detail retrieval, integrity API, provenance API, download API. | **PASSED** |
| `test_rbac_and_cross_case_idor_protection` | Cross-case boundary isolation and IDOR rejection. | **PASSED** |
| `test_strict_forensic_boundaries_no_findings_no_conclusions` | Verification that events are purely descriptive temporal records. | **PASSED** |

**Regression Suite Result**: 58/58 passed across Steps 10, 11, 12, and 13.
