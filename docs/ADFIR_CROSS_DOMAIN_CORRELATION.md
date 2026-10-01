# ADFIR — Cross-Domain Correlation Subsystem (Phase 2 / Step 14)

## 1. Subsystem Overview & Core Principles

The **Cross-Domain Correlation Subsystem** connects related normalized artifacts (Step 12, `NormalizedArtifact`) and timeline events (Step 13, `TimelineEvent`) across forensic domains (Filesystem, Memory, Network, Malware/Signatures, Logs, and Metadata) to produce auditable correlation groups (`ForensicCorrelationGroup`) and queryable relationship graphs (`ArtifactRelationship`).

```
                    ┌────────────────────────────┐
                    │ Step 12: Normalized        │
                    │ Artifacts (Entities)       │
                    └─────────────┬──────────────┘
                                  │
                                  ├────────────────────────────┐
                                  ▼                            ▼
                    ┌────────────────────────────┐    ┌────────────────────────────┐
                    │ Step 13: Unified Timeline  │    │ Step 14: Correlation       │
                    │ Events (UTC Chronology)    │───▶│ Engine                     │
                    └────────────────────────────┘    │  - Identifier Matcher      │
                                                      │  - Temporal Correlator     │
                                                      │  - Connected Component     │
                                                      │    Clustering              │
                                                      │  - Graph Builder           │
                                                      └─────────────┬──────────────┘
                                                                    │
                                                      ┌─────────────┴──────────────┐
                                                      ▼                            ▼
                                        ┌────────────────────────────┐┌────────────────────────────┐
                                        │ Artifact Relationships     ││ Forensic Correlation Groups│
                                        │ (Observable Edges)         ││ (Deterministic Clusters)   │
                                        └────────────────────────────┘└────────────────────────────┘
```

### Strict Forensic Boundaries
1. **Evidence-Derived Data, NOT Conclusions**: Relationships and correlation groups represent strictly observable, evidence-derived associations (shared cryptographic hashes, identical PIDs, network sockets linked to processes, temporal proximity, and logon accounts). They are **never** findings, incident conclusions, or attack hypotheses.
2. **NO Threat Interpretation or Attack Declaration**: The subsystem does **NOT**:
   - Declare attacks, breaches, or compromises.
   - Infer attacker tactics, techniques, procedures (TTPs), or intent.
   - Assign threat severity or maliciousness ratings (e.g. `CRITICAL`, `HIGH`).
   - Employ heuristic speculation or LLM reasoning.
3. **No Invented Relationships**: Relationships are established strictly when shared normalized identifiers or precise temporal bounds are verified across records.
4. **Immutability of Prior Subsystems**: Vault evidence, raw tool outputs, structured artifacts, normalized entities, and timeline events are strictly read-only and never modified during correlation.

---

## 2. Database Model & Schema Migration

### Table 1: `forensic_correlation_groups` (Alembic Revision `013_cross_domain_correlation_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `title` | String | No | Deterministic group summary (e.g. `Correlation Group: FILESYSTEM/MALWARE (9f86d081...)`) |
| `description` | Text | No | Objective summary of member counts and contributing domains |
| `member_artifact_ids` | JSON | No | Sorted list of participating `NormalizedArtifact` IDs |
| `member_event_ids` | JSON | No | Sorted list of participating `TimelineEvent` IDs |
| `relationship_ids` | JSON | No | Sorted list of member `ArtifactRelationship` IDs |
| `contributing_domains` | JSON | No | Sorted list of domains involved (`FILESYSTEM`, `MEMORY`, `NETWORK`, `MALWARE`, `LOGS`, etc.) |
| `source_evidence_ids` | JSON | No | Sorted list of all contributing evidence IDs |
| `confidence_score` | Float | No | Deterministic average confidence score across relationships |
| `provenance` | JSON | No | Aggregate provenance details and relationship types |
| `sha256_hash` | String(64) | No | Cryptographic SHA-256 hash of canonical group representation |
| `storage_path` | String | Yes | Isolated filesystem storage path |
| `created_at` | DateTime | No | UTC timestamp |

### Table 2: `artifact_relationships` (Alembic Revision `013_cross_domain_correlation_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `group_id` | String | Yes | Foreign key (`forensic_correlation_groups.id`, SET NULL) |
| `source_id` | String | No | Source entity/event ID |
| `source_type` | String | No | `NORMALIZED_ARTIFACT` or `TIMELINE_EVENT` |
| `source_domain` | String | No | Forensic domain (`FILESYSTEM`, `MEMORY`, `NETWORK`, etc.) |
| `target_id` | String | No | Target entity/event ID |
| `target_type` | String | No | `NORMALIZED_ARTIFACT` or `TIMELINE_EVENT` |
| `target_domain` | String | No | Forensic domain |
| `relationship_type` | String | No | Canonical relationship classification |
| `matching_identifier` | String | Yes | Extracted matching identifier value (hash, PID, IP, etc.) |
| `matching_field` | String | Yes | Property field name matched |
| `temporal_relationship` | JSON | Yes | Temporal details (`COINCIDENT`, `BEFORE`, `AFTER`, delta seconds) |
| `confidence_score` | Float | No | Deterministic confidence score (0.0 to 1.0) |
| `evidence_ids` | JSON | No | Sorted contributing evidence IDs |
| `provenance` | JSON | No | Dual-tier lineage trace for source and target |
| `sha256_hash` | String(64) | No | Cryptographic SHA-256 of canonical relationship payload |
| `storage_path` | String | Yes | Isolated filesystem storage path |
| `created_at` | DateTime | No | UTC timestamp |

---

## 3. Relationship Types & Confidence Scoring

Confidence scores are assigned strictly based on observable evidence quality and matching certainty, **never** threat severity:

| Relationship Type | Matching Criteria | Confidence | Domain Interaction |
| :--- | :--- | :--- | :--- |
| `FILE_HASH_MATCH` | Identical cryptographic SHA-256 or MD5 hash | **1.00** | Filesystem $\longleftrightarrow$ Malware / Signature hit, or cross-domain files |
| `MALWARE_TARGET_MATCH` | Filepath matches malware target file | **0.95** | Filesystem $\longleftrightarrow$ Malware hit |
| `PROCESS_MEMORY_MATCH` | Matching PID and process image name | **0.95** | Memory process $\longleftrightarrow$ Network socket / Event |
| `PROCESS_MEMORY_MATCH` | Matching PID only (e.g. socket owner PID) | **0.90** | Memory process $\longleftrightarrow$ Network socket |
| `USER_LOGON_MATCH` | Matching username on Windows logon event (Event 4624) | **0.95** | User account $\longleftrightarrow$ Windows Event Log |
| `BROWSER_NETWORK_MATCH` | Matching full URL or host between browser history and network socket | **0.95** | Browser $\longleftrightarrow$ Network connection |
| `BROWSER_NETWORK_MATCH` | Matching remote IP between browser and network socket | **0.90** | Browser $\longleftrightarrow$ Network connection |
| `SHARED_IDENTIFIER` | Identical external IP address | **0.90** | Cross-domain IP sharing |
| `SHARED_IDENTIFIER` | Identical domain or hostname | **0.85** | Cross-domain domain sharing |
| `SHARED_IDENTIFIER` | Identical full file path | **0.90** | Filesystem $\longleftrightarrow$ Metadata / Event |
| `SHARED_IDENTIFIER` | Identical username | **0.85** | Account $\longleftrightarrow$ Event / Process |
| `TEMPORAL_COINCIDENCE` | Timeline events occurring within $|t_1 - t_2| \le 5\text{s}$ | **0.85** | Any temporal pairs within 5 seconds |
| `TEMPORAL_SEQUENCE` | Timeline events occurring within $5\text{s} < |t_1 - t_2| \le W$ | **0.55 – 0.80** | Temporal pairs within correlation window $W$ (linear decay) |

---

## 4. Deterministic Grouping & Relationship Graph

### Correlation Groups (Connected Components)
- Entities connected by one or more relationships form an undirected graph.
- Deterministic connected components are computed using breadth-first traversal ordered by item ID.
- Each connected component containing $\ge 2$ items is formalized as a `ForensicCorrelationGroup`.
- Titles and descriptions strictly describe domain composition, member counts, and matching identifiers without declaring incidents or attacks.

### Queryable Relationship Graph
- **Nodes**: Represent `NormalizedArtifact` and `TimelineEvent` records with domain, entity type, labels, confidence, and group memberships.
- **Edges**: Represent `ArtifactRelationship` instances with relationship type, matching identifier, temporal metadata, and confidence.
- Supports multi-criteria filtering by `group_id`, `relationship_type`, `domain`, `evidence_id`, and `min_confidence`.

---

## 5. Storage Containment & Security

- **Storage Layout**:
  - Relationships: `data/storage/correlations/cases/{case_id}/relationships/{rel_id}.json`
  - Groups: `data/storage/correlations/cases/{case_id}/groups/{grp_id}.json`
- **File System Permissions**:
  - Directories: `0o700` (`drwx------`)
  - Files: `0o600` (`-rw-------`)
- **Evidence Vault Protection**:
  Storage path validation strictly prevents writing into `data/evidence/vault`.
- **RBAC & Multi-Tenant Case Isolation**:
  All endpoints require authenticated users with authorized case memberships. Cross-case access attempts are strictly rejected with HTTP 403 Forbidden.

---

## 6. REST API Reference

All routes are nested under `/api/v1/cases/{case_id}/correlations`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/correlations/generate` | Generates relationships and correlation groups for a case. |
| `GET` | `/cases/{case_id}/correlations/relationships` | Lists relationships with multi-criteria filtering (`relationship_type`, `domain`, `evidence_id`, `group_id`, `min_confidence`, pagination). |
| `GET` | `/cases/{case_id}/correlations/relationships/{relationship_id}` | Retrieves metadata and payload for a relationship. |
| `GET` | `/cases/{case_id}/correlations/relationships/{relationship_id}/integrity` | Verifies SHA-256 integrity and file consistency. |
| `GET` | `/cases/{case_id}/correlations/relationships/{relationship_id}/provenance` | Inspects end-to-end cryptographic lineage of both source and target. |
| `GET` | `/cases/{case_id}/correlations/groups` | Lists correlation groups with domain, evidence, and confidence filters. |
| `GET` | `/cases/{case_id}/correlations/groups/{group_id}` | Retrieves full group details including member artifacts, events, and edges. |
| `GET` | `/cases/{case_id}/correlations/groups/{group_id}/integrity` | Verifies group SHA-256 integrity. |
| `GET` | `/cases/{case_id}/correlations/graph` | Queries relationship graph (nodes, edges, groups) for traversal and visualization. |

---

## 7. Test Verification Summary

Validated with automated test coverage in [`backend/tests/test_cross_domain_correlation_subsystem.py`](file:///home/nandireddy/ADFIR/backend/tests/test_cross_domain_correlation_subsystem.py):

| Test Case | Verification Target | Status |
| :--- | :--- | :--- |
| `test_file_hash_and_malware_hit_correlation` | File hash ↔ Malware/YARA hit (hash match & target file match). | **PASSED** |
| `test_process_and_memory_artifact_correlation` | Process ↔ Memory network socket matching PID and process name. | **PASSED** |
| `test_user_and_logon_event_correlation` | User account ↔ Logon event 4624 matching username. | **PASSED** |
| `test_browser_and_network_artifact_correlation` | Browser URL/domain ↔ Network connection remote address. | **PASSED** |
| `test_temporal_correlation_coincidence_and_sequence` | Coincidence ($\le 5\text{s}$), sequence ($5\text{s} < \Delta t \le 60\text{s}$), and window exclusions. | **PASSED** |
| `test_shared_identifier_correlation` | Cross-domain shared external IP matching. | **PASSED** |
| `test_deterministic_relationship_generation_and_confidence` | Repeatability, canonical SHA-256 stability, evidence-based confidence. | **PASSED** |
| `test_correlation_grouping_and_connected_components` | Transitive connected components clustering, domain enumeration. | **PASSED** |
| `test_relationship_graph_construction` | Node and edge generation, queryable graph schema. | **PASSED** |
| `test_provenance_preservation_and_source_immutability` | 6-tier lineage trace and verification of read-only source records. | **PASSED** |
| `test_cryptographic_integrity_and_tamper_detection` | Valid SHA-256 verification and tamper detection. | **PASSED** |
| `test_storage_isolation_and_security` | Safe permissions (`0o600`/`0o700`) and evidence vault write prevention. | **PASSED** |
| `test_api_endpoints_and_rbac_idor_protection` | Full REST API test and cross-case IDOR rejection (403). | **PASSED** |
| `test_strict_forensic_boundaries_no_findings_no_conclusions` | Verification that no findings, severity, or attack claims are produced. | **PASSED** |

**Regression Suite Result**: 72/72 passed across Steps 10, 11, 12, 13, and 14.
