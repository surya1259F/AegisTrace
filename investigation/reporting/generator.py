from typing import Dict, Any, List
from datetime import datetime, timezone

class ReportGenerator:
    """
    Comprehensive 19-Section Forensically Sound DFIR Report Generator.
    Strictly distinguishes [FACT], [INFERENCE], and [UNVERIFIED].
    Reports 'INSUFFICIENT EVIDENCE' when findings lack concrete data backing.
    """

    def generate_report(
        self,
        investigation: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        custody_events: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        correlated_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        inv_name = investigation.get("name", "Investigation Case")
        inv_id = investigation.get("id", "N/A")
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        has_evidence = len(evidence_items) > 0
        has_findings = len(findings) > 0

        # Build timeline
        timeline = []
        for f in findings:
            raw_t = f.get("timestamp") or f.get("created_at")
            t = str(raw_t) if raw_t else "NOT_RECORDED"
            timeline.append({
                "timestamp": t,
                "event": f.get("title"),
                "tool": f.get("tool"),
                "evidence_ref": f.get("evidence_reference")
            })

        # Build IOCs — extracted strictly from verified evidence-backed finding details
        _IOC_FIELD_TYPE_MAP = {
            "ip_address":    "IP_ADDRESS",
            "c2_domain":     "DOMAIN",
            "domain":        "DOMAIN",
            "url":           "URL",
            "sha256":        "HASH_SHA256",
            "md5":           "HASH_MD5",
            "file_name":     "FILE_NAME",
            "process_name":  "PROCESS_NAME",
        }
        iocs = []
        for f in findings:
            has_provenance = bool(
                f.get("evidence_reference")
                or f.get("supporting_evidence_ids")
                or f.get("evidence_id")
                or f.get("supporting_artifact_ids")
                or f.get("artifact_id")
                or f.get("execution_id")
                or f.get("output_id")
            )
            if not has_provenance:
                continue
            title = f.get("title", "")
            details = f.get("details") or {}
            for field, ioc_type in _IOC_FIELD_TYPE_MAP.items():
                value = details.get(field)
                if value:
                    iocs.append({"type": ioc_type, "value": str(value), "context": title})

        # 19 Sections Markdown Generator
        md = [
            f"# ADFIR DIGITAL FORENSIC INVESTIGATION REPORT",
            f"**Investigation Name:** {inv_name}  ",
            f"**Investigation ID:** `{inv_id}`  ",
            f"**Date Generated:** {now_str}  ",
            f"**Status:** {investigation.get('status', 'OPEN')}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"[FACT] Investigation initialized with {len(evidence_items)} registered evidence artifact(s). "
            f"[FACT] Deterministic analysis produced {len(findings)} structured finding(s) with {len(correlated_events)} correlated chain(s).",
            "",
            "## 2. Investigation Overview",
            f"Scope: {investigation.get('description') or 'Comprehensive digital forensic triage and attack path reconstruction.'}",
            "",
            "## 3. Evidence Inventory",
            "| Item Name | Type | Size (Bytes) | SHA-256 Hash | Integrity |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        if evidence_items:
            for e in evidence_items:
                md.append(f"| {e.get('name')} | `{e.get('evidence_type')}` | {e.get('size_bytes', 0):,.0f} | `{e.get('sha256')}` | {e.get('integrity_status') or 'UNKNOWN'} |")
        else:
            md.append("| None | - | - | - | INSUFFICIENT EVIDENCE |")

        md.extend([
            "",
            "## 4. Chain of Custody",
            "| Timestamp (UTC) | Event Type | Actor | Description | Hash Snapshot |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        if custody_events:
            for c in custody_events:
                md.append(f"| {c.get('timestamp')} | `{c.get('event_type')}` | {c.get('actor')} | {c.get('description')} | `{str(c.get('sha256', 'N/A'))[:16]}...` |")
        else:
            md.append(
                "| N/A | NOT_RECORDED | NOT_RECORDED | "
                "INSUFFICIENT EVIDENCE — no chain-of-custody events recorded. | N/A |"
            )

        md.extend([
            "",
            "## 5. Investigation Methodology",
            "- **Cryptographic Integrity:** SHA-256 streaming hashing in 8 MiB chunks.",
            "- **Rule-Based Correlation:** Multi-source linking without stochastic hallucination.",
            "- **Verification Engine:** Provenance validation against raw tool output references.",
        ])

        # Build tool list from actual execution records in findings
        recorded_tools = sorted({f.get("tool") for f in findings if f.get("tool")})
        if recorded_tools:
            md.append("- **Deterministic Tool Adapters (recorded):** " + ", ".join(recorded_tools) + ".")
        else:
            md.append("- No specialist tool executions are recorded for this investigation.")

        md.extend([
            "",
            "## 6. Incident Timeline",
        ])

        if timeline:
            for ev in timeline:
                md.append(f"- **{ev['timestamp']}** — [{ev['tool']}] {ev['event']} (Ref: `{ev['evidence_ref']}`)")
        else:
            md.append("*[FACT] INSUFFICIENT EVIDENCE: No timestamped events extracted.*")

        md.extend([
            "",
            "## 7. Forensic Findings",
        ])

        if findings:
            for f in findings:
                status_tag = f"[{f.get('verification_status', 'UNVERIFIED')}]"
                conf = f"{f['confidence']*100:.0f}%" if f.get('confidence') is not None else "Unscored"
                md.append(f"### {status_tag} {f.get('title')}")
                md.append(f"- **Agent / Tool:** `{f.get('agent')}` / `{f.get('tool')}`")
                md.append(f"- **Category:** `{f.get('finding_type')}`")
                md.append(f"- **Confidence:** {conf}")
                md.append(f"- **Evidence Ref:** `{f.get('evidence_reference')}`")
                md.append(f"- **Description:** {f.get('description')}")
                md.append("")
        else:
            md.append("*INSUFFICIENT EVIDENCE: No findings recorded.*")

        md.extend([
            "## 8. Evidence References",
            "Finding references are reported from the provenance recorded by the investigation pipeline. Missing provenance is explicitly marked as UNKNOWN or INSUFFICIENT EVIDENCE.",
            "",
            "## 9. Attack Classification",
            "[INFERENCE] Attack classification requires investigator review of the attached findings. No automated classification is applied." if has_findings else "[FACT] INSUFFICIENT EVIDENCE: No attack classification possible.",
            "",
            "## 10. MITRE ATT&CK Mapping",
            "| Tactic | Technique ID | Technique Name | Supporting Finding |",
            "| :--- | :--- | :--- | :--- |",
        ])

        # Collect MITRE techniques from actual findings only
        mitre_rows = []
        for f in findings:
            techniques = f.get("mitre_techniques") or f.get("mitre_attack") or []
            if isinstance(techniques, list):
                for t in techniques:
                    tactic = t.get("tactic", "N/A")
                    tid = t.get("technique_id", "N/A")
                    tname = t.get("technique_name", "N/A")
                    mitre_rows.append(f"| {tactic} | {tid} | {tname} | {f.get('title', '')} |")
            elif isinstance(techniques, dict):
                tactic = techniques.get("tactic", "N/A")
                tid = techniques.get("technique_id", "N/A")
                tname = techniques.get("technique_name", "N/A")
                mitre_rows.append(f"| {tactic} | {tid} | {tname} | {f.get('title', '')} |")

        if mitre_rows:
            for row in mitre_rows:
                md.append(row)
        else:
            md.append("| INSUFFICIENT EVIDENCE | N/A | INSUFFICIENT EVIDENCE: No verified MITRE mapping recorded | - |")

        md.extend([
            "",
            "## 11. Confidence Assessment",
            "Overall Confidence: INVESTIGATOR REVIEW REQUIRED" if has_findings else "Overall Confidence: INSUFFICIENT EVIDENCE",
            "",
            "## 12. Correlation Graph",
        ])

        if correlated_events:
            for ce in correlated_events:
                md.append(f"- **{ce.get('title')}**: {ce.get('description')}")
        else:
            md.append("*INSUFFICIENT EVIDENCE: No cross-source correlations recorded.*")

        md.extend([
            "",
            "## 13. Root Cause Analysis",
            "[INFERENCE] Root cause analysis requires investigator review. See forensic findings for evidence-grounded indicators." if has_findings else "[INFERENCE] INSUFFICIENT EVIDENCE: Root cause could not be established from the available evidence.",
            "",
            "## 14. Impact Assessment",
            "Impact assessment requires investigator review of the evidence-grounded findings listed in Section 7." if has_findings else "INSUFFICIENT EVIDENCE: Impact could not be determined from the available evidence.",
            "",
            "## 15. Indicators of Compromise (IOCs)",
            "| Type | Value | Context |",
            "| :--- | :--- | :--- |",
        ])

        if iocs:
            for ioc in iocs:
                md.append(f"| {ioc['type']} | `{ioc['value']}` | {ioc['context']} |")
        else:
            md.append("| INSUFFICIENT EVIDENCE | INSUFFICIENT EVIDENCE: No verified IOC recorded | - |")

        md.extend([
            "",
            "## 16. Prevention Strategies",
            "The following are general defensive considerations and are not presented as "
            "case-specific findings. Applicability requires investigator validation against "
            "the verified evidence.",
            "",
            "1. Consider application allowlisting where appropriate.",
            "2. Consider enabling relevant PowerShell logging and restrictive execution policies.",
            "3. Consider restricting unnecessary lateral network communication.",
            "",
            "## 17. Remediation Recommendations",
            "No case-specific remediation action is asserted unless supported by verified "
            "findings and investigator review.",
            "",
            "Where verified findings justify action, the investigator may evaluate "
            "endpoint isolation, credential rotation, and blocking of verified malicious "
            "indicators.",
            "",
            "## 18. Limitations",
            "- Analysis is bounded by the submitted evidence artifacts.",
            "- Inactive or encrypted disk sectors may require specialized key recovery.",
            "- Tool availability is governed by the local system environment.",
            "",
            "## 19. Appendix",
            f"- ADFIR Version: `0.1.0`",
            f"- Cryptographic Standard: SHA-256 (FIPS 180-4)",
            f"- Generated via: ADFIR Autonomous DFIR Platform",
            "",
            "---",
            "Report contains only recorded forensic data, derived analysis, and explicitly "
            "marked unverified/investigator-review states. Final certification requires "
            "explicit investigator approval."
        ])

        full_md_text = "\n".join(md)

        return {
            "title": f"Investigation Report — {inv_name}",
            "investigation_id": inv_id,
            "executive_summary": f"Investigation {inv_name} completed with {len(findings)} findings across {len(evidence_items)} evidence artifacts.",
            "findings_count": len(findings),
            "evidence_count": len(evidence_items),
            "full_report_markdown": full_md_text,
            "generated_at": now_str
        }
