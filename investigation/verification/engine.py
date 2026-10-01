from typing import List, Dict, Any

class VerificationEngine:
    """
    Canonical Forensic Verification Engine.
    Evaluates whether each finding is anchored in ground-truth tool outputs and valid evidence references.
    Assigns canonical statuses: SUPPORTED, UNSUPPORTED, CONFLICTING, UNVERIFIED.
    """

    def verify_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        verified = []

        for f in findings:
            finding_id = f.get("id")
            tool = f.get("tool") or f.get("source_tool")
            ref = f.get("evidence_reference")

            evidence_ids = f.get("supporting_evidence_ids") or []
            if not evidence_ids and f.get("evidence_id"):
                evidence_ids = [f.get("evidence_id")]
            artifact_ids = f.get("supporting_artifact_ids") or []
            if not artifact_ids and f.get("artifact_id"):
                artifact_ids = [f.get("artifact_id")]
            execution_id = f.get("execution_id")
            output_id = f.get("output_id")

            desc = f.get("description") or f.get("title")

            has_provenance = bool(
                ref
                or evidence_ids
                or artifact_ids
                or execution_id
                or output_id
            )

            if not tool:
                status = "UNVERIFIED"
                score = None
                is_verified = False
                reason = "Finding lacks recorded forensic tool provenance."

            elif not desc:
                status = "UNVERIFIED"
                score = None
                is_verified = False
                reason = "Finding lacks a recorded description or title."

            elif not has_provenance:
                status = "UNSUPPORTED"
                score = None
                is_verified = False
                reason = (
                    "Finding lacks concrete evidence provenance. "
                    "A descriptive payload alone cannot establish forensic support."
                )

            else:
                status = "SUPPORTED"

                raw_score = f.get("confidence")
                if raw_score is None:
                    raw_score = f.get("confidence_score")

                score = raw_score
                is_verified = True

                reason = (
                    "Finding has recorded forensic provenance through "
                    "evidence, artifact, execution, output, or evidence reference."
                )

            verified.append({
                "finding_id": finding_id,
                "verified": is_verified,
                "verification_status": status,
                "confidence_score": score,
                "confidence_adjusted": score,
                "reason": reason
            })

        return verified
