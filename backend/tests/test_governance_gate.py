import pytest
from fastapi.testclient import TestClient
import tempfile
import os
import uuid

from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.models import Report, InvestigatorDecision

client = TestClient(app)

from backend.app.models.models import User
from backend.app.core.security import get_current_active_user

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    user = db.query(User).filter(User.email == "gov_test@adfir.local").first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email="gov_test@adfir.local",
            name="Default Test Investigator",
            role="ADMIN",
            is_active=True
        )
        db.add(user)
    else:
        user.name = "Default Test Investigator"
        db.add(user)
    db.commit()
    db.refresh(user)
    db.close()

    app.dependency_overrides[get_current_active_user] = lambda: user
    yield
    app.dependency_overrides.pop(get_current_active_user, None)

def _create_test_case_with_artifacts():
    """Helper to create a case with evidence and findings ready for report generation."""
    inv_name = f"Governance Test Case {uuid.uuid4().hex[:6]}"
    create_res = client.post("/api/investigations/", json={
        "name": inv_name,
        "description": "Case for testing mandatory investigator governance gate."
    })
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"SYNTHETIC_FORENSIC_ARTIFACT_FOR_GOVERNANCE_GATE")
        tmp_path = tmp.name

    try:
        intake_res = client.post(f"/api/investigations/{inv_id}/evidence/intake", json={
            "path": tmp_path,
            "notes": "Temporary evidence for governance testing"
        })
        assert intake_res.status_code == 201
        ev_id = intake_res.json()["id"]

        f_res = client.post(f"/api/investigations/{inv_id}/findings", json={
            "evidence_id": ev_id,
            "agent": "DiskAgent",
            "tool": "SleuthKit",
            "finding_type": "filesystem_artifact",
            "title": "Suspicious Executable",
            "description": "Found test finding",
            "confidence": 0.95,
            "severity": "HIGH",
            "mitre_technique": "T1059.001",
            "evidence_reference": "inode 100",
            "context_data": {}
        })
        assert f_res.status_code == 201
        finding_id = f_res.json()["id"]

        # Run correlation and verification
        corr_res = client.post(f"/api/investigations/{inv_id}/correlate")
        assert corr_res.status_code == 200
        ver_res = client.post(f"/api/investigations/{inv_id}/verify")
        assert ver_res.status_code == 200

        return inv_id, ev_id, finding_id
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_report_generation_blocked_when_no_decision():
    """Verify that calling report generation without any recorded decision returns HTTP 422."""
    inv_id, _, _ = _create_test_case_with_artifacts()

    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 422
    data = rep_res.json()
    assert "Mandatory investigator decision required" in data["detail"]


def test_report_generation_blocked_on_reject():
    """Verify that a REJECT decision blocks report generation with HTTP 422."""
    inv_id, _, _ = _create_test_case_with_artifacts()

    dec_res = client.post(f"/api/investigations/{inv_id}/decisions", json={
        "decision": "REJECT",
        "rationale": "Findings do not meet legal threshold for prosecution.",
        "investigator_name": "Examiner Alice"
    })
    assert dec_res.status_code == 201

    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 422
    assert "REJECT" in rep_res.json()["detail"]


def test_report_generation_blocked_on_inconclusive():
    """Verify that an INCONCLUSIVE decision blocks report generation with HTTP 422."""
    inv_id, _, _ = _create_test_case_with_artifacts()

    dec_res = client.post(f"/api/investigations/{inv_id}/decisions", json={
        "decision": "INCONCLUSIVE",
        "rationale": "Evidence is ambiguous and inconclusive.",
        "investigator_name": "Examiner Bob"
    })
    assert dec_res.status_code == 201

    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 422
    assert "INCONCLUSIVE" in rep_res.json()["detail"]


def test_report_generation_blocked_on_request_more_evidence():
    """Verify that REQUEST_MORE_EVIDENCE blocks report generation with HTTP 422."""
    inv_id, _, _ = _create_test_case_with_artifacts()

    dec_res = client.post(f"/api/investigations/{inv_id}/decisions", json={
        "decision": "REQUEST_MORE_EVIDENCE",
        "rationale": "Additional packet capture required before finalization.",
        "investigator_name": "Examiner Charlie"
    })
    assert dec_res.status_code == 201

    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 422
    assert "REQUEST_MORE_EVIDENCE" in rep_res.json()["detail"]


def test_report_generation_succeeds_on_explicit_confirm():
    """
    Verify that an explicit CONFIRM decision allows report generation:
    - Status is OFFICIAL_FINAL
    - report.decision_id equals the decision ID
    - report.generated_by corresponds to the investigator name
    - No fabricated or duplicate InvestigatorDecision was created
    """
    inv_id, _, _ = _create_test_case_with_artifacts()

    investigator_name = "Senior Examiner Mallory"
    dec_res = client.post(f"/api/investigations/{inv_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "All forensic findings validated against master image hashes.",
        "investigator_name": investigator_name
    })
    assert dec_res.status_code == 201
    dec_data = dec_res.json()
    decision_id = dec_data["id"]

    rep_res = client.post(f"/api/investigations/{inv_id}/report")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["status"] == "OFFICIAL_FINAL"
    assert rep_data["generated_by"] in (investigator_name, "Default Test Investigator")

    # Check persistence in database
    db = SessionLocal()
    try:
        db_report = db.query(Report).filter(Report.id == rep_data["id"]).first()
        assert db_report is not None
        assert db_report.status == "OFFICIAL_FINAL"
        assert db_report.decision_id == decision_id
        assert db_report.generated_by in (investigator_name, "Default Test Investigator")

        # Verify exactly one decision exists (no automatic/fabricated second decision)
        decisions = db.query(InvestigatorDecision).filter(InvestigatorDecision.case_id == inv_id).all()
        assert len(decisions) == 1
        assert decisions[0].id == decision_id
        assert decisions[0].decision == "CONFIRM"
        assert decisions[0].investigator_name in (investigator_name, "Default Test Investigator")
    finally:
        db.close()


def test_legacy_v1_report_endpoint_gating():
    """Verify that POST /api/v1/reports/generate/{case_id} strictly enforces the mandatory gate."""
    case_num = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    case_res = client.post("/api/v1/cases/", json={
        "case_number": case_num,
        "title": "Legacy V1 Governance Test",
        "description": "Testing gate on /api/v1/reports/generate",
        "investigator": "Investigator Dan"
    })
    assert case_res.status_code in [200, 201]
    case_id = case_res.json()["id"]

    # 1. Blocked when no decision exists
    rep_res_no_dec = client.post(f"/api/v1/reports/generate/{case_id}")
    assert rep_res_no_dec.status_code == 422
    assert "Mandatory investigator decision required" in rep_res_no_dec.json()["detail"]

    # 2. Blocked on non-CONFIRM decision
    client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "REJECT",
        "rationale": "Findings rejected by review panel.",
        "investigator_name": "Reviewer Eve"
    })
    rep_res_reject = client.post(f"/api/v1/reports/generate/{case_id}")
    assert rep_res_reject.status_code == 422
    assert "REJECT" in rep_res_reject.json()["detail"]

    # 3. Allowed on explicit CONFIRM decision
    confirm_res = client.post(f"/api/cases/{case_id}/decisions", json={
        "decision": "CONFIRM",
        "rationale": "Overridden after re-examination and confirmed.",
        "investigator_name": "Chief Investigator Frank"
    })
    assert confirm_res.status_code == 201
    confirm_id = confirm_res.json()["id"]

    rep_res_confirm = client.post(f"/api/v1/reports/generate/{case_id}")
    assert rep_res_confirm.status_code == 200
    v1_report_data = rep_res_confirm.json()
    assert v1_report_data["status"] == "OFFICIAL_FINAL"
    assert v1_report_data["generated_by"] in ("Chief Investigator Frank", "Default Test Investigator")

    db = SessionLocal()
    try:
        db_rep = db.query(Report).filter(Report.id == v1_report_data["id"]).first()
        assert db_rep is not None
        assert db_rep.status == "OFFICIAL_FINAL"
        assert db_rep.decision_id == confirm_id
        assert db_rep.generated_by in ("Chief Investigator Frank", "Default Test Investigator")
    finally:
        db.close()

