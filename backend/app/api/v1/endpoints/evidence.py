import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import get_current_active_user
from backend.app.models.models import Case, EvidenceItem, EvidenceAcquisition, ChainOfCustodyEvent, User
from backend.app.models.models import Case, EvidenceItem, EvidenceAcquisition, EvidenceIntelligence, ChainOfCustodyEvent, User
from backend.app.schemas.schemas import (
    EvidenceIntakeRequest,
    EvidenceResponse,
    EvidenceVerificationResponse,
    EvidenceIntelligenceResponse,
    EvidenceIntelligenceProfileResponse,
    EvidenceAcquisitionCreateRequest,
    EvidenceAcquisitionResponse,
    EvidenceManifestResponse,
    CustodyChainVerificationResponse,
    CustodyRecord,
)
from backend.app.services.authorization import get_authorized_case
from backend.app.services.custody import record_custody_event, verify_custody_chain
from backend.app.services.vault import stage_evidence_to_vault, verify_os_read_only
from backend.app.services.intelligence import EvidenceIntelligenceEngine
from backend.app.services.acquisition import (
    ingest_single_file_evidence,
    ingest_directory_evidence,
    AcquisitionError,
    DuplicateEvidenceError,
)
from backend.app.services.case_closure import check_case_not_closed

router = APIRouter()

@router.post("/intake", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
def intake_evidence(
    payload: EvidenceIntakeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(payload.case_id, db, current_user)
    check_case_not_closed(case)

    file_p = Path(payload.file_path).resolve()
    if not file_p.exists():
        raise HTTPException(status_code=400, detail=f"Evidence file not found on disk: {payload.file_path}")

    evidence_id = str(uuid.uuid4())

    # 1. Stage evidence to case vault with atomic copy and hash verification
    try:
        stage_res = stage_evidence_to_vault(source_path=str(file_p), case_id=case.id, evidence_id=evidence_id)
    except Exception as e:
        status_code = 500 if isinstance(e, IOError) else 400
        raise HTTPException(status_code=status_code, detail=f"Failed to stage evidence to vault: {str(e)}")

    # 2. Run Evidence Intelligence
    vault_file_path = stage_res.storage_path or stage_res.original_path
    intel_payload = EvidenceIntelligenceEngine.analyze_evidence(
        evidence_id=evidence_id,
        evidence_name=file_p.name,
        file_path=vault_file_path
    )
    intel_dict = intel_payload.model_dump()

    meta_dict = {
        "extension": file_p.suffix,
        "is_read_only": stage_res.read_only_verified,
        "notes": payload.acquisition_notes or payload.notes
    }

    new_evidence = EvidenceItem(
        id=evidence_id,
        case_id=payload.case_id,
        name=file_p.name,
        original_path=stage_res.original_path,
        storage_path=stage_res.storage_path,
        evidence_type=intel_payload.evidence_type,
        evidence_subtype=intel_payload.evidence_subtype,
        source_kind=intel_payload.source_kind,
        acquisition_method="INVESTIGATOR_IMPORT",
        detected_format=intel_payload.detected_format,
        platform_hint=intel_payload.platform_hint,
        size_bytes=stage_res.size_bytes,
        sha256=stage_res.sha256,
        status="REGISTERED",
        read_only_verified=stage_res.read_only_verified,
        integrity_status="VERIFIED",
        intake_status="INTAKE_COMPLETE",
        notes=payload.acquisition_notes or payload.notes,
        metadata_json=meta_dict,
        intelligence_json=intel_dict,
        created_by=current_user.email
    )
    db.add(new_evidence)
    db.commit()
    db.refresh(new_evidence)

    # 3. Chain of custody append-only recording
    record_custody_event(
        db=db,
        case_id=case.id,
        evidence_id=new_evidence.id,
        event_type="EVIDENCE_REGISTERED",
        actor=current_user.name or current_user.email,
        actor_id=current_user.id,
        description=f"Evidence file '{file_p.name}' ({intel_payload.source_kind}/{intel_payload.evidence_type}) ingested and cryptographically preserved in vault (SHA-256: {stage_res.sha256})",
        source_path=stage_res.original_path,
        destination_path=stage_res.storage_path,
        sha256=stage_res.sha256,
        metadata_json=meta_dict
    )

    return new_evidence

@router.get("/case/{case_id}", response_model=List[EvidenceResponse])
def list_evidence_for_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    return db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()

@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence_item(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)
    return evidence

@router.post("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def verify_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    case = get_authorized_case(evidence.case_id, db, current_user)

    target_path = evidence.storage_path or evidence.original_path
    if not target_path or not os.path.exists(target_path):
        evidence.integrity_status = "MISSING"
        evidence.status = "INTEGRITY_WARNING"
        evidence.error_message = f"Preserved file missing at path: {target_path}"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_MISMATCH",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"CRITICAL: Evidence file missing from storage path: {target_path}",
            sha256=evidence.sha256
        )
        return EvidenceVerificationResponse(
            evidence_id=evidence.id,
            integrity_status="MISSING",
            expected_sha256=evidence.sha256,
            current_sha256="",
            read_only_verified=False,
            verified_at=datetime.now(timezone.utc),
            message=f"Evidence file missing from storage path: {target_path}"
        )

    from backend.app.services.integrity import calculate_sha256
    current_sha256, _ = calculate_sha256(target_path)
    is_valid = (current_sha256.lower() == evidence.sha256.lower())
    ro_verified = verify_os_read_only(Path(target_path))

    if is_valid:
        evidence.integrity_status = "VERIFIED"
        evidence.read_only_verified = ro_verified
        evidence.error_message = None
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_VERIFIED",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"Cryptographic SHA-256 integrity re-verified for '{evidence.name}' (SHA-256: {current_sha256})",
            destination_path=target_path,
            sha256=current_sha256
        )
        msg = f"Evidence integrity verified successfully. SHA-256: {current_sha256}"
    else:
        evidence.integrity_status = "INTEGRITY_MISMATCH"
        evidence.status = "INTEGRITY_WARNING"
        evidence.error_message = f"Integrity mismatch detected! Baseline SHA-256: {evidence.sha256}, Current: {current_sha256}"
        db.commit()
        record_custody_event(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
            event_type="INTEGRITY_MISMATCH",
            actor=current_user.name or current_user.email,
            actor_id=current_user.id,
            description=f"CRITICAL: Cryptographic SHA-256 mismatch for '{evidence.name}'! Baseline: {evidence.sha256}, Current: {current_sha256}",
            destination_path=target_path,
            sha256=current_sha256
        )
        msg = f"CRITICAL: Evidence hash mismatch! Baseline: {evidence.sha256}, Current: {current_sha256}"

    return EvidenceVerificationResponse(
        evidence_id=evidence.id,
        integrity_status=evidence.integrity_status,
        expected_sha256=evidence.sha256,
        current_sha256=current_sha256,
        read_only_verified=ro_verified,
        verified_at=datetime.now(timezone.utc),
        message=msg
    )

@router.get("/{evidence_id}/custody", response_model=List[CustodyRecord])
def get_custody_for_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)
    return db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.evidence_id == evidence.id).order_by(ChainOfCustodyEvent.timestamp.asc()).all()

@router.get("/{evidence_id}/intelligence", response_model=EvidenceIntelligenceResponse)
def get_intelligence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)

    if evidence.intelligence_json and isinstance(evidence.intelligence_json, dict):
        return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=evidence.intelligence_json)
    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db, evidence, current_user, force_refresh=False)
    intel_dict = evidence.intelligence_json or {}
    return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=intel_dict)

    target_path = evidence.storage_path or evidence.original_path
    intel = EvidenceIntelligenceEngine.analyze_evidence(evidence.id, evidence.name, target_path)
    intel_dict = intel.model_dump()
    evidence.intelligence_json = intel_dict
    db.commit()
@router.post("/{evidence_id}/intelligence", response_model=EvidenceIntelligenceResponse)
def generate_intelligence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)

    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db, evidence, current_user, force_refresh=False)
    intel_dict = evidence.intelligence_json or {}
    return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=intel_dict)

@router.post("/{evidence_id}/intelligence/refresh", response_model=EvidenceIntelligenceResponse)
def refresh_intelligence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)

    target_path = evidence.storage_path or evidence.original_path
    intel = EvidenceIntelligenceEngine.analyze_evidence(evidence.id, evidence.name, target_path)
    intel_dict = intel.model_dump()

    evidence.evidence_type = intel.evidence_type
    evidence.evidence_subtype = intel.evidence_subtype
    evidence.source_kind = intel.source_kind
    evidence.detected_format = intel.detected_format
    evidence.platform_hint = intel.platform_hint
    evidence.intelligence_json = intel_dict
    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db, evidence, current_user, force_refresh=True)
    intel_dict = evidence.intelligence_json or {}
    return EvidenceIntelligenceResponse(evidence_id=evidence.id, intelligence=intel_dict)

@router.get("/{evidence_id}/intelligence/profile", response_model=EvidenceIntelligenceProfileResponse)
def get_intelligence_profile(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)

    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db, evidence, current_user, force_refresh=False)
    return profile

@router.get("/{evidence_id}/intelligence/tags")
def get_intelligence_tags(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    get_authorized_case(evidence.case_id, db, current_user)

    profile = EvidenceIntelligenceEngine.analyze_and_store_profile(db, evidence, current_user, force_refresh=False)
    return profile.tags_json or []

@router.get("/cases/{case_id}/evidence/intelligence", response_model=List[EvidenceIntelligenceProfileResponse])
def list_case_evidence_intelligence_profiles(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    profiles = []
    for item in evidence_items:
        prof = EvidenceIntelligenceEngine.analyze_and_store_profile(db, item, current_user, force_refresh=False)
        profiles.append(prof)
    return profiles

@router.post("/cases/{case_id}/acquisitions")
def create_evidence_acquisition(
    case_id: str,
    payload: EvidenceAcquisitionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    case = get_authorized_case(case_id, db, current_user)
    check_case_not_closed(case)
    
    try:
        if payload.acquisition_type.upper() == "DIRECTORY":
            acq, manifest = ingest_directory_evidence(
                db=db,
                case_id=case.id,
                source_path=payload.source_path,
                actor_id=current_user.id,
                actor_name=current_user.name or current_user.email,
                notes=payload.notes
            )
            return {
                "acquisition": EvidenceAcquisitionResponse.model_validate(acq),
                "manifest": manifest
            }
        else:
            item = ingest_single_file_evidence(
                db=db,
                case_id=case.id,
                source_path=payload.source_path,
                actor_id=current_user.id,
                actor_name=current_user.name or current_user.email,
                evidence_type_override=payload.evidence_type,
                acquisition_type=payload.acquisition_type.upper(),
                notes=payload.notes
            )
            return EvidenceResponse.model_validate(item)
    except DuplicateEvidenceError as dup_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Duplicate evidence detected: {str(dup_err)}"
        )
    except AcquisitionError as acq_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(acq_err)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence acquisition failed: {str(e)}"
        )

@router.get("/acquisitions/{acquisition_id}", response_model=EvidenceAcquisitionResponse)
def get_acquisition(
    acquisition_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    acq = db.query(EvidenceAcquisition).filter(EvidenceAcquisition.id == acquisition_id).first()
    if not acq:
        raise HTTPException(status_code=404, detail=f"Evidence acquisition {acquisition_id} not found")
    get_authorized_case(acq.case_id, db, current_user)
    return acq

@router.get("/acquisitions/{acquisition_id}/manifest", response_model=EvidenceManifestResponse)
def get_acquisition_manifest(
    acquisition_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    acq = db.query(EvidenceAcquisition).filter(EvidenceAcquisition.id == acquisition_id).first()
    if not acq:
        raise HTTPException(status_code=404, detail=f"Evidence acquisition {acquisition_id} not found")
    get_authorized_case(acq.case_id, db, current_user)

    from backend.app.core.config import settings
    manifest_file = settings.EVIDENCE_DIR / "vault" / acq.case_id / "acquisitions" / acq.id / "manifest.json"
    if not manifest_file.exists():
        raise HTTPException(status_code=404, detail=f"Manifest file not found for acquisition {acquisition_id}")

    try:
        import json
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read manifest file: {str(e)}")

@router.get("/{evidence_id}/custody/verify", response_model=CustodyChainVerificationResponse)
def verify_evidence_custody_chain(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence item {evidence_id} not found")
    case = get_authorized_case(evidence.case_id, db, current_user)

    is_valid, tampered_id, message, total_events = verify_custody_chain(db, evidence.id)
    return CustodyChainVerificationResponse(
        case_id=case.id,
        evidence_id=evidence.id,
        total_events=total_events,
        chain_valid=is_valid,
        tampered_event_id=tampered_id,
        message=message
    )

