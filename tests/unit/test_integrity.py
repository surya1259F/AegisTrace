import pytest
import os
import tempfile
from backend.app.services.integrity import calculate_sha256, verify_sha256, CHUNK_SIZE_8MB

def test_chunk_size_is_8mb():
    assert CHUNK_SIZE_8MB == 8 * 1024 * 1024

def test_calculate_sha256_synthetic_fixture():
    fixture_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-evidence.txt")
    hash_val, size = calculate_sha256(fixture_path)
    assert len(hash_val) == 64
    assert size > 0

def test_verify_sha256_valid_and_invalid():
    fixture_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-evidence.txt")
    actual_hash, _ = calculate_sha256(fixture_path)
    
    valid_res = verify_sha256(fixture_path, actual_hash)
    assert valid_res["valid"] is True
    assert valid_res["actual_hash"] == actual_hash

    invalid_res = verify_sha256(fixture_path, "0000000000000000000000000000000000000000000000000000000000000000")
    assert invalid_res["valid"] is False

def test_nonexistent_file_rejection():
    with pytest.raises(FileNotFoundError):
        calculate_sha256("/path/to/nonexistent/evidence_file.E01")


def test_missing_evidence_file_with_registered_hash_is_not_verified():
    from types import SimpleNamespace
    from backend.app.services.final_report import verify_evidence_file_integrity

    evidence = SimpleNamespace(
        id="missing-evidence-test",
        storage_path="/definitely/missing/evidence.bin",
        original_path="/also/missing/original.bin",
        sha256="a" * 64,
    )

    status, current_hash = verify_evidence_file_integrity(evidence)

    assert status == "UNCHECKED"
    assert current_hash is None
