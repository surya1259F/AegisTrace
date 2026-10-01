import pytest
import os
import tempfile
from backend.app.core.security import SecurityValidator

def test_path_traversal_rejection():
    with pytest.raises(ValueError):
        SecurityValidator.validate_and_canonicalize_path("../../../etc/shadow")

def test_null_byte_path_rejection():
    with pytest.raises(ValueError):
        SecurityValidator.validate_and_canonicalize_path("/tmp/test\0file.txt")

def test_evidence_immutability():
    # Verify that hashing and inspection never modify the original evidence bytes or timestamps
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"ORIGINAL_IMMUTABLE_FORENSIC_BYTES")
        tmp_path = tmp.name

    try:
        initial_stat = os.stat(tmp_path)
        canonical = SecurityValidator.validate_and_canonicalize_path(tmp_path)
        
        with open(canonical, "rb") as f:
            content = f.read()

        post_stat = os.stat(tmp_path)
        assert content == b"ORIGINAL_IMMUTABLE_FORENSIC_BYTES"
        assert initial_stat.st_mtime == post_stat.st_mtime
        assert initial_stat.st_size == post_stat.st_size
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
