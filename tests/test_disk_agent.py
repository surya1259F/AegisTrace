import pytest
import os
from pathlib import Path
from agents.disk.disk_agent import DiskAgent
from agents.disk.parsers.fls_parser import FlsParser, FlsParserResult
from tests.fixtures.disk.create_synthetic_disk import create_synthetic_disk_image

FIXTURE_DISK = Path(__file__).resolve().parent / "fixtures" / "disk" / "synthetic_disk.img"

@pytest.fixture(scope="module", autouse=True)
def ensure_fixture():
    create_synthetic_disk_image(FIXTURE_DISK)

def test_fls_parser_valid_output():
    sample_fls_output = (
        "r/r 3:\tNORMAL.TXT\n"
        "r/r * 4:\t_VIL.BAT\n"
        "d/d 12:\tWindows\n"
        "d/d * 15:\tDeletedFolder\n"
        "v/v 32691:\t$MBR\n"
        "V/V 32694:\t$OrphanFiles\n"
    )
    result = FlsParser.parse(sample_fls_output)
    assert result.parsed_count == 6
    assert len(result.entries) == 6
    
    # Check allocated file
    e1 = result.entries[0]
    assert e1.file_path == "NORMAL.TXT"
    assert e1.inode == "3"
    assert e1.is_deleted is False
    assert e1.entry_type == "file"

    # Check deleted file
    e2 = result.entries[1]
    assert e2.file_path == "_VIL.BAT"
    assert e2.inode == "4"
    assert e2.is_deleted is True
    assert e2.entry_type == "file"

    # Check deleted directory
    e4 = result.entries[3]
    assert e4.file_path == "DeletedFolder"
    assert e4.is_deleted is True
    assert e4.entry_type == "directory"

def test_fls_parser_malformed_input_handled_safely():
    malformed_output = (
        "GARBAGE_LINE_WITHOUT_INODE\n"
        "r/r 10:\tvalid.txt\n"
        "INVALID FORMAT 9999\n"
    )
    result = FlsParser.parse(malformed_output)
    assert result.parsed_count == 1
    assert len(result.parse_errors) == 2
    assert result.entries[0].file_path == "valid.txt"

def test_disk_agent_can_handle():
    agent = DiskAgent()
    assert agent.can_handle("disk_image") is True
    assert agent.can_handle("file") is True
    assert agent.can_handle("filesystem_image") is True
    assert agent.can_handle("memory_dump") is False
    assert agent.can_handle("network_capture") is False

def test_disk_agent_rejects_unsupported_evidence():
    agent = DiskAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "mem.dmp",
        "evidence_type": "memory_dump",
        "storage_path": "/vault/mem.dmp"
    })
    assert res["status"] == "UNSUPPORTED_EVIDENCE_TYPE"
    assert len(res["artifacts"]) == 0

def test_disk_agent_rejects_unvaulted_evidence():
    agent = DiskAgent()
    # Case 1: missing storage_path
    res1 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "raw.img",
        "evidence_type": "disk_image",
        "original_path": "/raw/raw.img"
    })
    assert res1["status"] == "UNVAULTED_EVIDENCE_REJECTED"

    # Case 2: storage_path == original_path
    res2 = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "raw.img",
        "evidence_type": "disk_image",
        "original_path": "/raw/raw.img",
        "storage_path": "/raw/raw.img"
    })
    assert res2["status"] == "UNVAULTED_EVIDENCE_REJECTED"

def test_disk_agent_handles_invalid_path():
    agent = DiskAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "missing.img",
        "evidence_type": "disk_image",
        "storage_path": "/nonexistent/path/missing.img"
    })
    assert res["status"] == "INVALID_EVIDENCE_PATH"

def test_disk_agent_executes_fls_on_synthetic_disk():
    agent = DiskAgent()
    res = agent.analyze({
        "id": "ev-100",
        "investigation_id": "inv-100",
        "name": "synthetic_disk.img",
        "evidence_type": "disk_image",
        "original_path": "/raw/source/synthetic_disk.img",
        "storage_path": str(FIXTURE_DISK)
    })
    assert res["status"] == "SUCCESS"
    assert res["artifacts_count"] >= 3
    assert res["findings_count"] >= 1
    
    # Check that deleted file was extracted as a candidate finding
    finding_titles = [f["title"] for f in res["findings"]]
    assert any("Deleted Filesystem Entry" in title for title in finding_titles)
    
    # Check provenance
    prov = res["provenance"]
    assert prov["agent"] in ["DiskAgent", "DiskForensicsAgent"]
    assert prov["tool"] == "SleuthKit"
    assert prov["operation"] == "fls_listing"
    assert os.path.exists(res["raw_output_reference"])
