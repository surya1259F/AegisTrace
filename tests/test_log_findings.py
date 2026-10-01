import pytest
from agents.log.parsers.security_events import SecurityEventParser
from agents.log.log_agent import LogAgent

def test_normal_4624_does_not_create_malicious_finding():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4624</EventID>
        <EventRecordID>101</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T10:00:00Z" />
        <Computer>DESKTOP-01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">standard_user</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="LogonType">2</Data>
      </EventData>
    </Event>
    """
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        temp_path = f.name

    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-1",
        "investigation_id": "inv-1",
        "name": "normal_logon.xml",
        "evidence_type": "log",
        "original_path": "/raw/source/normal_logon.xml",
        "storage_path": temp_path
    })
    # Must produce 1 artifact (WINDOWS_EVENT/LOGON)
    assert res["artifacts_count"] == 1
    # Must NOT produce candidate finding for benign 4624
    assert res["findings_count"] == 0

def test_4720_account_creation_finding():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4720</EventID>
        <EventRecordID>102</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T10:05:00Z" />
        <Computer>DC-01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">backdoor_admin</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="SubjectUserName">admin_user</Data>
      </EventData>
    </Event>
    """
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        temp_path = f.name

    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-2",
        "investigation_id": "inv-1",
        "name": "account_created.xml",
        "evidence_type": "log",
        "original_path": "/raw/source/account_created.xml",
        "storage_path": temp_path
    })
    assert res["artifacts_count"] == 1
    assert res["findings_count"] == 1
    f = res["findings"][0]
    assert f["finding_type"] == "windows_account_creation"
    assert "backdoor_admin" in f["title"]
    assert f["verification_status"] == "UNVERIFIED"

def test_4728_group_membership_change_finding():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4728</EventID>
        <EventRecordID>103</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T10:10:00Z" />
        <Computer>DC-01</Computer>
      </System>
      <EventData>
        <Data Name="MemberName">CN=backdoor_admin,OU=Users,DC=corp,DC=local</Data>
        <Data Name="TargetUserName">Domain Admins</Data>
        <Data Name="SubjectUserName">admin_user</Data>
      </EventData>
    </Event>
    """
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        temp_path = f.name

    agent = LogAgent()
    res = agent.analyze({
        "id": "ev-3",
        "investigation_id": "inv-1",
        "name": "group_change.xml",
        "evidence_type": "log",
        "original_path": "/raw/source/group_change.xml",
        "storage_path": temp_path
    })
    assert res["artifacts_count"] == 1
    assert res["findings_count"] == 1
    f = res["findings"][0]
    assert f["finding_type"] == "windows_group_membership_change"
    assert "Domain Admins" in f["title"]
    assert f["verification_status"] == "UNVERIFIED"
