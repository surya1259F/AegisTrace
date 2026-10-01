import pytest
from agents.log.parsers.security_events import SecurityEventParser
from agents.log.parsers.evtx_parser import EvtxParser
from pathlib import Path

SAMPLE_XML_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "log" / "sample_security_events.xml"

def test_parse_event_4624_logon_success():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4624</EventID>
        <EventRecordID>501</EventRecordID>
        <TimeCreated SystemTime="2026-08-24T12:00:00Z" />
        <Computer>HOST-A</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="IpAddress">10.0.0.5</Data>
        <Data Name="IpPort">54321</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4624
    assert ev.event_category == "logon_success"
    assert ev.user == "alice"
    assert ev.domain == "CORP"
    assert ev.logon_type == 10
    assert ev.source_ip == "10.0.0.5"
    assert ev.record_id == 501
    assert ev.computer == "HOST-A"

def test_parse_event_4625_logon_failure():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <EventRecordID>502</EventRecordID>
        <TimeCreated SystemTime="2026-08-24T12:01:00Z" />
        <Computer>HOST-A</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">bob_bad</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="IpAddress">192.168.1.99</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4625
    assert ev.event_category == "logon_failure"
    assert ev.user == "bob_bad"
    assert ev.source_ip == "192.168.1.99"

def test_parse_event_4672_privilege_assigned():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4672</EventID>
        <EventRecordID>503</EventRecordID>
        <TimeCreated SystemTime="2026-08-24T12:02:00Z" />
      </System>
      <EventData>
        <Data Name="SubjectUserName">admin</Data>
        <Data Name="SubjectDomainName">CORP</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4672
    assert ev.event_category == "special_privilege_assigned"
    assert ev.user == "admin"

def test_parse_event_4688_process_creation():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4688</EventID>
        <EventRecordID>504</EventRecordID>
      </System>
      <EventData>
        <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -NoP -NonI</Data>
        <Data Name="SubjectUserName">operator</Data>
        <Data Name="NewProcessId">0x444</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4688
    assert ev.event_category == "process_creation"
    assert ev.process_name == "C:\\Windows\\System32\\powershell.exe"
    assert ev.command_line == "powershell.exe -NoP -NonI"
    assert ev.user == "operator"

def test_parse_event_7045_service_installation():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Service Control Manager" />
        <EventID>7045</EventID>
        <EventRecordID>505</EventRecordID>
      </System>
      <EventData>
        <Data Name="ServiceName">PktService</Data>
        <Data Name="ImagePath">C:\\Windows\\Temp\\pkt.exe</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 7045
    assert ev.event_category == "service_installed"
    assert ev.service_name == "PktService"
    assert ev.service_file_name == "C:\\Windows\\Temp\\pkt.exe"

def test_parse_malformed_xml_returns_none():
    assert SecurityEventParser.parse_xml_string("<Event><broken xml") is None
    assert SecurityEventParser.parse_xml_string("") is None
    assert SecurityEventParser.parse_xml_string("   ") is None

def test_evtx_parser_reads_xml_fixture():
    res = EvtxParser.parse_file(str(SAMPLE_XML_FIXTURE))
    assert res.parsed_events_count == 5
    assert res.total_records_scanned == 5
    event_ids = [e.event_id for e in res.events]
    assert 4624 in event_ids
    assert 4625 in event_ids
    assert 4672 in event_ids
    assert 4688 in event_ids
    assert 7045 in event_ids

def test_parse_event_4720_account_created():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4720</EventID>
        <EventRecordID>601</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T11:00:00Z" />
        <Computer>DC-01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">svc_backup</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="SubjectUserName">administrator</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4720
    assert ev.event_category == "account_created"
    assert ev.target_user == "svc_backup"
    assert ev.user == "administrator"

def test_parse_event_4728_global_group_member_added():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4728</EventID>
        <EventRecordID>602</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T11:05:00Z" />
      </System>
      <EventData>
        <Data Name="MemberName">CN=svc_backup,CN=Users,DC=corp,DC=local</Data>
        <Data Name="TargetUserName">Domain Admins</Data>
        <Data Name="SubjectUserName">administrator</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4728
    assert ev.event_category == "global_group_member_added"
    assert ev.group_name == "Domain Admins"
    assert "svc_backup" in ev.member_name

def test_parse_event_4732_local_group_member_added():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4732</EventID>
        <EventRecordID>603</EventRecordID>
        <TimeCreated SystemTime="2026-08-25T11:10:00Z" />
      </System>
      <EventData>
        <Data Name="MemberName">CN=svc_backup,CN=Users,DC=corp,DC=local</Data>
        <Data Name="TargetUserName">Administrators</Data>
        <Data Name="SubjectUserName">administrator</Data>
      </EventData>
    </Event>
    """
    ev = SecurityEventParser.parse_xml_string(xml)
    assert ev is not None
    assert ev.event_id == 4732
    assert ev.event_category == "local_group_member_added"
    assert ev.group_name == "Administrators"
