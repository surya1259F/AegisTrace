import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class ParsedWindowsEvent(BaseModel):
    event_id: int
    provider_name: Optional[str] = None
    channel: Optional[str] = None
    computer: Optional[str] = None
    time_created: Optional[str] = None
    record_id: Optional[int] = None
    level: Optional[int] = None
    task: Optional[int] = None
    opcode: Optional[int] = None
    
    # Normalized security context
    user: Optional[str] = None
    domain: Optional[str] = None
    logon_type: Optional[int] = None
    source_ip: Optional[str] = None
    source_port: Optional[str] = None
    
    # Account & Group Management (4720, 4728, 4732)
    target_user: Optional[str] = None
    target_domain: Optional[str] = None
    group_name: Optional[str] = None
    member_name: Optional[str] = None
    
    # Process / Service context (4688, 4697, 7045)
    process_name: Optional[str] = None
    process_id: Optional[str] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    service_name: Optional[str] = None
    service_file_name: Optional[str] = None
    
    # Event category & raw fields
    event_category: str = "generic_event"
    event_data: Dict[str, str] = Field(default_factory=dict)
    raw_xml: str = ""

class SecurityEventParser:
    """
    Dedicated parser for Windows Security Event records (XML format).
    Extracts and normalizes Event IDs:
      - 4624: Successful Logon
      - 4625: Failed Logon
      - 4672: Special Privileges Assigned
      - 4688: Process Creation
      - 4697: Service Installed
      - 4720: User Account Created
      - 4728: Member Added to Global Group
      - 4732: Member Added to Local Group
      - 7045: Service Installed (System Event)
    """

    @staticmethod
    def _strip_ns(tag: str) -> str:
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    @classmethod
    def parse_xml_string(cls, xml_text: str) -> Optional[ParsedWindowsEvent]:
        if not xml_text or not xml_text.strip():
            return None

        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return None

        system_elem = None
        event_data_elem = None

        for child in root:
            tag_name = cls._strip_ns(child.tag).lower()
            if tag_name == "system":
                system_elem = child
            elif tag_name in ["eventdata", "userdata"]:
                event_data_elem = child

        if system_elem is None:
            return None

        # 1. Parse System Section
        event_id: Optional[int] = None
        provider_name: Optional[str] = None
        channel: Optional[str] = None
        computer: Optional[str] = None
        time_created: Optional[str] = None
        record_id: Optional[int] = None
        level: Optional[int] = None
        task: Optional[int] = None
        opcode: Optional[int] = None

        for elem in system_elem:
            tag = cls._strip_ns(elem.tag)
            if tag == "EventID":
                try:
                    event_id = int(elem.text.strip()) if elem.text else None
                except ValueError:
                    event_id = None
            elif tag == "Provider":
                provider_name = elem.attrib.get("Name") or elem.attrib.get("name")
            elif tag == "Channel":
                channel = elem.text.strip() if elem.text else None
            elif tag == "Computer":
                computer = elem.text.strip() if elem.text else None
            elif tag == "TimeCreated":
                time_created = elem.attrib.get("SystemTime") or elem.attrib.get("systemtime")
            elif tag == "EventRecordID":
                try:
                    record_id = int(elem.text.strip()) if elem.text else None
                except ValueError:
                    record_id = None
            elif tag == "Level":
                try:
                    level = int(elem.text.strip()) if elem.text else None
                except ValueError:
                    level = None
            elif tag == "Task":
                try:
                    task = int(elem.text.strip()) if elem.text else None
                except ValueError:
                    task = None
            elif tag == "Opcode":
                try:
                    opcode = int(elem.text.strip()) if elem.text else None
                except ValueError:
                    opcode = None

        if event_id is None:
            return None

        # 2. Parse EventData / UserData key-value pairs
        event_data_dict: Dict[str, str] = {}
        if event_data_elem is not None:
            for data_child in event_data_elem:
                name_attr = data_child.attrib.get("Name") or data_child.attrib.get("name")
                val_text = (data_child.text or "").strip()
                if name_attr:
                    event_data_dict[name_attr] = val_text
                else:
                    tag_key = cls._strip_ns(data_child.tag)
                    event_data_dict[tag_key] = val_text

        # 3. Categorize and Extract Security-Specific Fields
        user = None
        domain = None
        target_user = None
        target_domain = None
        group_name = None
        member_name = None
        logon_type = None
        source_ip = None
        source_port = None
        process_name = None
        process_id = None
        parent_process_name = None
        command_line = None
        service_name = None
        service_file_name = None
        category = "generic_event"

        if event_id == 4624:
            category = "logon_success"
            user = event_data_dict.get("TargetUserName") or event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("TargetDomainName") or event_data_dict.get("SubjectDomainName")
            target_user = event_data_dict.get("TargetUserName")
            target_domain = event_data_dict.get("TargetDomainName")
            source_ip = event_data_dict.get("IpAddress")
            source_port = event_data_dict.get("IpPort")
            lt_str = event_data_dict.get("LogonType")
            if lt_str and lt_str.isdigit():
                logon_type = int(lt_str)
        elif event_id == 4625:
            category = "logon_failure"
            user = event_data_dict.get("TargetUserName") or event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("TargetDomainName") or event_data_dict.get("SubjectDomainName")
            target_user = event_data_dict.get("TargetUserName")
            target_domain = event_data_dict.get("TargetDomainName")
            source_ip = event_data_dict.get("IpAddress")
            source_port = event_data_dict.get("IpPort")
            lt_str = event_data_dict.get("LogonType")
            if lt_str and lt_str.isdigit():
                logon_type = int(lt_str)
        elif event_id == 4672:
            category = "special_privilege_assigned"
            user = event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("SubjectDomainName")
        elif event_id == 4688:
            category = "process_creation"
            process_name = event_data_dict.get("NewProcessName") or event_data_dict.get("ProcessName")
            process_id = event_data_dict.get("NewProcessId") or event_data_dict.get("ProcessId")
            parent_process_name = event_data_dict.get("ParentProcessName")
            command_line = event_data_dict.get("CommandLine")
            user = event_data_dict.get("SubjectUserName") or event_data_dict.get("TargetUserName")
            domain = event_data_dict.get("SubjectDomainName") or event_data_dict.get("TargetDomainName")
        elif event_id in [4697, 7045]:
            category = "service_installed"
            service_name = event_data_dict.get("ServiceName")
            service_file_name = event_data_dict.get("ServiceFileName") or event_data_dict.get("ImagePath")
            user = event_data_dict.get("SubjectUserName") or event_data_dict.get("AccountName")
        elif event_id == 4720:
            category = "account_created"
            target_user = event_data_dict.get("TargetUserName")
            target_domain = event_data_dict.get("TargetDomainName")
            user = event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("SubjectDomainName")
        elif event_id == 4728:
            category = "global_group_member_added"
            group_name = event_data_dict.get("TargetUserName") or event_data_dict.get("GroupName")
            member_name = event_data_dict.get("MemberName") or event_data_dict.get("MemberSid")
            user = event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("SubjectDomainName")
        elif event_id == 4732:
            category = "local_group_member_added"
            group_name = event_data_dict.get("TargetUserName") or event_data_dict.get("GroupName")
            member_name = event_data_dict.get("MemberName") or event_data_dict.get("MemberSid")
            user = event_data_dict.get("SubjectUserName")
            domain = event_data_dict.get("SubjectDomainName")

        return ParsedWindowsEvent(
            event_id=event_id,
            provider_name=provider_name,
            channel=channel,
            computer=computer,
            time_created=time_created,
            record_id=record_id,
            level=level,
            task=task,
            opcode=opcode,
            user=user,
            domain=domain,
            target_user=target_user,
            target_domain=target_domain,
            group_name=group_name,
            member_name=member_name,
            logon_type=logon_type,
            source_ip=source_ip,
            source_port=source_port,
            process_name=process_name,
            process_id=process_id,
            parent_process_name=parent_process_name,
            command_line=command_line,
            service_name=service_name,
            service_file_name=service_file_name,
            event_category=category,
            event_data=event_data_dict,
            raw_xml=xml_text.strip()
        )
