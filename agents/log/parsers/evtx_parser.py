import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from agents.log.parsers.security_events import SecurityEventParser, ParsedWindowsEvent

class EvtxParserResult(BaseModel):
    events: List[ParsedWindowsEvent] = Field(default_factory=list)
    total_records_scanned: int = 0
    parsed_events_count: int = 0
    parse_errors: List[str] = Field(default_factory=list)
    file_path: str = ""

class EvtxParser:
    """
    Forensic parser for Windows Event Log (.evtx) files and exported event XML.
    Uses `python-evtx` (Evtx.Evtx) for binary record streaming and `SecurityEventParser` for XML parsing.
    """

    @staticmethod
    def _strip_ns(tag: str) -> str:
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    @classmethod
    def parse_file(cls, file_path: str, max_records: int = 5000) -> EvtxParserResult:
        result = EvtxParserResult(file_path=file_path)
        path_obj = Path(file_path)

        if not path_obj.exists() or not path_obj.is_file():
            result.parse_errors.append(f"File '{file_path}' does not exist or is not a regular file.")
            return result

        # Check if this is an XML file or a binary EVTX file
        is_xml = False
        try:
            with open(path_obj, "rb") as f:
                header = f.read(8)
                if header.startswith(b"ElfFile\x00"):
                    # Standard Windows EVTX signature (ElfFile\x00)
                    is_xml = False
                elif b"<" in header or path_obj.suffix.lower() == ".xml":
                    is_xml = True
                else:
                    is_xml = False
        except Exception as e:
            result.parse_errors.append(f"Failed to read file header: {str(e)}")
            return result

        if is_xml:
            return cls._parse_xml_file(path_obj, result, max_records)
        else:
            return cls._parse_binary_evtx(path_obj, result, max_records)

    @classmethod
    def _parse_binary_evtx(cls, path_obj: Path, result: EvtxParserResult, max_records: int) -> EvtxParserResult:
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            result.parse_errors.append("python-evtx library is not available.")
            return result

        try:
            with evtx.Evtx(str(path_obj)) as log:
                for record in log.records():
                    result.total_records_scanned += 1
                    try:
                        xml_content = record.xml()
                        parsed_event = SecurityEventParser.parse_xml_string(xml_content)
                        if parsed_event:
                            result.events.append(parsed_event)
                            result.parsed_events_count += 1
                    except Exception as rec_err:
                        result.parse_errors.append(f"Record {result.total_records_scanned} parse error: {str(rec_err)}")

                    if result.total_records_scanned >= max_records:
                        break
        except Exception as e:
            result.parse_errors.append(f"EVTX binary parsing error: {str(e)}")

        return result

    @classmethod
    def _parse_xml_file(cls, path_obj: Path, result: EvtxParserResult, max_records: int) -> EvtxParserResult:
        try:
            with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            try:
                root = ET.fromstring(content)
                tag_name = cls._strip_ns(root.tag).lower()
                if tag_name == "event":
                    parsed = SecurityEventParser.parse_xml_string(content)
                    if parsed:
                        result.events.append(parsed)
                        result.parsed_events_count += 1
                        result.total_records_scanned += 1
                    return result
                elif tag_name in ["events", "root"]:
                    for child in root:
                        if cls._strip_ns(child.tag).lower() == "event":
                            result.total_records_scanned += 1
                            xml_str = ET.tostring(child, encoding="utf-8").decode("utf-8")
                            parsed = SecurityEventParser.parse_xml_string(xml_str)
                            if parsed:
                                result.events.append(parsed)
                                result.parsed_events_count += 1
                            if result.total_records_scanned >= max_records:
                                break
                    return result
            except Exception:
                pass

            # Regex fallback with word boundary \b
            event_blocks = re.findall(r"(<Event\b[\s\S]*?<\/Event>)", content, re.IGNORECASE)
            for block in event_blocks:
                result.total_records_scanned += 1
                parsed_event = SecurityEventParser.parse_xml_string(block)
                if parsed_event:
                    result.events.append(parsed_event)
                    result.parsed_events_count += 1
                if result.total_records_scanned >= max_records:
                    break
        except Exception as e:
            result.parse_errors.append(f"XML file parsing error: {str(e)}")

        return result
