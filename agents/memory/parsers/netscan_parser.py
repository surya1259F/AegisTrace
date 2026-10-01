import re
from typing import List, Optional
from pydantic import BaseModel, Field

class ParsedNetScanEntry(BaseModel):
    offset: str
    proto: str # TCPv4, UDPv4, TCPv6, UDPv6
    local_addr: str
    local_port: Optional[int] = None
    foreign_addr: str
    foreign_port: Optional[int] = None
    state: str # LISTENING, ESTABLISHED, CLOSED, etc.
    pid: Optional[int] = None
    owner: str # Process name e.g. svchost.exe
    created: Optional[str] = None
    raw_line: str

class NetScanParserResult(BaseModel):
    entries: List[ParsedNetScanEntry] = Field(default_factory=list)
    total_lines: int = 0
    parsed_count: int = 0
    parse_errors: List[str] = Field(default_factory=list)

class NetScanParser:
    """
    Dedicated parser for Volatility 3 windows.netscan output.
    Header format: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
    """

    @classmethod
    def parse(cls, stdout_text: str) -> NetScanParserResult:
        result = NetScanParserResult()
        if not stdout_text:
            return result

        lines = stdout_text.splitlines()
        result.total_lines = len(lines)
        header_found = False

        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            if line_str.startswith("Volatility 3") or line_str.startswith("Progress:"):
                continue

            if "Offset" in line_str and "LocalAddr" in line_str:
                header_found = True
                continue

            if not header_found:
                continue

            cols = [c.strip() for c in re.split(r"\t+|\s{2,}", line_str) if c.strip()]
            if len(cols) >= 6:
                try:
                    offset_val = cols[0]
                    proto_val = cols[1]
                    local_addr_val = cols[2]
                    local_port_val = int(cols[3]) if cols[3].isdigit() else None
                    foreign_addr_val = cols[4]
                    foreign_port_val = int(cols[5]) if cols[5].isdigit() else None
                    
                    # Columns 6+ can be: State, PID, Owner, Created
                    state_val = cols[6] if len(cols) > 6 and not cols[6].isdigit() else "-"
                    
                    # Extract PID and Owner
                    pid_idx = 7 if len(cols) > 7 and cols[7].isdigit() else (6 if cols[6].isdigit() else None)
                    pid_val = int(cols[pid_idx]) if pid_idx is not None else None
                    owner_val = cols[pid_idx + 1] if pid_idx is not None and len(cols) > pid_idx + 1 else "Unknown"
                    created_val = cols[pid_idx + 2] if pid_idx is not None and len(cols) > pid_idx + 2 else None

                    entry = ParsedNetScanEntry(
                        offset=offset_val,
                        proto=proto_val,
                        local_addr=local_addr_val,
                        local_port=local_port_val,
                        foreign_addr=foreign_addr_val,
                        foreign_port=foreign_port_val,
                        state=state_val,
                        pid=pid_val,
                        owner=owner_val,
                        created=created_val,
                        raw_line=line_str
                    )
                    result.entries.append(entry)
                    result.parsed_count += 1
                except Exception as e:
                    result.parse_errors.append(f"Line {line_num}: Failed to parse netscan row '{line_str}': {str(e)}")
            else:
                result.parse_errors.append(f"Line {line_num}: Unexpected column count ({len(cols)}) in '{line_str}'")

        return result
