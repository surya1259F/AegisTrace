import re
from typing import List, Optional
from pydantic import BaseModel, Field

class ParsedPsTreeEntry(BaseModel):
    depth: int
    pid: int
    ppid: int
    image_file_name: str
    offset: str
    threads: Optional[int] = None
    handles: Optional[int] = None
    session_id: Optional[str] = None
    wow64: Optional[bool] = None
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    raw_line: str

class PsTreeParserResult(BaseModel):
    entries: List[ParsedPsTreeEntry] = Field(default_factory=list)
    total_lines: int = 0
    parsed_count: int = 0
    parse_errors: List[str] = Field(default_factory=list)

class PsTreeParser:
    """
    Dedicated parser for Volatility 3 windows.pstree output.
    Header format: PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime
    Hierarchical indentation uses leading '*' markers (e.g. '* 424', '** 528', '*** 668').
    """

    @classmethod
    def parse(cls, stdout_text: str) -> PsTreeParserResult:
        result = PsTreeParserResult()
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

            if "PID" in line_str and "ImageFileName" in line_str:
                header_found = True
                continue

            if not header_found:
                continue

            # Count depth asterisks if present at beginning of line
            depth = 0
            clean_line = line_str
            if clean_line.startswith("*"):
                match_stars = re.match(r"^(\*+)\s*(.*)$", clean_line)
                if match_stars:
                    depth = len(match_stars.group(1))
                    clean_line = match_stars.group(2)

            cols = [c.strip() for c in re.split(r"\t+|\s{2,}", clean_line) if c.strip()]
            if len(cols) >= 4:
                try:
                    pid_val = int(cols[0])
                    ppid_val = int(cols[1])
                    image_name = cols[2]
                    offset_val = cols[3]

                    threads_val = int(cols[4]) if len(cols) > 4 and cols[4].isdigit() else None
                    handles_val = int(cols[5]) if len(cols) > 5 and cols[5].isdigit() else None
                    session_val = cols[6] if len(cols) > 6 else None
                    wow64_val = (cols[7].lower() == "true") if len(cols) > 7 and cols[7] in ["True", "False"] else None
                    create_time_val = cols[8] if len(cols) > 8 and cols[8] != "N/A" else None
                    exit_time_val = cols[9] if len(cols) > 9 and cols[9] != "N/A" else None

                    entry = ParsedPsTreeEntry(
                        depth=depth,
                        pid=pid_val,
                        ppid=ppid_val,
                        image_file_name=image_name,
                        offset=offset_val,
                        threads=threads_val,
                        handles=handles_val,
                        session_id=session_val,
                        wow64=wow64_val,
                        create_time=create_time_val,
                        exit_time=exit_time_val,
                        raw_line=line_str
                    )
                    result.entries.append(entry)
                    result.parsed_count += 1
                except Exception as e:
                    result.parse_errors.append(f"Line {line_num}: Failed to parse pstree row '{line_str}': {str(e)}")
            else:
                result.parse_errors.append(f"Line {line_num}: Unexpected column count ({len(cols)}) in '{line_str}'")

        return result
