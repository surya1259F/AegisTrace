import re
from typing import List, Optional
from pydantic import BaseModel, Field

class ParsedFlsEntry(BaseModel):
    entry_type_raw: str
    entry_type: str # file, directory, virtual, symlink, device, pipe, socket, unknown
    is_deleted: bool
    inode: str
    file_path: str
    raw_line: str

class FlsParserResult(BaseModel):
    entries: List[ParsedFlsEntry] = Field(default_factory=list)
    total_lines: int = 0
    parsed_count: int = 0
    parse_errors: List[str] = Field(default_factory=list)

class FlsParser:
    """
    Robust, dedicated parser for The Sleuth Kit 'fls' command output.
    Parses allocated, deleted, virtual, and directory entries without fragile string splits.
    """

    # Regex matching: <type_prefix>[ *] <inode>:[\t ]<filename/path>
    # e.g. 'r/r 3:\tNORMAL.TXT', 'r/r * 4:\t_VIL.BAT', 'd/d * 12: MyDir'
    FLS_LINE_REGEX = re.compile(
        r"^(?P<type>[a-zA-Z\-]/[a-zA-Z\-])(?:\([a-zA-Z]+\))?\s+(?P<deleted>\*\s+)?(?P<inode>[0-9]+(?:-[0-9]+)*):[\t\s]+(?P<path>.+)$"
    )

    @classmethod
    def _map_entry_type(cls, type_raw: str) -> str:
        t = type_raw.lower()
        if t.startswith("r/"):
            return "file"
        elif t.startswith("d/"):
            return "directory"
        elif t.startswith("v/"):
            return "virtual"
        elif t.startswith("l/"):
            return "symlink"
        elif t.startswith("c/") or t.startswith("b/"):
            return "device"
        elif t.startswith("p/"):
            return "pipe"
        elif t.startswith("s/"):
            return "socket"
        return "unknown"

    @classmethod
    def parse(cls, stdout_text: str) -> FlsParserResult:
        result = FlsParserResult()
        if not stdout_text:
            return result

        lines = stdout_text.splitlines()
        result.total_lines = len(lines)

        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            match = cls.FLS_LINE_REGEX.match(line_str)
            if match:
                type_raw = match.group("type")
                is_del = bool(match.group("deleted"))
                inode_val = match.group("inode")
                file_path_val = match.group("path").strip()

                parsed = ParsedFlsEntry(
                    entry_type_raw=type_raw,
                    entry_type=cls._map_entry_type(type_raw),
                    is_deleted=is_del,
                    inode=inode_val,
                    file_path=file_path_val,
                    raw_line=line_str
                )
                result.entries.append(parsed)
                result.parsed_count += 1
            else:
                # Malformed or unparseable line
                # Ignore non-essential banner lines or record parse error
                if not line_str.startswith("#") and not line_str.startswith("Image:"):
                    result.parse_errors.append(f"Line {line_num}: Unparseable fls format: '{line_str}'")

        return result
