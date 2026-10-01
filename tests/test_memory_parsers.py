import pytest
from agents.memory.parsers.pslist_parser import PsListParser
from agents.memory.parsers.pstree_parser import PsTreeParser
from agents.memory.parsers.netscan_parser import NetScanParser

SAMPLE_PSLIST_OUTPUT = """
Volatility 3 Framework 2.28.0
Progress:  100.00		PDB scanning finished
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output
4	0	System	0xfa800062a040	84	-	N/A	False	2026-08-24 00:00:00.000000 	N/A	Disabled
424	4	smss.exe	0xfa8001712710	2	-	N/A	False	2026-08-24 00:00:01.000000 	N/A	Disabled
528	424	csrss.exe	0xfa8001b5bb30	9	-	0	False	2026-08-24 00:00:02.000000 	N/A	Disabled
600	424	wininit.exe	0xfa8001ca2060	3	-	0	False	2026-08-24 00:00:03.000000 	N/A	Disabled
1420	600	mimikatz.exe	0xfa8001d29060	2	-	0	False	2026-08-24 00:05:00.000000 	N/A	Disabled
"""

SAMPLE_PSTREE_OUTPUT = """
Volatility 3 Framework 2.28.0
Progress:  100.00		PDB scanning finished
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime
4	0	System	0xfa800062a040	84	-	N/A	False	2026-08-24 00:00:00.000000 	N/A
* 424	4	smss.exe	0xfa8001712710	2	-	N/A	False	2026-08-24 00:00:01.000000 	N/A
** 528	424	csrss.exe	0xfa8001b5bb30	9	-	0	False	2026-08-24 00:00:02.000000 	N/A
** 600	424	wininit.exe	0xfa8001ca2060	3	-	0	False	2026-08-24 00:00:03.000000 	N/A
*** 1420	600	mimikatz.exe	0xfa8001d29060	2	-	0	False	2026-08-24 00:05:00.000000 	N/A
"""

SAMPLE_NETSCAN_OUTPUT = """
Volatility 3 Framework 2.28.0
Progress:  100.00		PDB scanning finished
Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created
0xfa8001b44b80	TCPv4	0.0.0.0	135	0.0.0.0	0	LISTENING	788	svchost.exe	2026-08-24 00:00:05.000000
0xfa8001d2b800	TCPv4	192.168.1.50	49152	198.51.100.22	443	ESTABLISHED	1420	mimikatz.exe	2026-08-24 00:05:10.000000
0xfa8001e5a100	UDPv4	0.0.0.0	53	*	*	-	1012	dns.exe	2026-08-24 00:00:06.000000
"""

def test_pslist_parser_valid_output():
    res = PsListParser.parse(SAMPLE_PSLIST_OUTPUT)
    assert res.parsed_count == 5
    assert len(res.entries) == 5
    assert len(res.parse_errors) == 0

    p_sys = res.entries[0]
    assert p_sys.pid == 4
    assert p_sys.ppid == 0
    assert p_sys.image_file_name == "System"
    assert p_sys.offset == "0xfa800062a040"
    assert p_sys.threads == 84
    assert p_sys.wow64 is False

    p_mimi = res.entries[4]
    assert p_mimi.pid == 1420
    assert p_mimi.ppid == 600
    assert p_mimi.image_file_name == "mimikatz.exe"

def test_pslist_parser_malformed_rows():
    malformed = (
        "PID\tPPID\tImageFileName\tOffset(V)\n"
        "NOT_A_NUMBER\t4\tbad.exe\t0x1234\n"
        "100\t50\tvalid.exe\t0x5678\n"
        "TOO_FEW_COLUMNS\n"
    )
    res = PsListParser.parse(malformed)
    assert res.parsed_count == 1
    assert len(res.parse_errors) == 2
    assert res.entries[0].image_file_name == "valid.exe"

def test_pstree_parser_valid_output():
    res = PsTreeParser.parse(SAMPLE_PSTREE_OUTPUT)
    assert res.parsed_count == 5
    assert len(res.parse_errors) == 0

    assert res.entries[0].depth == 0
    assert res.entries[0].image_file_name == "System"

    assert res.entries[1].depth == 1
    assert res.entries[1].image_file_name == "smss.exe"

    assert res.entries[4].depth == 3
    assert res.entries[4].image_file_name == "mimikatz.exe"

def test_netscan_parser_valid_output():
    res = NetScanParser.parse(SAMPLE_NETSCAN_OUTPUT)
    assert res.parsed_count == 3
    assert len(res.parse_errors) == 0

    n1 = res.entries[0]
    assert n1.proto == "TCPv4"
    assert n1.local_port == 135
    assert n1.state == "LISTENING"
    assert n1.owner == "svchost.exe"
    assert n1.pid == 788

    n2 = res.entries[1]
    assert n2.proto == "TCPv4"
    assert n2.foreign_addr == "198.51.100.22"
    assert n2.foreign_port == 443
    assert n2.state == "ESTABLISHED"
    assert n2.owner == "mimikatz.exe"
    assert n2.pid == 1420

def test_empty_and_header_only_outputs():
    assert PsListParser.parse("").parsed_count == 0
    assert PsTreeParser.parse("").parsed_count == 0
    assert NetScanParser.parse("").parsed_count == 0

    header_only = "Volatility 3 Framework\nPID\tPPID\tImageFileName\tOffset(V)\n"
    assert PsListParser.parse(header_only).parsed_count == 0
