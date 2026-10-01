import pytest
from agents.malware.parsers.yara_parser import YaraParser

SAMPLE_YARA_OUTPUT = """
ADFIR_Synthetic_Test_Marker [test_tag] [description="Synthetic test rule",author="ADFIR"] /path/to/test_marker_file.txt
0x48:$token: ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77
"""

SAMPLE_MULTI_MATCH_OUTPUT = """
Rule_Alpha [tagA] [version="1.0"] /path/to/sample.bin
0x10:$a: evil_token_1
0x50:$b: evil_token_2
Rule_Beta [] [version="2.0"] /path/to/sample.bin
0x90:$c: suspicious_url_marker
"""

def test_yara_parser_single_match():
    res = YaraParser.parse(SAMPLE_YARA_OUTPUT)
    assert res.parsed_count == 1
    assert len(res.matches) == 1

    match = res.matches[0]
    assert match.rule_name == "ADFIR_Synthetic_Test_Marker"
    assert "test_tag" in match.tags
    assert match.metadata.get("author") == "ADFIR"
    assert match.metadata.get("description") == "Synthetic test rule"
    assert match.target_path == "/path/to/test_marker_file.txt"
    assert len(match.string_matches) == 1

    s0 = match.string_matches[0]
    assert s0.offset == "0x48"
    assert s0.identifier == "$token"
    assert s0.matched_text == "ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"

def test_yara_parser_multiple_matches():
    res = YaraParser.parse(SAMPLE_MULTI_MATCH_OUTPUT)
    assert res.parsed_count == 2
    assert len(res.matches) == 2

    m1 = res.matches[0]
    assert m1.rule_name == "Rule_Alpha"
    assert "tagA" in m1.tags
    assert len(m1.string_matches) == 2
    assert m1.string_matches[0].offset == "0x10"
    assert m1.string_matches[1].offset == "0x50"

    m2 = res.matches[1]
    assert m2.rule_name == "Rule_Beta"
    assert len(m2.string_matches) == 1
    assert m2.string_matches[0].offset == "0x90"

def test_yara_parser_empty_and_whitespace_output():
    assert YaraParser.parse("").parsed_count == 0
    assert YaraParser.parse("   \n\n\t  ").parsed_count == 0

def test_yara_parser_simple_header_without_tags_or_meta():
    raw = "Simple_Rule /tmp/file.txt\n0x01:$s: test_data\n"
    res = YaraParser.parse(raw)
    assert res.parsed_count == 1
    assert res.matches[0].rule_name == "Simple_Rule"
    assert res.matches[0].target_path == "/tmp/file.txt"
    assert len(res.matches[0].string_matches) == 1
