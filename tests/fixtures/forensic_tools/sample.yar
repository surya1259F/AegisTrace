rule Synthetic_Test_Rule
{
    meta:
        description = "Synthetic test YARA rule for ADFIR tool execution validation"
        author = "ADFIR Engineering"
        version = "1.0"
    strings:
        $token = "ADFIR_TEST_SIGNATURE_ALPHA_77"
    condition:
        $token
}
