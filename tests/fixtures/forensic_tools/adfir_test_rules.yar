rule ADFIR_Synthetic_Test_Marker
{
    meta:
        description = "Deterministic synthetic marker rule for ADFIR tool execution validation"
        author = "ADFIR Engineering"
        version = "1.0.0"
        category = "test_fixture"
    strings:
        $token = "ADFIR_SYNTHETIC_TEST_TOKEN_ALPHA_77"
    condition:
        $token
}
