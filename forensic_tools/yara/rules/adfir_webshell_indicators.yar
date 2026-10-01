rule ADFIR_Webshell_Indicators
{
    meta:
        description = "Detects synthetic webshell indicator patterns in script files"
        author = "ADFIR Engineering"
        version = "1.0.0"
        category = "webshell"
    strings:
        $ws1 = "c99shell" nocase
        $ws2 = "r57shell" nocase
        $ws3 = "eval(base64_decode(" nocase
        $ws4 = "passthru($_POST[" nocase
    condition:
        any of ($ws*)
}
