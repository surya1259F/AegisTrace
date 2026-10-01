rule ADFIR_Suspicious_Command_Patterns
{
    meta:
        description = "Detects suspicious command-line execution patterns"
        author = "ADFIR Engineering"
        version = "1.0.0"
        category = "suspicious_command"
    strings:
        $cmd1 = "powershell.exe -enc" nocase
        $cmd2 = "powershell -encodedcommand" nocase
        $cmd3 = "certutil -urlcache -split -f" nocase
        $cmd4 = "bitsadmin /transfer" nocase
    condition:
        any of ($cmd*)
}
