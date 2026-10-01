# ADFIR Controlled YARA Rule Repository

This directory contains deterministic, locally reviewed, and versioned YARA signature rules.
Rules in this directory are validated by `YaraRuleRepository` and executed through `PlatformAwareToolRegistry`.

## Invariant Rules
- No external/untrusted rule downloads at runtime.
- No arbitrary user-supplied rule paths from the API or frontend.
- All rules must compile without syntax errors.
