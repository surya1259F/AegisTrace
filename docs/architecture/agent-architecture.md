# Agent Architecture

Specialist agents inherit from the abstract `Agent` base class:
- `can_handle(evidence_type)`
- `plan(evidence_item)`
- `analyze(evidence_item, parameters)`
- `validate(findings)`

## Implemented & Planned Agents
- **DiskAgent (Implemented):** Interfaces with SleuthKit (`fls`) to parse partition tables and recover deleted file inodes.
- **MemoryAgent (Interface Ready):** Volatility 3 process tree and network socket parser.
- **MalwareAgent (Interface Ready):** YARA rule scanner.
- **BrowserAgent (Interface Ready):** History and download database parser.
- **LogAgent (Interface Ready):** EVTX and syslog security event analyzer.
- **CorrelationAgent & VerificationAgent:** Rule-based causal graph linkage and truth calibration.
- **ReportAgent:** 19-section synthesis engine.
