# ADFIR Conceptual System Architecture

This document specifies the end-to-end dataflow and component architecture of the ADFIR platform.

```mermaid
flowchart TD
    subgraph UI ["Desktop Presentation Layer"]
        A["React 19 + TypeScript UI\n(AppShell, Sidebar, Views)"]
        B["Zustand Reactive Store\n(investigationStore)"]
        A <--> B
    end

    subgraph DESKTOP ["Desktop Native Wrapper"]
        C["Tauri Desktop Core (Rust)\n(Window Management & Security)"]
    end

    subgraph BACKEND ["Python Core Engine (FastAPI)"]
        D["REST API Router\n(/api/investigations, /api/system)"]
        E["Investigation Manager\n(CRUD & Workspace Lifecycle)"]
        F["Evidence Integrity Service\n(Streaming 8MB SHA-256)"]
        G["Investigation Planner\n(Autonomous Evidence Triage)"]
        H["Task Scheduler & Resource Manager\n(Concurrency & Status Tracking)"]
        
        D --> E
        D --> F
        E --> G
        G --> H
    end

    subgraph AGENTS ["Specialist Agent Layer"]
        AG1["DiskAgent [IMPLEMENTED]\n(SleuthKit Adapter)"]
        AG2["MemoryAgent [UNDER DEVELOPMENT]\n(Volatility 3 Runner)"]
        AG3["MalwareAgent [UNDER DEVELOPMENT]\n(YARA Pattern Matcher)"]
        AG4["LogAgent [UNDER DEVELOPMENT]\n(EVTX / Syslog Parser)"]
        AG5["BrowserAgent [UNDER DEVELOPMENT]\n(SQLite History Extractor)"]
        AG6["NetworkAgent [UNDER DEVELOPMENT]\n(PCAP Packet Dissector)"]

        H --> AG1
        H --> AG2
        H --> AG3
        H --> AG4
        H --> AG5
        H --> AG6
    end

    subgraph TOOLS ["Forensic Tool Layer (Ground Truth)"]
        TR["PlatformAwareToolRegistry\n(Linux / Windows Discovery, shell=False)"]
        T1["The Sleuth Kit (fls)"]
        T2["Volatility 3 (vol)"]
        T3["YARA Scanner"]
        T4["ExifTool Parser"]

        AG1 --> TR --> T1
        AG2 --> TR --> T2
        AG3 --> TR --> T3
        AG4 --> TR --> T4
    end

    subgraph SYNTHESIS ["Correlation, Verification & Reporting"]
        SF["Structured Findings\n(Evidence Inodes, Offsets, Raw Refs)"]
        CE["Deterministic Correlation Engine\n(Multi-Source Indicator Graph)"]
        VE["Verification Matrix Engine\n(SUPPORTED / UNSUPPORTED / CONFLICTING)"]
        LLM["Isolated LLM Reasoning Layer\n(Untrusted Data Sanitization)"]
        RG["19-Section Court-Ready Report Generator\n([FACT] vs [INFERENCE] Distinction)"]

        T1 & T2 & T3 & T4 --> SF
        SF --> CE
        SF --> VE
        CE & VE --> LLM
        LLM --> RG
    end

    UI <--> DESKTOP
    DESKTOP <--> D
    RG --> D
```

---

## Agent Implementation Matrix

| Agent | Current Implementation Status | Backing Forensic Engine / Tool |
| :--- | :---: | :--- |
| **`BaseAgent`** | **IMPLEMENTED** | Abstract Base Class contract (`can_handle`, `plan`, `analyze`, `validate`) |
| **`DiskAgent`** | **IMPLEMENTED** | The Sleuth Kit (`fls`) filesystem directory tree parser |
| **`PlannerAgent`** | **IMPLEMENTED** | `InvestigationPlanner` deterministic triage service |
| **`CorrelationAgent`** | **IMPLEMENTED** | `CorrelationEngine` entity clustering service |
| **`VerificationAgent`** | **IMPLEMENTED** | `VerificationEngine` provenance scoring service |
| **`ReportAgent`** | **IMPLEMENTED** | `ReportGenerator` 19-section Markdown synthesis service |
| **`MemoryAgent`** | **UNDER DEVELOPMENT** | Volatility 3 (`vol`) memory dump introspection plugins |
| **`MalwareAgent`** | **UNDER DEVELOPMENT** | YARA (`yara`) signature matcher and rule bank |
| **`LogAgent`** | **UNDER DEVELOPMENT** | Windows Event Log (`.evtx`) security parser |
| **`BrowserAgent`** | **UNDER DEVELOPMENT** | SQLite browser history and cookie parser |
| **`NetworkAgent`** | **UNDER DEVELOPMENT** | PCAP packet dissector and flow reconstructor |
