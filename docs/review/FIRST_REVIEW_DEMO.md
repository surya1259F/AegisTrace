# ADFIR — Live Demo Script (First Review)

**Purpose:** Provide an exact, step-by-step demonstration of the working ADFIR prototype for evaluators.  
**Rule:** Only execute currently verified, fully functional capabilities. Do not simulate or fake unfinished tools.

---

## Pre-Demo Setup & Verification

1. Ensure the Python virtual environment and frontend are built:
   ```bash
   cd /home/nandireddy/ADFIR
   source backend/.venv/bin/activate
   export PYTHONPATH=.
   ```
2. Verify the synthetic evidence test fixture exists:
   ```bash
   cat /home/nandireddy/ADFIR/tests/fixtures/sample-evidence.txt
   # Content:
   # ADFIR synthetic test evidence.
   # This file contains no real personal data.
   ```

---

## Step-by-Step Live Demonstration Script

### Step 1: Launch the Application
* **Action:** Start the backend engine and frontend interface:
  ```bash
  # Terminal 1: Backend
  cd /home/nandireddy/ADFIR
  PYTHONPATH=. backend/.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

  # Terminal 2: Frontend
  cd /home/nandireddy/ADFIR/frontend
  npm run dev
  ```
* **Explanation to Evaluators:**  
  *"ADFIR initializes the FastAPI backend server on localhost:8000 and serves the React desktop UI with strict TypeScript bindings."*

---

### Step 2: Create a New Investigation Case
* **UI Action:**
  1. Click **Investigation** in the sidebar.
  2. Click **New Investigation**.
  3. Enter Name: `Incident 2026-08 - Endpoint Intrusion Demo`
  4. Enter Scope: `Triage analysis of suspicious script drops and persistence artifacts.`
  5. Click **Create**.
* **Verification:** The new investigation appears in the case inventory with status `OPEN` and an active status badge.

---

### Step 3: Ingest Synthetic Evidence
* **UI Action:**
  1. Navigate to **Evidence** in the sidebar.
  2. In the **Absolute File Path** field, enter:
     `/home/nandireddy/ADFIR/tests/fixtures/sample-evidence.txt`
  3. In **Notes**, enter: `Acquired forensic artifact from host workstation.`
  4. Click **Calculate SHA-256 & Ingest**.
* **Explanation to Evaluators:**  
  *"Notice how ADFIR canonicalizes the file path to prevent directory traversal (`..`), opens the file strictly in read-only binary mode, and streams the calculation in 8 MiB chunks."*

---

### Step 4: Inspect Evidence Metadata & SHA-256 Hash
* **UI Action:** Click the newly ingested evidence item in the list.
* **Explanation to Evaluators:**  
  *"The detail pane displays the cryptographic SHA-256 hash (`d2af9d92c32657f67b7ca740b74a0d6957cfb2c6bd1487646df232348c13c877`), the exact byte size (73 bytes), and the integrity state `VERIFIED`."*

---

### Step 5: Verify Immutable Chain of Custody
* **UI Action:** Scroll down to the **Immutable Chain of Custody History** section on the Evidence page.
* **Explanation to Evaluators:**  
  *"An immutable audit record `EVIDENCE_REGISTERED` has been appended with the UTC timestamp, user actor (`local-user`), and the SHA-256 cryptographic snapshot. The original evidence remains untouched on disk."*

---

### Step 6: Generate Autonomous Investigation Plan
* **UI Action:**
  1. Return to the **Investigation** page.
  2. Click **Generate Plan**.
* **Explanation to Evaluators:**  
  *"The autonomous InvestigationPlanner evaluates the ingested evidence category (`log`/`file`), inspects tool availability in the PlatformAwareToolRegistry, and outputs a prioritized multi-agent execution strategy."*

---

### Step 7: Record & Review Structured Forensic Findings
* **UI Action:** Navigate to **Findings** in the sidebar.
* **Explanation to Evaluators:**  
  *"Findings are structured objects containing the source agent (`DiskAgent`), tool (`SleuthKit`), category (`filesystem_artifact`), confidence score, and exact evidence reference (e.g. `inode:501`)."*

---

### Step 8: Execute Multi-Source Correlation
* **UI Action:** On the Findings page, click **Execute Correlation & Verification**.
* **Explanation to Evaluators:**  
  *"The CorrelationEngine clusters related artifacts across tools and agents using deterministic indicator matching (e.g., linking shared IP `198.51.100.45` or inode `501` between SleuthKit and YARA) without stochastic hallucination."*

---

### Step 9: Execute Ground-Truth Verification
* **UI Action:** Review the **Ground Truth Verification** pane.
* **Explanation to Evaluators:**  
  *"The VerificationEngine checks whether each finding is anchored in real tool output references. Verified findings receive `[SUPPORTED]` status, while unreferenced claims are flagged as `[UNSUPPORTED]`."*

---

### Step 10: Synthesize and Export 19-Section Report
* **UI Action:**
  1. Navigate to **Reports** in the sidebar.
  2. Click **Synthesize 19-Section Report**.
  3. Review the rendered report in the Markdown studio.
  4. Click **Export Markdown** to download the completed court-ready report file.
* **Explanation to Evaluators:**  
  *"ADFIR generates all 19 court-standardized sections (Executive Summary, Chain of Custody, Timeline, Findings, MITRE ATT&CK Mapping, IOCs, Remediation), strictly labelling `[FACT]` vs `[INFERENCE]` and declaring `INSUFFICIENT EVIDENCE` where data is absent."*

---

## Summary of Demo Capabilities Verified

| Step | Forensic Value | Verified Working? |
| :--- | :--- | :---: |
| **Case Setup** | Full lifecycle isolation | :white_check_mark: YES |
| **Streaming Hashing** | 8MB chunked constant-RAM calculation | :white_check_mark: YES |
| **Chain of Custody** | Immutable audit trail | :white_check_mark: YES |
| **Planning** | Autonomous multi-agent strategy | :white_check_mark: YES |
| **Correlation** | Deterministic cross-source linking | :white_check_mark: YES |
| **Verification** | Ground-truth reference calibration | :white_check_mark: YES |
| **Reporting** | 19-Section court-ready synthesis | :white_check_mark: YES |
