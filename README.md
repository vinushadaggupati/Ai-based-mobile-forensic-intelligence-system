# AI-Based Mobile Forensic Intelligence System (MFIS)

A professional digital forensics intelligence system engineered specifically for **Android mobile investigations**. The system connects to Android devices via authorized **ADB (Android Debug Bridge)**, accepts multi-format evidence uploads from laptops and mobile transfers, computes cryptographically secure **SHA-256** hashes to guarantee chain-of-custody, maintains a relational database in **SQLite** with Write-Ahead Logging (WAL), performs digital forensic analysis across multiple artifacts, leverages local **Ollama (`llama3.2:3b`)** for AI-assisted interpretation, and generates court-admissible **20-section PDF forensic investigation reports**, JSON case deliverables, and CSV findings tables.

---

## 🏛️ System Architecture

```text
               +-------------------------------------------------------+
               |        EVIDENCE ACQUISITION (THREE MODES)             |
               +-------------------------------------------------------+
                  |                         |                       |
            [OPTION A]                 [OPTION B]              [OPTION C]
        Authorized ADB           Laptop Evidence Upload      Mobile Transfer
    (getprop, dumpsys, bugreport)  (DB, SQLite, Log, JSON)   (Exported Folders)
                  \                         |                       /
                   \                        |                      /
                    +-----------------------v---------------------+
                                            |
                               [SHA-256 Binary Stream Hashing]
                                  (hashlib, 64 KB Chunks)
                                            |
                      +---------------------+---------------------+
                      |                                           |
             [Master Preservation]                        [Isolated Working Copy]
         evidence_storage/<case_id>/                     working_copies/<case_id>/
             (Read-Only Master)                            (Analysis & Inspection)
                      |                                           |
                      +---------------------+---------------------+
                                            |
                                  [SQLite Database]
                                (database/forensic.db)
                                  WAL Journaling Mode
                                            |
               +----------------------------+----------------------------+
               |                                                         |
    [Forensic Analysis Engine]                                [Local Ollama AI]
  - SQLite Freelist Carving                                  - Model: llama3.2:3b
  - Chromium URL History Extraction                          - Air-gapped / Local only
  - Logcat Root & Tor Anomaly Scans                          - Tri-Category Findings:
  - Anti-Forensic App Profiling                                * Confirmed Evidence
  - Telephony & SMS Pattern Matches                           * AI Observation
                                                              * Possible Lead
               |                                                         |
               +----------------------------+----------------------------+
                                            |
                           [Official Forensic Reports]
                          - 20-Section PDF (ReportLab)
                          - Structured Case Deliverable (JSON)
                          - Categorized Findings Table (CSV)
```

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **User Interface** | **Streamlit** (Multi-Page Architecture) | Interactive investigator workstation & dashboard |
| **Mobile Acquisition** | **Android Debug Bridge (ADB)** | Authorized USB connection & non-root logical extraction |
| **Evidence Database** | **SQLite3** (WAL Mode + Foreign Keys) | Persistent case registry, evidence catalog, and audit trail |
| **Integrity Assurance** | **SHA-256 (`hashlib`)** | Cryptographic hash calculation and tamper verification |
| **Data Processing** | **Pandas** | Tabular evidence structuring and reporting |
| **Forensic Analysis** | **Custom Python Modules** | SQLite freelists, Chromium history, logcat, and package analysis |
| **Local AI Inference** | **Ollama (`llama3.2:3b`)** | Natural language synthesis and cross-evidence reasoning |
| **Report Generation** | **ReportLab (Python)** | Professional 20-section court-admissible PDF generation |
| **Chain-of-Custody** | **SQLite Audit Logging** | Immutable forensic operation event trail |

---

## 📋 Forensic Modules & Capabilities

### 1. Project Dashboard (`pages/1_📊_Dashboard.py`)
- Live KPIs: Total cases, connected Android devices, evidence files, analyzed evidence, verified files, integrity mismatches, and reports generated.
- Tri-category findings breakdown: **Confirmed Evidence**, **AI Observations**, and **Possible Leads**.
- Recent investigation audit stream and interactive visual charts.

### 2. Case Management (`pages/2_📁_Case_Management.py`)
- Create new investigation cases with unique generated Case IDs (`CASE-YYYYMMDD-XXXXXX`).
- Record case metadata: case title, narrative description, investigator name, agency, and creation timestamp.
- Switch between active cases and view comprehensive dossiers for each investigation.

### 3. Android Device Connection (`pages/3_📱_Connect_Android_Device.py`)
- Detects whether Google Android SDK Platform Tools (`adb`) is installed and in system PATH.
- Real-time device scanning (`adb devices -l`) displaying device serial, model, manufacturer, and Android version.
- Detects USB debugging authorization status (`device` vs `unauthorized`).
- Pulls comprehensive system diagnostics: `getprop`, `dumpsys battery`, storage space, and root/su status.
- Official Android SDK Platform-Tools installation guidance when ADB is missing:
  - Download: [Google Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools)

### 4. Evidence Acquisition - Three Distinct Methods (`pages/4_📥_Evidence_Acquisition.py`)
- **Option A: Android Connection via ADB**
  - Logical extraction of authorized device parameters, package lists (`pm list packages -3`), dumpsys telephony/location, and accessible files.
  - Transparent documentation of Android security limitations: non-root logical acquisition cannot bypass screen locks or extract private SELinux-sandboxed databases without root.
- **Option B: Upload Evidence from Laptop**
  - Ingest forensic files: `.db`, `.sqlite`, `.log`, `.txt`, `.json`, `.csv`, `.xml`, and zip archives.
  - Generates unique Evidence ID, calculates SHA-256, stores original master file in `evidence_storage/<case_id>/`, and creates an isolated working copy in `working_copies/<case_id>/`.
- **Option C: Mobile-Transferred Files**
  - Ingest previously exported SD card directories, MTP dumps, or device backup packages.

### 5. Evidence Management & Catalog (`pages/5_🗄️_Evidence_Management.py`)
- Tabular evidence inventory with filtering by Case ID and evidence type.
- Preview raw file contents safely (first 100 lines / formatted JSON).
- Inspect acquisition timestamps, source paths, and file sizes.

### 6. SHA-256 Integrity Verification (`pages/6_🔒_Integrity_Verification.py`)
- Recalculates SHA-256 hashes of physical evidence files using streaming binary chunks.
- Validates against original stored acquisition hashes:
  - `INTEGRITY VERIFIED`
  - `INTEGRITY MISMATCH` (Alerts examiner to potential tampering)
  - `VERIFICATION FAILED` (File missing or inaccessible)
- Interactive Tamper Simulation tool to demonstrate cryptographic tamper detection in court.

### 7. Digital Forensic Analysis (`pages/7_🔬_Forensic_Analysis.py`)
- Automated multi-artifact rule engine:
  - **Suspicious SMS & Chat Keywords**: `burn the phone`, `wipe the sd card`, `delete the logs`, `cold wallet`, `0.6 btc`, `mixer`, `encrypted channel`.
  - **Anti-Forensic Tools**: Detects installed packages such as Orbot (`org.torproject.android`), iShredder (`com.protectstar.ishredder`), Wickr Me (`com.mywickr.wickr2`), and crypto wallets.
  - **Unusual Calling Patterns**: Flags off-hours late-night calls (22:00–05:00 UTC) and rapid-dial clusters.
  - **Suspicious Web Destinations**: Darknet `.onion` domains, cryptocurrency mixers, and anti-forensics forums.
  - **Mock GPS Spoofing**: Detects developer mock location provider activity.
- Classifies all findings into:
  1. `CONFIRMED EVIDENCE` (Direct forensic artifacts)
  2. `AI OBSERVATION` (Probabilistic correlations)
  3. `POSSIBLE LEAD` (Recommended lines of inquiry)

### 8. SQLite Database Examination (`pages/8_🗃️_SQLite_Database_Examination.py`)
- Inspects SQLite header (magic bytes `SQLite format 3\000`, page size, freelist trunk count).
- Browses tables, schemas, and queries live records.
- Flags unallocated space and deleted freelist blocks suitable for Autopsy / The Sleuth Kit carving.

### 9. AI-Assisted Evidence Analysis (`pages/9_🤖_AI_Analysis.py`)
- Local inference via **Ollama (`llama3.2:3b`)** running at `http://127.0.0.1:11434`.
- Constructs structured forensic prompt payloads from case metadata, devices, evidence inventory, and findings.
- Generates executive narrative summaries, anomaly explanations, and concrete recommendations.
- Automatic deterministic fallback engine ensures seamless operation even when Ollama is offline or the model is not yet pulled.

### 10. Investigation Timeline (`pages/10_⏱️_Timeline.py`)
- Unified chronological timeline showing case creation, device acquisitions, suspicious findings, and integrity verifications in temporal order.

### 11. Automated Forensic Report Generation (`pages/11_📄_Report_Generation.py`)
- Generates official court-admissible reports in three formats:
  1. **PDF Report (ReportLab)**: Structured into 20 formal forensic sections:
     - Section 1: Executive Case Header & Investigation ID
     - Section 2: Case Overview & Investigator Credentials
     - Section 3: Android Device Hardware Profile
     - Section 4: Acquisition Methodology & Non-Root Limitations
     - Section 5: Evidence Inventory & Preservation Paths
     - Section 6: Cryptographic SHA-256 Hash Verification Table
     - Section 7: Telephony & Call Log Analysis
     - Section 8: SMS & Messaging Analysis (Suspicious Keyword Hits)
     - Section 9: Installed Applications & Anti-Forensic Tool Profiling
     - Section 10: Chromium Browser History & Darknet Exploration
     - Section 11: GPS Telemetry & Geospatial Movement Anomalies
     - Section 12: Android System Logcat & Privilege Escalation Findings
     - Section 13: SQLite Freelist & Database Storage Inspection
     - Section 14: Categorized Findings Table (Confirmed / AI / Leads)
     - Section 15: Cross-Artifact Correlation Analysis
     - Section 16: Local Ollama AI Investigative Synthesis
     - Section 17: Forensic Threat & Risk Assessment
     - Section 18: Chain-of-Custody Audit Log Excerpt
     - Section 19: Actionable Recommendations (Technical & Legal)
     - Section 20: Examiner Certification & Court Attestation Signature Block
  2. **JSON Report**: Complete structured data deliverable for case archival.
  3. **CSV Export**: Spreadsheet of all categorized forensic findings.

### 12. Chain-of-Custody Audit Logs (`pages/12_📋_Audit_Logs.py`)
- Immutable log table tracking every action: `CREATE_CASE`, `ACQUIRE_EVIDENCE`, `INTEGRITY_VERIFICATION`, `FORENSIC_ANALYSIS`, and `GENERATE_REPORT`.
- Downloadable audit log in CSV format.

---

## 🚀 Quickstart & Installation

### Prerequisites
1. **Python 3.10 or higher** installed and available in PATH.
2. *(Optional for mobile)* **Android SDK Platform Tools (ADB)** in PATH.
3. *(Optional for AI)* **Ollama** installed with `llama3.2:3b` model.

### 1. Clone & Install Dependencies

```powershell
# Navigate to project directory
cd Ai-based-mobile-forensic-intelligence-system-1

# Install required Python packages
pip install -r requirements.txt
```

### 2. Launch the System

Double-click `run_app.bat` or run:

```powershell
python -m streamlit run app.py
```

The forensic workstation will open in your default browser at:
`http://localhost:8501`

Alternatively, launch using the interactive launcher:
```powershell
.\start-system.bat
```

---

## 🧪 Running Automated Verification Tests

The project includes an end-to-end verification script testing all modules:

```powershell
python test_forensic_pipeline.py
```

This validates:
- SQLite schema creation and WAL mode activation
- Case creation and metadata storage
- Synthetic evidence generation and binary SHA-256 hashing
- Working copy duplication and isolation
- Valid hash verification and tamper detection
- Forensic analysis with tri-category findings classification
- AI summary generation (Ollama / heuristic fallback)
- 20-Section PDF report generation via ReportLab
- JSON and CSV report export
- Audit trail recording and KPI metric aggregation

---

## 🤖 Ollama Local AI Setup (Optional)

1. Download Ollama from [ollama.com](https://ollama.com).
2. Start the Ollama server:
   ```powershell
   ollama serve
   ```
3. Pull the recommended forensic model:
   ```powershell
   ollama run llama3.2:3b
   ```
4. The system will automatically detect the running Ollama instance at `http://127.0.0.1:11434`. If Ollama is not running, the system automatically uses its built-in forensic heuristic engine.

---

## 🔒 Forensic Standards Compliance
- **NIST SP 800-101 Rev. 1**: Guidelines on Mobile Device Forensics.
- **ISO/IEC 27037**: Guidelines for Identification, Collection, Acquisition, and Preservation of Digital Evidence.
- **ACPO Good Practice Guide**: Digital Evidence principles (no action taken should change data held on a device).
