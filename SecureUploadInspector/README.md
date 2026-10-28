# SecureUpload Inspector — File Upload Security and Validation System
**An Academic Cybersecurity Micro-Project for Defense-in-Depth File Ingestion Controls**

---

## 1. Project Title
**SecureUpload Inspector — Multi-Vector File Upload Security and Validation System (Academic Edition)**

---

## 2. Abstract
Web applications routinely accept user-supplied files, exposing internal servers to critical security risks including Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), directory traversal, and resource exhaustion (CWE-434, OWASP Top 10). **SecureUpload Inspector** is a defense-in-depth security verification engine that validates untrusted file uploads across multiple inspection vectors: low-level magic byte signature verification, cryptographic SHA-256 fingerprinting, path traversal defense, double extension detection, and cross-vector MIME concordance checks. Operating entirely offline without external cloud dependencies, the system applies a deterministic policy engine to classify files as `ACCEPTED`, `REJECTED`, or `REVIEW REQUIRED`, safely segregates storage, maintains an auditable SQLite persistence log, and provides structured compliance reporting for academic evaluation.

---

## 3. Problem Statement
Many web applications validate uploaded files using shallow, easily bypassable checks:
1. **Relying solely on filename extensions:** Attackers rename executable binaries (e.g., `malware.exe` to `invoice.pdf` or `webshell.php.png`) to bypass superficial allowlists.
2. **Blindly trusting HTTP `Content-Type` headers:** The `Content-Type` header is set by the client browser or attacker proxy (`curl`, Burp Suite) and can be spoofed arbitrarily.
3. **Improper file storage:** Storing user files inside public web roots (`static/` or `public/`) with user-supplied filenames enables direct URL execution and directory traversal.
4. **False senses of security:** Mistaking format compliance for proof of safety, ignoring embedded payloads (e.g., PDF `/JavaScript` actions or macro vectors).

---

## 4. Objectives
- Implement low-level header magic-byte verification for standard binary formats (`%PDF-`, PNG, JPEG) and heuristic text evaluation.
- Detect and block path traversal sequences (`..`, `/`, `\`), null-byte injections, and obfuscated double extensions.
- Enforce cross-vector concordance between client MIME headers, declared extensions, and detected signatures.
- Execute memory-bounded streaming SHA-256 calculation for non-blocking forensic fingerprinting.
- Implement segregated storage isolation: accepted files in private vault outside web root; rejected files strictly quarantined or purged immediately.
- Provide a responsive Security Operations Center (SOC) dashboard, paginated audit history, and structured plain-text and JSON compliance reports.

---

## 5. Scope
- **In Scope:**
  - File header magic byte detection for PDF, PNG, JPEG, and PE/MZ headers.
  - Plain-text heuristic analysis (cautious character frequency and null byte scanning).
  - Multi-vector policy validation and heuristic risk scoring (0–100).
  - Storage segregation, atomic writes, and random server-side filename assignment (`<uuid>.accepted`).
  - SQLite persistence, paginated audit logs, administrative policy configuration, and report exports.
- **Out of Scope (By Design):**
  - Full dynamic sandboxing or executing uploaded binaries.
  - Deep unpacking of encrypted archive formats (`.zip`, `.tar.gz`).
  - Antivirus signature database integration (e.g., ClamAV/VirusTotal).

---

## 6. Technology Stack
- **Language & Runtime:** Python 3.11+ (Validated on Python 3.14 on Windows 11)
- **Web Framework:** Flask (WSGI, application factory pattern, custom error handlers)
- **Security & Forms:** Flask-WTF (CSRF protection, CSRF token validation)
- **Database:** SQLite 3 (parameterized queries, index optimization, thread-safe connections)
- **Frontend / UI:** HTML5, Jinja2 template inheritance, vanilla CSS3 (Dark Navy SOC aesthetic), vanilla JavaScript (No React, Next.js, or external JS dependencies)
- **Testing:** Pytest (comprehensive unit, integration, and scenario tests)

---

## 7. Architecture

```
                                  [ Client Browser / HTTP Client ]
                                                 │
                                                 │ Multipart POST /upload (with CSRF)
                                                 ▼
                             ┌───────────────────────────────────────┐
                             │    Flask Application Layer (app.py)   │
                             │  - MAX_CONTENT_LENGTH enforcement     │
                             │  - CSRF Token Validation              │
                             │  - Security Response Headers          │
                             └───────────────────┬───────────────────┘
                                                 │
                                                 ▼
                             ┌───────────────────────────────────────┐
                             │  Inspection Service (Orchestrator)    │
                             └───────────────────┬───────────────────┘
                                                 │
        ┌───────────────────┬────────────────────┼───────────────────┬───────────────────┐
        ▼                   ▼                    ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐    ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ File Signatures│   │ Filename Rules│    │ MIME & Headers│   │ Incremental   │   │ Policy Engine │
│ Magic bytes:  │   │ Traversal: .. │    │ Cross-vector  │   │ SHA-256       │   │ Decision:     │
│ PDF, PNG, JPEG│   │ Double-ext:   │    │ concordance   │   │ 64KB chunking │   │ ACCEPTED,     │
│ Text heuristic│   │ .pdf.exe      │    │ verification  │   │ Digesting     │   │ REJECTED,     │
│ PE detection  │   │ Null bytes \0 │    │ Client vs Byte│   │               │   │ REVIEW_REQ    │
└───────────────┘   └───────────────┘    └───────────────┘   └───────────────┘   └───────┬───────┘
                                                                                         │
                                                 ┌───────────────────────────────────────┤
                                                 │ Outcome / Verdict
                                                 ▼
                             ┌───────────────────────────────────────┐
                             │  Safe Storage Layer (quarantine.py)   │
                             │  - Atomic write-then-rename           │
                             │  - Random UUID server filenames       │
                             │  - Accepted: instance/accepted_uploads│
                             │  - Quarantined: instance/quarantine   │
                             │  - Discard: immediate unlink          │
                             │  - Non-executable permissions         │
                             └───────────────────┬───────────────────┘
                                                 │
                                                 ▼
                             ┌───────────────────────────────────────┐
                             │  Persistence Layer (database.py)      │
                             │  - SQLite audit history               │
                             │  - Dynamic dashboard statistics       │
                             │  - App settings key-value store       │
                             └───────────────────────────────────────┘
```

---

## 8. Module Descriptions

| Module | Location | Purpose & Security Controls |
| :--- | :--- | :--- |
| `app.py` | Root | WSGI application factory, HTTP route definitions, CSRF protection, security headers middleware (`X-Content-Type-Options: nosniff`, `Content-Security-Policy`), and custom error handlers (`400`, `404`, `413`, `500`). |
| `config.py` | Root | Central configuration profiles (`DevelopmentConfig`, `TestingConfig`, `ProductionConfig`). Enforces `DEBUG=False` by default, sets storage paths outside web root, and specifies policy constants. |
| `file_signatures.py` | `inspector/` | Bounded file signature analyzer. Reads up to 4096 bytes to detect `%PDF-` (PDF), `\x89PNG\r\n\x1a\n` (PNG), `\xff\xd8\xff` (JPEG SOI), and PE `MZ` headers. Evaluates UTF-8 text heuristics cautiously. |
| `filename_validation.py` | `inspector/` | Evaluates filenames against path traversal sequences (`..`, `/`, `\`), null byte injections (`\x00`), control characters, length constraints, and disguised executable double extensions (e.g., `file.pdf.exe`). |
| `mime_detection.py` | `inspector/` | Multi-vector concordance checker. Compares client-declared `Content-Type` headers against extension expectations and detected magic byte signatures. Flags spoofing attempts. |
| `hashing.py` | `inspector/` | Incremental streaming SHA-256 digest calculation using 64 KB buffers to protect server RAM from exhaustion. Implements timing-attack-resistant constant-time comparison (`hmac.compare_digest`). |
| `policy_engine.py` | `inspector/` | Evaluates modular policy rules (`POL-SIZE-001`, `POL-NAME-001`, `POL-EXT-001`, `POL-SIG-001`, `POL-AGREE-001`) and outputs deterministic decisions (`ACCEPTED`, `REJECTED`, `REVIEW_REQUIRED`). |
| `risk_assessment.py` | `inspector/` | Calculates heuristic risk score (0–100) based on severity weights (`CRITICAL`: 45, `HIGH`: 30, `MEDIUM`: 15, `LOW`: 5). Caps score at 100 and deduplicates repeated rules. |
| `inspection_service.py` | `services/` | 10-stage inspection orchestrator unifying validation, policy checks, cryptographic hashing, segregated storage writes, SQLite persistence, and audit logging. |
| `quarantine_service.py` | `services/` | Segregated storage manager. Stores accepted uploads in `instance/accepted_uploads/` using UUID filenames (`<uuid>.accepted`). Segregates rejected uploads to `instance/quarantine/` or purges them immediately. Applies atomic write-then-rename and non-executable file permissions (`0o600`). |
| `report_service.py` | `services/` | Generates formatted plain-text inspection reports (`/inspection/<id>/report`) and machine-readable JSON exports (`/inspection/<id>/report.json`). Emits checks summary, itemized findings, recommended actions, and cybersecurity disclaimers. |
| `database.py` | `storage/` | SQLite database manager. Manages `inspections`, `app_settings`, and `audit_events` tables. Provides parameterized queries (`?`), schema migrations, paginated history filtering, and real-time dashboard calculations. |
| `audit_log.py` | `storage/` | Dedicated audit logger writing administrative configuration updates and inspection verdicts to SQLite and append-only disk logs. |

---

## 9. Folder Structure

```
SecureUploadInspector/
├── app.py                      # Flask entrypoint, routing, headers & error handlers
├── config.py                   # Configuration profiles & security limits
├── requirements.txt            # Python dependencies (Flask, Flask-WTF, pytest)
├── README.md                   # Full academic project documentation
├── .gitignore                  # Git exclusions for instance, quarantine, and bytecode
├── .env.example                # Sanitized sample environment file
├── inspector/                  # Core File Inspection Engine
│   ├── __init__.py             # Module exports
│   ├── file_signatures.py      # Magic byte header analysis & text heuristics
│   ├── filename_validation.py  # Path traversal, null byte, and double-extension checks
│   ├── mime_detection.py       # Cross-vector MIME vs signature concordance
│   ├── hashing.py              # Incremental streaming SHA-256 calculation
│   ├── policy_engine.py        # Rule-based policy evaluation & decision synthesis
│   └── risk_assessment.py      # Bounded heuristic risk scoring (0-100)
├── services/                   # Application Services Layer
│   ├── __init__.py             # Service exports
│   ├── inspection_service.py   # 10-stage inspection orchestration pipeline
│   ├── quarantine_service.py   # Isolated storage, atomic writes & quarantine vaults
│   └── report_service.py       # Plain text & JSON compliance report generation
├── storage/                    # Persistence & Audit Layer
│   ├── __init__.py             # Storage exports
│   ├── database.py             # SQLite schemas, migrations & metrics aggregation
│   └── audit_log.py            # Event logging & configuration change tracking
├── templates/                  # Jinja2 SOC Templates
│   ├── base.html               # Shared layout, sidebar navigation, footer, disclaimers
│   ├── dashboard.html          # Operational metrics counters, distribution & activity
│   ├── upload.html             # Drag-and-drop file ingestion interface
│   ├── results.html            # Immediate post-upload verdict summary
│   ├── inspection_detail.html  # Comprehensive audit findings, hashes & remediation
│   ├── history.html            # Paginated audit history with multi-vector filtering
│   ├── settings.html           # Policy administration & allowed extension settings
│   ├── about.html              # Threat model & academic rationale
│   └── error.html              # Custom HTTP error pages (400, 404, 413, 500)
├── static/                     # Static Frontend Assets
│   ├── css/style.css           # Dark navy SOC stylesheet & print formatting
│   └── js/app.js               # Drag-and-drop, honest processing state & clipboard copy
├── tests/                      # Automated Pytest Suite (86 tests)
│   ├── conftest.py             # Test fixtures & mock byte payloads
│   ├── test_signatures.py      # Magic byte and text heuristic unit tests
│   ├── test_filename_validation.py # Traversal, null byte & extension tests
│   ├── test_hashing.py         # Chunked SHA-256 and constant-time comparison tests
│   ├── test_policy_engine.py   # Policy evaluations & decision logic tests
│   ├── test_storage_security.py# Storage segregation, quota & atomic write tests
│   ├── test_upload_routes.py   # Flask HTTP upload routes & CSRF tests
│   ├── test_history.py         # Database statistics & pagination tests
│   ├── test_reports.py         # Text report & JSON export tests
│   ├── test_demonstration_scenarios.py # Faculty demonstration scenarios (TEST A-J)
│   └── e2e_verify.py           # Live HTTP workflow verification script
├── data/                       # Application data directory (.gitkeep)
└── instance/                   # Runtime SQLite database & quarantine vaults (.gitkeep)
```

---

## 10. Installation

### Prerequisites
- Python 3.11 or later installed on the system (Python 3.14 verified)
- PowerShell or Windows Command Prompt

### Clone or Open Workspace
Navigate to the project root directory:
```powershell
cd s:\EHMICRO\SecureUploadInspector
```

---

## 11. Windows Execution Commands

Execute the following exact commands in PowerShell to configure and run the project:

```powershell
# 1. Create a dedicated Python virtual environment
py -3 -m venv .venv

# 2. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install pinned dependencies
python -m pip install -r requirements.txt

# 4. Execute the automated test suite
python -m pytest -q

# 5. Start the SecureUpload Inspector server
python app.py
```

### Localhost Access
Upon starting, the application prints its local address:
```
 * Running on http://127.0.0.1:5050
```
Open your browser to: **`http://127.0.0.1:5050`**

*(Note: Debug mode is disabled by default for security; the application binds strictly to loopback interface `127.0.0.1`.)*

---

## 12. Test Execution

The project includes an extensive test suite comprising **86 automated tests** across 10 test modules.

To run tests with full verbose output:
```powershell
pytest -v
```

To run only the faculty demonstration scenarios (TEST A through TEST J):
```powershell
pytest -v tests/test_demonstration_scenarios.py
```

To run live end-to-end HTTP verification against the running daemon:
```powershell
python tests/e2e_verify.py
```

---

## 13. Demonstration Procedure (5-Minute Faculty Walkthrough)

Follow this step-by-step procedure to present the system to faculty or evaluators:

1. **Step 1: Open the SOC Dashboard (`http://127.0.0.1:5050/`)**
   - Review live metric counters (Total Inspected, Accepted, Rejected, Review Required).
   - Point out that every number and format distribution bar is calculated dynamically from SQLite database records without hardcoded numbers.

2. **Step 2: Demonstrate TEST A (Valid PDF Upload)**
   - Navigate to **Inspect File** (`/upload`).
   - Drag or select a legitimate PDF (e.g., `paper.pdf`).
   - Click **Start Security Inspection**.
   - Observe immediate redirect to the results page: **VERDICT: ACCEPTED** with green checkmark icon, SHA-256 hash, and concordance between `.pdf` extension and `%PDF-` header.

3. **Step 3: Demonstrate TEST B (Extension/Signature Mismatch)**
   - On the upload page, select a PNG image renamed to `fake_document.pdf`.
   - Submit the file.
   - Observe **VERDICT: REJECTED** with red X icon.
   - Point out rule `POL-AGREE-001`: Extension `.pdf` conflicted with detected signature `PNG`. Note that this rejected file was prevented from entering accepted storage.

4. **Step 4: Demonstrate TEST C (Prohibited Extension)**
   - Attempt to upload an executable named `tool.exe`.
   - Observe immediate rejection under rule `POL-EXT-001` (extension `.exe` not permitted).

5. **Step 5: View Audit History & Reports (`/history`)**
   - Click **Inspection History** on the sidebar.
   - Demonstrate server-side pagination, decision filtering (`ACCEPTED` vs `REJECTED`), and filename search.
   - Open the audit details for any entry.
   - Click **Text Report** (`/inspection/<id>/report`) to demonstrate plain-text export.
   - Click **JSON Export** (`/inspection/<id>/report.json`) to demonstrate programmatic audit schema.
   - Click **Print Report** to showcase the `@media print` print-friendly stylesheet.

6. **Step 6: Demonstrate Security Settings (`/settings`)**
   - Navigate to **Security Policies**.
   - Demonstrate editing the maximum file size limit or toggling **Discard Rejected Files Immediately**.
   - Save configuration; verify CSRF protection and show that unauthorized extensions (e.g., `.exe`, `.sh`) are rejected by server-side validation.

---

## 14. Sample Test Cases

| Test Case | Filename | Content / Bytes | Expected Outcome | Applied Rules |
| :--- | :--- | :--- | :--- | :--- |
| **TEST A** | `document.pdf` | Genuine `%PDF-1.4` bytes | `ACCEPTED` | All checks pass |
| **TEST B** | `spoof.pdf` | Valid PNG header `\x89PNG...` | `REJECTED` | `POL-AGREE-001` (Extension vs Signature mismatch) |
| **TEST C** | `setup.exe` | Any bytes with `.exe` extension | `REJECTED` | `POL-EXT-001` (Disallowed extension allowlist) |
| **TEST D** | `huge.pdf` | Bytes exceeding configured size limit | `REJECTED` / `413` | `POL-SIZE-002` (File size boundary exceeded) |
| **TEST E** | `audit.txt` | Modified content compared to baseline | Hashes differ | Cryptographic SHA-256 sensitivity verification |
| **TEST F** | `blob.txt` | Arbitrary binary with null bytes | `REJECTED` / `REVIEW` | Text heuristic failure (Never declared safe) |
| **TEST G** | `report.pdf` | Genuine PDF exported to JSON & text | Concordant data | Report values match stored database fields |
| **TEST H** | `trojan.pdf` | PE executable header `MZ...` | Quarantined / Purged | File never enters `accepted_uploads/` |
| **TEST I** | `../../passwd.pdf` | Path traversal sequence in filename | `REJECTED` | `POL-NAME-001` (Path traversal sequence intercepted) |
| **TEST J** | N/A | Fresh empty database initialized | Zero-state 200 OK | Safe empty statistics without crashing |

---

## 15. Security Measures Implemented
- **Segregated Storage Vaults:** Accepted files are stored outside the public web root in `instance/accepted_uploads/` with random UUID filenames (`<uuid>.accepted`). User-supplied filenames are never used as storage paths.
- **Rejection Guarantee:** Rejected files **never** enter accepted storage under any circumstance; they are isolated in `instance/quarantine/` or purged immediately based on policy.
- **No Public Serving:** Uploaded files cannot be accessed or executed through public static URLs (no `/static/` exposure or inline rendering).
- **Atomic Operations:** Staging files are written to temporary files and atomically renamed only upon validation completion, preventing corrupted partial files.
- **CSRF Protection:** Flask-WTF CSRF protection active on all state-changing endpoints (`POST /upload`, `POST /settings`).
- **Memory-Bounded Reads:** Incremental 64 KB chunking prevents RAM exhaustion from large files.
- **Strict Content Security Policy (CSP):** Defense-in-depth CSP meta headers preventing unauthorized inline script injection.
- **SQL Injection Defense:** 100% parameterized queries (`?`) across all database queries.
- **Localhost Binding:** Binds strictly to loopback interface `127.0.0.1` with `DEBUG=False`.

---

## 16. Limitations & Academic Assertions

### Mandatory Academic Security Notice
> **"Passing file validation does not guarantee that a file is free of malware. This tool validates file properties and configured upload policies; it is not a complete antivirus engine."**

### Key Technical Limitations
1. **File Validation vs. Antivirus Detection:**  
   SecureUpload Inspector validates that a file adheres to structural specifications (magic bytes, MIME headers, naming rules) and organizational policies. An attacker can construct a structurally valid PDF containing embedded malicious JavaScript (`/JavaScript` objects), an Adobe Reader zero-day exploit, or a polyglot executable that executes in specific software. Validation is a gatekeeping layer, not an antivirus solution.
2. **Binary Formats vs. Probable Text Heuristics:**  
   Binary formats (PDF, PNG, JPEG) possess standardized, deterministic magic byte signatures at offset 0. Conversely, plain-text files (`.txt`) have no universal header marker. The system evaluates plain-text cautiously using UTF-8 decodability, printable character ratios, and null byte scans. Therefore, plain text is classified as *probable text* rather than certified binary format.
3. **No Dynamic Sandboxing:**  
   The application does not execute files inside an isolated hypervisor or analyze runtime behavioral indicators (e.g., process spawning, registry modification, network egress).

---

## 17. Future Enhancements
- **Internal Object Decomposition:** Deep AST parsing of PDF streams to detect and quarantine `/Launch`, `/JavaScript`, and `/EmbeddedFiles` actions.
- **Image Decompression Scrubbing:** Re-encoding accepted PNG and JPEG images using Pillow to strip malicious EXIF metadata and neutralize steganographic polyglots.
- **Dynamic Sandbox Connector:** Dispatching accepted files to an isolated container (e.g., Docker micro-VM or Cuckoo Sandbox) for runtime dynamic analysis.
- **Cryptographic Hash Feeds:** Offline hash matching against known CVE and threat intelligence feeds (e.g., SHA-256 blocklists).
