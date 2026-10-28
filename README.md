# EHMICRO — SecureUpload Inspector

> **An Academic Cybersecurity Micro-Project for Defense-in-Depth File Ingestion Controls**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: Pytest](https://img.shields.io/badge/tests-pytest-green.svg)](https://docs.pytest.org/)
[![Security: OWASP Top 10](https://img.shields.io/badge/security-OWASP%20A04%2FA08-red.svg)](https://owasp.org/)

---

## 1. Overview & Abstract

Web applications routinely accept user-supplied files, exposing internal servers to critical security risks including Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), directory traversal, and resource exhaustion (CWE-434, OWASP Top 10).

**SecureUpload Inspector** is a defense-in-depth security verification engine that validates untrusted file uploads across multiple inspection vectors:
- Low-level magic byte signature verification (offset 0 inspection for PDF, PNG, JPEG, and PE/MZ binaries)
- Cryptographic SHA-256 fingerprinting via memory-bounded 64 KB streaming chunks
- Path traversal defense (`..`, absolute paths, null bytes `\0`, directory escape sequences)
- Obfuscated double-extension detection (e.g. `document.pdf.exe`)
- Cross-vector MIME concordance checks (validating declared client HTTP `Content-Type` against signature and extension)
- Segregated storage vaults outside web roots using cryptographically random UUID names (`<uuid>.accepted`)
- Strict quarantine and configurable purge policies for rejected submissions
- Immutable SQLite audit trails, dynamic Security Operations Center (SOC) dashboard, and structured compliance reports (plain-text and JSON)

---

## 2. Repository Structure

```
EHMICRO/
├── .gitignore                          # Global version control exclusions
├── pytest.ini                          # Root test runner configuration
├── README.md                           # Repository documentation
└── SecureUploadInspector/              # Core Application Package
    ├── app.py                          # Flask application factory & HTTP routes
    ├── config.py                       # Security policy configuration & environments
    ├── requirements.txt                # Python dependencies
    ├── pytest.ini                      # Sub-package pytest configuration
    ├── .env.example                    # Template environment variables
    ├── .gitignore                      # Sub-package exclusions
    ├── README.md                       # Comprehensive project manual
    ├── data/                           # Data persistence directory (.gitkeep)
    ├── instance/                       # Runtime isolated vaults (.gitkeep)
    ├── inspector/                      # Core Security Inspection Engines
    │   ├── __init__.py
    │   ├── file_signatures.py          # Magic-byte detection (PDF, PNG, JPEG, PE)
    │   ├── filename_validation.py      # Traversal, null byte & extension analysis
    │   ├── hashing.py                  # Streaming cryptographic SHA-256 calculator
    │   ├── mime_detection.py           # Cross-vector MIME concordance checks
    │   └── policy_engine.py            # Decision matrix & heuristic risk scoring
    ├── services/                       # Orchestration Services
    │   ├── __init__.py
    │   ├── inspection_service.py       # Multi-vector inspection coordinator
    │   ├── quarantine_service.py       # Isolated vaults & safe storage handlers
    │   └── report_service.py           # Text, JSON & printable report generators
    ├── storage/                        # Persistence & Auditing
    │   ├── __init__.py
    │   ├── database.py                 # Thread-safe parameterized SQLite engine
    │   └── audit_log.py                # Structured audit event logger
    ├── static/                         # Frontend Static Assets
    │   ├── css/style.css               # SOC dark-mode stylesheet & print media
    │   ├── js/app.js                   # Client-side UI utilities & drag-and-drop
    │   └── images/                     # Static UI assets
    ├── templates/                      # Jinja2 Security Templates
    │   ├── base.html                   # Master template with CSP meta headers
    │   ├── dashboard.html              # SOC live metrics dashboard
    │   ├── upload.html                 # Secure multi-file upload portal
    │   ├── results.html                # Inspection verdict & violation breakdowns
    │   ├── history.html                # Paginated audit log explorer
    │   ├── inspection_detail.html      # Forensic audit inspection drill-down
    │   ├── settings.html               # Administrative policy control panel
    │   ├── about.html                  # Educational security architecture guide
    │   └── error.html                  # Safe generic error views
    └── tests/                          # Automated Pytest Suite
        ├── conftest.py                 # Pytest fixtures & in-memory test DB
        ├── test_signatures.py          # Magic-byte test coverage
        ├── test_filename_validation.py # Path traversal & double-extension tests
        ├── test_policy_engine.py       # Policy evaluation & risk score tests
        ├── test_hashing.py             # SHA-256 sensitivity & chunking tests
        ├── test_storage_security.py    # Quarantine isolation & permissions tests
        ├── test_upload_routes.py       # HTTP route & CSRF validation tests
        ├── test_reports.py             # Plain-text & JSON report tests
        ├── test_history.py             # Pagination & query filter tests
        ├── test_demonstration_scenarios.py # Scenarios TEST A - TEST J
        └── e2e_verify.py               # Live daemon end-to-end verification script
```

---

## 3. Quick Start

### Prerequisites
- Python 3.11 or higher
- PowerShell, Bash, or Command Prompt
- `pip` package manager

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pradeepzxi/EHMICRO.git
   cd EHMICRO
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(On macOS/Linux: `source .venv/bin/activate`)*

3. **Install dependencies:**
   ```powershell
   pip install -r SecureUploadInspector/requirements.txt
   ```

4. **Launch the application:**
   ```powershell
   python SecureUploadInspector/app.py
   ```
   The application will bind locally to `http://127.0.0.1:5050/`.

---

## 4. Running Tests

Run the full automated pytest suite from repository root:

```powershell
pytest
```

To run with verbose output and test names:
```powershell
pytest -v
```

To run specific scenario tests:
```powershell
pytest SecureUploadInspector/tests/test_demonstration_scenarios.py -v
```

---

## 5. Security Architecture

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

## 6. Academic Security Notice & Disclaimer

> **"Passing file validation does not guarantee that a file is free of malware. This tool validates file properties and configured upload policies; it is not a complete antivirus engine."**

This system is built as an educational and academic demonstration of defense-in-depth ingestion controls, format verification, and storage isolation.

---

## 7. License

Licensed under the MIT License. See LICENSE for details.
