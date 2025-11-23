# Project Structure Overview

## Main Security Analysis Project

```
project/
├── input processing.py              # Main entry point for security analysis
├── enhanced_analysis.py             # Enhanced analysis features (file tree, deduplication)
├── validation_checker.py            # Input validation and sanitization checks
├── pdf_report_generator.py          # PDF report generation with charts
├── project_documentation_generator.py  # Documentation generator
├── concept_map_python.py            # Concept mapping visualization
├── demo_analyzer.py                 # Demo analyzer
│
├── security_checks/                 # NEW: Framework-specific security checks
│   ├── __init__.py                  # Module entry point with run_all_security_checks()
│   ├── base_checker.py              # Base class for all security checkers
│   ├── README.md                    # Module documentation
│   └── framework_checks/            # Framework-specific implementations
│       ├── __init__.py
│       ├── python_frameworks.py     # Django, Flask, FastAPI, Uvicorn
│       ├── javascript_frameworks.py # Express.js, Node.js
│       ├── java_frameworks.py       # Spring Boot, Spring Security
│       └── dotnet_frameworks.py     # ASP.NET, ASP.NET Core, .NET
│
├── test_project/                    # Sample vulnerable project for testing
│   ├── app.py
│   ├── script.js
│   ├── server.php
│   ├── utils.py
│   ├── config/
│   │   ├── creds.env
│   │   └── settings.json
│   └── src/
│       ├── helper.py
│       └── module.js
│
├── requirements.txt                 # Python dependencies
├── README_SECURITY_ANALYZER.md      # Main project README
├── QUICKSTART.md                    # Quick start guide
├── SECURITY_CHECKS_INTEGRATION.md   # NEW: Integration guide
├── PROJECT_STRUCTURE.md             # NEW: This file
└── VALIDATION_FEATURES.md           # Validation features documentation
```

## Module Responsibilities

### Core Analysis Engine

**input processing.py**
- Main orchestration of security analysis
- Project structure extraction (Python, JavaScript, PHP, JSON, ENV)
- Security pattern detection (dangerous functions, secrets, taint sources)
- Framework security checks integration (NEW)
- Risk assessment and scoring
- Report generation

**enhanced_analysis.py**
- File tree hierarchy with risk indicators
- Intelligent findings deduplication
- Data flow diagram generation
- Exploit scenario generation
- Professional formatting utilities

**validation_checker.py**
- Input validation checks
- Boundary checks
- Sanitization verification
- Client-side vs server-side validation
- Unsafe deserialization detection

### Framework Security Checks (NEW)

**security_checks/__init__.py**
- Main entry point: `run_all_security_checks(files_data)`
- Coordinates all framework checkers
- Error handling and result aggregation

**security_checks/base_checker.py**
- Abstract base class for all checkers
- Common functionality (pattern matching, finding creation)
- Standardized finding structure
- Helper methods for code analysis

**security_checks/framework_checks/python_frameworks.py**
- Django security checks (debug, SECRET_KEY, ALLOWED_HOSTS, middleware)
- Flask security checks (debug, SECRET_KEY, CSRF, sessions, CORS)
- FastAPI security checks (reload, CORS, authentication)
- Uvicorn security checks (workers, host binding)

**security_checks/framework_checks/javascript_frameworks.py**
- Express.js checks (headers, CSRF, Helmet, sessions, rate limiting)
- Node.js checks (credentials, eval, child_process, crypto)

**security_checks/framework_checks/java_frameworks.py**
- Spring Boot checks (actuator endpoints, debug, H2 console)
- Spring Security checks (authentication, CSRF)
- Java general checks (SQL injection, deserialization)

**security_checks/framework_checks/dotnet_frameworks.py**
- ASP.NET checks (request validation, ViewState)
- ASP.NET Core checks (HTTPS, HSTS, CORS, authorization)
- Web.config checks (debug, connection strings)
- .NET general checks (SQL injection, crypto)

### Report Generation

**pdf_report_generator.py**
- Professional PDF reports with charts
- Risk visualization
- Executive summaries
- Technical details

**project_documentation_generator.py**
- Project documentation generation
- API documentation
- Architecture documentation

### Utilities

**concept_map_python.py**
- Concept mapping visualization
- Relationship analysis

**demo_analyzer.py**
- Demo and testing utilities

## Data Flow

```
1. User runs: python "input processing.py" <project_folder>
                     ↓
2. scan_project() discovers all files
                     ↓
3. For each file:
   - extract_*_structure() → Parse code structure
   - analyze_file_security() → Detect security issues
                     ↓
4. run_all_security_checks() → Framework-specific checks (NEW)
                     ↓
5. build_taint_flow_analysis() → Correlate sources and sinks
                     ↓
6. calculate_risk_score() → Compute overall risk (includes framework findings)
                     ↓
7. generate_security_report() → Create comprehensive report
                     ↓
8. Output: JSON file + Console report + PDF (optional)
```

## Key Features by Module

### Framework Security Checks (NEW)

| Framework | Checks | Severity Levels |
|-----------|--------|-----------------|
| Django | 7 check types | High, Medium |
| Flask | 8 check types | Critical, High, Medium |
| FastAPI | 4 check types | High, Medium |
| Express.js | 10 check types | Critical, High, Medium |
| Node.js | 7 check types | Critical, High, Medium, Low |
| Spring Boot | 9 check types | Critical, High, Medium |
| Spring Security | 4 check types | Critical, High |
| ASP.NET | 6 check types | High, Medium |
| ASP.NET Core | 6 check types | High, Medium |
| .NET Config | 7 check types | High, Medium, Low |

### Existing Security Features

| Feature | Module | Description |
|---------|--------|-------------|
| Dangerous Functions | input processing | Detects eval, exec, system, etc. |
| Secret Detection | input processing | API keys, tokens, passwords |
| Taint Analysis | input processing | Source → Sink data flow |
| Input Validation | validation_checker | Missing validation detection |
| Sanitization | validation_checker | Unsanitized sinks |
| File Tree | enhanced_analysis | Risk-annotated file tree |
| Deduplication | enhanced_analysis | Intelligent finding aggregation |
| Exploit Scenarios | enhanced_analysis | Red team perspective |
| PDF Reports | pdf_report_generator | Professional reports |

## Integration Points

### How Framework Checks Integrate

```python
# In input processing.py - process_project()

if security_analysis:
    # Run framework-specific security checks (NEW)
    framework_findings = []
    try:
        from security_checks import run_all_security_checks
        framework_findings = run_all_security_checks(detailed_files)
        result["framework_security_findings"] = framework_findings
    except ImportError:
        result["framework_security_findings"] = []
    
    # Include framework findings in risk score (UPDATED)
    result["risk_assessment"] = calculate_risk_score(
        security_data, 
        framework_findings  # <-- Framework findings included
    )
```

### Report Structure

```
A) EXECUTIVE SUMMARY
B) FILE TREE HIERARCHY
C) HIGH-RISK FINDINGS TABLE
D) DATA FLOW MAP & TAINT ANALYSIS
E) DANGEROUS FUNCTIONS OVERVIEW
F) HARDCODED SECRETS & SENSITIVE DATA
G) FRAMEWORK-SPECIFIC SECURITY FINDINGS  ← NEW SECTION
H) INPUT VALIDATION & SANITIZATION
I) POTENTIAL EXPLOIT SCENARIOS
J) DEFENSIVE MEASURES
K) TECHNICAL DEEP-DIVE
L) CRITICAL IMMEDIATE FIXES
```

## Adding New Features

### To Add a New Framework Checker:

1. Create file in `security_checks/framework_checks/`
2. Extend `BaseSecurityChecker`
3. Implement `check()` method
4. Register in `security_checks/__init__.py`

### To Add a New Analysis Type:

1. Add detection function in `input processing.py`
2. Call from `analyze_file_security()`
3. Update `calculate_risk_score()`
4. Add section to report in `generate_security_report()`

## Performance Characteristics

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| File scanning | O(n) | n = number of files |
| Structure extraction | O(m) | m = lines of code per file |
| Pattern matching | O(p × m) | p = number of patterns |
| Framework checks | O(c × f) | c = checkers, f = relevant files |
| Taint analysis | O(n²) | Worst case, typically much faster |
| Report generation | O(r) | r = number of findings |

**Overall**: Linear with project size for typical projects

## Dependencies

```
Core:
- Python 3.x
- ast (built-in)
- re (built-in)
- json (built-in)

Optional:
- esprima (JavaScript parsing)
- phply (PHP parsing)
- reportlab (PDF generation)
- matplotlib (Charts)
```

## File Size Statistics

```
Core modules:
- input processing.py:    ~1,200 lines
- enhanced_analysis.py:      ~460 lines
- validation_checker.py:     ~340 lines

New module:
- base_checker.py:           ~170 lines
- python_frameworks.py:      ~340 lines
- javascript_frameworks.py:  ~285 lines
- java_frameworks.py:        ~270 lines
- dotnet_frameworks.py:      ~390 lines

Total new code: ~1,455 lines
```

## Testing

```bash
# Test framework checks
python "input processing.py" test_project -json

# Test full analysis
python "input processing.py" test_project

# Test PDF generation
python "input processing.py" test_project -pdf

# Test both outputs
python "input processing.py" test_project -json -pdf
```

## Summary

The project now features:
- ✅ Modular architecture with clear separation of concerns
- ✅ Framework-specific security checks for 4 major ecosystems
- ✅ Comprehensive security analysis (static + framework)
- ✅ Professional reporting (console, JSON, PDF)
- ✅ Easy to extend and maintain
- ✅ Well-documented codebase
- ✅ Production-ready integration

**Total Security Checks**: 70+ different check types across all modules


