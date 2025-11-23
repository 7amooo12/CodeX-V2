# Security Checks Integration Guide

## Overview

This document describes the integration of the new **security_checks** module into the main security analysis engine. The module provides framework-specific security checks for Python, JavaScript, Java, and .NET frameworks.

## What's New

### Framework-Specific Security Checks

The new `security_checks` module adds comprehensive security checks for:

1. **Python Frameworks**
   - Django (debug mode, SECRET_KEY, ALLOWED_HOSTS, middleware, SSL)
   - Flask (debug mode, SECRET_KEY, CSRF, session security, CORS)
   - FastAPI (reload mode, CORS, authentication)
   - Uvicorn (worker config, host binding)

2. **JavaScript Frameworks**
   - Express.js (headers, CSRF, Helmet, sessions, CORS, rate limiting)
   - Node.js (credentials, eval, child_process, crypto, prototype pollution)

3. **Java Frameworks**
   - Spring Boot (actuator endpoints, debug mode, H2 console, Swagger, CORS)
   - Spring Security (authentication, CSRF, credentials)
   - Java General (SQL injection, deserialization, weak crypto)

4. **.NET Frameworks**
   - ASP.NET (request validation, ViewState, event validation)
   - ASP.NET Core (HTTPS, HSTS, CORS, authorization, anti-forgery)
   - Web.config (debug mode, connection strings, SSL settings)
   - .NET General (SQL injection, deserialization, weak crypto)

## Module Structure

```
security_checks/
├── __init__.py                    # Main entry point
├── base_checker.py                # Base class for all checkers
├── framework_checks/              # Framework-specific implementations
│   ├── __init__.py
│   ├── python_frameworks.py       # Python framework checks
│   ├── javascript_frameworks.py   # JavaScript framework checks
│   ├── java_frameworks.py         # Java framework checks
│   └── dotnet_frameworks.py       # .NET framework checks
└── README.md                      # Module documentation
```

## Integration Points

### 1. Main Analysis Engine (`input processing.py`)

The security checks are integrated into the `process_project()` function:

```python
if security_analysis:
    # Run framework-specific security checks
    framework_findings = []
    try:
        from security_checks import run_all_security_checks
        framework_findings = run_all_security_checks(detailed_files)
        result["framework_security_findings"] = framework_findings
    except ImportError:
        result["framework_security_findings"] = []
    
    result["security_analysis"] = security_data
    result["taint_flows"] = build_taint_flow_analysis(security_data)
    result["risk_assessment"] = calculate_risk_score(security_data, framework_findings)
```

### 2. Risk Assessment

Framework findings are now included in the overall risk score calculation:

```python
def calculate_risk_score(security_data: dict, framework_findings: list = None) -> dict:
    # ... existing code ...
    
    # Add framework-specific findings to risk score
    if framework_findings:
        for finding in framework_findings:
            severity = finding.get("severity", "medium").lower()
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
            # ... etc
```

### 3. Report Generation

A new section "G) FRAMEWORK-SPECIFIC SECURITY FINDINGS" has been added to the security report:

- Groups findings by severity
- Shows top 15 findings per severity level
- Includes file, type, line number, and recommendations

## Usage

### Basic Command

```bash
# Run full security analysis
python "input processing.py" <project_folder>

# Generate JSON output
python "input processing.py" <project_folder> -json

# Generate PDF report
python "input processing.py" <project_folder> -pdf

# Generate both JSON and PDF
python "input processing.py" <project_folder> -json -pdf
```

### Example Output

The JSON output now includes a `framework_security_findings` array:

```json
{
  "framework_security_findings": [
    {
      "file": "app.py",
      "issue": "Django debug mode enabled in production",
      "severity": "high",
      "type": "config",
      "line": 23,
      "recommendation": "Set DEBUG = False in production"
    }
  ],
  "security_analysis": { ... },
  "risk_assessment": {
    "total_findings": 28,
    "critical": 10,
    "high": 9,
    "medium": 8,
    "low": 1,
    "risk_level": "CRITICAL"
  }
}
```

## Architecture Benefits

### 1. Modularity
- Each framework has its own checker class
- Easy to add new frameworks without modifying existing code
- Clean separation of concerns

### 2. Scalability
- Framework checks run independently
- Can be easily parallelized in the future
- Minimal performance impact

### 3. Maintainability
- Base class provides common functionality
- Consistent interface across all checkers
- Easy to test individual checkers

### 4. Extensibility
- Simple to add new framework checks
- Can be used as a standalone module
- Well-documented API

## Adding New Framework Checks

To add checks for a new framework:

1. **Create a new checker file** in `security_checks/framework_checks/`:

```python
from ..base_checker import BaseSecurityChecker

class NewFrameworkChecker(BaseSecurityChecker):
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.ext']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        # Add your checks here
        return findings
```

2. **Register the checker** in `security_checks/__init__.py`:

```python
from .framework_checks.new_framework import NewFrameworkChecker

checkers = [
    # ... existing checkers ...
    NewFrameworkChecker()
]
```

3. **Test your checker**:

```bash
python "input processing.py" test_project -json
```

## Testing

The integration has been tested with the `test_project` directory:

```bash
# Test output
[*] Analyzing project: test_project
[*] Security analysis: enabled
[*] JSON output: enabled

[+] JSON output saved to: security_analysis.json

Total findings: 28
- Critical: 10 (including framework findings)
- High: 9
- Medium: 8
- Low: 1
```

## Performance

- **Minimal overhead**: Framework checks only run on relevant files
- **Fast execution**: Uses efficient pattern matching and regex
- **Graceful degradation**: Errors in one checker don't affect others

## Future Enhancements

Potential improvements for the security_checks module:

1. **Additional Frameworks**
   - Ruby on Rails
   - Laravel (PHP)
   - Next.js / React
   - Vue.js
   - Angular

2. **Advanced Features**
   - Framework version detection
   - Configuration file parsing (JSON, YAML, TOML)
   - Dependency vulnerability checking
   - Custom rule definitions

3. **Performance**
   - Parallel checker execution
   - Caching of file analysis
   - Incremental scanning

4. **Integration**
   - CI/CD pipeline integration
   - IDE plugins
   - Git hooks
   - REST API

## Troubleshooting

### Issue: Framework checks not running

**Solution**: Check if the security_checks module is in the Python path:

```python
import sys
print(sys.path)

# Or manually add:
sys.path.append('path/to/security_checks')
```

### Issue: No findings for a framework

**Solution**: Verify the framework is detected:

1. Check file extensions in `supported_extensions`
2. Ensure framework-specific patterns exist in code
3. Review checker logic for your specific case

### Issue: Unicode errors on Windows

**Solution**: The system now handles Unicode gracefully. If you still see errors:

```python
import sys
import codecs
sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
```

## Summary

The security_checks module successfully integrates framework-specific security checks into the main security analysis engine. It provides:

✅ Comprehensive checks for 4 major framework ecosystems
✅ Clean, modular architecture
✅ Easy to extend and maintain
✅ Minimal performance impact
✅ Well-documented and tested

## Contact

For questions or contributions, please refer to the main project repository.


