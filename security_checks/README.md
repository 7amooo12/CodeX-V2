# Security Checks Module

## Overview

This module provides comprehensive framework-specific security checks for multiple programming languages and frameworks. It's designed to be modular, scalable, and easy to maintain.

## Structure

```
security_checks/
├── __init__.py                    # Main module entry point
├── base_checker.py                # Base class for all checkers
├── framework_checks/              # Framework-specific checks
│   ├── __init__.py
│   ├── python_frameworks.py       # Django, Flask, FastAPI
│   ├── javascript_frameworks.py   # Express.js, Node.js
│   ├── java_frameworks.py         # Spring Boot
│   └── dotnet_frameworks.py       # ASP.NET, .NET Core
└── README.md                      # This file
```

## Features

### Python Framework Checks
- **Django**: Debug mode, SECRET_KEY exposure, ALLOWED_HOSTS, middleware, SSL settings
- **Flask**: Debug mode, SECRET_KEY, CSRF protection, session security, CORS
- **FastAPI**: Reload mode, CORS, authentication
- **Uvicorn**: Worker configuration, host binding

### JavaScript Framework Checks
- **Express.js**: X-Powered-By header, CSRF, Helmet, session security, CORS, rate limiting
- **Node.js**: Hardcoded credentials, eval usage, child_process, crypto, prototype pollution

### Java Framework Checks
- **Spring Boot**: Actuator endpoints, debug mode, H2 console, Swagger UI, CORS
- **Spring Security**: permitAll, CSRF, Basic auth, hardcoded credentials
- **General Java**: SQL injection, deserialization, weak crypto

### .NET Framework Checks
- **ASP.NET**: Request validation, ViewState, event validation, custom errors
- **ASP.NET Core**: HTTPS redirection, HSTS, CORS, authorization, anti-forgery tokens
- **Web.config**: Debug mode, connection strings, timeout, SSL settings
- **General .NET**: SQL injection, deserialization, weak crypto

## Usage

### Basic Usage

```python
from security_checks import run_all_security_checks

# files_data should be a dict mapping file paths to file information
files_data = {
    "path/to/file.py": {...},
    "path/to/file.js": {...}
}

findings = run_all_security_checks(files_data)

for finding in findings:
    print(f"{finding['severity']}: {finding['issue']}")
    print(f"File: {finding['file']}")
    print(f"Recommendation: {finding.get('recommendation', 'N/A')}")
```

### Integration with Existing Project

The module is already integrated with `input processing.py`. When you run the security analysis, framework-specific checks are automatically executed:

```bash
python "input processing.py" <project_folder> -json
```

Results will include a `framework_security_findings` section with all detected issues.

## Adding New Checkers

### 1. Create a New Checker Class

Create a new file in `framework_checks/` directory:

```python
from ..base_checker import BaseSecurityChecker

class MyFrameworkChecker(BaseSecurityChecker):
    """Security checker for MyFramework"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.ext']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Run all security checks"""
        findings = []
        
        # Your checks here
        if "dangerous_pattern" in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Dangerous pattern detected",
                severity="high",
                finding_type="misconfiguration",
                recommendation="Fix the issue"
            ))
        
        return findings
```

### 2. Register the Checker

Add your checker to `security_checks/__init__.py`:

```python
from .framework_checks.my_framework import MyFrameworkChecker

# Add to checkers list in run_all_security_checks()
checkers = [
    PythonFrameworkChecker(),
    JavaScriptFrameworkChecker(),
    JavaFrameworkChecker(),
    DotNetFrameworkChecker(),
    MyFrameworkChecker()  # Add your checker
]
```

## Finding Structure

Each finding follows this structure:

```python
{
    "file": str,              # Path to the file
    "issue": str,             # Description of the issue
    "severity": str,          # critical|high|medium|low|info
    "type": str,              # config|exposure|misconfiguration|injection|etc
    "line": int,              # (Optional) Line number
    "recommendation": str     # (Optional) How to fix
}
```

## Severity Levels

- **CRITICAL**: Immediate action required (RCE, hardcoded secrets, SQL injection)
- **HIGH**: Should be fixed soon (missing authentication, CSRF, weak crypto)
- **MEDIUM**: Security concern (missing headers, debug mode, CORS)
- **LOW**: Minor issue (single worker, timeout settings)
- **INFO**: Informational (configuration suggestions)

## Best Practices

1. **Keep checks focused**: Each check should look for one specific issue
2. **Provide clear recommendations**: Always include actionable fix suggestions
3. **Use appropriate severity levels**: Be consistent with severity assignment
4. **Test thoroughly**: Test your checkers with real code samples
5. **Document patterns**: Explain what each pattern is looking for

## Testing

To test your checker:

1. Create a sample vulnerable file
2. Run the analysis on that file
3. Verify findings are correct

```python
# test_checker.py
from security_checks.framework_checks.my_framework import MyFrameworkChecker

checker = MyFrameworkChecker()
code = "vulnerable code here"
findings = checker.check(code, "test.ext")

assert len(findings) > 0
assert findings[0]['severity'] == 'high'
```

## Performance Considerations

- **File filtering**: Checkers only run on relevant file types (see `supported_extensions`)
- **Early returns**: Return early if framework is not detected
- **Efficient patterns**: Use simple string matching before regex when possible
- **Error handling**: Gracefully handle parsing errors

## Contributing

When adding new framework checks:

1. Create a new checker class extending `BaseSecurityChecker`
2. Implement comprehensive checks for that framework
3. Update this README with supported frameworks
4. Add test cases
5. Update the main `__init__.py` to include your checker

## License

Same as the main project.

## Support

For issues or questions about this module, please refer to the main project documentation.



