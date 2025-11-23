"""
Security Checks Module
======================

Comprehensive framework-specific security checks for multiple languages and frameworks.

This module provides:
- Python framework checks (Django, Flask, FastAPI)
- JavaScript framework checks (Express.js, Node.js)
- Java framework checks (Spring Boot)
- .NET framework checks (ASP.NET)

Usage:
    from security_checks import run_all_security_checks
    
    findings = run_all_security_checks(files_data)
"""

from .base_checker import BaseSecurityChecker
from .framework_checks.python_frameworks import PythonFrameworkChecker
from .framework_checks.javascript_frameworks import JavaScriptFrameworkChecker
from .framework_checks.java_frameworks import JavaFrameworkChecker
from .framework_checks.dotnet_frameworks import DotNetFrameworkChecker


def run_all_security_checks(files_data: dict) -> list:
    """
    Run all framework-specific security checks on provided files.
    
    Args:
        files_data: Dictionary mapping file paths to file information
        
    Returns:
        List of security findings with severity, type, and recommendations
    """
    findings = []
    
    # Initialize all checkers
    checkers = [
        PythonFrameworkChecker(),
        JavaScriptFrameworkChecker(),
        JavaFrameworkChecker(),
        DotNetFrameworkChecker()
    ]
    
    # Run all checkers on all files
    for path, info in files_data.items():
        try:
            code = load_code(path)
            
            for checker in checkers:
                if checker.can_check_file(path, info):
                    findings.extend(checker.check(code, path))
                    
        except Exception as e:
            # Log error but continue checking other files
            findings.append({
                "file": path,
                "issue": f"Error analyzing file: {str(e)}",
                "severity": "info",
                "type": "error"
            })
    
    return findings


def load_code(path: str) -> str:
    """Load code from file safely"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


__all__ = [
    'BaseSecurityChecker',
    'PythonFrameworkChecker',
    'JavaScriptFrameworkChecker',
    'JavaFrameworkChecker',
    'DotNetFrameworkChecker',
    'run_all_security_checks',
    'load_code'
]


