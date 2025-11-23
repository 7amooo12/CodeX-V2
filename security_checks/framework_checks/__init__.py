"""
Framework-Specific Security Checks
==================================

This package contains security checkers for various frameworks:
- Python frameworks (Django, Flask, FastAPI)
- JavaScript frameworks (Express.js, Node.js)
- Java frameworks (Spring Boot)
- .NET frameworks (ASP.NET)
"""

from .python_frameworks import PythonFrameworkChecker
from .javascript_frameworks import JavaScriptFrameworkChecker
from .java_frameworks import JavaFrameworkChecker
from .dotnet_frameworks import DotNetFrameworkChecker

__all__ = [
    'PythonFrameworkChecker',
    'JavaScriptFrameworkChecker',
    'JavaFrameworkChecker',
    'DotNetFrameworkChecker'
]


