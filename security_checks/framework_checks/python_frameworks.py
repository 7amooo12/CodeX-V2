"""
Python Framework Security Checker
==================================

Checks for security issues in Python web frameworks:
- Django: Debug mode, secret key exposure, middleware issues
- Flask: Debug mode, secret key exposure, CORS issues
- FastAPI: Debug mode, reload in production, CORS issues
- Uvicorn: Reload mode, workers configuration
"""

import re
from typing import List, Dict, Any
from ..base_checker import BaseSecurityChecker


class PythonFrameworkChecker(BaseSecurityChecker):
    """Security checker for Python web frameworks"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.py']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Run all Python framework security checks"""
        findings = []
        
        # Django checks
        findings.extend(self.check_django(code, file_path))
        
        # Flask checks
        findings.extend(self.check_flask(code, file_path))
        
        # FastAPI checks
        findings.extend(self.check_fastapi(code, file_path))
        
        # Uvicorn checks
        findings.extend(self.check_uvicorn(code, file_path))
        
        return findings
    
    def check_django(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Django-specific security issues"""
        findings = []
        
        # Check for DEBUG = True
        if "DEBUG = True" in code or "DEBUG=True" in code:
            line = self.get_line_number(code, "DEBUG")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Django debug mode enabled in production",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Set DEBUG = False in production. Debug mode exposes sensitive information."
            ))
        
        # Check for hardcoded SECRET_KEY
        secret_key_patterns = [
            r"SECRET_KEY\s*=\s*['\"]([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{20,})['\"]",
            r"SECRET_KEY\s*=\s*['\"](?!.*env)(?!.*os\.environ)(?!.*config\.)([^'\"]+)['\"]"
        ]
        
        for pattern in secret_key_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Django SECRET_KEY is hardcoded",
                    severity="critical",
                    finding_type="exposure",
                    line=match['line'],
                    recommendation="Move SECRET_KEY to environment variables. Use os.environ.get('SECRET_KEY')"
                ))
        
        # Check for ALLOWED_HOSTS = []
        if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*\]", code):
            line = self.get_line_number(code, "ALLOWED_HOSTS")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Django ALLOWED_HOSTS is empty",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Configure ALLOWED_HOSTS with your domain names to prevent Host header attacks."
            ))
        
        # Check for ALLOWED_HOSTS = ['*']
        if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"][*]['\"]", code):
            line = self.get_line_number(code, "ALLOWED_HOSTS")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Django ALLOWED_HOSTS allows all hosts (*)",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Restrict ALLOWED_HOSTS to specific domain names."
            ))
        
        # Check for missing security middleware
        security_middleware = [
            'SecurityMiddleware',
            'CsrfViewMiddleware',
            'XFrameOptionsMiddleware'
        ]
        
        for middleware in security_middleware:
            if 'MIDDLEWARE' in code and middleware not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=f"Django {middleware} not found in MIDDLEWARE",
                    severity="medium",
                    finding_type="config",
                    recommendation=f"Add 'django.middleware.{middleware.lower()}.{middleware}' to MIDDLEWARE"
                ))
        
        # Check for SECURE_SSL_REDIRECT = False
        if re.search(r"SECURE_SSL_REDIRECT\s*=\s*False", code):
            line = self.get_line_number(code, "SECURE_SSL_REDIRECT")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Django SECURE_SSL_REDIRECT is disabled",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Enable SECURE_SSL_REDIRECT = True to redirect all HTTP to HTTPS"
            ))
        
        return findings
    
    def check_flask(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Flask-specific security issues"""
        findings = []
        
        # Check for app.run with debug=True
        debug_patterns = [
            r"app\.run\([^)]*debug\s*=\s*True",
            r"app\.debug\s*=\s*True",
            r"Flask\([^)]*debug\s*=\s*True"
        ]
        
        for pattern in debug_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Flask debug mode enabled",
                    severity="high",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Disable debug mode in production: app.run(debug=False)"
                ))
        
        # Check for hardcoded SECRET_KEY in Flask
        if 'Flask' in code and re.search(r"SECRET_KEY\s*=\s*['\"](?!.*env)([^'\"]+)['\"]", code):
            line = self.get_line_number(code, "SECRET_KEY")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Flask SECRET_KEY is hardcoded",
                severity="critical",
                finding_type="exposure",
                line=line,
                recommendation="Use environment variables: app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')"
            ))
        
        # Check for missing CSRF protection
        if 'Flask' in code and 'flask_wtf' not in code.lower() and 'CSRFProtect' not in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Flask application missing CSRF protection",
                severity="high",
                finding_type="config",
                recommendation="Install and configure flask-wtf for CSRF protection"
            ))
        
        # Check for session cookie security
        if 'Flask' in code:
            if 'SESSION_COOKIE_SECURE' not in code or re.search(r"SESSION_COOKIE_SECURE\s*=\s*False", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Flask SESSION_COOKIE_SECURE not enabled",
                    severity="medium",
                    finding_type="config",
                    recommendation="Set SESSION_COOKIE_SECURE = True to send cookies only over HTTPS"
                ))
            
            if 'SESSION_COOKIE_HTTPONLY' not in code or re.search(r"SESSION_COOKIE_HTTPONLY\s*=\s*False", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Flask SESSION_COOKIE_HTTPONLY not enabled",
                    severity="medium",
                    finding_type="config",
                    recommendation="Set SESSION_COOKIE_HTTPONLY = True to prevent JavaScript access to cookies"
                ))
        
        # Check for CORS misconfiguration
        if 'flask_cors' in code.lower() or 'CORS' in code:
            if re.search(r"CORS\([^)]*origins\s*=\s*['\"][*]['\"]", code):
                line = self.get_line_number(code, "CORS")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Flask CORS configured to allow all origins (*)",
                    severity="medium",
                    finding_type="config",
                    line=line,
                    recommendation="Restrict CORS to specific trusted origins"
                ))
        
        return findings
    
    def check_fastapi(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for FastAPI-specific security issues"""
        findings = []
        
        # Check for reload enabled
        reload_patterns = [
            r"uvicorn\.run\([^)]*reload\s*=\s*True",
            r"--reload"
        ]
        
        for pattern in reload_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="FastAPI/Uvicorn reload enabled in production",
                    severity="medium",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Disable reload in production: uvicorn.run(app, reload=False)"
                ))
        
        # Check for CORS misconfiguration in FastAPI
        if 'FastAPI' in code and 'CORSMiddleware' in code:
            if re.search(r"allow_origins\s*=\s*\[\s*['\"][*]['\"]", code):
                line = self.get_line_number(code, "allow_origins")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="FastAPI CORS configured to allow all origins (*)",
                    severity="medium",
                    finding_type="config",
                    line=line,
                    recommendation="Restrict CORS allow_origins to specific trusted domains"
                ))
            
            if re.search(r"allow_credentials\s*=\s*True", code) and re.search(r"allow_origins\s*=\s*\[\s*['\"][*]['\"]", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="FastAPI CORS allows credentials with wildcard origins - security risk",
                    severity="high",
                    finding_type="config",
                    recommendation="Do not use allow_credentials=True with allow_origins=['*']"
                ))
        
        # Check for missing authentication
        if 'FastAPI' in code and '@app.post' in code or '@app.get' in code:
            if 'Depends' not in code and 'OAuth2' not in code and 'HTTPBearer' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="FastAPI endpoints detected without authentication dependencies",
                    severity="medium",
                    finding_type="config",
                    recommendation="Implement authentication using Depends() and OAuth2/JWT"
                ))
        
        return findings
    
    def check_uvicorn(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Uvicorn-specific security issues"""
        findings = []
        
        # Check for single worker in production
        if 'uvicorn.run' in code:
            if 'workers' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Uvicorn running with single worker (not production-ready)",
                    severity="low",
                    finding_type="config",
                    recommendation="Use multiple workers for production: uvicorn.run(app, workers=4)"
                ))
        
        # Check for host=0.0.0.0 without proper firewall
        if re.search(r"uvicorn\.run\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]", code):
            line = self.get_line_number(code, "host")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Uvicorn configured to listen on 0.0.0.0 (all interfaces)",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Bind to localhost or use reverse proxy. Ensure firewall rules are properly configured."
            ))
        
        return findings



