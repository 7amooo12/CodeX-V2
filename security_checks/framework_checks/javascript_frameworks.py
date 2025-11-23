"""
JavaScript Framework Security Checker
======================================

Checks for security issues in JavaScript frameworks:
- Express.js: Headers, CSRF, session security, environment configuration
- Node.js: Module security, environment variables
"""

import re
from typing import List, Dict, Any
from ..base_checker import BaseSecurityChecker


class JavaScriptFrameworkChecker(BaseSecurityChecker):
    """Security checker for JavaScript/Node.js frameworks"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.js', '.ts', '.mjs']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Run all JavaScript framework security checks"""
        findings = []
        
        # Express.js checks
        findings.extend(self.check_express(code, file_path))
        
        # Node.js general checks
        findings.extend(self.check_nodejs(code, file_path))
        
        return findings
    
    def check_express(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Express.js-specific security issues"""
        findings = []
        
        # Only run if this is an Express.js file
        if 'express' not in code.lower():
            return findings
        
        # Check for X-Powered-By header not disabled
        has_express = 'require(' in code and 'express' in code or 'from' in code and 'express' in code
        
        if has_express:
            # Check if X-Powered-By is disabled
            disabled_patterns = [
                r"app\.disable\(['\"]x-powered-by['\"]\)",
                r"app\.disable\(['\"]X-Powered-By['\"]\)",
                r"app\.set\(['\"]x-powered-by['\"]\s*,\s*false\)"
            ]
            
            is_disabled = any(re.search(pattern, code) for pattern in disabled_patterns)
            
            if not is_disabled:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js X-Powered-By header not disabled",
                    severity="medium",
                    finding_type="misconfiguration",
                    recommendation="Disable X-Powered-By header: app.disable('x-powered-by')"
                ))
        
        # Check for development environment in production
        dev_patterns = [
            r"app\.set\(['\"]env['\"]\s*,\s*['\"]development['\"]\)",
            r"process\.env\.NODE_ENV\s*=\s*['\"]development['\"]",
            r"NODE_ENV\s*=\s*['\"]development['\"]"
        ]
        
        for pattern in dev_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js configured for development environment",
                    severity="medium",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Set NODE_ENV=production for production deployments"
                ))
        
        # Check for missing helmet middleware
        if has_express and 'helmet' not in code.lower():
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Express.js missing Helmet security middleware",
                severity="high",
                finding_type="config",
                recommendation="Install and use helmet: npm install helmet && app.use(helmet())"
            ))
        
        # Check for missing CSRF protection
        if has_express and 'csrf' not in code.lower() and 'csurf' not in code.lower():
            # Only flag if we see POST/PUT/DELETE routes
            if re.search(r"app\.(post|put|delete|patch)", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js missing CSRF protection",
                    severity="high",
                    finding_type="config",
                    recommendation="Install and use csurf middleware for CSRF protection"
                ))
        
        # Check for insecure session configuration
        if 'express-session' in code or 'session(' in code:
            # Check for secret hardcoded
            if re.search(r"secret\s*:\s*['\"](?!.*process\.env)([^'\"]+)['\"]", code):
                line = self.get_line_number(code, "secret")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js session secret is hardcoded",
                    severity="critical",
                    finding_type="exposure",
                    line=line,
                    recommendation="Use environment variable: secret: process.env.SESSION_SECRET"
                ))
            
            # Check for secure: false
            if re.search(r"secure\s*:\s*false", code):
                line = self.get_line_number(code, "secure")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js session cookie not marked as secure",
                    severity="medium",
                    finding_type="config",
                    line=line,
                    recommendation="Set secure: true for HTTPS-only cookies"
                ))
            
            # Check for httpOnly: false
            if re.search(r"httpOnly\s*:\s*false", code):
                line = self.get_line_number(code, "httpOnly")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js session cookie httpOnly disabled",
                    severity="high",
                    finding_type="config",
                    line=line,
                    recommendation="Set httpOnly: true to prevent XSS attacks"
                ))
        
        # Check for CORS misconfiguration
        cors_patterns = [
            r"cors\(\s*\)",
            r"origin\s*:\s*['\"][*]['\"]",
            r"origin\s*:\s*true"
        ]
        
        for pattern in cors_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            if matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js CORS configured to allow all origins",
                    severity="medium",
                    finding_type="config",
                    line=matches[0]['line'] if matches else None,
                    recommendation="Restrict CORS to specific trusted origins"
                ))
                break
        
        # Check for missing rate limiting
        if has_express and 'rate-limit' not in code.lower() and 'limiter' not in code.lower():
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Express.js missing rate limiting middleware",
                severity="medium",
                finding_type="config",
                recommendation="Install and use express-rate-limit to prevent abuse"
            ))
        
        # Check for body-parser size limits
        if 'body-parser' in code or 'express.json' in code:
            if not re.search(r"limit\s*:", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Express.js body-parser has no size limit configured",
                    severity="medium",
                    finding_type="config",
                    recommendation="Set body size limit: express.json({ limit: '10mb' })"
                ))
        
        # Check for trust proxy configuration
        if has_express and re.search(r"app\.set\(['\"]trust proxy['\"]\s*,\s*true\)", code):
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Express.js trust proxy enabled - ensure proxy is properly configured",
                severity="low",
                finding_type="config",
                recommendation="Only enable trust proxy if behind a reverse proxy. Verify proxy configuration."
            ))
        
        return findings
    
    def check_nodejs(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for general Node.js security issues"""
        findings = []
        
        # Check for hardcoded credentials
        credential_patterns = [
            r"password\s*[:=]\s*['\"](?!.*process\.env)([^'\"]{6,})['\"]",
            r"api[_-]?key\s*[:=]\s*['\"](?!.*process\.env)([^'\"]{10,})['\"]",
            r"token\s*[:=]\s*['\"](?!.*process\.env)([^'\"]{10,})['\"]"
        ]
        
        for pattern in credential_patterns:
            matches = self.find_pattern_in_code(code, pattern, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Hardcoded credentials detected in Node.js code",
                    severity="critical",
                    finding_type="exposure",
                    line=match['line'],
                    recommendation="Move credentials to environment variables using process.env"
                ))
        
        # Check for eval usage
        if 'eval(' in code:
            matches = self.find_pattern_in_code(code, r"eval\s*\(")
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Use of eval() detected - potential code injection risk",
                    severity="critical",
                    finding_type="code_execution",
                    line=match['line'],
                    recommendation="Avoid eval(). Use safer alternatives like JSON.parse() or Function constructor"
                ))
        
        # Check for child_process usage without sanitization
        if 'child_process' in code or 'exec(' in code or 'spawn(' in code:
            # Check if input is sanitized
            has_sanitization = any(pattern in code for pattern in ['escape', 'sanitize', 'validate'])
            
            if not has_sanitization:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="child_process used without input sanitization",
                    severity="high",
                    finding_type="command_injection",
                    recommendation="Validate and sanitize all inputs before executing commands. Use execFile or spawn with array arguments."
                ))
        
        # Check for insecure random number generation
        if re.search(r"Math\.random\(\)", code):
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Math.random() used - not cryptographically secure",
                severity="low",
                finding_type="weak_crypto",
                recommendation="Use crypto.randomBytes() for security-sensitive random values"
            ))
        
        # Check for deprecated crypto functions
        deprecated_crypto = [
            r"crypto\.createCipher\(",  # Deprecated
            r"md5",
            r"sha1"
        ]
        
        for pattern in deprecated_crypto:
            matches = self.find_pattern_in_code(code, pattern, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Deprecated or weak cryptographic function detected",
                    severity="medium",
                    finding_type="weak_crypto",
                    line=match['line'],
                    recommendation="Use crypto.createCipheriv() and strong algorithms like AES-256, SHA-256"
                ))
        
        # Check for prototype pollution vulnerable patterns
        if re.search(r"Object\.assign\([^)]*req\.(body|query|params)", code):
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Potential prototype pollution vulnerability",
                severity="high",
                finding_type="injection",
                recommendation="Validate object keys before Object.assign(). Use Object.create(null) or sanitize inputs."
            ))
        
        return findings

