"""
Java Framework Security Checker
================================

Checks for security issues in Java frameworks:
- Spring Boot: Actuator endpoints, security configuration, debug mode
- Spring Security: Authentication, authorization issues
- General Java: Serialization, SQL injection
"""

import re
from typing import List, Dict, Any
from ..base_checker import BaseSecurityChecker


class JavaFrameworkChecker(BaseSecurityChecker):
    """Security checker for Java frameworks"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.java', '.xml', '.properties', '.yml', '.yaml']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Run all Java framework security checks"""
        findings = []
        
        # Spring Boot checks
        findings.extend(self.check_spring_boot(code, file_path))
        
        # Spring Security checks
        findings.extend(self.check_spring_security(code, file_path))
        
        # General Java security checks
        findings.extend(self.check_java_general(code, file_path))
        
        return findings
    
    def check_spring_boot(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Spring Boot security issues"""
        findings = []
        
        # Define insecure actuator endpoints
        insecure_endpoints = [
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/metrics",
            "/actuator/trace",
            "/actuator/dump",
            "/actuator/heapdump",
            "/actuator/threaddump",
            "/actuator/configprops",
            "/actuator/logfile",
            "/actuator/loggers",
            "/actuator/mappings",
            "/h2-console",
            "/beans",
            "/env",
            "/metrics",
            "/trace",
            "/dump",
            "/jolokia",
            "/swagger-ui",
            "/v2/api-docs"
        ]
        
        for endpoint in insecure_endpoints:
            if endpoint in code:
                line = self.get_line_number(code, endpoint)
                
                # Determine severity based on endpoint
                if endpoint in ['/actuator/heapdump', '/actuator/dump', '/h2-console', '/jolokia']:
                    severity = "critical"
                elif endpoint in ['/actuator/env', '/actuator/configprops', '/actuator/loggers']:
                    severity = "high"
                else:
                    severity = "high"
                
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=f"Spring Boot insecure endpoint exposed: {endpoint}",
                    severity=severity,
                    finding_type="exposure",
                    line=line,
                    recommendation=f"Secure or disable {endpoint}. Use management.endpoints.web.exposure.include to control access."
                ))
        
        # Check for debug mode enabled
        debug_patterns = [
            r"debug\s*=\s*true",
            r"logging\.level\.root\s*=\s*DEBUG",
            r"spring\.devtools\.restart\.enabled\s*=\s*true"
        ]
        
        for pattern in debug_patterns:
            matches = self.find_pattern_in_code(code, pattern, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Spring Boot debug mode enabled",
                    severity="medium",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Disable debug mode in production"
                ))
        
        # Check for management port exposed
        if re.search(r"management\.port\s*=\s*8080", code) or \
           re.search(r"management\.server\.port\s*=\s*8080", code):
            line = self.get_line_number(code, "management")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Spring Boot management endpoints on same port as application",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Use a separate port for management endpoints and restrict access"
            ))
        
        # Check for CORS misconfiguration
        if re.search(r"@CrossOrigin\s*\(\s*\*", code) or \
           re.search(r"allowedOrigins\s*=\s*['\"][*]['\"]", code):
            line = self.get_line_number(code, "CrossOrigin")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Spring Boot CORS configured to allow all origins (*)",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Restrict CORS to specific trusted origins"
            ))
        
        # Check for exposed swagger UI in production
        if '/swagger-ui' in code or 'springdoc.swagger-ui' in code:
            if not re.search(r"springdoc\.swagger-ui\.enabled\s*=\s*false", code):
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Swagger UI exposed in production",
                    severity="medium",
                    finding_type="exposure",
                    recommendation="Disable Swagger UI in production: springdoc.swagger-ui.enabled=false"
                ))
        
        # Check for H2 console in production
        if '/h2-console' in code or 'spring.h2.console.enabled' in code:
            if re.search(r"spring\.h2\.console\.enabled\s*=\s*true", code):
                line = self.get_line_number(code, "h2.console")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="H2 database console enabled - critical security risk",
                    severity="critical",
                    finding_type="exposure",
                    line=line,
                    recommendation="Disable H2 console in production: spring.h2.console.enabled=false"
                ))
        
        return findings
    
    def check_spring_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Spring Security issues"""
        findings = []
        
        # Check for permitAll() on sensitive endpoints
        if re.search(r"\.permitAll\(\)", code):
            matches = self.find_pattern_in_code(code, r"\.permitAll\(\)")
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Spring Security endpoint configured with permitAll() - no authentication required",
                    severity="high",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Review permitAll() usage. Ensure only public endpoints use this configuration."
                ))
        
        # Check for CSRF disabled
        if re.search(r"\.csrf\(\)\.disable\(\)", code) or \
           re.search(r"csrf\.disabled", code):
            line = self.get_line_number(code, "csrf")
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Spring Security CSRF protection disabled",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Enable CSRF protection unless using token-based authentication"
            ))
        
        # Check for HTTP Basic authentication without HTTPS
        if re.search(r"httpBasic\(\)", code) and not re.search(r"requiresSecure\(\)", code):
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Spring Security HTTP Basic authentication without HTTPS requirement",
                severity="high",
                finding_type="config",
                recommendation="Always use HTTPS with Basic authentication or use OAuth2/JWT"
            ))
        
        # Check for hardcoded credentials
        if re.search(r"\.password\(['\"](?!.*\{)([^'\"]+)['\"]\)", code):
            matches = self.find_pattern_in_code(code, r"\.password\(['\"]([^'\"]+)['\"]\)")
            for match in matches:
                if not '{' in match['context']:  # Not using password encoder
                    findings.append(self.create_finding(
                        file_path=file_path,
                        issue="Hardcoded password in Spring Security configuration",
                        severity="critical",
                        finding_type="exposure",
                        line=match['line'],
                        recommendation="Use password encoders and store credentials securely"
                    ))
        
        return findings
    
    def check_java_general(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for general Java security issues"""
        findings = []
        
        # Check for SQL injection vulnerabilities
        sql_patterns = [
            r"Statement\.execute\(",
            r"Statement\.executeQuery\(",
            r"createQuery\(['\"][^'\"]*\+",
            r"createNativeQuery\(['^'\"]*\+"
        ]
        
        for pattern in sql_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="Potential SQL injection vulnerability - string concatenation in query",
                    severity="critical",
                    finding_type="injection",
                    line=match['line'],
                    recommendation="Use PreparedStatement or JPA with parameters instead of string concatenation"
                ))
        
        # Check for deserialization vulnerabilities
        if 'ObjectInputStream' in code or 'readObject(' in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Unsafe deserialization detected - potential RCE vulnerability",
                severity="critical",
                finding_type="deserialization",
                recommendation="Avoid deserializing untrusted data. Use safer formats like JSON."
            ))
        
        # Check for weak random number generation
        if 'java.util.Random' in code or 'Math.random(' in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue="Weak random number generator used",
                severity="medium",
                finding_type="weak_crypto",
                recommendation="Use java.security.SecureRandom for security-sensitive operations"
            ))
        
        # Check for weak cryptography
        weak_crypto = [
            'DES',
            'MD5',
            'SHA1',
            'RC4'
        ]
        
        for algo in weak_crypto:
            if algo in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=f"Weak cryptographic algorithm detected: {algo}",
                    severity="high",
                    finding_type="weak_crypto",
                    recommendation=f"Replace {algo} with AES-256, SHA-256, or stronger algorithms"
                ))
        
        return findings



