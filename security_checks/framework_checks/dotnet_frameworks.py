"""
.NET Framework Security Checker
================================

Checks for security issues in .NET frameworks:
- ASP.NET: Request validation, ViewState, event validation
- ASP.NET Core: Security headers, CORS, authentication
- .NET Configuration: Web.config security settings
"""

import re
from typing import List, Dict, Any
from ..base_checker import BaseSecurityChecker


class DotNetFrameworkChecker(BaseSecurityChecker):
    """Security checker for .NET frameworks"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.cs', '.cshtml', '.aspx', '.config', '.xml']
    
    def check(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Run all .NET framework security checks"""
        findings = []
        
        # ASP.NET checks
        findings.extend(self.check_aspnet(code, file_path))
        
        # ASP.NET Core checks
        findings.extend(self.check_aspnet_core(code, file_path))
        
        # Web.config checks
        findings.extend(self.check_webconfig(code, file_path))
        
        # General .NET security checks
        findings.extend(self.check_dotnet_general(code, file_path))
        
        return findings
    
    def check_aspnet(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for ASP.NET security issues"""
        findings = []
        
        # Check for request validation disabled
        validation_patterns = [
            r'<httpRuntime\s+requestValidationMode\s*=\s*["\']2\.0["\']',
            r'<httpRuntime\s+requestValidationMode\s*=\s*["\']0["\']',
            r'validateRequest\s*=\s*["\']false["\']',
            r'ValidateRequest\s*=\s*false'
        ]
        
        for pattern in validation_patterns:
            matches = self.find_pattern_in_code(code, pattern, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=".NET request validation disabled - XSS vulnerability",
                    severity="high",
                    finding_type="misconfiguration",
                    line=match['line'],
                    recommendation="Enable request validation to prevent XSS attacks. Remove validateRequest='false' or use requestValidationMode='4.5'"
                ))
        
        # Check for ViewState encryption disabled
        viewstate_patterns = [
            r'<pages\s+[^>]*enableViewStateMac\s*=\s*["\']false["\']',
            r'EnableViewStateMac\s*=\s*false'
        ]
        
        for pattern in viewstate_patterns:
            matches = self.find_pattern_in_code(code, pattern, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=".NET ViewState MAC disabled - tampering vulnerability",
                    severity="high",
                    finding_type="misconfiguration",
                    line=match['line'],
                    recommendation="Enable ViewState MAC: enableViewStateMac='true'"
                ))
        
        # Check for event validation disabled
        if re.search(r'EnableEventValidation\s*=\s*false', code, re.IGNORECASE):
            line = self.get_line_number(code, "EnableEventValidation")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET event validation disabled",
                severity="medium",
                finding_type="misconfiguration",
                line=line,
                recommendation="Enable event validation to prevent injection attacks"
            ))
        
        # Check for unsafe request filtering
        if re.search(r'<requestFiltering\s+allowUnlisted\s*=\s*["\']true["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "requestFiltering")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET request filtering configured unsafely",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Set allowUnlisted='false' for better security"
            ))
        
        # Check for custom errors disabled
        if re.search(r'<customErrors\s+mode\s*=\s*["\']Off["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "customErrors")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET custom errors disabled - information disclosure",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Enable custom errors in production: mode='RemoteOnly' or 'On'"
            ))
        
        return findings
    
    def check_aspnet_core(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for ASP.NET Core security issues"""
        findings = []
        
        # Check for missing HTTPS redirection
        if 'ASP.NET' in code or 'Startup' in code or 'Program' in code:
            if 'UseHttpsRedirection' not in code and 'app.UseHttpsRedirection' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core missing HTTPS redirection",
                    severity="medium",
                    finding_type="config",
                    recommendation="Add app.UseHttpsRedirection() in Configure method"
                ))
        
        # Check for missing HSTS
        if 'ASP.NET' in code or 'Startup' in code:
            if 'UseHsts' not in code and 'app.UseHsts' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core missing HSTS (HTTP Strict Transport Security)",
                    severity="medium",
                    finding_type="config",
                    recommendation="Add app.UseHsts() for production environments"
                ))
        
        # Check for CORS misconfiguration
        cors_patterns = [
            r'WithOrigins\(["\'][*]["\']\)',
            r'AllowAnyOrigin\(\)',
            r'SetIsOriginAllowed.*true'
        ]
        
        for pattern in cors_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core CORS configured to allow all origins",
                    severity="medium",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Restrict CORS to specific trusted origins using WithOrigins()"
                ))
        
        # Check for authentication missing
        if 'Controller' in code or '[ApiController]' in code:
            if '[Authorize]' not in code and 'RequireAuthorization' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core controller without authorization",
                    severity="high",
                    finding_type="config",
                    recommendation="Add [Authorize] attribute to controllers/actions requiring authentication"
                ))
        
        # Check for AllowAnonymous on sensitive operations
        if re.search(r'\[AllowAnonymous\]', code):
            matches = self.find_pattern_in_code(code, r'\[AllowAnonymous\]')
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core [AllowAnonymous] attribute detected",
                    severity="medium",
                    finding_type="config",
                    line=match['line'],
                    recommendation="Review [AllowAnonymous] usage. Ensure only public endpoints use this attribute."
                ))
        
        # Check for ValidateAntiForgeryToken missing on POST actions
        if re.search(r'\[HttpPost\]', code):
            if '[ValidateAntiForgeryToken]' not in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue="ASP.NET Core POST action without anti-forgery token validation",
                    severity="high",
                    finding_type="config",
                    recommendation="Add [ValidateAntiForgeryToken] to POST actions for CSRF protection"
                ))
        
        return findings
    
    def check_webconfig(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for Web.config security issues"""
        findings = []
        
        # Only check if this is a config file
        if not (file_path.endswith('.config') or 'web.config' in file_path.lower()):
            return findings
        
        # Check for debug mode enabled
        if re.search(r'<compilation\s+[^>]*debug\s*=\s*["\']true["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "debug")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET debug mode enabled in Web.config",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Disable debug mode in production: <compilation debug='false'/>"
            ))
        
        # Check for trace enabled
        if re.search(r'<trace\s+enabled\s*=\s*["\']true["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "trace")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET tracing enabled - information disclosure",
                severity="medium",
                finding_type="config",
                line=line,
                recommendation="Disable tracing in production: <trace enabled='false'/>"
            ))
        
        # Check for connection strings in plain text
        if re.search(r'<connectionStrings>', code, re.IGNORECASE):
            if not re.search(r'configProtectionProvider', code, re.IGNORECASE):
                line = self.get_line_number(code, "connectionStrings")
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=".NET connection strings not encrypted",
                    severity="high",
                    finding_type="exposure",
                    line=line,
                    recommendation="Encrypt connection strings using aspnet_regiis.exe or Azure Key Vault"
                ))
        
        # Check for forms authentication timeout
        if re.search(r'<forms\s+[^>]*timeout\s*=\s*["\'](\d+)["\']', code):
            match = re.search(r'timeout\s*=\s*["\'](\d+)["\']', code)
            if match:
                timeout = int(match.group(1))
                if timeout > 60:  # More than 60 minutes
                    line = self.get_line_number(code, "timeout")
                    findings.append(self.create_finding(
                        file_path=file_path,
                        issue=f".NET forms authentication timeout too long: {timeout} minutes",
                        severity="low",
                        finding_type="config",
                        line=line,
                        recommendation="Set forms authentication timeout to reasonable value (e.g., 30 minutes)"
                    ))
        
        # Check for requireSSL disabled
        if re.search(r'requireSSL\s*=\s*["\']false["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "requireSSL")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET requireSSL disabled for cookies",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Enable requireSSL='true' for secure cookie transmission"
            ))
        
        # Check for httpOnlyCookies disabled
        if re.search(r'httpOnlyCookies\s*=\s*["\']false["\']', code, re.IGNORECASE):
            line = self.get_line_number(code, "httpOnlyCookies")
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET httpOnlyCookies disabled - XSS vulnerability",
                severity="high",
                finding_type="config",
                line=line,
                recommendation="Enable httpOnlyCookies='true' to prevent JavaScript cookie access"
            ))
        
        return findings
    
    def check_dotnet_general(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for general .NET security issues"""
        findings = []
        
        # Check for SQL injection vulnerabilities
        sql_patterns = [
            r'SqlCommand\([^)]*\+',
            r'\.CommandText\s*=\s*[^;]*\+',
            r'ExecuteReader\([^)]*\+',
            r'ExecuteScalar\([^)]*\+'
        ]
        
        for pattern in sql_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=".NET SQL injection vulnerability - string concatenation in query",
                    severity="critical",
                    finding_type="injection",
                    line=match['line'],
                    recommendation="Use parameterized queries with SqlParameter instead of string concatenation"
                ))
        
        # Check for hardcoded passwords
        password_patterns = [
            r'password\s*=\s*["\'](?!.*\{)([^"\']{6,})["\']',
            r'Password\s*=\s*["\'](?!.*\{)([^"\']{6,})["\']'
        ]
        
        for pattern in password_patterns:
            matches = self.find_pattern_in_code(code, pattern)
            for match in matches:
                # Skip if it's in a connection string variable name or config
                if 'ConnectionString' not in match['context']:
                    findings.append(self.create_finding(
                        file_path=file_path,
                        issue=".NET hardcoded password detected",
                        severity="critical",
                        finding_type="exposure",
                        line=match['line'],
                        recommendation="Use configuration files, environment variables, or Azure Key Vault for passwords"
                    ))
        
        # Check for weak random number generation
        if 'new Random()' in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET weak random number generator used",
                severity="medium",
                finding_type="weak_crypto",
                recommendation="Use System.Security.Cryptography.RNGCryptoServiceProvider for security-sensitive operations"
            ))
        
        # Check for insecure deserialization
        if 'BinaryFormatter' in code or 'NetDataContractSerializer' in code:
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET insecure deserialization - potential RCE vulnerability",
                severity="critical",
                finding_type="deserialization",
                recommendation="Avoid BinaryFormatter and NetDataContractSerializer. Use DataContractSerializer or JSON.NET"
            ))
        
        # Check for weak cryptography
        weak_crypto = [
            'DESCryptoServiceProvider',
            'MD5CryptoServiceProvider',
            'SHA1CryptoServiceProvider',
            'RC2CryptoServiceProvider'
        ]
        
        for crypto in weak_crypto:
            if crypto in code:
                findings.append(self.create_finding(
                    file_path=file_path,
                    issue=f".NET weak cryptographic algorithm: {crypto}",
                    severity="high",
                    finding_type="weak_crypto",
                    recommendation=f"Replace {crypto} with AesCryptoServiceProvider or SHA256CryptoServiceProvider"
                ))
        
        # Check for XPath injection
        if re.search(r'SelectSingleNode\([^)]*\+', code) or re.search(r'SelectNodes\([^)]*\+', code):
            findings.append(self.create_finding(
                file_path=file_path,
                issue=".NET XPath injection vulnerability",
                severity="high",
                finding_type="injection",
                recommendation="Use parameterized XPath queries or validate/sanitize input"
            ))
        
        return findings



