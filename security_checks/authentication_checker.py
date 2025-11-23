"""
Authentication & Session Security Checker
==========================================

Detects authentication and session management vulnerabilities:
- Weak session timeouts
- Missing session rotation
- Insecure cookie flags
- Missing MFA/2FA
- Hardcoded credentials in auth code
- Weak password policies
"""

import re
from typing import List, Dict, Any


class AuthenticationSecurityChecker:
    """Checks for authentication and session management security issues"""
    
    @staticmethod
    def check_weak_session_timeout(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect weak session timeout configurations"""
        findings = []
        
        try:
            code_lower = code.lower()
            
            # Python/Django - session timeout
            if language == 'python':
                # Very long session timeout (> 1 hour = 3600 seconds)
                if 'session_cookie_age' in code_lower:
                    matches = re.finditer(r'session_cookie_age\s*=\s*(\d+)', code, re.IGNORECASE)
                    for match in matches:
                        timeout = int(match.group(1))
                        if timeout > 7200:  # > 2 hours
                            line_num = code[:match.start()].count('\n') + 1
                            findings.append({
                                'type': 'weak_session_timeout',
                                'severity': 'MEDIUM',
                                'language': language,
                                'file': file_path,
                                'line': line_num,
                                'timeout_seconds': timeout,
                                'message': f"Session timeout too long: {timeout} seconds ({timeout/3600:.1f} hours)",
                                'recommendation': "Set session timeout to reasonable value (30-60 minutes for sensitive apps)"
                            })
                
                # Flask - permanent_session_lifetime
                if 'permanent_session_lifetime' in code_lower:
                    if 'timedelta' not in code_lower:
                        findings.append({
                            'type': 'weak_session_timeout',
                            'severity': 'MEDIUM',
                            'language': language,
                            'file': file_path,
                            'message': "Session lifetime configuration without timedelta",
                            'recommendation': "Use timedelta for session lifetime: permanent_session_lifetime = timedelta(minutes=30)"
                        })
            
            # JavaScript/Express - session maxAge
            elif language in ['javascript', 'typescript']:
                # maxAge: 0 means unlimited session
                if re.search(r'maxage\s*:\s*0', code_lower):
                    line_num = None
                    match = re.search(r'maxage\s*:\s*0', code_lower)
                    if match:
                        line_num = code[:match.start()].count('\n') + 1
                    
                    findings.append({
                        'type': 'unlimited_session',
                        'severity': 'HIGH',
                        'language': language,
                        'file': file_path,
                        'line': line_num,
                        'message': "Express session configured with unlimited age (maxAge: 0)",
                        'recommendation': "Set appropriate session timeout: cookie: { maxAge: 1800000 } // 30 minutes"
                    })
                
                # Check for very long maxAge
                matches = re.finditer(r'maxage\s*:\s*(\d+)', code_lower)
                for match in matches:
                    max_age = int(match.group(1))
                    if max_age > 7200000:  # > 2 hours in milliseconds
                        line_num = code[:match.start()].count('\n') + 1
                        findings.append({
                            'type': 'weak_session_timeout',
                            'severity': 'MEDIUM',
                            'language': language,
                            'file': file_path,
                            'line': line_num,
                            'timeout_ms': max_age,
                            'message': f"Session maxAge too long: {max_age}ms ({max_age/3600000:.1f} hours)",
                            'recommendation': "Set session timeout to 30-60 minutes for security"
                        })
            
            # Java/Spring - session timeout
            elif language == 'java':
                if 'session.timeout' in code_lower or 'session-timeout' in code_lower:
                    matches = re.finditer(r'session[.-]timeout\s*[:=]\s*(\d+)', code, re.IGNORECASE)
                    for match in matches:
                        timeout = int(match.group(1))
                        if timeout > 120:  # > 2 hours (usually in minutes)
                            line_num = code[:match.start()].count('\n') + 1
                            findings.append({
                                'type': 'weak_session_timeout',
                                'severity': 'MEDIUM',
                                'language': language,
                                'file': file_path,
                                'line': line_num,
                                'timeout_minutes': timeout,
                                'message': f"Session timeout too long: {timeout} minutes ({timeout/60:.1f} hours)",
                                'recommendation': "Set session timeout to 30-60 minutes"
                            })
            
            # PHP - session.gc_maxlifetime
            elif language == 'php':
                if 'session.gc_maxlifetime' in code_lower:
                    matches = re.finditer(r'session\.gc_maxlifetime[\'\"]\s*,\s*(\d+)', code, re.IGNORECASE)
                    for match in matches:
                        timeout = int(match.group(1))
                        if timeout > 7200:  # > 2 hours
                            line_num = code[:match.start()].count('\n') + 1
                            findings.append({
                                'type': 'weak_session_timeout',
                                'severity': 'MEDIUM',
                                'language': language,
                                'file': file_path,
                                'line': line_num,
                                'timeout_seconds': timeout,
                                'message': f"PHP session timeout too long: {timeout} seconds",
                                'recommendation': "Set session timeout to 1800-3600 seconds (30-60 minutes)"
                            })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_missing_session_rotation(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect missing session rotation on login/privilege change"""
        findings = []
        
        try:
            code_lower = code.lower()
            
            # Check if there's login functionality
            has_login = any(pattern in code_lower for pattern in [
                'def login', 'function login', 'login(', '@login',
                'signin', 'authenticate', 'auth_user'
            ])
            
            if has_login:
                # Check for session rotation/regeneration
                has_rotation = any(pattern in code_lower for pattern in [
                    'regenerate', 'rotate', 'session.regenerate',
                    'session_regenerate_id', 'rotate_session',
                    'new_session', 'regeneratesession'
                ])
                
                if not has_rotation:
                    findings.append({
                        'type': 'missing_session_rotation',
                        'severity': 'MEDIUM',
                        'language': language,
                        'file': file_path,
                        'message': "Login functionality detected without session rotation",
                        'recommendation': "Regenerate session ID after login to prevent session fixation: session.regenerate() or session_regenerate_id()"
                    })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_insecure_cookie_flags(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect missing security flags on cookies"""
        findings = []
        
        try:
            code_lower = code.lower()
            
            # Check if cookies are used
            has_cookie = any(pattern in code_lower for pattern in [
                'setcookie', 'set-cookie', 'cookie:', 'set_cookie',
                'response.cookie', 'res.cookie', 'addcookie'
            ])
            
            if has_cookie:
                # Check HttpOnly flag
                if 'httponly' not in code_lower:
                    findings.append({
                        'type': 'missing_httponly',
                        'severity': 'HIGH',
                        'language': language,
                        'file': file_path,
                        'message': "Cookies used without HttpOnly flag",
                        'recommendation': "Set HttpOnly flag to prevent XSS attacks from accessing cookies"
                    })
                
                # Check Secure flag
                if 'secure' not in code_lower and 'https' not in code_lower:
                    findings.append({
                        'type': 'missing_secure_flag',
                        'severity': 'HIGH',
                        'language': language,
                        'file': file_path,
                        'message': "Cookies used without Secure flag",
                        'recommendation': "Set Secure flag to ensure cookies are only sent over HTTPS"
                    })
                
                # Check SameSite flag
                if 'samesite' not in code_lower:
                    findings.append({
                        'type': 'missing_samesite',
                        'severity': 'MEDIUM',
                        'language': language,
                        'file': file_path,
                        'message': "Cookies used without SameSite attribute",
                        'recommendation': "Set SameSite attribute to 'Strict' or 'Lax' to prevent CSRF attacks"
                    })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_missing_mfa(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect missing multi-factor authentication"""
        findings = []
        
        try:
            code_lower = code.lower()
            
            # Check for authentication implementation
            has_auth = any(pattern in code_lower for pattern in [
                'def login', 'function login', 'authenticate',
                'signin', 'user_login', '@login'
            ])
            
            if has_auth:
                # Check for MFA/2FA implementation
                has_mfa = any(pattern in code_lower for pattern in [
                    'mfa', '2fa', 'two-factor', 'twofactor', 'totp',
                    'otp', 'authenticator', 'verify_code', 'verification_code'
                ])
                
                if not has_mfa:
                    findings.append({
                        'type': 'missing_mfa',
                        'severity': 'MEDIUM',
                        'language': language,
                        'file': file_path,
                        'message': "Authentication code without MFA/2FA implementation",
                        'recommendation': "Implement multi-factor authentication for sensitive applications"
                    })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_weak_password_policy(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect weak or missing password policies"""
        findings = []
        
        try:
            code_lower = code.lower()
            
            # Check for password-related code
            has_password_handling = any(pattern in code_lower for pattern in [
                'password', 'passwd', 'pwd', 'register', 'signup',
                'create_user', 'createuser', 'set_password'
            ])
            
            if has_password_handling:
                # Check for password length validation
                has_length_check = any(pattern in code_lower for pattern in [
                    'len(password)', 'length', 'minlength', 'min_length',
                    'password.length', 'strlen(', 'size()'
                ])
                
                if not has_length_check:
                    findings.append({
                        'type': 'missing_password_length_check',
                        'severity': 'MEDIUM',
                        'language': language,
                        'file': file_path,
                        'message': "Password handling without length validation",
                        'recommendation': "Enforce minimum password length (at least 8-12 characters)"
                    })
                
                # Check for complexity requirements
                has_complexity = any(pattern in code_lower for pattern in [
                    're.search', 'regex', 'pattern', 'complexity',
                    'uppercase', 'lowercase', 'digit', 'special'
                ])
                
                if not has_complexity:
                    findings.append({
                        'type': 'missing_password_complexity',
                        'severity': 'LOW',
                        'language': language,
                        'file': file_path,
                        'message': "Password handling without complexity requirements",
                        'recommendation': "Enforce password complexity (uppercase, lowercase, numbers, special characters)"
                    })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_authentication_bypass(code: str, language: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect potential authentication bypass vulnerabilities"""
        findings = []
        
        try:
            # Check for hardcoded bypass conditions
            bypass_patterns = [
                r'if.*==.*["\']admin["\'].*:?\s*return\s+true',
                r'if.*password.*==.*["\'].*["\'].*:?\s*return',
                r'auth\s*=\s*true',
                r'authenticated\s*=\s*true',
                r'is_authenticated\s*=\s*true',
                r'bypass.*auth',
                r'skip.*auth'
            ]
            
            for pattern in bypass_patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'potential_auth_bypass',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'line': line_num,
                        'pattern': match.group(0)[:50],
                        'message': "Potential authentication bypass detected",
                        'recommendation': "Review authentication logic for hardcoded bypasses or weak conditions"
                    })
        
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def analyze_authentication_security(file_path: str, language: str) -> Dict[str, List[dict]]:
        """Perform comprehensive authentication security analysis on a file"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return {
                "weak_session_timeout": [],
                "missing_session_rotation": [],
                "insecure_cookie_flags": [],
                "missing_mfa": [],
                "weak_password_policy": [],
                "auth_bypass": []
            }
        
        checker = AuthenticationSecurityChecker()
        
        return {
            "weak_session_timeout": checker.check_weak_session_timeout(content, language, file_path),
            "missing_session_rotation": checker.check_missing_session_rotation(content, language, file_path),
            "insecure_cookie_flags": checker.check_insecure_cookie_flags(content, language, file_path),
            "missing_mfa": checker.check_missing_mfa(content, language, file_path),
            "weak_password_policy": checker.check_weak_password_policy(content, language, file_path),
            "auth_bypass": checker.check_authentication_bypass(content, language, file_path)
        }


