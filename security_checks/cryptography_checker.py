"""
Cryptography Misuse Detector
=============================

Detects cryptographic vulnerabilities and misuse patterns across multiple languages.
Checks for weak hashing, weak encryption, predictable random, improper password hashing,
ECB mode usage, and JWT security issues.
"""

import re
from typing import List, Dict, Any


class CryptographyMisuseDetector:
    """Detects cryptography misuse across multiple languages"""
    
    @staticmethod
    def _detect_language(code):
        """Auto-detect programming language from code"""
        if 'import ' in code and 'def ' in code:
            return 'python'
        elif 'function ' in code or 'const ' in code or 'let ' in code:
            return 'javascript'
        elif 'public class ' in code or 'import java.' in code:
            return 'java'
        elif '<?php' in code or 'function ' in code and '$' in code:
            return 'php'
        return 'unknown'
    
    @staticmethod
    def detect_weak_hashing(code, language='python', file_path=''):
        """Detect weak hashing algorithms (MD5, SHA1)"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_weak = ['hashlib.md5', 'hashlib.sha1', 'md5(', 'sha1(']
            
            js_weak = ['crypto.createHash("md5")', 'crypto.createHash(\'md5\')',
                       'crypto.createHash("sha1")', 'crypto.createHash(\'sha1\')',
                       'CryptoJS.MD5', 'CryptoJS.SHA1', 'md5(', 'sha1(']
            
            java_weak = ['MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-1")',
                         'MessageDigest.getInstance("SHA1")', 'DigestUtils.md5', 'DigestUtils.sha1']
            
            php_weak = ['md5(', 'sha1(', 'hash("md5"', 'hash(\'md5\'', 'hash("sha1"', 'hash(\'sha1\'']
            
            weak_patterns = {
                'python': python_weak,
                'javascript': js_weak,
                'typescript': js_weak,
                'java': java_weak,
                'php': php_weak,
                'html': [],
                'json': [],
                'env': []
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            patterns = weak_patterns.get(language.lower(), python_weak)
            
            for pattern in patterns:
                if pattern in code:
                    # Find line number
                    line_num = None
                    try:
                        index = code.index(pattern)
                        line_num = code[:index].count('\n') + 1
                    except ValueError:
                        pass
                    
                    findings.append({
                        'type': 'weak_hashing',
                        'severity': 'HIGH',
                        'language': language,
                        'file': file_path,
                        'pattern': pattern,
                        'line': line_num,
                        'message': f"Weak hashing algorithm detected: '{pattern}'",
                        'recommendation': "Use SHA-256, SHA-512, or SHA-3 instead of MD5/SHA1"
                    })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def detect_weak_encryption(code, language='python', file_path=''):
        """Detect weak encryption algorithms (DES, RC4, 3DES)"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_weak = ['DES.new', 'DES3.new', 'ARC4.new', 'Blowfish.new', 'mode=ECB']
            
            js_weak = ['createCipheriv("des"', 'createCipheriv("rc4"', 'createCipheriv("des3"',
                      'CryptoJS.DES', 'CryptoJS.RC4', 'CryptoJS.TripleDES']
            
            java_weak = ['Cipher.getInstance("DES', 'Cipher.getInstance("DESede',
                        'Cipher.getInstance("RC4', 'Cipher.getInstance("Blowfish']
            
            php_weak = ['mcrypt_encrypt(MCRYPT_DES', 'mcrypt_encrypt(MCRYPT_3DES',
                       'openssl_encrypt("des-', 'openssl_encrypt("rc4']
            
            weak_patterns = {
                'python': python_weak,
                'javascript': js_weak,
                'typescript': js_weak,
                'java': java_weak,
                'php': php_weak,
                'html': [],
                'json': [],
                'env': []
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            patterns = weak_patterns.get(language.lower(), python_weak)
            
            for pattern in patterns:
                if pattern in code:
                    line_num = None
                    try:
                        index = code.index(pattern)
                        line_num = code[:index].count('\n') + 1
                    except ValueError:
                        pass
                    
                    findings.append({
                        'type': 'weak_encryption',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'pattern': pattern,
                        'line': line_num,
                        'message': f"Weak encryption algorithm detected: '{pattern}'",
                        'recommendation': "Use AES-256-GCM or ChaCha20-Poly1305 for encryption"
                    })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def detect_predictable_random(code, language='python', file_path=''):
        """Detect use of predictable random number generators"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_weak = ['random.random(', 'random.randint(', 'random.choice(', 'random.seed(']
            python_secure = ['secrets.', 'os.urandom(', 'random.SystemRandom()']
            
            js_weak = ['Math.random(', 'Math.floor(Math.random()']
            js_secure = ['crypto.randomBytes(', 'crypto.getRandomValues(', 'window.crypto.getRandomValues']
            
            java_weak = ['new Random(', 'Math.random(', 'Random.nextInt']
            java_secure = ['SecureRandom', 'new SecureRandom()']
            
            php_weak = ['rand(', 'mt_rand(', 'srand(', 'mt_srand(']
            php_secure = ['random_bytes(', 'random_int(', 'openssl_random_pseudo_bytes(']
            
            weak_patterns = {
                'python': (python_weak, python_secure),
                'javascript': (js_weak, js_secure),
                'typescript': (js_weak, js_secure),
                'java': (java_weak, java_secure),
                'php': (php_weak, php_secure),
                'html': ([], []),
                'json': ([], []),
                'env': ([], [])
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            weak, secure = weak_patterns.get(language.lower(), (python_weak, python_secure))
            
            has_weak = any(pattern in code for pattern in weak)
            has_secure = any(pattern in code for pattern in secure)
            
            if has_weak and not has_secure:
                # Find line number of first weak pattern
                line_num = None
                for pattern in weak:
                    if pattern in code:
                        try:
                            index = code.index(pattern)
                            line_num = code[:index].count('\n') + 1
                            break
                        except ValueError:
                            pass
                
                findings.append({
                    'type': 'predictable_random',
                    'severity': 'HIGH',
                    'language': language,
                    'file': file_path,
                    'line': line_num,
                    'message': f"Predictable random number generator detected in {language}",
                    'recommendation': "Use cryptographically secure RNG: secrets (Python), crypto.randomBytes (JS), SecureRandom (Java)"
                })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def detect_non_salted_hashing(code, language='python', file_path=''):
        """Detect password hashing without salt"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_indicators = ['password', 'passwd', 'pwd']
            python_hash_funcs = ['hashlib.sha256', 'hashlib.sha512', 'hashlib.blake2b']
            python_proper = ['bcrypt.', 'scrypt', 'argon2', 'pbkdf2', 'salt']
            
            js_indicators = ['password', 'passwd', 'pwd']
            js_hash_funcs = ['createHash(', 'crypto.createHash', 'sha256', 'sha512']
            js_proper = ['bcrypt', 'scrypt', 'argon2', 'pbkdf2', 'salt']
            
            java_indicators = ['password', 'passwd', 'pwd']
            java_hash_funcs = ['MessageDigest.getInstance', 'DigestUtils']
            java_proper = ['BCrypt', 'SCrypt', 'PBKDF2', 'salt']
            
            php_indicators = ['password', 'passwd', 'pwd']
            php_hash_funcs = ['hash(', 'sha256(', 'hash_hmac(']
            php_proper = ['password_hash(', 'crypt(', 'salt']
            
            patterns = {
                'python': (python_indicators, python_hash_funcs, python_proper),
                'javascript': (js_indicators, js_hash_funcs, js_proper),
                'typescript': (js_indicators, js_hash_funcs, js_proper),
                'java': (java_indicators, java_hash_funcs, java_proper),
                'php': (php_indicators, php_hash_funcs, php_proper),
                'html': ([], [], []),
                'json': ([], [], []),
                'env': ([], [], [])
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            indicators, hash_funcs, proper = patterns.get(language.lower(), (python_indicators, python_hash_funcs, python_proper))
            
            code_lower = code.lower()
            
            has_password = any(ind in code_lower for ind in indicators)
            has_hash = any(func in code for func in hash_funcs)
            has_proper = any(prop in code_lower for prop in proper)
            
            if has_password and has_hash and not has_proper:
                findings.append({
                    'type': 'unsalted_password_hash',
                    'severity': 'CRITICAL',
                    'language': language,
                    'file': file_path,
                    'message': f"Password hashing without salt or proper algorithm in {language}",
                    'recommendation': "Use bcrypt, argon2, or scrypt for password hashing with automatic salting"
                })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def detect_ecb_mode(code, language='python', file_path=''):
        """Detect use of ECB mode encryption"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_ecb = ['MODE_ECB', 'mode=AES.MODE_ECB', 'ECB']
            
            js_ecb = ['mode: CryptoJS.mode.ECB', 'mode.ECB', '"ecb"', "'ecb'"]
            
            java_ecb = ['Cipher.getInstance("AES/ECB', '/ECB/', 'ECBMode']
            
            php_ecb = ['MCRYPT_MODE_ECB', '"ecb"', "'ecb'", 'openssl_encrypt("aes-', '-ecb']
            
            ecb_patterns = {
                'python': python_ecb,
                'javascript': js_ecb,
                'typescript': js_ecb,
                'java': java_ecb,
                'php': php_ecb,
                'html': [],
                'json': [],
                'env': []
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            patterns = ecb_patterns.get(language.lower(), python_ecb)
            
            for pattern in patterns:
                if pattern in code:
                    line_num = None
                    try:
                        index = code.index(pattern)
                        line_num = code[:index].count('\n') + 1
                    except ValueError:
                        pass
                    
                    findings.append({
                        'type': 'ecb_mode',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'pattern': pattern,
                        'line': line_num,
                        'message': f"ECB mode encryption detected: '{pattern}'",
                        'recommendation': "Use CBC, GCM, or CTR mode instead of ECB. ECB mode leaks patterns in plaintext."
                    })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def detect_jwt_without_signature(code, language='python', file_path=''):
        """Detect JWT without signature or using 'none' algorithm"""
        findings = []
        try:
            if not isinstance(code, str):
                return findings
            
            python_jwt = ['algorithm="none"', "algorithm='none'", 'algorithms=["none"]',
                         'jwt.decode(', 'verify_signature=False', 'verify=False']
            
            js_jwt = ['algorithm: "none"', "algorithm: 'none'", 'algorithms: ["none"]',
                     'jwt.verify(', 'verify: false', '{verify: false}']
            
            java_jwt = ['Algorithm.none()', 'algorithm("none")', 'setAllowedClockSkewSeconds']
            
            php_jwt = ['"none"', "'none'", "verify' => false", 'JWT::decode(']
            
            jwt_patterns = {
                'python': python_jwt,
                'javascript': js_jwt,
                'typescript': js_jwt,
                'java': java_jwt,
                'php': php_jwt,
                'html': [],
                'json': [],
                'env': []
            }
            
            if language == 'auto':
                language = CryptographyMisuseDetector._detect_language(code) or 'python'
            
            patterns = jwt_patterns.get(language.lower(), python_jwt)
            
            for pattern in patterns:
                if pattern in code and 'none' in pattern.lower():
                    line_num = None
                    try:
                        index = code.index(pattern)
                        line_num = code[:index].count('\n') + 1
                    except ValueError:
                        pass
                    
                    findings.append({
                        'type': 'jwt_none_algorithm',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'pattern': pattern,
                        'line': line_num,
                        'message': f"JWT 'none' algorithm or disabled verification detected",
                        'recommendation': "Always use a strong signing algorithm (HS256, RS256, ES256) and verify JWT signatures"
                    })
                elif pattern in code and 'verify' in pattern.lower() and 'false' in pattern.lower():
                    line_num = None
                    try:
                        index = code.index(pattern)
                        line_num = code[:index].count('\n') + 1
                    except ValueError:
                        pass
                    
                    findings.append({
                        'type': 'jwt_verify_disabled',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'pattern': pattern,
                        'line': line_num,
                        'message': f"JWT signature verification disabled",
                        'recommendation': "Always verify JWT signatures to prevent token forgery"
                    })
            
            # Check ENV files for JWT secrets
            if language == 'env':
                if 'JWT_SECRET' in code or 'JWT_KEY' in code:
                    lines = code.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        if 'JWT_SECRET' in line or 'JWT_KEY' in line:
                            value = line.split('=')[-1].strip() if '=' in line else ''
                            if value and len(value) < 32:
                                findings.append({
                                    'type': 'weak_jwt_secret',
                                    'severity': 'HIGH',
                                    'language': language,
                                    'file': file_path,
                                    'line': line_num,
                                    'message': f"JWT secret appears weak (too short): {len(value)} characters",
                                    'recommendation': "Use at least 256-bit (32 characters) secret for JWT signing"
                                })
        
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def analyze_cryptography_security(file_path: str, language: str) -> Dict[str, List[dict]]:
        """Perform comprehensive cryptography analysis on a file"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return {
                "weak_hashing": [],
                "weak_encryption": [],
                "predictable_random": [],
                "unsalted_passwords": [],
                "ecb_mode": [],
                "jwt_issues": []
            }
        
        detector = CryptographyMisuseDetector()
        
        return {
            "weak_hashing": detector.detect_weak_hashing(content, language, file_path),
            "weak_encryption": detector.detect_weak_encryption(content, language, file_path),
            "predictable_random": detector.detect_predictable_random(content, language, file_path),
            "unsalted_passwords": detector.detect_non_salted_hashing(content, language, file_path),
            "ecb_mode": detector.detect_ecb_mode(content, language, file_path),
            "jwt_issues": detector.detect_jwt_without_signature(content, language, file_path)
        }


