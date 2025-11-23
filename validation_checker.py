"""
Advanced Input Validation and Sanitization Checker
Detects missing validation, boundary checks, sanitization issues, and unsafe deserialization
"""

import re
from typing import List, Dict, Any


class InputValidationSanitizationChecker:
    """Checks for input validation and sanitization issues across multiple languages"""
    
    @staticmethod
    def check_missing_input_validation(code, language='python', file_path=''):
        """Check for missing input validation/type checking"""
        findings = []
        
        # Python validation patterns
        python_validation = ['isinstance(', 'type(', 'validate', 'check', 'assert ', 'if not ', 'raise ValueError', 'raise TypeError']
        
        # JavaScript/TypeScript validation patterns
        js_validation = ['typeof ', 'instanceof ', 'validate', 'isNaN(', 'Number.isInteger(', 'Array.isArray(', 'if (!', 'if(!', 'throw new']
        
        # Java validation patterns
        java_validation = ['instanceof ', 'validate', 'Objects.requireNonNull', 'if (null', 'if(null', 'throws IllegalArgumentException', 'Pattern.matches']
        
        # PHP validation patterns
        php_validation = ['is_string(', 'is_int(', 'is_array(', 'filter_var(', 'validate', 'empty(', 'isset(', 'preg_match(']
        
        # HTML validation patterns
        html_validation = ['required', 'pattern=', 'min=', 'max=', 'minlength=', 'maxlength=', 'type="email"', 'type="number"']
        
        # JSON validation patterns (JSON Schema)
        json_validation = ['"type":', '"required":', '"pattern":', '"minimum":', '"maximum":', '"minLength":', '"maxLength":', '"enum":', '"format":']
        
        # ENV file validation patterns
        env_validation = ['validate', 'required', 'check', 'schema']
        
        validation_patterns = {
            'python': python_validation,
            'javascript': js_validation,
            'typescript': js_validation,
            'java': java_validation,
            'php': php_validation,
            'html': html_validation,
            'json': json_validation,
            'env': env_validation
        }
        
        patterns = validation_patterns.get(language.lower(), python_validation)
        has_validation = any(pattern in code for pattern in patterns)
        
        if not has_validation:
            findings.append({
                'type': 'missing_validation',
                'severity': 'HIGH',
                'language': language,
                'file': file_path,
                'message': f"No input validation detected for {language}",
                'recommendation': "Implement input validation using type checking, validation libraries, or validation frameworks"
            })
        
        return findings
    
    @staticmethod
    def check_missing_boundary_checks(code, language='python', file_path=''):
        """Check for missing boundary checks"""
        findings = []
        
        # Python boundary checks
        python_checks = ['len(', 'range(', 'if ', '< ', '> ', '<=', '>=', 'min(', 'max(']
        
        # JavaScript/TypeScript boundary checks
        js_checks = ['length', 'if (', 'if(', '<', '>', '<=', '>=', 'Math.min', 'Math.max']
        
        # Java boundary checks
        java_checks = ['length', 'size()', 'if (', 'if(', '<', '>', '<=', '>=', 'Math.min', 'Math.max']
        
        # PHP boundary checks
        php_checks = ['strlen(', 'count(', 'sizeof(', 'if (', 'if(', '<', '>', '<=', '>=', 'min(', 'max(']
        
        # JSON boundary checks (in schema)
        json_checks = ['"minimum":', '"maximum":', '"minLength":', '"maxLength":', '"minItems":', '"maxItems":', '"minProperties":', '"maxProperties":']
        
        # ENV boundary checks
        env_checks = ['MIN_', 'MAX_', 'LENGTH', 'LIMIT']
        
        boundary_patterns = {
            'python': python_checks,
            'javascript': js_checks,
            'typescript': js_checks,
            'java': java_checks,
            'php': php_checks,
            'json': json_checks,
            'env': env_checks
        }
        
        patterns = boundary_patterns.get(language.lower(), python_checks)
        has_checks = any(check in code for check in patterns)
        
        if not has_checks:
            findings.append({
                'type': 'missing_boundary_checks',
                'severity': 'MEDIUM',
                'language': language,
                'file': file_path,
                'message': f"No boundary checks detected in {language}",
                'recommendation': "Implement boundary checks to prevent buffer overflows and out-of-bounds access"
            })
        
        return findings
    
    @staticmethod
    def check_missing_sanitization_before_sinks(code, language='python', file_path=''):
        """Check sanitization before sensitive operations"""
        findings = []
        
        # Define sinks per language
        python_sinks = ['execute(', 'system(', 'eval(', 'exec(', 'subprocess.', '__import__']
        js_sinks = ['eval(', 'Function(', 'innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML']
        java_sinks = ['Runtime.exec(', 'ProcessBuilder', 'executeQuery(', 'createQuery(']
        php_sinks = ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru(', 'mysql_query(', 'mysqli_query(']
        json_sinks = []
        env_sinks = []
        
        # Define sanitizers per language
        python_sanitizers = ['escape', 'sanitize', 'clean', 'quote', 'html.escape', 're.escape', 'shlex.quote']
        js_sanitizers = ['escape', 'sanitize', 'encodeURIComponent', 'encodeURI', 'DOMPurify', 'textContent']
        java_sanitizers = ['escape', 'sanitize', 'encode', 'PreparedStatement', 'setString(']
        php_sanitizers = ['htmlspecialchars(', 'htmlentities(', 'mysqli_real_escape_string(', 'filter_', 'prepared statement', 'bindParam']
        json_sanitizers = ['validate', 'schema', 'sanitize']
        env_sanitizers = ['validate', 'sanitize', 'escape']
        
        sinks_map = {
            'python': python_sinks,
            'javascript': js_sinks,
            'typescript': js_sinks,
            'java': java_sinks,
            'php': php_sinks,
            'json': json_sinks,
            'env': env_sinks
        }
        
        sanitizers_map = {
            'python': python_sanitizers,
            'javascript': js_sanitizers,
            'typescript': js_sanitizers,
            'java': java_sanitizers,
            'php': php_sanitizers,
            'json': json_sanitizers,
            'env': env_sanitizers
        }
        
        # Special checks for JSON
        if language == 'json':
            if '"$schema"' not in code:
                findings.append({
                    'type': 'missing_json_schema',
                    'severity': 'MEDIUM',
                    'language': language,
                    'file': file_path,
                    'message': "JSON file has no schema validation defined",
                    'recommendation': "Define JSON Schema for validation"
                })
            return findings
        
        # Special checks for ENV
        if language == 'env':
            dangerous_env_patterns = ['eval', 'exec', '$(', '`', '|', ';']
            for pattern in dangerous_env_patterns:
                if pattern in code:
                    findings.append({
                        'type': 'dangerous_env_pattern',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'message': f"Potentially dangerous pattern '{pattern}' in ENV file",
                        'recommendation': "Remove executable patterns from ENV files"
                    })
            return findings
        
        sinks = sinks_map.get(language.lower(), python_sinks)
        sanitizers = sanitizers_map.get(language.lower(), python_sanitizers)
        
        for sink in sinks:
            if sink in code:
                has_sanitizer = any(s in code for s in sanitizers)
                if not has_sanitizer:
                    findings.append({
                        'type': 'unsanitized_sink',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'sink': sink,
                        'message': f"'{sink}' used without sanitization in {language}",
                        'recommendation': f"Always sanitize input before using {sink}. Use appropriate escaping/encoding functions"
                    })
        
        return findings
    
    @staticmethod
    def check_client_side_validation_only(code, file_path=''):
        """Check if relying only on client-side validation"""
        findings = []
        
        # HTML/JavaScript client-side validation indicators
        client_indicators = [
            'required', 'pattern=', 'onsubmit=', 'onclick=',
            'oninput=', 'onchange=', 'validate()', 'checkValidity()'
        ]
        
        # Server-side validation indicators
        server_indicators = [
            'POST', 'GET', 'request.', 'req.body', '$_POST', '$_GET',
            '@RequestMapping', '@PostMapping', 'HttpServletRequest',
            'validate', 'filter_input', 'sanitize'
        ]
        
        has_client_validation = any(indicator in code for indicator in client_indicators)
        has_server_validation = any(indicator in code for indicator in server_indicators)
        
        if has_client_validation and not has_server_validation:
            findings.append({
                'type': 'client_side_validation_only',
                'severity': 'CRITICAL',
                'file': file_path,
                'message': "Client-side validation only detected - ALWAYS validate server-side!",
                'recommendation': "Implement server-side validation. Client-side validation can be bypassed easily"
            })
        
        return findings
    
    @staticmethod
    def check_unsafe_deserialization(code, language='python', file_path=''):
        """Check for unsafe deserialization"""
        findings = []
        
        # Python unsafe deserialization
        python_unsafe = ['pickle.loads(', 'pickle.load(', 'yaml.load(', 'marshal.loads(', 'jsonpickle.decode(']
        
        # JavaScript/TypeScript unsafe deserialization
        js_unsafe = ['eval(', 'Function(', 'JSON.parse(', 'vm.runInContext']
        
        # Java unsafe deserialization
        java_unsafe = ['ObjectInputStream', 'readObject(', 'XMLDecoder', 'XStream']
        
        # PHP unsafe deserialization
        php_unsafe = ['unserialize(', 'unserialize($_']
        
        # ENV deserialization (check for code execution patterns)
        env_unsafe = ['eval', 'exec', '$(', '`']
        
        unsafe_patterns = {
            'python': python_unsafe,
            'javascript': js_unsafe,
            'typescript': js_unsafe,
            'java': java_unsafe,
            'php': php_unsafe,
            'json': [],
            'env': env_unsafe
        }
        
        # Special handling for JSON
        if language == 'json':
            if 'eval' in code or 'function' in code.lower():
                findings.append({
                    'type': 'executable_json',
                    'severity': 'CRITICAL',
                    'language': language,
                    'file': file_path,
                    'message': "JSON contains executable code patterns",
                    'recommendation': "Remove executable code from JSON files"
                })
            return findings
        
        # Special handling for ENV
        if language == 'env':
            for pattern in env_unsafe:
                if pattern in code:
                    findings.append({
                        'type': 'executable_env',
                        'severity': 'CRITICAL',
                        'language': language,
                        'file': file_path,
                        'message': f"Potentially executable pattern '{pattern}' in ENV file",
                        'recommendation': "Remove executable patterns from ENV files"
                    })
            return findings
        
        patterns = unsafe_patterns.get(language.lower(), python_unsafe)
        
        for pattern in patterns:
            if pattern in code:
                findings.append({
                    'type': 'unsafe_deserialization',
                    'severity': 'CRITICAL',
                    'language': language,
                    'file': file_path,
                    'pattern': pattern,
                    'message': f"Unsafe deserialization '{pattern}' detected in {language}",
                    'recommendation': "Use safe deserialization methods. For Python use yaml.safe_load(), for PHP use JSON, avoid pickle with untrusted data"
                })
        
        # Check for safe alternatives
        if language == 'python':
            if 'yaml.safe_load(' in code:
                # Good practice detected
                pass
        
        return findings


def analyze_validation_security(file_path: str, language: str) -> Dict[str, List[dict]]:
    """Perform comprehensive validation security analysis on a file"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return {
            "validation_issues": [],
            "boundary_issues": [],
            "sanitization_issues": [],
            "client_side_issues": [],
            "deserialization_issues": []
        }
    
    checker = InputValidationSanitizationChecker()
    
    return {
        "validation_issues": checker.check_missing_input_validation(content, language, file_path),
        "boundary_issues": checker.check_missing_boundary_checks(content, language, file_path),
        "sanitization_issues": checker.check_missing_sanitization_before_sinks(content, language, file_path),
        "client_side_issues": checker.check_client_side_validation_only(content, file_path),
        "deserialization_issues": checker.check_unsafe_deserialization(content, language, file_path)
    }


