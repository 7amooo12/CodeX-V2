class SecurityCodeAnalysis:
    """Security Code Analysis Modules Implementation"""
    
    def __init__(self):
        self.analysis_results = []
    
    # ===== INPUT PROCESSING MODULE =====
    
    class InputProcessingModule:
        """Handles dangerous functions detection"""
        
        @staticmethod
        def detect_common_dangerous_functions(code):
            """Detect eval, exec, system calls"""
            dangerous_funcs = ['eval', 'exec', 'system', '__import__']
            findings = []
            for func in dangerous_funcs:
                if func in code:
                    findings.append(f"Warning: Dangerous function '{func}' detected")
            return findings
        
        @staticmethod
        def detect_runtime_exec_pickle(code):
            """Detect runtime.exec and pickle.load"""
            dangerous_patterns = ['runtime.exec', 'pickle.load', 'pickle.loads']
            findings = []
            for pattern in dangerous_patterns:
                if pattern in code:
                    findings.append(f"Warning: Unsafe operation '{pattern}' detected")
            return findings
        
        @staticmethod
        def detect_json_parse_untrusted(code):
            """Detect JSON parsing of untrusted input"""
            if 'json.loads' in code or 'json.load' in code:
                return ["Warning: JSON parsing detected - ensure input is trusted"]
            return []
        
        @staticmethod
        def detect_file_network_operations(code):
            """Detect file/network operations"""
            operations = ['open(', 'file(', 'urlopen', 'requests.', 'urllib']
            findings = []
            for op in operations:
                if op in code:
                    findings.append(f"Info: File/Network operation '{op}' detected")
            return findings
        
        @staticmethod
        def check_owasp_cwe_list(code):
            """Check against OWASP and CWE patterns"""
            # Simplified check for common vulnerabilities
            patterns = {
                'SQL Injection': ['execute(', 'cursor.execute'],
                'XSS': ['innerHTML', 'document.write'],
                'Path Traversal': ['../', '..\\']
            }
            findings = []
            for vuln_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if pattern in code:
                        findings.append(f"OWASP/CWE Alert: Potential {vuln_type}")
            return findings
    
    # ===== DATA FLOW ANALYSIS MODULE =====
    
    class DataFlowAnalysisModule:
        """Analyzes data flow and taint propagation"""
        
        @staticmethod
        def track_user_input_variables(code):
            """Track variables that receive user input"""
            input_patterns = ['input(', 'request.', 'sys.argv', 'os.environ']
            findings = []
            for pattern in input_patterns:
                if pattern in code:
                    findings.append(f"Tracked: User input via '{pattern}'")
            return findings
        
        @staticmethod
        def detect_data_flow_sensitive_sink(code):
            """Detect sensitive sinks like DB queries, command execution"""
            sinks = ['execute(', 'system(', 'eval(', 'subprocess.']
            findings = []
            for sink in sinks:
                if sink in code:
                    findings.append(f"Sensitive Sink: '{sink}' - verify input sanitization")
            return findings
        
        @staticmethod
        def propagation_map_tainted_variables(code):
            """Map propagation of tainted variables"""
            # Simplified taint tracking
            return ["Info: Perform full taint analysis to track variable propagation"]
        
        @staticmethod
        def check_for_sanitization(code):
            """Check if sanitization functions are used"""
            sanitizers = ['escape', 'sanitize', 'validate', 'clean']
            findings = []
            has_sanitizer = any(s in code.lower() for s in sanitizers)
            if has_sanitizer:
                findings.append("Good: Sanitization detected in code")
            else:
                findings.append("Warning: No obvious sanitization found")
            return findings
    
    # ===== HARDCODED SECRETS DETECTOR =====
    
    class HardcodedSecretsDetector:
        """Detects hardcoded secrets in code"""
        
        @staticmethod
        def detect_hardcoded_passwords(code):
            """Detect hardcoded passwords"""
            password_patterns = ['password =', 'pwd =', 'passwd =', 'pass =']
            findings = []
            for pattern in password_patterns:
                if pattern.lower() in code.lower():
                    findings.append(f"CRITICAL: Hardcoded password pattern detected: '{pattern}'")
            return findings
        
        @staticmethod
        def detect_api_keys_jwt_private_keys(code):
            """Detect API keys, JWT secrets, private keys"""
            key_patterns = [
                'api_key', 'apikey', 'api-key',
                'jwt_secret', 'private_key', 'secret_key',
                'access_token', 'auth_token'
            ]
            findings = []
            for pattern in key_patterns:
                if pattern.lower() in code.lower():
                    findings.append(f"CRITICAL: Potential secret '{pattern}' hardcoded")
            return findings
        
        @staticmethod
        def detect_database_connection_strings(code):
            """Detect database connection strings"""
            db_patterns = ['mongodb://', 'mysql://', 'postgresql://', 'jdbc:', 'connection_string']
            findings = []
            for pattern in db_patterns:
                if pattern.lower() in code.lower():
                    findings.append(f"CRITICAL: Database connection string detected: '{pattern}'")
            return findings
        
        @staticmethod
        def detect_aws_github_keys(code):
            """Detect AWS and GitHub auth tokens"""
            import re
            findings = []
            # AWS patterns
            if re.search(r'AKIA[0-9A-Z]{16}', code):
                findings.append("CRITICAL: AWS Access Key ID detected")
            # GitHub patterns
            if re.search(r'ghp_[a-zA-Z0-9]{36}', code):
                findings.append("CRITICAL: GitHub Personal Access Token detected")
            return findings
        
        @staticmethod
        def detect_base64_encoded_payloads(code):
            """Detect Base64 encoded payloads"""
            import re
            if re.search(r'base64\.b64decode|base64\.decode', code):
                return ["Warning: Base64 decoding detected - verify payload safety"]
            return []
    
    # ===== INPUT VALIDATION & SANITIZATION CHECKER =====
    
    class InputValidationSanitizationChecker:
        """Checks for input validation and sanitization issues"""
        
        @staticmethod
        def check_missing_input_validation(code):
            """Check for missing input validation/type checking"""
            validation_keywords = ['isinstance', 'type(', 'validate', 'check']
            has_validation = any(kw in code for kw in validation_keywords)
            if not has_validation:
                return ["Warning: No input validation detected"]
            return ["Good: Input validation present"]
        
        @staticmethod
        def check_missing_boundary_checks(code):
            """Check for missing boundary checks"""
            boundary_checks = ['len(', 'range(', 'if ', '< ', '> ']
            has_checks = any(check in code for check in boundary_checks)
            if not has_checks:
                return ["Warning: No boundary checks detected"]
            return ["Info: Boundary checks present"]
        
        @staticmethod
        def check_missing_sanitization_before_sinks(code):
            """Check sanitization before sensitive operations"""
            sinks = ['execute', 'system', 'eval']
            sanitizers = ['escape', 'sanitize', 'clean']
            findings = []
            for sink in sinks:
                if sink in code:
                    has_sanitizer = any(s in code for s in sanitizers)
                    if not has_sanitizer:
                        findings.append(f"CRITICAL: '{sink}' used without sanitization")
            return findings
        
        @staticmethod
        def check_client_side_validation_only(code):
            """Check if relying only on client-side validation"""
            if 'javascript' in code.lower() or 'onclick' in code.lower():
                return ["Warning: Possible client-side only validation - always validate server-side"]
            return []
        
        @staticmethod
        def check_unsafe_deserialization(code):
            """Check for unsafe deserialization"""
            unsafe_patterns = ['pickle.loads', 'yaml.load', 'marshal.loads']
            findings = []
            for pattern in unsafe_patterns:
                if pattern in code:
                    findings.append(f"CRITICAL: Unsafe deserialization '{pattern}' detected")
            return findings
    
    # ===== MAIN ANALYSIS METHOD =====
    
    def analyze_code(self, code_string):
        """Run all security checks on the provided code"""
        results = {
            'Input Processing': [],
            'Data Flow Analysis': [],
            'Hardcoded Secrets': [],
            'Input Validation': []
        }
        
        # Input Processing Module
        input_module = self.InputProcessingModule()
        results['Input Processing'].extend(input_module.detect_common_dangerous_functions(code_string))
        results['Input Processing'].extend(input_module.detect_runtime_exec_pickle(code_string))
        results['Input Processing'].extend(input_module.detect_json_parse_untrusted(code_string))
        results['Input Processing'].extend(input_module.detect_file_network_operations(code_string))
        results['Input Processing'].extend(input_module.check_owasp_cwe_list(code_string))
        
        # Data Flow Analysis Module
        data_flow = self.DataFlowAnalysisModule()
        results['Data Flow Analysis'].extend(data_flow.track_user_input_variables(code_string))
        results['Data Flow Analysis'].extend(data_flow.detect_data_flow_sensitive_sink(code_string))
        results['Data Flow Analysis'].extend(data_flow.propagation_map_tainted_variables(code_string))
        results['Data Flow Analysis'].extend(data_flow.check_for_sanitization(code_string))
        
        # Hardcoded Secrets Detector
        secrets = self.HardcodedSecretsDetector()
        results['Hardcoded Secrets'].extend(secrets.detect_hardcoded_passwords(code_string))
        results['Hardcoded Secrets'].extend(secrets.detect_api_keys_jwt_private_keys(code_string))
        results['Hardcoded Secrets'].extend(secrets.detect_database_connection_strings(code_string))
        results['Hardcoded Secrets'].extend(secrets.detect_aws_github_keys(code_string))
        results['Hardcoded Secrets'].extend(secrets.detect_base64_encoded_payloads(code_string))
        
        # Input Validation & Sanitization Checker
        validation = self.InputValidationSanitizationChecker()
        results['Input Validation'].extend(validation.check_missing_input_validation(code_string))
        results['Input Validation'].extend(validation.check_missing_boundary_checks(code_string))
        results['Input Validation'].extend(validation.check_missing_sanitization_before_sinks(code_string))
        results['Input Validation'].extend(validation.check_client_side_validation_only(code_string))
        results['Input Validation'].extend(validation.check_unsafe_deserialization(code_string))
        
        return results
    
    def print_report(self, results):
        """Print formatted security analysis report"""
        print("=" * 70)
        print("SECURITY CODE ANALYSIS REPORT")
        print("=" * 70)
        
        for category, findings in results.items():
            print(f"\n[{category}]")
            if findings:
                for finding in findings:
                    print(f"  • {finding}")
            else:
                print("  ✓ No issues detected")
        
        print("\n" + "=" * 70)


# ===== EXAMPLE USAGE =====
if __name__ == "__main__":
    analyzer = SecurityCodeAnalysis()
    
    # Test with vulnerable code sample
    vulnerable_code = """
import pickle
import os

password = "admin123"
api_key = "sk_live_123456789"

user_input = input("Enter command: ")
os.system(user_input)

data = pickle.loads(untrusted_data)
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)
"""
    
    print("Analyzing code sample...\n")
    results = analyzer.analyze_code(vulnerable_code)
    analyzer.print_report(results)
