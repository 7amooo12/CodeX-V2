"""
Anti-Pattern and Security Issues Detector
Detects common security anti-patterns and coding issues across multiple languages
"""

import os
import re
import ast
from typing import Dict, List, Any
from collections import defaultdict


class AntiPatternDetector:
    """Comprehensive anti-pattern and security issue detector"""
    
    def __init__(self):
        self.issues = {
            'password_variables': [],
            'sql_concatenation': [],
            'api_without_timeout': [],
            'unsafe_file_paths': [],
            'dead_code': [],
            'env_issues': []
        }
    
    def scan_directory(self, directory: str = ".") -> Dict[str, Any]:
        """
        Recursively scan files in the given directory for anti-patterns.
        """
        print(f"\n[*] Starting Anti-Pattern Detection on: {directory}")
        
        # Handle single file
        if os.path.isfile(directory):
            ext = directory.lower().split('.')[-1]
            if ext == 'py':
                self.scan_python_file(directory)
            elif ext in ['js', 'jsx', 'ts', 'tsx']:
                self.scan_js_file(directory)
            elif ext == 'env' or directory.endswith('.env'):
                self.scan_env_file(directory)
            
            summary = self._generate_summary()
            self._print_console_summary(summary)
            
            return {
                'findings': self.issues,
                'summary': summary
            }
        
        # Scan directory
        for root, dirs, files in os.walk(directory):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '.svn', 'node_modules', '__pycache__', 
                                                     'venv', 'env', '.venv', 'build', 'dist']]
            
            for file in files:
                filepath = os.path.join(root, file)
                ext = file.lower().split('.')[-1]
                
                if ext == 'py':
                    self.scan_python_file(filepath)
                elif ext in ['js', 'jsx', 'ts', 'tsx']:
                    self.scan_js_file(filepath)
                elif ext == 'env' or file.endswith('.env'):
                    self.scan_env_file(filepath)
        
        summary = self._generate_summary()
        self._print_console_summary(summary)
        
        return {
            'findings': self.issues,
            'summary': summary
        }
    
    def scan_python_file(self, filepath: str):
        """
        Analyze Python file for anti-patterns using AST and regex.
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except Exception as e:
            return  # Skip files with errors
        
        # Detect various anti-patterns
        self.detect_password_vars_python(tree, filepath)
        self.detect_sql_concat_python(tree, filepath)
        self.detect_api_without_timeout_python(tree, source, filepath)
        self.detect_filesystem_access_python(tree, source, filepath)
        self.detect_dead_code_python(tree, filepath)
    
    def detect_password_vars_python(self, tree: ast.AST, filepath: str):
        """
        Detect password stored in simple variables in Python.
        """
        password_var_names = {'pass', 'password', 'pwd', 'passwd', 'secret', 'api_key', 'apikey'}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(pwd in var_name for pwd in password_var_names):
                            # Check if assigned a string value
                            is_string = False
                            if hasattr(ast, 'Constant') and isinstance(node.value, ast.Constant):
                                if isinstance(node.value.value, str):
                                    is_string = True
                            elif hasattr(node.value, 's'):  # For older Python versions
                                is_string = True
                            
                            if is_string:
                                self.issues['password_variables'].append({
                                    'file': filepath,
                                    'line': node.lineno,
                                    'type': 'Plain Password Variable',
                                    'severity': 'critical',
                                    'language': 'python',
                                    'variable_name': target.id,
                                    'message': f"Variable '{target.id}' assigned plain password/secret. Use environment variables.",
                                    'recommendation': 'Use os.getenv() or python-dotenv to load secrets from environment'
                                })
    
    def detect_sql_concat_python(self, tree: ast.AST, filepath: str):
        """
        Detect SQL queries built by string concatenation in Python.
        """
        # Also check variable assignments for SQL queries with concatenation
        for node in ast.walk(tree):
            # Check execute() calls
            if isinstance(node, ast.Call):
                func_name = ''
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name in ['execute', 'executemany', 'raw']:
                    if len(node.args) > 0:
                        arg = node.args[0]
                        
                        # Check for string concatenation
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            self.issues['sql_concatenation'].append({
                                'file': filepath,
                                'line': node.lineno,
                                'type': 'SQL String Concatenation',
                                'severity': 'critical',
                                'language': 'python',
                                'pattern': 'execute() with +',
                                'message': 'SQL query built by string concatenation (SQL Injection risk)',
                                'recommendation': 'Use parameterized queries or ORM libraries (SQLAlchemy, Django ORM)'
                            })
                        
                        # Check for f-strings
                        elif hasattr(ast, 'JoinedStr') and isinstance(arg, ast.JoinedStr):
                            self.issues['sql_concatenation'].append({
                                'file': filepath,
                                'line': node.lineno,
                                'type': 'SQL F-String Formatting',
                                'severity': 'critical',
                                'language': 'python',
                                'pattern': 'execute() with f-string',
                                'message': 'SQL query built with f-string (SQL Injection risk)',
                                'recommendation': 'Use parameterized queries with ? or %s placeholders'
                            })
                        
                        # Check for Name (variable) that might be concatenated query
                        elif isinstance(arg, ast.Name):
                            # Look for the variable assignment
                            var_name = arg.id
                            for other_node in ast.walk(tree):
                                if isinstance(other_node, ast.Assign):
                                    for target in other_node.targets:
                                        if isinstance(target, ast.Name) and target.id == var_name:
                                            # Check if the assignment uses concatenation or f-string
                                            if isinstance(other_node.value, ast.BinOp) and isinstance(other_node.value.op, ast.Add):
                                                self.issues['sql_concatenation'].append({
                                                    'file': filepath,
                                                    'line': node.lineno,
                                                    'type': 'SQL String Concatenation',
                                                    'severity': 'critical',
                                                    'language': 'python',
                                                    'pattern': 'execute() with concatenated variable',
                                                    'message': 'SQL query variable built by string concatenation (SQL Injection risk)',
                                                    'recommendation': 'Use parameterized queries or ORM libraries (SQLAlchemy, Django ORM)'
                                                })
                                                break
                                            elif hasattr(ast, 'JoinedStr') and isinstance(other_node.value, ast.JoinedStr):
                                                self.issues['sql_concatenation'].append({
                                                    'file': filepath,
                                                    'line': node.lineno,
                                                    'type': 'SQL F-String Formatting',
                                                    'severity': 'critical',
                                                    'language': 'python',
                                                    'pattern': 'execute() with f-string variable',
                                                    'message': 'SQL query variable built with f-string (SQL Injection risk)',
                                                    'recommendation': 'Use parameterized queries with ? or %s placeholders'
                                                })
                                                break
    
    def detect_api_without_timeout_python(self, tree: ast.AST, source: str, filepath: str):
        """
        Detect API requests made without timeout parameter.
        """
        pattern = re.compile(r'requests\.(get|post|put|delete|head|options|patch)\s*\(([^)]*)\)', re.MULTILINE)
        matches = pattern.finditer(source)
        
        for m in matches:
            params = m.group(2)
            if 'timeout' not in params:
                start_pos = m.start()
                line_no = source.count('\n', 0, start_pos) + 1
                
                self.issues['api_without_timeout'].append({
                    'file': filepath,
                    'line': line_no,
                    'type': 'API Call Without Timeout',
                    'severity': 'medium',
                    'language': 'python',
                    'method': m.group(1),
                    'message': f"requests.{m.group(1)}() missing timeout parameter",
                    'recommendation': 'Add timeout parameter: requests.get(url, timeout=30)'
                })
    
    def detect_filesystem_access_python(self, tree: ast.AST, source: str, filepath: str):
        """
        Detect unsafe file system access with user input.
        """
        user_input_vars = set()
        
        # Collect variables from user input
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    func_id = getattr(node.value.func, 'id', '')
                    if func_id in ['input', 'raw_input']:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                user_input_vars.add(target.id)
            
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    if any(keyword in arg.arg.lower() for keyword in ['user', 'input', 'filename', 'path', 'file']):
                        user_input_vars.add(arg.arg)
        
        # Detect unsafe file operations
        dangerous_funcs = ['open', 'remove', 'rename', 'unlink', 'rmdir', 'removedirs']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_dangerous = False
                func_name = ''
                
                if isinstance(node.func, ast.Name) and node.func.id in dangerous_funcs:
                    is_dangerous = True
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute) and node.func.attr in dangerous_funcs:
                    is_dangerous = True
                    func_name = node.func.attr
                
                if is_dangerous and len(node.args) > 0:
                    arg0 = node.args[0]
                    suspicious = False
                    
                    # Check if uses user input variable
                    if isinstance(arg0, ast.Name) and arg0.id in user_input_vars:
                        suspicious = True
                    # Check if uses string concatenation
                    elif isinstance(arg0, ast.BinOp):
                        suspicious = True
                    # Check if uses f-string
                    elif hasattr(ast, 'JoinedStr') and isinstance(arg0, ast.JoinedStr):
                        suspicious = True
                    
                    if suspicious:
                        self.issues['unsafe_file_paths'].append({
                            'file': filepath,
                            'line': node.lineno,
                            'type': 'Unsafe File Path',
                            'severity': 'high',
                            'language': 'python',
                            'operation': func_name,
                            'message': f"File operation {func_name}() with unsanitized user input",
                            'recommendation': 'Validate and sanitize file paths, use os.path.join() and check allowed directories'
                        })
    
    def detect_dead_code_python(self, tree: ast.AST, filepath: str):
        """
        Detect unused functions and variables in Python file.
        """
        func_defs = {}
        var_defs = {}
        func_calls = set()
        var_uses = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_defs[node.name] = node.lineno
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_defs[target.id] = node.lineno
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    func_calls.add(node.func.attr)
            elif isinstance(node, ast.Name):
                var_uses.add(node.id)
        
        # Unused functions
        for func_name, lineno in func_defs.items():
            if func_name not in func_calls and not func_name.startswith('__') and func_name not in ['main', 'setup', 'teardown']:
                self.issues['dead_code'].append({
                    'file': filepath,
                    'line': lineno,
                    'type': 'Unused Function',
                    'severity': 'low',
                    'language': 'python',
                    'identifier': func_name,
                    'message': f"Function '{func_name}' defined but never called",
                    'recommendation': 'Remove unused function or add it to __all__ if it\'s part of public API'
                })
        
        # Unused variables (only flag if not used at all)
        for var_name, lineno in var_defs.items():
            if var_name not in var_uses and not var_name.startswith('_'):
                self.issues['dead_code'].append({
                    'file': filepath,
                    'line': lineno,
                    'type': 'Unused Variable',
                    'severity': 'low',
                    'language': 'python',
                    'identifier': var_name,
                    'message': f"Variable '{var_name}' defined but never used",
                    'recommendation': 'Remove unused variable or prefix with _ if intentionally unused'
                })
    
    def scan_js_file(self, filepath: str):
        """
        Analyze JavaScript/TypeScript file with regex heuristics.
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except Exception:
            return
        
        lines = source.splitlines()
        language = 'typescript' if filepath.endswith(('.ts', '.tsx')) else 'javascript'
        
        # 1) Detect password variables
        pass_pattern = re.compile(r'\b(var|let|const)\s+(pass|password|pwd|passwd|secret|apiKey|api_key)\s*=\s*["\'].*?["\']', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            match = pass_pattern.search(line)
            if match:
                self.issues['password_variables'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'Plain Password Variable',
                    'severity': 'critical',
                    'language': language,
                    'variable_name': match.group(2),
                    'message': f"Password/secret stored in plain variable '{match.group(2)}'",
                    'recommendation': 'Use process.env or environment configuration'
                })
        
        # 2) SQL concatenation
        sql_pattern = re.compile(r'(query|execute|sql)\s*\(?\s*[=:]\s*.*?\+.*?["\']', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if sql_pattern.search(line) and ('SELECT' in line.upper() or 'INSERT' in line.upper() or 'UPDATE' in line.upper()):
                self.issues['sql_concatenation'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'SQL String Concatenation',
                    'severity': 'critical',
                    'language': language,
                    'pattern': 'String concatenation',
                    'message': 'SQL query built by string concatenation (SQL Injection risk)',
                    'recommendation': 'Use ORM (Sequelize, TypeORM) or parameterized queries'
                })
        
        # 3) API without timeout
        api_pattern = re.compile(r'\b(fetch|axios\.get|axios\.post)\s*\(', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if api_pattern.search(line):
                context = ' '.join(lines[max(0, i-2):min(len(lines), i+3)]).lower()
                if 'timeout' not in context and 'abortsignal' not in context:
                    self.issues['api_without_timeout'].append({
                        'file': filepath,
                        'line': i,
                        'type': 'API Call Without Timeout',
                        'severity': 'medium',
                        'language': language,
                        'method': 'fetch/axios',
                        'message': 'API request without timeout or abort signal',
                        'recommendation': 'Add timeout or AbortController for fetch(), or timeout config for axios'
                    })
        
        # 4) Unsafe filesystem access
        fs_pattern = re.compile(r'\bfs\.(readFile|writeFile|unlink|rmdir|rm)\s*\(', re.IGNORECASE)
        user_input_vars = set()
        var_decl_pattern = re.compile(r'\b(var|let|const)\s+(\w+)\s*=\s*.*(input|req\.body|req\.query|req\.params)', re.IGNORECASE)
        
        for i, line in enumerate(lines, 1):
            m = var_decl_pattern.search(line)
            if m:
                user_input_vars.add(m.group(2))
        
        for i, line in enumerate(lines, 1):
            if fs_pattern.search(line):
                if any(uvar in line for uvar in user_input_vars):
                    self.issues['unsafe_file_paths'].append({
                        'file': filepath,
                        'line': i,
                        'type': 'Unsafe File Path',
                        'severity': 'high',
                        'language': language,
                        'operation': 'fs operation',
                        'message': 'File system access with unsanitized user input',
                        'recommendation': 'Validate file paths, use path.join() and check against allowed directories'
                    })
    
    def scan_env_file(self, filepath: str):
        """
        Scan .env file for plaintext passwords.
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return
        
        password_pattern = re.compile(r'(pass(word)?|pwd|passwd|secret|api[_-]?key)\s*=\s*.+', re.IGNORECASE)
        
        for i, line in enumerate(lines, 1):
            if password_pattern.search(line) and not line.strip().startswith('#'):
                self.issues['env_issues'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'Password in .env',
                    'severity': 'critical',
                    'language': 'env',
                    'message': 'Potential password/secret stored in .env file',
                    'recommendation': 'Ensure .env is in .gitignore and not committed to repository'
                })
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary"""
        summary = {
            'total_password_vars': len(self.issues['password_variables']),
            'total_sql_concat': len(self.issues['sql_concatenation']),
            'total_api_timeout': len(self.issues['api_without_timeout']),
            'total_unsafe_paths': len(self.issues['unsafe_file_paths']),
            'total_dead_code': len(self.issues['dead_code']),
            'total_env_issues': len(self.issues['env_issues']),
            'total_issues': 0,
            'issues_by_severity': defaultdict(int),
            'issues_by_language': defaultdict(int),
            'issues_by_file': defaultdict(int)
        }
        
        # Aggregate statistics
        for category, findings in self.issues.items():
            summary['total_issues'] += len(findings)
            
            for finding in findings:
                severity = finding.get('severity', 'low')
                language = finding.get('language', 'unknown')
                file_path = finding.get('file', 'unknown')
                
                summary['issues_by_severity'][severity] += 1
                summary['issues_by_language'][language] += 1
                summary['issues_by_file'][file_path] += 1
        
        return summary
    
    def _print_console_summary(self, summary: Dict[str, Any]):
        """Print summary to console"""
        print(f"[+] Anti-Pattern Detection Complete!")
        print(f"  - Password Variables: {summary['total_password_vars']}")
        print(f"  - SQL Concatenation: {summary['total_sql_concat']}")
        print(f"  - API Without Timeout: {summary['total_api_timeout']}")
        print(f"  - Unsafe File Paths: {summary['total_unsafe_paths']}")
        print(f"  - Dead Code: {summary['total_dead_code']}")
        print(f"  - Env Issues: {summary['total_env_issues']}")


def detect_antipatterns(directory: str = ".") -> Dict[str, Any]:
    """Main function to detect anti-patterns"""
    detector = AntiPatternDetector()
    return detector.scan_directory(directory)


# Example usage
if __name__ == "__main__":
    import sys
    
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print("=" * 70)
    print("ANTI-PATTERN & SECURITY ISSUES DETECTOR")
    print("=" * 70)
    
    results = detect_antipatterns(directory)
    
    print(f"\n{'=' * 70}")
    print("DETAILED REPORT")
    print('=' * 70)
    
    findings = results['findings']
    
    # Print findings by category
    if findings.get('password_variables'):
        print(f"\n[CRITICAL] PASSWORD VARIABLES ({len(findings['password_variables'])} found):")
        for i, finding in enumerate(findings['password_variables'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['password_variables']) > 5:
            print(f"  ... and {len(findings['password_variables']) - 5} more")
    
    if findings.get('sql_concatenation'):
        print(f"\n[CRITICAL] SQL CONCATENATION ({len(findings['sql_concatenation'])} found):")
        for i, finding in enumerate(findings['sql_concatenation'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['sql_concatenation']) > 5:
            print(f"  ... and {len(findings['sql_concatenation']) - 5} more")
    
    if findings.get('api_without_timeout'):
        print(f"\n[MEDIUM] API WITHOUT TIMEOUT ({len(findings['api_without_timeout'])} found):")
        for i, finding in enumerate(findings['api_without_timeout'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['api_without_timeout']) > 5:
            print(f"  ... and {len(findings['api_without_timeout']) - 5} more")
    
    if findings.get('unsafe_file_paths'):
        print(f"\n[HIGH] UNSAFE FILE PATHS ({len(findings['unsafe_file_paths'])} found):")
        for i, finding in enumerate(findings['unsafe_file_paths'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['unsafe_file_paths']) > 5:
            print(f"  ... and {len(findings['unsafe_file_paths']) - 5} more")

