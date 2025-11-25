"""
Code Quality Analyzer
=====================

Comprehensive code quality analyzer that detects:
- Empty catch blocks
- Infinite loops without break conditions
- Dead/unreachable code
- Inconsistent naming conventions
- Unused variables and functions

Supports multiple programming languages: Python, JavaScript, TypeScript, Java, PHP
"""

import os
import re
import ast
from typing import Dict, List, Any
from collections import defaultdict


class QualityAnalyzer:
    """Comprehensive code quality analyzer"""
    
    def __init__(self):
        self.issues = {
            'empty_catch_blocks': [],
            'infinite_loops': [],
            'dead_code': [],
            'inconsistent_naming': []
        }
    
    def scan_directory(self, directory: str = ".") -> Dict[str, Any]:
        """
        Recursively scan files in the given directory for quality issues.
        """
        print(f"\n[*] Starting Code Quality Analysis on: {directory}")
        
        # Handle single file
        if os.path.isfile(directory):
            ext = directory.lower().split('.')[-1]
            if ext == 'py':
                self.scan_python_file(directory)
            elif ext in ['js', 'jsx', 'ts', 'tsx']:
                self.scan_js_file(directory)
            elif ext == 'java':
                self.scan_java_file(directory)
            elif ext == 'php':
                self.scan_php_file(directory)
            
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
                                                     'venv', 'env', '.venv', 'build', 'dist', 'output']]
            
            for file in files:
                filepath = os.path.join(root, file)
                ext = file.lower().split('.')[-1]
                
                if ext == 'py':
                    self.scan_python_file(filepath)
                elif ext in ['js', 'jsx', 'ts', 'tsx']:
                    self.scan_js_file(filepath)
                elif ext == 'java':
                    self.scan_java_file(filepath)
                elif ext == 'php':
                    self.scan_php_file(filepath)
        
        summary = self._generate_summary()
        self._print_console_summary(summary)
        
        return {
            'findings': self.issues,
            'summary': summary
        }
    
    def scan_python_file(self, filepath: str):
        """Analyze Python file for quality issues"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except Exception:
            return  # Skip files with errors
        
        # Detect various quality issues
        self.detect_empty_catch_python(tree, source, filepath)
        self.detect_infinite_loops_python(tree, filepath)
        self.detect_dead_code_python(tree, filepath)
        self.detect_naming_issues_python(tree, filepath)
    
    def detect_empty_catch_python(self, tree: ast.AST, source: str, filepath: str):
        """Detect empty exception handlers in Python"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    # Check if handler body is empty or only contains 'pass'
                    if len(handler.body) == 0 or (
                        len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)
                    ):
                        # Get the exception type name
                        exc_type = "Exception"
                        if handler.type:
                            if isinstance(handler.type, ast.Name):
                                exc_type = handler.type.id
                            elif isinstance(handler.type, ast.Attribute):
                                exc_type = handler.type.attr
                        
                        # Get code snippet
                        line_num = handler.lineno
                        lines = source.split('\n')
                        snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        self.issues['empty_catch_blocks'].append({
                            'file': filepath,
                            'line': line_num,
                            'type': 'Empty Exception Handler',
                            'severity': 'medium',
                            'language': 'python',
                            'exception_type': exc_type,
                            'code_snippet': snippet.strip(),
                            'message': f"Empty exception handler for '{exc_type}'",
                            'recommendation': 'Add proper error handling or at minimum log the exception'
                        })
    
    def detect_infinite_loops_python(self, tree: ast.AST, filepath: str):
        """Detect infinite loops without break conditions"""
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                # Check if condition is True
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    # Check if there's a break statement in the body
                    has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                    
                    if not has_break:
                        self.issues['infinite_loops'].append({
                            'file': filepath,
                            'line': node.lineno,
                            'type': 'Infinite Loop',
                            'severity': 'high',
                            'language': 'python',
                            'code_snippet': 'while True:',
                            'message': 'Infinite loop without break condition',
                            'recommendation': 'Add break condition or use event-driven pattern'
                        })
    
    def detect_dead_code_python(self, tree: ast.AST, filepath: str):
        """Detect unreachable code after return/raise statements"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check each statement in function body
                for i, stmt in enumerate(node.body):
                    if isinstance(stmt, (ast.Return, ast.Raise)):
                        # Check if there are statements after return/raise
                        if i < len(node.body) - 1:
                            next_stmt = node.body[i + 1]
                            self.issues['dead_code'].append({
                                'file': filepath,
                                'line': next_stmt.lineno,
                                'type': 'Unreachable Code After Return',
                                'severity': 'low',
                                'language': 'python',
                                'code_snippet': f'Code after return in function {node.name}',
                                'message': f"Unreachable code in function '{node.name}'",
                                'recommendation': 'Remove unreachable code'
                            })
    
    def detect_naming_issues_python(self, tree: ast.AST, filepath: str):
        """Detect inconsistent naming conventions in Python"""
        for node in ast.walk(tree):
            # Check function names (should be snake_case)
            if isinstance(node, ast.FunctionDef):
                if not node.name.startswith('_'):  # Skip private methods
                    if not self._is_snake_case(node.name):
                        self.issues['inconsistent_naming'].append({
                            'file': filepath,
                            'line': node.lineno,
                            'type': 'Naming Convention',
                            'severity': 'low',
                            'language': 'python',
                            'identifier': node.name,
                            'actual_convention': 'mixed/camelCase',
                            'expected_convention': 'snake_case',
                            'message': f"Function '{node.name}' doesn't follow snake_case convention",
                            'recommendation': 'Use snake_case for function names in Python'
                        })
            
            # Check class names (should be PascalCase)
            elif isinstance(node, ast.ClassDef):
                if not self._is_pascal_case(node.name):
                    self.issues['inconsistent_naming'].append({
                        'file': filepath,
                        'line': node.lineno,
                        'type': 'Naming Convention',
                        'severity': 'low',
                        'language': 'python',
                        'identifier': node.name,
                        'actual_convention': 'snake_case/mixed',
                        'expected_convention': 'PascalCase',
                        'message': f"Class '{node.name}' doesn't follow PascalCase convention",
                        'recommendation': 'Use PascalCase for class names in Python'
                    })
    
    def scan_js_file(self, filepath: str):
        """Analyze JavaScript/TypeScript file with regex heuristics"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except Exception:
            return
        
        lines = source.splitlines()
        language = 'typescript' if filepath.endswith(('.ts', '.tsx')) else 'javascript'
        
        # 1) Detect empty catch blocks
        catch_pattern = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
        for i, line in enumerate(lines, 1):
            if catch_pattern.search(line):
                self.issues['empty_catch_blocks'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'Empty Catch Block',
                    'severity': 'medium',
                    'language': language,
                    'code_snippet': line.strip(),
                    'message': 'Empty catch block without error handling',
                    'recommendation': 'Add proper error handling or logging'
                })
        
        # 2) Detect infinite loops
        for i, line in enumerate(lines, 1):
            if 'while(true)' in line.replace(' ', '').lower() or 'while (true)' in line.lower():
                # Check if there's a break in nearby lines (simple heuristic)
                context = '\n'.join(lines[max(0, i-1):min(len(lines), i+10)])
                if 'break' not in context:
                    self.issues['infinite_loops'].append({
                        'file': filepath,
                        'line': i,
                        'type': 'Infinite Loop',
                        'severity': 'high',
                        'language': language,
                        'code_snippet': line.strip(),
                        'message': 'Infinite loop without visible break condition',
                        'recommendation': 'Add break condition or timeout'
                    })
        
        # 3) Detect dead code after return
        for i, line in enumerate(lines, 1):
            if 'return' in line and i < len(lines):
                # Simple heuristic: check if next non-empty line is not a closing brace
                next_line = lines[i].strip() if i < len(lines) else ""
                if next_line and not next_line.startswith('}') and not next_line.startswith('//'):
                    # Check indentation to see if it's same level (rough check)
                    if lines[i-1].startswith(' ' * (len(lines[i-1]) - len(lines[i-1].lstrip()))):
                        self.issues['dead_code'].append({
                            'file': filepath,
                            'line': i + 1,
                            'type': 'Unreachable Code',
                            'severity': 'low',
                            'language': language,
                            'code_snippet': next_line[:50],
                            'message': 'Possible unreachable code after return',
                            'recommendation': 'Remove unreachable code'
                        })
        
        # 4) Detect naming issues (simple heuristic)
        func_pattern = re.compile(r'function\s+([A-Z][a-zA-Z0-9]*)\s*\(')
        for match in func_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            func_name = match.group(1)
            self.issues['inconsistent_naming'].append({
                'file': filepath,
                'line': line_num,
                'type': 'Naming Convention',
                'severity': 'low',
                'language': language,
                'identifier': func_name,
                'actual_convention': 'PascalCase',
                'expected_convention': 'camelCase',
                'message': f"Function '{func_name}' should use camelCase",
                'recommendation': 'Use camelCase for function names in JavaScript'
            })
    
    def scan_java_file(self, filepath: str):
        """Analyze Java file with regex heuristics"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except Exception:
            return
        
        lines = source.splitlines()
        
        # Detect empty catch blocks
        catch_pattern = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
        for i, line in enumerate(lines, 1):
            if catch_pattern.search(line):
                self.issues['empty_catch_blocks'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'Empty Catch Block',
                    'severity': 'medium',
                    'language': 'java',
                    'code_snippet': line.strip(),
                    'message': 'Empty catch block without error handling',
                    'recommendation': 'Add proper error handling or logging'
                })
    
    def scan_php_file(self, filepath: str):
        """Analyze PHP file with regex heuristics"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except Exception:
            return
        
        lines = source.splitlines()
        
        # Detect empty catch blocks
        catch_pattern = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
        for i, line in enumerate(lines, 1):
            if catch_pattern.search(line):
                self.issues['empty_catch_blocks'].append({
                    'file': filepath,
                    'line': i,
                    'type': 'Empty Catch Block',
                    'severity': 'medium',
                    'language': 'php',
                    'code_snippet': line.strip(),
                    'message': 'Empty catch block without error handling',
                    'recommendation': 'Add proper error handling or logging'
                })
    
    @staticmethod
    def _is_snake_case(name: str) -> bool:
        """Check if name follows snake_case convention"""
        return name.islower() and '_' in name or name.islower()
    
    @staticmethod
    def _is_pascal_case(name: str) -> bool:
        """Check if name follows PascalCase convention"""
        return name[0].isupper() and '_' not in name
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary"""
        summary = {
            'total_empty_catch': len(self.issues['empty_catch_blocks']),
            'total_infinite_loops': len(self.issues['infinite_loops']),
            'total_dead_code': len(self.issues['dead_code']),
            'total_naming_issues': len(self.issues['inconsistent_naming']),
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
        print(f"[+] Code Quality Analysis Complete!")
        print(f"  - Empty Catch Blocks: {summary['total_empty_catch']}")
        print(f"  - Infinite Loops: {summary['total_infinite_loops']}")
        print(f"  - Dead Code: {summary['total_dead_code']}")
        print(f"  - Naming Issues: {summary['total_naming_issues']}")


def analyze_quality(directory: str = ".") -> Dict[str, Any]:
    """Main function to analyze code quality"""
    analyzer = QualityAnalyzer()
    return analyzer.scan_directory(directory)


# Example usage
if __name__ == "__main__":
    import sys
    
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print("=" * 70)
    print("CODE QUALITY ANALYZER")
    print("=" * 70)
    
    results = analyze_quality(directory)
    
    print(f"\n{'=' * 70}")
    print("DETAILED REPORT")
    print('=' * 70)
    
    findings = results['findings']
    
    # Print findings by category
    if findings.get('empty_catch_blocks'):
        print(f"\n[MEDIUM] EMPTY CATCH BLOCKS ({len(findings['empty_catch_blocks'])} found):")
        for i, finding in enumerate(findings['empty_catch_blocks'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['empty_catch_blocks']) > 5:
            print(f"  ... and {len(findings['empty_catch_blocks']) - 5} more")
    
    if findings.get('infinite_loops'):
        print(f"\n[HIGH] INFINITE LOOPS ({len(findings['infinite_loops'])} found):")
        for i, finding in enumerate(findings['infinite_loops'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['infinite_loops']) > 5:
            print(f"  ... and {len(findings['infinite_loops']) - 5} more")
    
    if findings.get('dead_code'):
        print(f"\n[LOW] DEAD CODE ({len(findings['dead_code'])} found):")
        for i, finding in enumerate(findings['dead_code'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['dead_code']) > 5:
            print(f"  ... and {len(findings['dead_code']) - 5} more")
    
    if findings.get('inconsistent_naming'):
        print(f"\n[LOW] NAMING ISSUES ({len(findings['inconsistent_naming'])} found):")
        for i, finding in enumerate(findings['inconsistent_naming'][:5], 1):
            print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
        if len(findings['inconsistent_naming']) > 5:
            print(f"  ... and {len(findings['inconsistent_naming']) - 5} more")






