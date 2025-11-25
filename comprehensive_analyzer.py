#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMPREHENSIVE SECURITY & QUALITY ANALYZER
==========================================
Unified analyzer that runs ALL checks with complete control

Usage:
    python comprehensive_analyzer.py <project_path> [-pdf|-json|-both]
    
Examples:
    python comprehensive_analyzer.py test_project -pdf
    python comprehensive_analyzer.py test_project -json
    python comprehensive_analyzer.py test_project -both
    python comprehensive_analyzer.py test_project  (default: both)
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, Any, List
from collections import defaultdict

# Fix encoding for Windows console
if sys.platform == 'win32':
    try:
        # Try to set UTF-8 encoding for stdout
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'ignore')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'ignore')
    except:
        # If that fails, just continue
        pass

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import all analyzers
from core.input_processor import (
    scan_project,
    analyze_file_security,
    detect_dangerous_functions,
    detect_secrets_in_content,
    detect_taint_sources
)
from analyzers.quality_analyzer import QualityAnalyzer
from analyzers.antipattern_detector import AntiPatternDetector
from modules.vulnerability_scanner import VulnerabilityScanner
from security_checks.authentication_checker import AuthenticationSecurityChecker
from security_checks.cryptography_checker import CryptographyMisuseDetector
from security_checks.validation_checker import InputValidationSanitizationChecker

# Import framework checkers
from security_checks.framework_checks.python_frameworks import PythonFrameworkChecker
from security_checks.framework_checks.javascript_frameworks import JavaScriptFrameworkChecker
from security_checks.framework_checks.java_frameworks import JavaFrameworkChecker
from security_checks.framework_checks.dotnet_frameworks import DotNetFrameworkChecker

# PDF Generator (optional)
try:
    from reports.pdf_report_generator import SecurityReportPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("[!] Warning: PDF generator not available. Install: pip install reportlab matplotlib")


class ComprehensiveAnalyzer:
    """Ultimate comprehensive analyzer - ALL CHECKS INCLUDED"""
    
    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)
        self.results = {
            'metadata': {
                'project_path': self.project_path,
                'scan_time': datetime.now().isoformat(),
                'analyzer_version': '2.0',
            },
            'dangerous_functions': [],
            'secrets': [],
            'taint_analysis': [],
            'taint_flows': [],  # NEW: Taint flow paths (source -> sink)
            'validation_issues': [],
            'crypto_issues': [],
            'auth_issues': [],
            'quality_issues': {},
            'quality_analysis': {},  # NEW: Structured quality data
            'antipatterns': {},
            'antipattern_analysis': {},  # NEW: Structured antipattern data
            'framework_issues': [],
            'framework_security': [],  # NEW: Alias for compatibility
            'framework_security_findings': [],  # NEW: Another alias
            'vulnerability_scan': {},
            'summary': {},
            'files_scanned': [],
            'file_tree': {},  # NEW: File tree structure
            'unified_findings': [],  # NEW: Deduplicated findings table
            'recommendations': [],  # NEW: Security recommendations
            'risk_level': 'UNKNOWN'
        }
    
    def analyze_all(self) -> Dict[str, Any]:
        """Run ALL security and quality checks"""
        
        print("=" * 80)
        print("🔥 COMPREHENSIVE SECURITY & QUALITY ANALYSIS 🔥")
        print("=" * 80)
        print(f"\n📂 Project: {self.project_path}\n")
        
        if not os.path.exists(self.project_path):
            print(f"❌ Error: Project path does not exist: {self.project_path}")
            sys.exit(1)
        
        # Step 1: Core Security Analysis
        print("🔍 [1/8] Running Core Security Analysis (Dangerous Functions, Secrets, Taint)...")
        self._run_core_security_analysis()
        
        # Step 2: Validation & Sanitization Check
        print("🛡️  [2/8] Running Input Validation & Sanitization Checks...")
        self._run_validation_checks()
        
        # Step 3: Cryptography Analysis
        print("🔐 [3/8] Running Cryptography Misuse Detection...")
        self._run_crypto_checks()
        
        # Step 4: Authentication & Session Security
        print("🔑 [4/8] Running Authentication & Session Security Checks...")
        self._run_auth_checks()
        
        # Step 5: Framework-Specific Checks
        print("🏗️  [5/8] Running Framework-Specific Security Checks...")
        self._run_framework_checks()
        
        # Step 6: Quality Analysis
        print("✨ [6/8] Running Code Quality Analysis...")
        self._run_quality_checks()
        
        # Step 7: Anti-Pattern Detection
        print("⚠️  [7/8] Running Anti-Pattern Detection...")
        self._run_antipattern_checks()
        
        # Step 8: Vulnerability Scanning
        print("🔍 [8/8] Running Vulnerability Scan (Dependencies)...")
        self._run_vulnerability_scan()
        
        # Calculate Summary
        print("\n📊 Calculating Summary...")
        self._calculate_summary()
        
        # Generate additional structures for PDF compatibility
        print("\n🔧 Generating Additional Structures...")
        self._generate_pdf_compatible_structures()
        
        print("\n✅ Analysis Complete!")
        return self.results
    
    def _run_core_security_analysis(self):
        """Core security: dangerous functions, secrets, taint sources"""
        try:
            # Scan project structure
            project_data = scan_project(self.project_path)
            self.results['files_scanned'] = project_data.get('files', [])
            
            # Analyze each file
            all_dangerous = []
            all_secrets = []
            all_taint = []
            
            for file_info in project_data.get('files', []):
                file_path = file_info.get('path', '')
                language = file_info.get('language', 'unknown')
                
                if not os.path.exists(file_path):
                    continue
                
                # Analyze file
                file_results = analyze_file_security(file_path, language)
                
                # Collect dangerous functions
                if 'dangerous_functions' in file_results:
                    all_dangerous.extend(file_results['dangerous_functions'])
                
                # Collect secrets
                if 'secrets' in file_results:
                    all_secrets.extend(file_results['secrets'])
                
                # Collect taint sources
                if 'taint_sources' in file_results:
                    all_taint.extend(file_results['taint_sources'])
            
            self.results['dangerous_functions'] = all_dangerous
            self.results['secrets'] = all_secrets
            self.results['taint_analysis'] = all_taint
            
            print(f"   ✓ Dangerous Functions: {len(all_dangerous)}")
            print(f"   ✓ Secrets Found: {len(all_secrets)}")
            print(f"   ✓ Taint Sources: {len(all_taint)}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_validation_checks(self):
        """Input validation and sanitization checks"""
        try:
            from security_checks.validation_checker import analyze_validation_security
            
            validation_findings = []
            for file_info in self.results.get('files_scanned', []):
                file_path = file_info.get('path', '')
                language = file_info.get('language', 'unknown')
                
                if os.path.exists(file_path):
                    results = analyze_validation_security(file_path, language)
                    if results:
                        for key, findings in results.items():
                            if isinstance(findings, list):
                                validation_findings.extend(findings)
            
            self.results['validation_issues'] = validation_findings
            print(f"   ✓ Validation Issues: {len(validation_findings)}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_crypto_checks(self):
        """Cryptography misuse detection"""
        try:
            crypto_findings = []
            for file_info in self.results.get('files_scanned', []):
                file_path = file_info.get('path', '')
                language = file_info.get('language', 'unknown')
                
                if os.path.exists(file_path):
                    results = CryptographyMisuseDetector.analyze_cryptography_security(file_path, language)
                    if results:
                        for key, findings in results.items():
                            if isinstance(findings, list):
                                crypto_findings.extend(findings)
            
            self.results['crypto_issues'] = crypto_findings
            print(f"   ✓ Crypto Issues: {len(crypto_findings)}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_auth_checks(self):
        """Authentication and session security checks"""
        try:
            auth_findings = []
            for file_info in self.results.get('files_scanned', []):
                file_path = file_info.get('path', '')
                language = file_info.get('language', 'unknown')
                
                if os.path.exists(file_path):
                    results = AuthenticationSecurityChecker.analyze_authentication_security(file_path, language)
                    if results:
                        for key, findings in results.items():
                            if isinstance(findings, list):
                                auth_findings.extend(findings)
            
            self.results['auth_issues'] = auth_findings
            print(f"   ✓ Auth Issues: {len(auth_findings)}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_framework_checks(self):
        """Framework-specific security checks"""
        framework_findings = []
        
        try:
            # Initialize checkers
            checkers = [
                PythonFrameworkChecker(),
                JavaScriptFrameworkChecker(),
                JavaFrameworkChecker(),
                DotNetFrameworkChecker()
            ]
            
            # Check each file with appropriate checkers
            for file_info in self.results.get('files_scanned', []):
                file_path = file_info.get('path', '')
                
                if not os.path.exists(file_path):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    
                    for checker in checkers:
                        # Check if this checker supports this file type
                        ext = os.path.splitext(file_path)[1]
                        if hasattr(checker, 'supported_extensions'):
                            if ext not in checker.supported_extensions:
                                continue
                        
                        # Run check
                        findings = checker.check(code, file_path)
                        if findings:
                            # Ensure findings is a list, not dict
                            if isinstance(findings, list):
                                framework_findings.extend(findings)
                            elif isinstance(findings, dict):
                                # Convert dict to list of findings
                                for key, items in findings.items():
                                    if isinstance(items, list):
                                        framework_findings.extend(items)
                            
                except Exception:
                    pass
            
            # Store as list
            self.results['framework_issues'] = framework_findings
            print(f"   ✓ Framework Issues: {len(framework_findings)}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_quality_checks(self):
        """Code quality analysis"""
        try:
            analyzer = QualityAnalyzer()
            quality_results = analyzer.scan_directory(self.project_path)
            
            # Fix: analyzer returns 'findings', not 'issues'
            self.results['quality_issues'] = quality_results.get('findings', {})
            
            total = sum(len(v) for v in self.results['quality_issues'].values())
            print(f"   ✓ Quality Issues: {total}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_antipattern_checks(self):
        """Anti-pattern detection"""
        try:
            detector = AntiPatternDetector()
            antipattern_results = detector.scan_directory(self.project_path)
            
            # Fix: detector returns 'findings', not 'issues'
            self.results['antipatterns'] = antipattern_results.get('findings', {})
            
            total = sum(len(v) for v in self.results['antipatterns'].values())
            print(f"   ✓ Anti-Patterns: {total}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    def _run_vulnerability_scan(self):
        """Vulnerability scanning for dependencies"""
        try:
            # Run fast scan (OSV only by default for speed)
            scanner = VulnerabilityScanner(use_nvd=False, use_github=False)
            scan_result = scanner.scan_project(self.project_path)
            
            # Store results
            self.results['vulnerability_scan'] = scan_result.to_dict()
            
            total_vulns = scan_result.total_vulnerabilities
            vulnerable_pkgs = scan_result.get_summary()['vulnerable_packages']
            
            print(f"   ✓ Vulnerable Packages: {vulnerable_pkgs}/{scan_result.total_dependencies}")
            print(f"   ✓ Total Vulnerabilities: {total_vulns}")
            
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
            self.results['vulnerability_scan'] = {'error': str(e), 'packages': []}
    
    def _calculate_summary(self):
        """Calculate comprehensive summary"""
        # Get vulnerability count
        vuln_scan = self.results.get('vulnerability_scan', {})
        vuln_summary = vuln_scan.get('summary', {})
        vuln_count = vuln_summary.get('total_vulnerabilities', 0)
        
        summary = {
            'dangerous_functions_count': len(self.results.get('dangerous_functions', [])),
            'secrets_count': len(self.results.get('secrets', [])),
            'taint_sources_count': len(self.results.get('taint_analysis', [])),
            'validation_issues_count': len(self.results.get('validation_issues', [])),
            'crypto_issues_count': len(self.results.get('crypto_issues', [])),
            'auth_issues_count': len(self.results.get('auth_issues', [])),
            'framework_issues_count': len(self.results.get('framework_issues', [])),
            'quality_issues_count': sum(len(v) for v in self.results.get('quality_issues', {}).values()),
            'antipattern_count': sum(len(v) for v in self.results.get('antipatterns', {}).values()),
            'vulnerability_count': vuln_count,
            'files_scanned': len(self.results.get('files_scanned', [])),
        }
        
        # Total issues
        total_issues = sum([
            summary['dangerous_functions_count'],
            summary['secrets_count'],
            summary['taint_sources_count'],
            summary['validation_issues_count'],
            summary['crypto_issues_count'],
            summary['auth_issues_count'],
            summary['framework_issues_count'],
            summary['quality_issues_count'],
            summary['antipattern_count'],
            summary['vulnerability_count']
        ])
        
        summary['total_issues'] = total_issues
        
        # Risk level
        if total_issues >= 50 or summary['secrets_count'] >= 5:
            risk_level = 'CRITICAL'
        elif total_issues >= 20 or summary['secrets_count'] >= 2:
            risk_level = 'HIGH'
        elif total_issues >= 5:
            risk_level = 'MEDIUM'
        elif total_issues > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'CLEAN'
        
        summary['risk_level'] = risk_level
        self.results['risk_level'] = risk_level
        self.results['summary'] = summary
    
    def _generate_pdf_compatible_structures(self):
        """Generate additional data structures for PDF compatibility"""
        # 1. Generate taint flows (combine sources with potential sinks)
        self._generate_taint_flows()
        
        # 2. Generate structured quality analysis
        self._generate_quality_analysis()
        
        # 3. Generate structured antipattern analysis
        self._generate_antipattern_analysis()
        
        # 4. Generate file tree
        self._generate_file_tree()
        
        # 5. Generate unified findings table
        self._generate_unified_findings()
        
        # 6. Generate recommendations
        self._generate_recommendations()
        
        # 7. Set framework aliases for compatibility
        self.results['framework_security'] = self.results.get('framework_issues', [])
        self.results['framework_security_findings'] = self.results.get('framework_issues', [])
    
    def _generate_taint_flows(self):
        """Generate taint flow paths from taint sources"""
        taint_flows = []
        
        # Group dangerous functions by file to find potential sinks
        sinks_by_file = defaultdict(list)
        for func in self.results.get('dangerous_functions', []):
            if func.get('category') in ['sql_injection', 'command_injection', 'code_injection']:
                sinks_by_file[func.get('file')].append(func)
        
        # Create flows from sources to sinks in the same file
        for source in self.results.get('taint_analysis', []):
            source_file = source.get('file')
            if source_file in sinks_by_file:
                for sink in sinks_by_file[source_file]:
                    flow = {
                        'source': source.get('source', 'unknown'),
                        'sink': sink.get('function', 'unknown'),
                        'flow_path': [source.get('source'), 'processing', sink.get('function')],
                        'file': source_file,
                        'line_start': source.get('line', 0),
                        'line_end': sink.get('line', 0),
                        'severity': 'HIGH' if sink.get('severity') == 'CRITICAL' else 'MEDIUM'
                    }
                    taint_flows.append(flow)
        
        self.results['taint_flows'] = taint_flows
    
    def _generate_quality_analysis(self):
        """Structure quality data for PDF"""
        quality_issues = self.results.get('quality_issues', {})
        
        self.results['quality_analysis'] = {
            'findings': quality_issues,
            'summary': {
                'total_issues': sum(len(v) for v in quality_issues.values()),
                'total_empty_catch': len(quality_issues.get('empty_catch_blocks', [])),
                'total_infinite_loops': len(quality_issues.get('infinite_loops', [])),
                'total_dead_code': len(quality_issues.get('dead_code', [])),
                'total_naming_issues': len(quality_issues.get('inconsistent_naming', []))
            }
        }
    
    def _generate_antipattern_analysis(self):
        """Structure antipattern data for PDF"""
        antipatterns = self.results.get('antipatterns', {})
        
        self.results['antipattern_analysis'] = {
            'findings': antipatterns,
            'summary': {
                'total_issues': sum(len(v) for v in antipatterns.values()),
                'password_variables': len(antipatterns.get('password_variables', [])),
                'sql_concatenation': len(antipatterns.get('sql_concatenation', [])),
                'api_without_timeout': len(antipatterns.get('api_without_timeout', [])),
                'unsafe_file_paths': len(antipatterns.get('unsafe_file_paths', []))
            }
        }
    
    def _generate_file_tree(self):
        """Generate hierarchical file tree structure"""
        file_tree = {}
        
        for file_info in self.results.get('files_scanned', []):
            file_path = file_info.get('path', '')
            
            # Count issues per file
            issue_count = 0
            max_severity = 'LOW'
            
            for finding in self.results.get('dangerous_functions', []):
                if finding.get('file') == file_path:
                    issue_count += 1
                    if finding.get('severity') in ['CRITICAL', 'HIGH']:
                        max_severity = 'HIGH'
            
            for finding in self.results.get('secrets', []):
                if finding.get('file') == file_path:
                    issue_count += 1
                    max_severity = 'CRITICAL'
            
            # Build tree structure
            parts = file_path.replace('\\', '/').split('/')
            current = file_tree
            
            for i, part in enumerate(parts):
                if part not in current:
                    is_file = i == len(parts) - 1
                    current[part] = {
                        'name': part,
                        'path': '/'.join(parts[:i+1]),
                        'is_file': is_file,
                        'children': {} if not is_file else None,
                        'issue_count': issue_count if is_file else 0,
                        'severity': max_severity if is_file else 'LOW'
                    }
                current = current[part].get('children', {}) if not current[part]['is_file'] else current
        
        self.results['file_tree'] = file_tree
    
    def _generate_unified_findings(self):
        """Generate deduplicated unified findings table"""
        unified = []
        seen = set()
        finding_id = 1
        
        # Add dangerous functions
        for item in self.results.get('dangerous_functions', []):
            key = f"{item.get('file')}:{item.get('line')}:{item.get('function')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'DF-{finding_id:04d}',
                    'category': 'Dangerous Function',
                    'vulnerability': item.get('function', 'unknown'),
                    'file': item.get('file', 'unknown'),
                    'line': item.get('line', 0),
                    'severity': item.get('severity', 'MEDIUM'),
                    'description': item.get('context', ''),
                    'type': item.get('category', 'unknown')
                })
                finding_id += 1
        
        # Add secrets
        for item in self.results.get('secrets', []):
            key = f"{item.get('file')}:{item.get('line')}:{item.get('type')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'SEC-{finding_id:04d}',
                    'category': 'Hardcoded Secret',
                    'vulnerability': item.get('type', 'unknown'),
                    'file': item.get('file', 'unknown'),
                    'line': item.get('line', 0),
                    'severity': 'CRITICAL',
                    'description': item.get('context', ''),
                    'type': item.get('type', 'unknown')
                })
                finding_id += 1
        
        # Add validation issues
        for item in self.results.get('validation_issues', []):
            key = f"{item.get('file', item.get('filepath', ''))}:{item.get('line')}:{item.get('type')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'VAL-{finding_id:04d}',
                    'category': 'Validation Issue',
                    'vulnerability': item.get('type', 'unknown'),
                    'file': item.get('file', item.get('filepath', 'unknown')),
                    'line': item.get('line', 0),
                    'severity': item.get('severity', 'MEDIUM'),
                    'description': item.get('message', ''),
                    'recommendation': item.get('recommendation', ''),
                    'type': item.get('type', 'unknown')
                })
                finding_id += 1
        
        # Add crypto issues
        for item in self.results.get('crypto_issues', []):
            key = f"{item.get('file', item.get('filepath', ''))}:{item.get('line')}:{item.get('type')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'CRY-{finding_id:04d}',
                    'category': 'Cryptography',
                    'vulnerability': item.get('type', 'unknown'),
                    'file': item.get('file', item.get('filepath', 'unknown')),
                    'line': item.get('line', 0),
                    'severity': item.get('severity', 'HIGH'),
                    'description': item.get('message', ''),
                    'recommendation': item.get('recommendation', ''),
                    'type': item.get('type', 'unknown')
                })
                finding_id += 1
        
        # Add auth issues
        for item in self.results.get('auth_issues', []):
            key = f"{item.get('file', item.get('filepath', ''))}:{item.get('line')}:{item.get('type')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'AUTH-{finding_id:04d}',
                    'category': 'Authentication',
                    'vulnerability': item.get('type', 'unknown'),
                    'file': item.get('file', item.get('filepath', 'unknown')),
                    'line': item.get('line', 0),
                    'severity': item.get('severity', 'HIGH'),
                    'description': item.get('message', ''),
                    'type': item.get('type', 'unknown')
                })
                finding_id += 1
        
        # Add framework issues
        for item in self.results.get('framework_issues', []):
            key = f"{item.get('file', item.get('filepath', ''))}:{item.get('line')}:{item.get('type')}"
            if key not in seen:
                seen.add(key)
                unified.append({
                    'id': f'FW-{finding_id:04d}',
                    'category': 'Framework Security',
                    'vulnerability': item.get('type', 'unknown'),
                    'file': item.get('file', item.get('filepath', 'unknown')),
                    'line': item.get('line', 0),
                    'severity': item.get('severity', 'MEDIUM'),
                    'description': item.get('message', ''),
                    'recommendation': item.get('recommendation', ''),
                    'type': item.get('type', 'unknown'),
                    'framework': item.get('framework', 'unknown')
                })
                finding_id += 1
        
        self.results['unified_findings'] = unified
    
    def _generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Recommendations based on secrets found
        if self.results.get('secrets', []):
            recommendations.append({
                'category': 'Secret Management',
                'priority': 'CRITICAL',
                'title': 'Remove Hardcoded Secrets',
                'description': 'Move all hardcoded credentials to environment variables or secure vaults.',
                'steps': [
                    'Use environment variables for sensitive configuration',
                    'Implement secrets management (e.g., AWS Secrets Manager, HashiCorp Vault)',
                    'Add .env files to .gitignore',
                    'Rotate all exposed credentials immediately'
                ]
            })
        
        # Recommendations based on dangerous functions
        if self.results.get('dangerous_functions', []):
            recommendations.append({
                'category': 'Code Security',
                'priority': 'HIGH',
                'title': 'Replace Dangerous Functions',
                'description': 'Replace or properly sanitize dangerous function calls.',
                'steps': [
                    'Review all uses of eval(), exec(), and similar functions',
                    'Implement input validation and sanitization',
                    'Use safe alternatives when available',
                    'Apply principle of least privilege'
                ]
            })
        
        # Recommendations based on crypto issues
        if self.results.get('crypto_issues', []):
            recommendations.append({
                'category': 'Cryptography',
                'priority': 'HIGH',
                'title': 'Update Cryptographic Implementations',
                'description': 'Replace weak or broken cryptographic algorithms.',
                'steps': [
                    'Use SHA-256 or stronger for hashing',
                    'Use AES-256-GCM for encryption',
                    'Generate random IVs for each encryption',
                    'Use crypto-secure random generators'
                ]
            })
        
        # Recommendations based on vulnerabilities
        vuln_scan = self.results.get('vulnerability_scan', {})
        if vuln_scan.get('total_vulnerabilities', 0) > 0:
            recommendations.append({
                'category': 'Dependencies',
                'priority': 'HIGH',
                'title': 'Update Vulnerable Dependencies',
                'description': f'Found {vuln_scan.get("total_vulnerabilities")} vulnerabilities in dependencies.',
                'steps': [
                    'Run: pip install --upgrade (package names)',
                    'Review breaking changes in changelogs',
                    'Test thoroughly after updates',
                    'Consider using automated dependency scanning'
                ]
            })
        
        self.results['recommendations'] = recommendations
    
    def save_json(self, output_path: str = None):
        """Save results as JSON"""
        if output_path is None:
            output_dir = os.path.join(os.path.dirname(__file__), "output")
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, "comprehensive_analysis.json")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 JSON Report Saved: {output_path}")
        return output_path
    
    def generate_pdf(self, output_path: str = None):
        """Generate comprehensive PDF report with ALL features"""
        if not PDF_AVAILABLE:
            print("\n⚠️  PDF generation not available. Install: pip install reportlab matplotlib")
            return None
        
        if output_path is None:
            output_dir = os.path.join(os.path.dirname(__file__), "output")
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, "comprehensive_analysis.pdf")
        
        try:
            # Prepare data in format expected by full PDF generator
            summary = self.results.get('summary', {})
            
            # Build risk assessment with proper structure
            risk_assessment = {
                'risk_level': self.results.get('risk_level', 'UNKNOWN'),
                'total_findings': summary.get('total_issues', 0),
                'critical': summary.get('secrets_count', 0),
                'high': summary.get('dangerous_functions_count', 0) + summary.get('auth_issues_count', 0),
                'medium': summary.get('validation_issues_count', 0) + summary.get('framework_issues_count', 0),
                'low': summary.get('quality_issues_count', 0) + summary.get('antipattern_count', 0)
            }
            
            # Detect languages from files scanned
            languages = set()
            for file_info in self.results.get('files_scanned', []):
                lang = file_info.get('language', 'unknown')
                if lang and lang != 'unknown':
                    languages.add(lang)
            
            # Build security_analysis dictionary organized by file AND flat lists
            security_analysis_by_file = {}
            
            # Process all findings and organize by file
            for finding in self.results.get('dangerous_functions', []):
                file_path = finding.get('file', 'unknown')
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['dangerous_functions'].append(finding)
            
            for finding in self.results.get('secrets', []):
                file_path = finding.get('file', 'unknown')
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['secrets'].append(finding)
            
            for finding in self.results.get('taint_analysis', []):
                file_path = finding.get('file', 'unknown')
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['taint_sources'].append(finding)
            
            for finding in self.results.get('validation_issues', []):
                file_path = finding.get('file', finding.get('filepath', 'unknown'))
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['validation'].append(finding)
            
            for finding in self.results.get('crypto_issues', []):
                file_path = finding.get('file', finding.get('filepath', 'unknown'))
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['cryptography'].append(finding)
            
            for finding in self.results.get('auth_issues', []):
                file_path = finding.get('file', finding.get('filepath', 'unknown'))
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['authentication'].append(finding)
            
            for finding in self.results.get('framework_issues', []):
                file_path = finding.get('file', finding.get('filepath', 'unknown'))
                if file_path not in security_analysis_by_file:
                    security_analysis_by_file[file_path] = {
                        'dangerous_functions': [],
                        'secrets': [],
                        'taint_sources': [],
                        'validation': [],
                        'cryptography': [],
                        'authentication': [],
                        'framework_security': []
                    }
                security_analysis_by_file[file_path]['framework_security'].append(finding)
            
            # Format quality analysis data properly
            quality_issues = self.results.get('quality_issues', {})
            quality_data = {
                'findings': quality_issues if quality_issues else {},
                'summary': {
                    'total_issues': sum(len(v) for v in quality_issues.values()) if quality_issues else 0,
                    'total_empty_catch': len(quality_issues.get('empty_catch_blocks', [])) if quality_issues else 0,
                    'total_infinite_loops': len(quality_issues.get('infinite_loops', [])) if quality_issues else 0,
                    'total_dead_code': len(quality_issues.get('dead_code', [])) if quality_issues else 0,
                    'total_naming_issues': len(quality_issues.get('inconsistent_naming', [])) if quality_issues else 0
                }
            }
            
            # Format antipattern analysis data properly
            antipatterns = self.results.get('antipatterns', {})
            antipattern_data = {
                'findings': antipatterns if antipatterns else {},
                'summary': {
                    'total_issues': sum(len(v) for v in antipatterns.values()) if antipatterns else 0,
                    'password_variables': len(antipatterns.get('password_variables', [])) if antipatterns else 0,
                    'sql_concatenation': len(antipatterns.get('sql_concatenation', [])) if antipatterns else 0,
                    'api_without_timeout': len(antipatterns.get('api_without_timeout', [])) if antipatterns else 0,
                    'unsafe_file_paths': len(antipatterns.get('unsafe_file_paths', [])) if antipatterns else 0
                }
            }
            
            # Prepare complete PDF data structure with all sections
            pdf_data = {
                'project_name': os.path.basename(self.project_path),
                'project_path': self.project_path,
                'scan_time': self.results['metadata']['scan_time'],
                'risk_assessment': risk_assessment,
                'project_languages': list(languages) if languages else ['Multiple'],
                'security_analysis': security_analysis_by_file,
                # Also include flat lists for sections that need them
                'dangerous_functions': self.results.get('dangerous_functions', []),
                'secrets': self.results.get('secrets', []),
                'taint_flows': self.results.get('taint_analysis', []),
                'validation': self.results.get('validation_issues', []),
                'cryptography': self.results.get('crypto_issues', []),
                'authentication': self.results.get('auth_issues', []),
                'framework_security': self.results.get('framework_issues', []),
                'framework_security_findings': self.results.get('framework_issues', []),  # Alternative key
                'quality_analysis': quality_data,
                'antipatterns': antipatterns,
                'antipattern_analysis': antipattern_data,  # Properly formatted
                'vulnerability_scan': self.results.get('vulnerability_scan', {}),  # NEW: Dependency vulnerabilities
                'files_scanned': self.results.get('files_scanned', []),
                'summary': summary
            }
            
            # Debug: Print data being passed
            print(f"\n📊 PDF Data Summary:")
            print(f"   - Auth Issues: {len(pdf_data.get('authentication', []))}")
            print(f"   - Framework Issues: {len(pdf_data.get('framework_security_findings', []))}")
            print(f"   - Quality Data: {'findings' in pdf_data.get('quality_analysis', {})}")
            print(f"   - Antipattern Data: {type(pdf_data.get('antipattern_analysis', {}))}")
            vuln_scan = pdf_data.get('vulnerability_scan', {})
            vuln_count = vuln_scan.get('summary', {}).get('total_vulnerabilities', 0)
            print(f"   - Vulnerability Scan: {vuln_count} vulnerabilities")
            
            # Generate PDF using full-featured generator
            report = SecurityReportPDF(filename=output_path)
            report.generate(pdf_data, project_name=os.path.basename(self.project_path))
            
            print(f"\n📄 PDF Report Saved: {output_path}")
            print(f"    ✅ Complete report with charts, visualizations, and all findings!")
            return output_path
            
        except Exception as e:
            print(f"\n⚠️  PDF generation error: {e}")
            import traceback
            traceback.print_exc()
            print("\n💡 Tip: Make sure reportlab and matplotlib are installed")
            return None
    
    def print_summary(self):
        """Print beautiful summary to console"""
        summary = self.results['summary']
        
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"\n🎯 Risk Level: {self.results['risk_level']}")
        print(f"📂 Files Scanned: {summary['files_scanned']}")
        print(f"⚠️  Total Issues: {summary['total_issues']}")
        
        print("\n" + "-" * 80)
        print("SECURITY FINDINGS:")
        print("-" * 80)
        print(f"  🔴 Dangerous Functions:     {summary['dangerous_functions_count']:>6}")
        print(f"  🔑 Secrets Found:           {summary['secrets_count']:>6}")
        print(f"  🌊 Taint Sources:           {summary['taint_sources_count']:>6}")
        print(f"  🛡️  Validation Issues:       {summary['validation_issues_count']:>6}")
        print(f"  🔐 Crypto Issues:           {summary['crypto_issues_count']:>6}")
        print(f"  🔑 Auth Issues:             {summary['auth_issues_count']:>6}")
        print(f"  🏗️  Framework Issues:        {summary['framework_issues_count']:>6}")
        
        print("\n" + "-" * 80)
        print("CODE QUALITY:")
        print("-" * 80)
        print(f"  ✨ Quality Issues:          {summary['quality_issues_count']:>6}")
        print(f"  ⚠️  Anti-Patterns:           {summary['antipattern_count']:>6}")
        
        print("\n" + "-" * 80)
        print("DEPENDENCY VULNERABILITIES:")
        print("-" * 80)
        print(f"  🔍 Known Vulnerabilities:   {summary['vulnerability_count']:>6}")
        
        print("\n" + "=" * 80)
        
        # Top issues breakdown
        if self.results.get('dangerous_functions'):
            print("\n🔴 TOP DANGEROUS FUNCTIONS:")
            func_count = defaultdict(int)
            for finding in self.results['dangerous_functions'][:20]:
                func = finding.get('function', 'unknown')
                func_count[func] += 1
            
            for func, count in sorted(func_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   • {func}: {count} occurrence(s)")
        
        if self.results.get('secrets'):
            print("\n🔑 SECRETS DETECTED:")
            for secret in self.results['secrets'][:5]:
                print(f"   • {secret.get('type', 'Unknown')} in {os.path.basename(secret.get('file', 'unknown'))}")
        
        print("\n" + "=" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🔥 Comprehensive Security & Quality Analyzer - ALL CHECKS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python comprehensive_analyzer.py test_project -pdf
  python comprehensive_analyzer.py test_project -json
  python comprehensive_analyzer.py test_project -both
  python comprehensive_analyzer.py test_project  (default: both)
        """
    )
    
    parser.add_argument('project_path', help='Path to project directory to analyze')
    parser.add_argument('-pdf', '--pdf-only', action='store_true', help='Generate PDF report only')
    parser.add_argument('-json', '--json-only', action='store_true', help='Generate JSON report only')
    parser.add_argument('-both', '--both', action='store_true', help='Generate both PDF and JSON (default)')
    parser.add_argument('-o', '--output', help='Custom output path (without extension)')
    
    args = parser.parse_args()
    
    # Determine output format
    if args.pdf_only:
        output_format = 'pdf'
    elif args.json_only:
        output_format = 'json'
    else:
        output_format = 'both'  # Default
    
    # Run analysis
    analyzer = ComprehensiveAnalyzer(args.project_path)
    results = analyzer.analyze_all()
    
    # Print summary
    analyzer.print_summary()
    
    # Generate outputs
    if output_format in ['json', 'both']:
        json_path = f"{args.output}.json" if args.output else None
        analyzer.save_json(json_path)
    
    if output_format in ['pdf', 'both']:
        pdf_path = f"{args.output}.pdf" if args.output else None
        analyzer.generate_pdf(pdf_path)
    
    print("\n✅ All Done!")
    print("=" * 80)


if __name__ == "__main__":
    main()

