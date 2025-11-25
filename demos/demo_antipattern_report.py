"""
Demo script for Anti-Pattern Detector integrated with PDF Report
"""

import os
from antipattern_detector import detect_antipatterns


def generate_antipattern_report_demo(directory_path="."):
    """
    Generate a complete report with anti-pattern detection included
    """
    
    print("=" * 70)
    print("ANTI-PATTERN & SECURITY ISSUES DETECTION")
    print("=" * 70)
    
    # ========================================
    # STEP 1: Run Anti-Pattern Detection
    # ========================================
    print("\n[1/3] Running Anti-Pattern Detection...")
    antipattern_results = detect_antipatterns(directory_path)
    
    # ========================================
    # STEP 2: Prepare Analysis Results
    # ========================================
    print("\n[2/3] Preparing analysis results...")
    
    # This is where you would combine with your existing security analysis
    analysis_result = {
        # Your existing security analysis results
        'security_analysis': {},
        'risk_assessment': {
            'risk_level': 'HIGH',
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'project_languages': [],
        'taint_flows': [],
        'framework_security_findings': [],
        'quality_analysis': {},
        
        # NEW: Anti-pattern analysis results
        'antipattern_analysis': antipattern_results
    }
    
    # ========================================
    # STEP 3: Generate PDF Report
    # ========================================
    print("\n[3/3] Generating PDF report...")
    
    try:
        from pdf_report_generator import SecurityReportPDF
        
        report = SecurityReportPDF(filename="antipattern_analysis_report.pdf")
        output_file = report.generate(analysis_result, project_name=os.path.basename(os.path.abspath(directory_path)))
        
        print(f"\n[+] Report generated successfully: {output_file}")
        print(f"\n{'=' * 70}")
        print("SUMMARY")
        print('=' * 70)
        
        # Print summary
        summary = antipattern_results.get('summary', {})
        print(f"\nTotal Anti-Pattern Issues: {summary.get('total_issues', 0)}")
        print(f"  • Password Variables: {summary.get('total_password_vars', 0)}")
        print(f"  • SQL Concatenation: {summary.get('total_sql_concat', 0)}")
        print(f"  • API Without Timeout: {summary.get('total_api_timeout', 0)}")
        print(f"  • Unsafe File Paths: {summary.get('total_unsafe_paths', 0)}")
        print(f"  • Dead Code: {summary.get('total_dead_code', 0)}")
        print(f"  • Env Issues: {summary.get('total_env_issues', 0)}")
        
        if summary.get('issues_by_severity'):
            print(f"\nBy Severity:")
            for severity, count in sorted(summary['issues_by_severity'].items(), key=lambda x: x[1], reverse=True):
                print(f"  • {severity.upper()}: {count}")
        
        print(f"\n{'=' * 70}")
        
    except ImportError as e:
        print(f"\n[!] Error: Could not import pdf_report_generator: {e}")
        print("[!] Make sure reportlab is installed: pip install reportlab matplotlib")
        
        # Still show results in console
        print(f"\n{'=' * 70}")
        print("ANTI-PATTERN RESULTS (Console Output)")
        print('=' * 70)
        
        findings = antipattern_results['findings']
        
        # Password variables
        if findings.get('password_variables'):
            print(f"\n[CRITICAL] PASSWORD VARIABLES ({len(findings['password_variables'])} found):")
            for i, finding in enumerate(findings['password_variables'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
            if len(findings['password_variables']) > 5:
                print(f"  ... and {len(findings['password_variables']) - 5} more")
        
        # SQL concatenation
        if findings.get('sql_concatenation'):
            print(f"\n[CRITICAL] SQL INJECTION RISKS ({len(findings['sql_concatenation'])} found):")
            for i, finding in enumerate(findings['sql_concatenation'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
            if len(findings['sql_concatenation']) > 5:
                print(f"  ... and {len(findings['sql_concatenation']) - 5} more")
        
        # API without timeout
        if findings.get('api_without_timeout'):
            print(f"\n[MEDIUM] API WITHOUT TIMEOUT ({len(findings['api_without_timeout'])} found):")
            for i, finding in enumerate(findings['api_without_timeout'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
            if len(findings['api_without_timeout']) > 5:
                print(f"  ... and {len(findings['api_without_timeout']) - 5} more")
        
        # Unsafe file paths
        if findings.get('unsafe_file_paths'):
            print(f"\n[HIGH] UNSAFE FILE PATHS ({len(findings['unsafe_file_paths'])} found):")
            for i, finding in enumerate(findings['unsafe_file_paths'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['message']}")
            if len(findings['unsafe_file_paths']) > 5:
                print(f"  ... and {len(findings['unsafe_file_paths']) - 5} more")


def integration_example():
    """
    Example of how to integrate anti-pattern detector with existing analyzers
    """
    print("\n" + "=" * 70)
    print("INTEGRATION EXAMPLE")
    print("=" * 70)
    
    code_example = '''
# In your main security analysis script, add:

from antipattern_detector import detect_antipatterns

# After your security and quality analysis:
security_results = run_security_analysis(".")
quality_results = analyze_quality(".")

# Run anti-pattern detection:
antipattern_results = detect_antipatterns(".")

# Combine all results:
combined_results = {
    'security_analysis': security_results.get('security_analysis', {}),
    'risk_assessment': security_results.get('risk_assessment', {}),
    'taint_flows': security_results.get('taint_flows', []),
    'framework_security_findings': security_results.get('framework_security_findings', []),
    'project_languages': security_results.get('project_languages', []),
    
    # Add quality analysis
    'quality_analysis': quality_results,
    
    # Add anti-pattern analysis
    'antipattern_analysis': antipattern_results
}

# Generate comprehensive PDF with all findings:
from pdf_report_generator import SecurityReportPDF

report = SecurityReportPDF("complete_analysis_report.pdf")
report.generate(combined_results, project_name="Your Project")
    '''
    
    print(code_example)
    print("=" * 70)


if __name__ == "__main__":
    import sys
    
    # Get directory from command line or use current directory
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    
    # Run demo
    generate_antipattern_report_demo(directory)
    
    # Show integration example
    integration_example()


