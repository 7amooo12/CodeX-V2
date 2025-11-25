"""
Complete Analysis Runner - Integrates All Analyzers
Runs security, quality, and anti-pattern analysis, then generates comprehensive PDF report
"""

import os
import sys


def run_complete_analysis(directory_path="."):
    """
    Run all analyses and generate comprehensive PDF report
    """
    
    print("=" * 80)
    print("COMPREHENSIVE CODE ANALYSIS - COMPLETE SUITE")
    print("=" * 80)
    print(f"\nTarget Directory: {os.path.abspath(directory_path)}")
    print(f"\nThis will run:")
    print("  1. Quality Analysis (Empty Catch, Infinite Loops, Dead Code, Naming)")
    print("  2. Anti-Pattern Detection (Passwords, SQL Injection, API Timeout, etc.)")
    print("  3. Generate comprehensive PDF report")
    print()
    
    # ========================================
    # STEP 1: Run Quality Analysis
    # ========================================
    print("\n" + "=" * 80)
    print("[1/3] RUNNING QUALITY ANALYSIS")
    print("=" * 80)
    
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from analyzers.quality_analyzer import analyze_quality
        quality_results = analyze_quality(directory_path)
        print(f"\n[+] Quality Analysis Complete: {quality_results['summary']['total_issues']} issues found")
    except ImportError as e:
        print(f"\n[!] Warning: Quality analyzer not available: {e}")
        quality_results = None
    except Exception as e:
        print(f"\n[!] Error during quality analysis: {e}")
        quality_results = None
    
    # ========================================
    # STEP 2: Run Anti-Pattern Detection
    # ========================================
    print("\n" + "=" * 80)
    print("[2/3] RUNNING ANTI-PATTERN DETECTION")
    print("=" * 80)
    
    try:
        from analyzers.antipattern_detector import detect_antipatterns
        antipattern_results = detect_antipatterns(directory_path)
        print(f"\n[+] Anti-Pattern Detection Complete: {antipattern_results['summary']['total_issues']} issues found")
    except ImportError as e:
        print(f"\n[!] Warning: Anti-pattern detector not available: {e}")
        antipattern_results = None
    except Exception as e:
        print(f"\n[!] Error during anti-pattern detection: {e}")
        antipattern_results = None
    
    # ========================================
    # STEP 3: Generate PDF Report
    # ========================================
    print("\n" + "=" * 80)
    print("[3/3] GENERATING COMPREHENSIVE PDF REPORT")
    print("=" * 80)
    
    # Prepare combined results
    combined_results = {
        # Security analysis placeholders (can be filled by your security analyzer)
        'security_analysis': {},
        'risk_assessment': {
            'risk_level': 'MEDIUM',
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'project_languages': ['python', 'javascript'],
        'taint_flows': [],
        'framework_security_findings': [],
        
        # Quality analysis results
        'quality_analysis': quality_results if quality_results else {},
        
        # Anti-pattern analysis results
        'antipattern_analysis': antipattern_results if antipattern_results else {}
    }
    
    try:
        from reports.pdf_report_generator import SecurityReportPDF
        
        output_filename = "complete_code_analysis_report.pdf"
        report = SecurityReportPDF(filename=output_filename)
        
        project_name = os.path.basename(os.path.abspath(directory_path))
        output_file = report.generate(combined_results, project_name=project_name)
        
        print(f"\n[+] PDF Report Generated Successfully!")
        print(f"\n    Output File: {output_file}")
        print(f"    Location: {os.path.abspath(output_file)}")
        
    except ImportError as e:
        print(f"\n[!] Error: Could not import PDF report generator: {e}")
        print("[!] Make sure reportlab is installed: pip install reportlab matplotlib")
        return False
    except Exception as e:
        print(f"\n[!] Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # ========================================
    # SUMMARY
    # ========================================
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    
    # Quality Analysis Summary
    if quality_results:
        print("\n[QUALITY ANALYSIS]")
        summary = quality_results.get('summary', {})
        print(f"  Total Issues: {summary.get('total_issues', 0)}")
        print(f"    - Empty Catch Blocks: {summary.get('total_empty_catch', 0)}")
        print(f"    - Infinite Loops: {summary.get('total_infinite_loops', 0)}")
        print(f"    - Dead Code: {summary.get('total_dead_code', 0)}")
        print(f"    - Naming Issues: {summary.get('total_naming_issues', 0)}")
    else:
        print("\n[QUALITY ANALYSIS] Not performed")
    
    # Anti-Pattern Summary
    if antipattern_results:
        print("\n[ANTI-PATTERN DETECTION]")
        summary = antipattern_results.get('summary', {})
        print(f"  Total Issues: {summary.get('total_issues', 0)}")
        print(f"    - Password Variables: {summary.get('total_password_vars', 0)}")
        print(f"    - SQL Concatenation: {summary.get('total_sql_concat', 0)}")
        print(f"    - API Without Timeout: {summary.get('total_api_timeout', 0)}")
        print(f"    - Unsafe File Paths: {summary.get('total_unsafe_paths', 0)}")
        print(f"    - Dead Code: {summary.get('total_dead_code', 0)}")
        print(f"    - Env Issues: {summary.get('total_env_issues', 0)}")
    else:
        print("\n[ANTI-PATTERN DETECTION] Not performed")
    
    # Combined Statistics
    total_all_issues = 0
    if quality_results:
        total_all_issues += quality_results.get('summary', {}).get('total_issues', 0)
    if antipattern_results:
        total_all_issues += antipattern_results.get('summary', {}).get('total_issues', 0)
    
    print(f"\n[COMBINED STATISTICS]")
    print(f"  Total Issues Found: {total_all_issues}")
    print(f"  PDF Report: {output_filename}")
    
    print("\n" + "=" * 80)
    print("[SUCCESS] ANALYSIS COMPLETE!")
    print("=" * 80)
    print(f"\nOpen the report: {output_filename}")
    print()
    
    return True


def show_usage():
    """Show usage information"""
    print("""
Usage: python run_complete_analysis.py [directory]

Arguments:
  directory    Optional. Directory to analyze. Defaults to current directory.

Examples:
  python run_complete_analysis.py              # Analyze current directory
  python run_complete_analysis.py .            # Analyze current directory
  python run_complete_analysis.py ./src        # Analyze src directory
  python run_complete_analysis.py C:\\Project   # Analyze specific path

What it does:
  1. Runs quality analysis (code quality issues)
  2. Runs anti-pattern detection (security anti-patterns)
  3. Generates comprehensive PDF report with all findings

Output:
  - complete_code_analysis_report.pdf
    """)


if __name__ == "__main__":
    # Check for help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_usage()
        sys.exit(0)
    
    # Get directory from command line or use current directory
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    
    # Verify directory exists
    if not os.path.exists(directory):
        print(f"[!] Error: Directory not found: {directory}")
        sys.exit(1)
    
    # Run complete analysis
    success = run_complete_analysis(directory)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

