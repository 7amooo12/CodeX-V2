"""
Demo script showing how to integrate Quality Analyzer with PDF Report Generator
"""

import os
from quality_analyzer import analyze_quality

def generate_quality_report_demo(directory_path="."):
    """
    Generate a complete report with quality analysis included
    
    This function demonstrates how to integrate quality_analyzer with
    your existing security report generation pipeline.
    """
    
    print("=" * 70)
    print("COMPREHENSIVE CODE ANALYSIS - SECURITY + QUALITY")
    print("=" * 70)
    
    # ========================================
    # STEP 1: Run Quality Analysis
    # ========================================
    print("\n[1/3] Running Code Quality Analysis...")
    quality_results = analyze_quality(directory_path)
    
    # ========================================
    # STEP 2: Prepare Analysis Results
    # ========================================
    print("\n[2/3] Preparing analysis results...")
    
    # This is where you would typically combine your existing security analysis
    # with the new quality analysis
    analysis_result = {
        # Your existing security analysis results
        'security_analysis': {},  # Would be populated from your security analyzer
        'risk_assessment': {
            'risk_level': 'MEDIUM',
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'project_languages': [],
        'taint_flows': [],
        'framework_security_findings': [],
        
        # NEW: Quality analysis results
        'quality_analysis': quality_results
    }
    
    # ========================================
    # STEP 3: Generate PDF Report
    # ========================================
    print("\n[3/3] Generating PDF report...")
    
    try:
        from pdf_report_generator import SecurityReportPDF
        
        report = SecurityReportPDF(filename="quality_analysis_report.pdf")
        output_file = report.generate(analysis_result, project_name=os.path.basename(os.path.abspath(directory_path)))
        
        print(f"\n✓ Report generated successfully: {output_file}")
        print(f"\n{'=' * 70}")
        print("SUMMARY")
        print('=' * 70)
        
        # Print summary
        summary = quality_results.get('summary', {})
        print(f"\nTotal Quality Issues: {summary.get('total_issues', 0)}")
        print(f"  • Empty Catch Blocks: {summary.get('total_empty_catch', 0)}")
        print(f"  • Infinite Loops: {summary.get('total_infinite_loops', 0)}")
        print(f"  • Dead Code: {summary.get('total_dead_code', 0)}")
        print(f"  • Naming Issues: {summary.get('total_naming_issues', 0)}")
        
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
        print("QUALITY ANALYSIS RESULTS (Console Output)")
        print('=' * 70)
        
        findings = quality_results['findings']
        
        # Empty catch blocks
        if findings.get('empty_catch_blocks'):
            print(f"\n[EMPTY CATCH] ({len(findings['empty_catch_blocks'])} found):")
            for i, finding in enumerate(findings['empty_catch_blocks'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['code_snippet']}")
            if len(findings['empty_catch_blocks']) > 5:
                print(f"  ... and {len(findings['empty_catch_blocks']) - 5} more")
        
        # Infinite loops
        if findings.get('infinite_loops'):
            print(f"\n[INFINITE LOOPS] ({len(findings['infinite_loops'])} found):")
            for i, finding in enumerate(findings['infinite_loops'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['code_snippet']}")
            if len(findings['infinite_loops']) > 5:
                print(f"  ... and {len(findings['infinite_loops']) - 5} more")
        
        # Dead code
        if findings.get('dead_code'):
            print(f"\n[DEAD CODE] ({len(findings['dead_code'])} found):")
            for i, finding in enumerate(findings['dead_code'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['type']}")
            if len(findings['dead_code']) > 5:
                print(f"  ... and {len(findings['dead_code']) - 5} more")
        
        # Naming issues
        if findings.get('inconsistent_naming'):
            print(f"\n[NAMING ISSUES] ({len(findings['inconsistent_naming'])} found):")
            for i, finding in enumerate(findings['inconsistent_naming'][:5], 1):
                print(f"  {i}. {finding['file']}:{finding['line']} - {finding['identifier']} "
                      f"({finding['actual_convention']} -> {finding['expected_convention']})")
            if len(findings['inconsistent_naming']) > 5:
                print(f"  ... and {len(findings['inconsistent_naming']) - 5} more")


def integrate_with_existing_analyzer():
    """
    Example of how to integrate quality analyzer with your existing security analyzer
    """
    print("\n" + "=" * 70)
    print("INTEGRATION EXAMPLE")
    print("=" * 70)
    
    code_example = '''
# In your main security analysis script, add:

from quality_analyzer import analyze_quality

# After your security analysis:
security_results = run_security_analysis(".")

# Run quality analysis:
quality_results = analyze_quality(".")

# Combine results:
combined_results = {
    'security_analysis': security_results.get('security_analysis', {}),
    'risk_assessment': security_results.get('risk_assessment', {}),
    'taint_flows': security_results.get('taint_flows', []),
    'framework_security_findings': security_results.get('framework_security_findings', []),
    'project_languages': security_results.get('project_languages', []),
    
    # Add quality analysis
    'quality_analysis': quality_results
}

# Generate PDF with both security and quality findings:
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
    generate_quality_report_demo(directory)
    
    # Show integration example
    integrate_with_existing_analyzer()

