#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone Vulnerability Scanner

Scans project dependencies for known security vulnerabilities
using OSV, NVD, and GitHub Security Advisories.

Usage:
    python scan_vulnerabilities.py <project_path> [--nvd] [--github] [--output json/console]
    
Examples:
    python scan_vulnerabilities.py .
    python scan_vulnerabilities.py test_project --nvd
    python scan_vulnerabilities.py my_project --github --output json
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vulnerability_scanner import VulnerabilityScanner


def main():
    parser = argparse.ArgumentParser(
        description='Scan project dependencies for security vulnerabilities'
    )
    parser.add_argument(
        'project_path',
        help='Path to project directory'
    )
    parser.add_argument(
        '--nvd',
        action='store_true',
        help='Enable NVD API queries (slower, requires API key for best performance)'
    )
    parser.add_argument(
        '--github',
        action='store_true',
        help='Enable GitHub Security Advisories (requires GITHUB_TOKEN env var)'
    )
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'both'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--output-file',
        default=None,
        help='JSON output file path (default: vulnerability_scan_TIMESTAMP.json)'
    )
    
    args = parser.parse_args()
    
    # Validate project path
    if not os.path.exists(args.project_path):
        print(f"Error: Project path does not exist: {args.project_path}")
        sys.exit(1)
    
    # Run scan
    scanner = VulnerabilityScanner(
        use_nvd=args.nvd,
        use_github=args.github
    )
    
    result = scanner.scan_project(args.project_path)
    
    # Save JSON if requested
    if args.output in ['json', 'both']:
        if args.output_file:
            json_path = args.output_file
        else:
            output_dir = os.path.join(os.path.dirname(__file__), "output")
            os.makedirs(output_dir, exist_ok=True)
            # Save both timestamped and standard versions
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(output_dir, f"vulnerability_scan_{timestamp}.json")
            json_path_standard = os.path.join(output_dir, "vulnerability_scan.json")
        
        try:
            result_dict = result.to_dict()
            
            # Save timestamped version
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            # Save standard version for documentation generator
            with open(json_path_standard, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            print(f"\nJSON reports saved:")
            print(f"  - {json_path} ({os.path.getsize(json_path) / 1024:.1f} KB)")
            print(f"  - {json_path_standard} ({os.path.getsize(json_path_standard) / 1024:.1f} KB)")
            print(f"\nThe standard file (vulnerability_scan.json) will be automatically used")
            print(f"by the documentation generator to populate the Vulnerability Management section.\n")
        
        except Exception as e:
            print(f"\nError saving JSON: {e}\n")
    
    # Print quick summary if only JSON output
    if args.output == 'json':
        summary = result.get_summary()
        print("\n" + "="*80)
        print("QUICK SUMMARY")
        print("="*80)
        print(f"Total Dependencies: {summary['total_dependencies']}")
        print(f"Vulnerable Packages: {summary['vulnerable_packages']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        
        if summary['total_vulnerabilities'] > 0:
            print(f"\nSeverity Breakdown:")
            if summary['critical']:
                print(f"  CRITICAL: {summary['critical']}")
            if summary['high']:
                print(f"  HIGH:     {summary['high']}")
            if summary['medium']:
                print(f"  MEDIUM:   {summary['medium']}")
            if summary['low']:
                print(f"  LOW:      {summary['low']}")
        
        print("="*80 + "\n")
    
    # Exit with appropriate code
    summary = result.get_summary()
    if summary['critical'] > 0:
        sys.exit(2)  # Critical vulnerabilities found
    elif summary['high'] > 0:
        sys.exit(1)  # High vulnerabilities found
    else:
        sys.exit(0)  # Success


if __name__ == '__main__':
    main()






