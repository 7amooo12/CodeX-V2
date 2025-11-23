#!/usr/bin/env python3
"""
Demo script to test the Security Analyzer on vulnerable samples
"""

import os
import sys
import json

# Add the project directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import the analyzer (renamed to avoid space in filename)
# For this demo, we'll run it as a subprocess
import subprocess

def run_analyzer(target_path):
    """Run the security analyzer on a target path"""
    script_path = os.path.join(os.path.dirname(__file__), "input processing.py")
    
    print(f"\n{'='*80}")
    print(f"Running Security Analyzer on: {target_path}")
    print(f"{'='*80}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, target_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        return result.returncode
    except subprocess.TimeoutExpired:
        print("❌ Analyzer timed out (>60 seconds)")
        return 1
    except Exception as e:
        print(f"❌ Error running analyzer: {e}")
        return 1

def create_test_directory():
    """Create a test directory with vulnerable samples"""
    test_dir = os.path.join(os.path.dirname(__file__), "test_samples")
    os.makedirs(test_dir, exist_ok=True)
    
    # Create a simple vulnerable Python file in test directory
    vuln_py = os.path.join(test_dir, "vulnerable.py")
    with open(vuln_py, "w") as f:
        f.write("""
import os
import sys

# Hardcoded secret
API_KEY = "AKIAIOSFODNN7EXAMPLE"

# Dangerous function
user_input = sys.argv[1] if len(sys.argv) > 1 else ""
eval(user_input)  # CRITICAL

# Command injection
os.system("ls " + user_input)  # HIGH RISK
""")
    
    # Create a vulnerable JS file
    vuln_js = os.path.join(test_dir, "vulnerable.js")
    with open(vuln_js, "w") as f:
        f.write("""
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const user_code = process.argv[2];
eval(user_code);  // CRITICAL
""")
    
    # Create an .env file with secrets
    env_file = os.path.join(test_dir, ".env")
    with open(env_file, "w") as f:
        f.write("""
DB_PASSWORD=SuperSecret123!
API_KEY=sk_live_abcdefghijklmnopqrstuvwxyz
AWS_SECRET=AKIAIOSFODNN7EXAMPLETEST
""")
    
    print(f"✅ Created test directory: {test_dir}")
    return test_dir

def main():
    """Main demo function"""
    print("="*80)
    print("SECURITY ANALYZER DEMO")
    print("="*80)
    
    # Check if vulnerable samples exist
    project_dir = os.path.dirname(__file__)
    samples = [
        "test_vulnerable_sample.py",
        "test_vulnerable_sample.js",
        "test_vulnerable_sample.php"
    ]
    
    available_samples = [s for s in samples if os.path.exists(os.path.join(project_dir, s))]
    
    if not available_samples:
        print("\n⚠️  No vulnerable sample files found.")
        print("Creating test samples...")
        test_dir = create_test_directory()
        print("\n🚀 Running analyzer on test directory...")
        return run_analyzer(test_dir)
    
    print("\n📋 Available vulnerable samples:")
    for i, sample in enumerate(available_samples, 1):
        print(f"  {i}. {sample}")
    
    print("\n💡 Choose an option:")
    print("  1. Analyze individual file (enter number)")
    print("  2. Analyze entire project directory")
    print("  3. Create and analyze test directory")
    print("  0. Exit")
    
    try:
        choice = input("\nYour choice (default: 2): ").strip() or "2"
        
        if choice == "0":
            print("Exiting...")
            return 0
        elif choice == "3":
            test_dir = create_test_directory()
            return run_analyzer(test_dir)
        elif choice == "2":
            return run_analyzer(project_dir)
        elif choice.isdigit() and 1 <= int(choice) <= len(available_samples):
            sample_path = os.path.join(project_dir, available_samples[int(choice)-1])
            return run_analyzer(sample_path)
        else:
            print("❌ Invalid choice")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())


