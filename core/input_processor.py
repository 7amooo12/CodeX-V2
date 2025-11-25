"""
Core Input Processor & Security Analyzer
=========================================

Comprehensive code analysis engine that:
1. Scans and parses multi-language projects
2. Performs deep security analysis
3. Detects dangerous patterns and vulnerabilities
4. Generates comprehensive reports

Supports: Python, JavaScript, TypeScript, Java, PHP, HTML, JSON, ENV files
"""

import os
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ast
import json as _json
import re
import base64
import math
from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict

# Import security checkers
try:
    from security_checks.authentication_checker import AuthenticationSecurityChecker
    from security_checks.cryptography_checker import CryptographyMisuseDetector
    from security_checks.validation_checker import InputValidationSanitizationChecker, analyze_validation_security
except ImportError:
    AuthenticationSecurityChecker = None
    CryptographyMisuseDetector = None
    InputValidationSanitizationChecker = None
    analyze_validation_security = None

# Import framework checkers
try:
    from security_checks import run_all_security_checks
except ImportError:
    run_all_security_checks = None

# Supported languages
SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".html": "html",
    ".php": "php",
    ".json": "json",
    ".env": "env",
    ".c": "c",
    ".cpp": "cpp",
    ".sh": "bash",
    ".bash": "bash"
}

# Dangerous function patterns per language
DANGEROUS_PATTERNS = {
    "python": {
        "code_execution": ["eval", "exec", "compile", "execfile", "__import__"],
        "command_injection": ["os.system", "subprocess.call", "subprocess.run", "subprocess.Popen", 
                              "os.popen", "os.spawn", "commands.getoutput"],
        "deserialization": ["pickle.load", "pickle.loads", "marshal.load", "yaml.load", 
                           "yaml.unsafe_load", "shelve.open"],
        "file_operations": ["open", "file", "io.open", "pathlib.Path"],
        "network": ["urllib.request", "requests.get", "requests.post", "socket.socket", "ftplib"],
        "crypto_weak": ["md5", "sha1", "random.random"]
    },
    "javascript": {
        "code_execution": ["eval", "Function", "setTimeout", "setInterval", "vm.runInContext"],
        "command_injection": ["child_process.exec", "child_process.execSync", "child_process.spawn"],
        "deserialization": ["JSON.parse", "eval", "vm.runInThisContext"],
        "file_operations": ["fs.readFile", "fs.writeFile", "fs.unlink", "fs.rmdir"],
        "network": ["http.request", "https.request", "fetch", "axios", "XMLHttpRequest"],
        "dangerous_modules": ["child_process", "vm", "cluster"]
    },
    "php": {
        "code_execution": ["eval", "assert", "preg_replace", "create_function", "call_user_func"],
        "command_injection": ["system", "shell_exec", "exec", "passthru", "popen", "proc_open", "backticks"],
        "deserialization": ["unserialize", "unserialize_callback_func"],
        "file_operations": ["file_get_contents", "file_put_contents", "fopen", "include", "require", 
                           "include_once", "require_once"],
        "sql_injection": ["mysql_query", "mysqli_query", "pg_query"],
        "network": ["curl_exec", "file_get_contents", "fsockopen"]
    },
    "java": {
        "code_execution": ["Runtime.getRuntime().exec", "ProcessBuilder", "ScriptEngine.eval", 
                          "Class.forName", "URLClassLoader"],
        "deserialization": ["ObjectInputStream.readObject", "XMLDecoder.readObject"],
        "sql_injection": ["Statement.execute", "Statement.executeQuery"],
        "file_operations": ["FileInputStream", "FileOutputStream", "FileReader", "FileWriter"],
        "reflection": ["Method.invoke", "Constructor.newInstance"]
    },
}

# Taint sources (user input origins)
TAINT_SOURCES = {
    "python": ["sys.argv", "input(", "request.args", "request.form", "request.json", 
               "os.environ", "request.GET", "request.POST"],
    "javascript": ["process.argv", "req.query", "req.body", "req.params", "process.env", 
                   "location.search", "document.cookie"],
    "php": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "$argv"],
    "java": ["request.getParameter", "request.getHeader", "System.getenv", "args["]
}

# Secret patterns
SECRET_PATTERNS = {
    "api_key": r"(?i)(api[_-]?key|apikey|api[_-]?token)[\s]*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
    "aws_key": r"(AKIA[0-9A-Z]{16})",
    "github_token": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "slack_token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24})",
    "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "password": r"(?i)(password|passwd|pwd)[\s]*[=:]\s*['\"]([^'\"]{6,})['\"]",
    "connection_string": r"(?i)(mongodb|mysql|postgresql|postgres)://[^\s;]+",
    "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
    "stripe_key": r"(sk_live_[a-zA-Z0-9]{24}|pk_live_[a-zA-Z0-9]{24})"
}


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension"""
    _, ext = os.path.splitext(file_path)
    return SUPPORTED_LANGUAGES.get(ext.lower(), "unknown")


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect high-entropy strings (potential secrets)"""
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def detect_secrets_in_content(content: str, file_path: str) -> List[dict]:
    """Detect hardcoded secrets using regex patterns"""
    findings = []
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            secret_value = match.group(0)
            findings.append({
                "type": secret_type,
                "value": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                "file": file_path,
                "line": content[:match.start()].count('\n') + 1
            })
    
    # High entropy string detection
    words = re.findall(r'["\']([a-zA-Z0-9+/=_\-]{20,})["\']', content)
    for word in words:
        entropy = calculate_entropy(word)
        if entropy > 5.0:  # High entropy threshold
            findings.append({
                "type": "high_entropy_string",
                "value": word[:50] + "...",
                "file": file_path,
                "entropy": round(entropy, 2)
            })
    
    return findings


def detect_dangerous_functions(content: str, language: str, file_path: str) -> List[dict]:
    """Detect dangerous function calls in code"""
    findings = []
    
    if language not in DANGEROUS_PATTERNS:
        return findings
    
    patterns = DANGEROUS_PATTERNS[language]
    
    for category, functions in patterns.items():
        for func in functions:
            pattern = re.escape(func).replace(r'\*', '.*')
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                context = content[line_start:line_end].strip()
                
                findings.append({
                    "function": func,
                    "category": category,
                    "language": language,
                    "file": file_path,
                    "line": line_num,
                    "context": context[:150]
                })
    
    return findings


def detect_taint_sources(content: str, language: str, file_path: str) -> List[dict]:
    """Detect user input sources (taint sources)"""
    findings = []
    
    if language not in TAINT_SOURCES:
        return findings
    
    sources = TAINT_SOURCES[language]
    
    for source in sources:
        pattern = re.escape(source)
        matches = re.finditer(pattern, content)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.end())
            if line_end == -1:
                line_end = len(content)
            context = content[line_start:line_end].strip()
            
            findings.append({
                "source": source,
                "language": language,
                "file": file_path,
                "line": line_num,
                "context": context[:150]
            })
    
    return findings


def analyze_file_security(file_path: str, language: str) -> dict:
    """Perform comprehensive security analysis on a single file"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return {
            "dangerous_functions": [],
            "secrets": [],
            "taint_sources": [],
            "validation_issues": [],
            "error": "Could not read file"
        }
    
    result = {
        "dangerous_functions": detect_dangerous_functions(content, language, file_path),
        "secrets": detect_secrets_in_content(content, file_path),
        "taint_sources": detect_taint_sources(content, language, file_path)
    }
    
    # Add validation analysis if available
    if analyze_validation_security:
        try:
            validation_results = analyze_validation_security(file_path, language)
            result.update(validation_results)
        except Exception:
            pass
    
    # Add cryptography analysis if available
    if CryptographyMisuseDetector:
        try:
            crypto_results = CryptographyMisuseDetector.analyze_cryptography_security(file_path, language)
            result.update(crypto_results)
        except Exception:
            pass
    
    # Add authentication analysis if available
    if AuthenticationSecurityChecker:
        try:
            auth_results = AuthenticationSecurityChecker.analyze_authentication_security(file_path, language)
            result.update(auth_results)
        except Exception:
            pass
    
    return result


def scan_project(root_path: str) -> Dict[str, Any]:
    """Scan project directory and collect file information"""
    project_data = {"files": [], "languages": set()}
    
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Skip common non-source directories
        dirnames[:] = [d for d in dirnames if d not in [
            '.git', '.svn', 'node_modules', '__pycache__', 
            'venv', 'env', '.venv', 'build', 'dist', 'output'
        ]]
        
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            lang = detect_language(file_path)
            project_data["files"].append({
                "path": file_path,
                "language": lang,
                "extension": os.path.splitext(filename)[1]
            })
            if lang != "unknown":
                project_data["languages"].add(lang)
    
    return project_data


def build_taint_flow_analysis(security_data: dict) -> List[dict]:
    """Build taint flow analysis by correlating sources and sinks"""
    flows = []
    
    files_with_sources = {}
    files_with_sinks = {}
    
    for file_path, data in security_data.items():
        if data.get("taint_sources"):
            files_with_sources[file_path] = data["taint_sources"]
        if data.get("dangerous_functions"):
            files_with_sinks[file_path] = data["dangerous_functions"]
    
    # Correlate sources and sinks in the same file
    for file_path in files_with_sources:
        if file_path in files_with_sinks:
            for source in files_with_sources[file_path]:
                for sink in files_with_sinks[file_path]:
                    if source["line"] < sink["line"]:
                        flows.append({
                            "file": file_path,
                            "source": source["source"],
                            "source_line": source["line"],
                            "sink": sink["function"],
                            "sink_line": sink["line"],
                            "risk": "HIGH",
                            "description": f"Tainted data from {source['source']} may flow to {sink['function']}"
                        })
    
    return flows


def calculate_risk_score(security_data: dict, framework_findings: list = None) -> dict:
    """Calculate overall risk score and categorize findings"""
    critical = 0
    high = 0
    medium = 0
    low = 0
    
    for file_data in security_data.values():
        # Dangerous functions
        for func in file_data.get("dangerous_functions", []):
            if func["category"] in ["code_execution", "command_injection", "deserialization"]:
                critical += 1
            elif func["category"] in ["sql_injection", "buffer_overflow"]:
                high += 1
            else:
                medium += 1
        
        # Secrets
        for secret in file_data.get("secrets", []):
            if secret["type"] in ["aws_key", "private_key", "github_token"]:
                critical += 1
            else:
                medium += 1
        
        # Count other issues with severity levels
        for key in ["validation_issues", "boundary_issues", "sanitization_issues", 
                    "client_side_issues", "deserialization_issues", "weak_hashing",
                    "weak_encryption", "predictable_random", "unsalted_passwords",
                    "ecb_mode", "jwt_issues", "auth_bypass", "insecure_cookie_flags"]:
            for issue in file_data.get(key, []):
                severity = issue.get("severity", "medium").upper()
                if severity == "CRITICAL":
                    critical += 1
                elif severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                else:
                    low += 1
    
    # Add framework findings
    if framework_findings:
        for finding in framework_findings:
            severity = finding.get("severity", "medium").lower()
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
            elif severity == "medium":
                medium += 1
            else:
                low += 1
    
    total = critical + high + medium + low
    risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
    
    return {
        "total_findings": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_level": risk_level
    }


def process_project(root_path: str, security_analysis: bool = True) -> Dict[str, Any]:
    """Process project with comprehensive security analysis"""
    print(f"[*] Scanning project: {root_path}")
    
    project_info = scan_project(root_path)
    security_data = {}
    
    print(f"[*] Found {len(project_info['files'])} files")
    print(f"[*] Languages detected: {', '.join(project_info['languages'])}")
    
    # Perform security analysis on each file
    if security_analysis:
        print(f"[*] Running security analysis...")
        for i, file_entry in enumerate(project_info["files"], 1):
            path = file_entry["path"]
            lang = file_entry["language"]
            
            if lang != "unknown":
                if i % 10 == 0:
                    print(f"[*] Analyzed {i}/{len(project_info['files'])} files...")
                security_data[path] = analyze_file_security(path, lang)
    
    result = {
        "project_languages": list(project_info["languages"]),
        "total_files": len(project_info["files"])
    }
    
    if security_analysis:
        # Run framework-specific checks
        framework_findings = []
        if run_all_security_checks:
            try:
                print("[*] Running framework-specific security checks...")
                framework_findings = run_all_security_checks({f["path"]: f for f in project_info["files"]})
                result["framework_security_findings"] = framework_findings
            except Exception as e:
                result["framework_security_findings"] = [{"error": str(e)}]
        
        result["security_analysis"] = security_data
        result["taint_flows"] = build_taint_flow_analysis(security_data)
        result["risk_assessment"] = calculate_risk_score(security_data, framework_findings)
        
        print(f"[+] Analysis complete!")
        print(f"[+] Risk Level: {result['risk_assessment']['risk_level']}")
        print(f"[+] Total Findings: {result['risk_assessment']['total_findings']}")
    
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python input_processor.py <project_folder>")
        sys.exit(1)
    
    root = sys.argv[1]
    result = process_project(root, security_analysis=True)
    
    # Save to JSON
    output_file = "security_analysis.json"
    with open(output_file, "w", encoding="utf-8") as f:
        _json.dump(result, f, indent=4, default=str)
    
    print(f"\n[+] Results saved to: {output_file}")






