import os
import ast
import json as _json
import re
import base64
import math
from collections import defaultdict
from typing import Dict, Any, List, Set, Tuple

# --- Supported languages ---
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

# ============================================================================
# SECURITY ANALYSIS PATTERNS
# ============================================================================

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

# --- Language detection ---
def detect_language(file_path):
    _, ext = os.path.splitext(file_path)
    return SUPPORTED_LANGUAGES.get(ext.lower(), "unknown")

# ============================================================================
# SECURITY UTILITY FUNCTIONS
# ============================================================================

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

def safe_decode_base64(encoded_str: str) -> dict:
    """Safely decode Base64 strings and analyze content"""
    try:
        # Remove common prefixes/suffixes
        cleaned = encoded_str.strip().strip('"').strip("'")
        decoded_bytes = base64.b64decode(cleaned, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        
        # Check for suspicious patterns in decoded content
        suspicious_keywords = ["eval", "exec", "system", "shell", "cmd", "powershell", 
                              "bash", "import", "require", "download", "http"]
        found_suspicious = [kw for kw in suspicious_keywords if kw.lower() in decoded_str.lower()]
        
        return {
            "decoded": decoded_str[:200],  # Truncate for safety
            "suspicious": len(found_suspicious) > 0,
            "keywords": found_suspicious,
            "length": len(decoded_str)
        }
    except Exception:
        return None

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
        if entropy > 4.5:  # High entropy threshold
            # Check if it's Base64
            base64_result = safe_decode_base64(word)
            if base64_result and base64_result.get("suspicious"):
                findings.append({
                    "type": "suspicious_base64",
                    "value": word[:50] + "...",
                    "decoded": base64_result["decoded"],
                    "keywords": base64_result["keywords"],
                    "file": file_path,
                    "entropy": round(entropy, 2)
                })
            elif entropy > 5.0:
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
            # Create regex pattern that's not too greedy
            pattern = re.escape(func).replace(r'\*', '.*')
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                # Get surrounding context
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

def detect_file_network_operations(content: str, language: str, file_path: str) -> List[dict]:
    """Detect file and network operations"""
    findings = []
    
    # File operation patterns
    file_patterns = {
        "file_write": [r"\.write\(", r"writeFile", r"file_put_contents", r"fopen.*['\"]w"],
        "file_delete": [r"\.unlink\(", r"\.rmdir\(", r"unlink\(", r"remove\(", r"delete\("],
        "file_read": [r"\.read\(", r"readFile", r"file_get_contents", r"fopen.*['\"]r"]
    }
    
    # Network patterns
    network_patterns = {
        "http_request": [r"http\.request", r"requests\.get", r"requests\.post", r"curl_exec", 
                         r"fetch\(", r"axios\.", r"XMLHttpRequest"],
        "download": [r"wget", r"curl.*-o", r"download", r"urllib\.request"],
        "socket": [r"socket\.", r"fsockopen", r"new Socket"]
    }
    
    all_patterns = {**file_patterns, **network_patterns}
    
    for category, patterns in all_patterns.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                context = content[line_start:line_end].strip()
                
                findings.append({
                    "operation": category,
                    "pattern": pattern,
                    "language": language,
                    "file": file_path,
                    "line": line_num,
                    "context": context[:150]
                })
    
    return findings

# --- Scan project ---
def scan_project(root_path):
    project_data = {"files": [], "languages": set()}
    for dirpath, _, filenames in os.walk(root_path):
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

# --- Python structure ---
def extract_python_structure(file_path):
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append(node.name)
            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        globals_found.append(target.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    imports.extend([alias.name for alias in node.names])
                else:
                    imports.append(node.module)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- JavaScript structure ---
import esprima
def extract_javascript_structure(file_path):
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        ast_tree = esprima.parseModule(source)
        for node in ast_tree.body:
            if node.type == "ImportDeclaration":
                imports.append(node.source.value)
            elif node.type == "FunctionDeclaration" and node.id:
                functions.append(node.id.name)
            elif node.type == "ClassDeclaration" and node.id:
                classes.append(node.id.name)
            elif node.type == "VariableDeclaration":
                for decl in node.declarations:
                    if decl.id.type == "Identifier":
                        globals_found.append(decl.id.name)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- PHP structure ---
from phply.phplex import lexer as php_lexer
from phply.phpparse import make_parser as php_make_parser
def extract_php_structure(file_path):
    functions, classes, globals_found, imports = [], [], [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        parser = php_make_parser()
        ast_tree = parser.parse(code, lexer=php_lexer.clone())
        visited = set()

        def walk(node):
            node_id = id(node)
            if node_id in visited:
                return
            visited.add(node_id)
            if isinstance(node, list):
                for n in node: walk(n)
                return
            if not hasattr(node, "__class__"): return
            t = type(node).__name__
            if t == "Function":
                functions.append(node.name)
            elif t == "Class":
                classes.append(node.name)
            elif t == "Global":
                for g in getattr(node, "nodes", []):
                    globals_found.append(getattr(g, "name", None))
            elif t == "Include":
                imports.append(str(getattr(node, "expr", "")))
            for attr in dir(node):
                if attr.startswith("_"): continue
                val = getattr(node, attr, None)
                if isinstance(val, list) or hasattr(val, "__dict__"):
                    walk(val)
        walk(ast_tree)
    except Exception:
        pass
    return {"functions": functions, "classes": classes, "globals": globals_found, "imports": imports}

# --- JSON structure ---
def extract_json_structure(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        content = re.sub(r"//.*", "", content)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.S)
        data = _json.loads(content)
    except Exception:
        return {"keys": [], "secrets": []}

    keys, secrets = [], []
    def find(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(k)
                if any(s in k.lower() for s in ["secret", "token", "password", "key"]):
                    secrets.append({k: v})
                find(v)
        elif isinstance(obj, list):
            for entry in obj: find(entry)
    find(data)
    return {"keys": list(set(keys)), "secrets": secrets}

# --- .env structure ---
def extract_env_structure(file_path):
    variables, secrets = [], []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip()
                variables.append({key: value})
                if any(s in key.lower() for s in ["key", "secret", "token", "pass", "pwd"]):
                    secrets.append({key: value})
    except Exception:
        pass
    return {"variables": variables, "secrets": secrets}

# ============================================================================
# COMPREHENSIVE SECURITY ANALYSIS
# ============================================================================

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
            "file_network_ops": [],
            "validation_issues": [],
            "boundary_issues": [],
            "sanitization_issues": [],
            "client_side_issues": [],
            "deserialization_issues": [],
            "error": "Could not read file"
        }
    
    # Import validation checker
    try:
        from validation_checker import analyze_validation_security
        validation_results = analyze_validation_security(file_path, language)
    except Exception:
        validation_results = {
            "validation_issues": [],
            "boundary_issues": [],
            "sanitization_issues": [],
            "client_side_issues": [],
            "deserialization_issues": []
        }
    
    # Import cryptography checker
    try:
        from security_checks.cryptography_checker import CryptographyMisuseDetector
        crypto_results = CryptographyMisuseDetector.analyze_cryptography_security(file_path, language)
    except Exception:
        crypto_results = {
            "weak_hashing": [],
            "weak_encryption": [],
            "predictable_random": [],
            "unsalted_passwords": [],
            "ecb_mode": [],
            "jwt_issues": []
        }
    
    # Import authentication checker
    try:
        from security_checks.authentication_checker import AuthenticationSecurityChecker
        auth_results = AuthenticationSecurityChecker.analyze_authentication_security(file_path, language)
    except Exception:
        auth_results = {
            "weak_session_timeout": [],
            "missing_session_rotation": [],
            "insecure_cookie_flags": [],
            "missing_mfa": [],
            "weak_password_policy": [],
            "auth_bypass": []
        }
    
    result = {
        "dangerous_functions": detect_dangerous_functions(content, language, file_path),
        "secrets": detect_secrets_in_content(content, file_path),
        "taint_sources": detect_taint_sources(content, language, file_path),
        "file_network_ops": detect_file_network_operations(content, language, file_path)
    }
    
    # Add validation analysis results
    result.update(validation_results)
    
    # Add cryptography analysis results
    result.update(crypto_results)
    
    # Add authentication analysis results
    result.update(auth_results)
    
    return result

def build_taint_flow_analysis(security_data: dict) -> List[dict]:
    """Build taint flow analysis by correlating sources and sinks"""
    flows = []
    
    # Get all files with taint sources
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
                    # If source appears before sink in same file
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
            elif secret["type"] == "suspicious_base64":
                high += 1
            else:
                medium += 1
        
        # File/Network operations
        for op in file_data.get("file_network_ops", []):
            if op["operation"] in ["file_delete", "download"]:
                medium += 1
            else:
                low += 1
        
        # Validation issues (NEW)
        for issue in file_data.get("validation_issues", []):
            if issue.get("severity") == "CRITICAL":
                critical += 1
            elif issue.get("severity") == "HIGH":
                high += 1
            else:
                medium += 1
        
        # Boundary issues (NEW)
        for issue in file_data.get("boundary_issues", []):
            if issue.get("severity") == "HIGH":
                high += 1
            else:
                medium += 1
        
        # Sanitization issues (NEW)
        for issue in file_data.get("sanitization_issues", []):
            if issue.get("severity") == "CRITICAL":
                critical += 1
            else:
                high += 1
        
        # Client-side validation issues (NEW)
        for issue in file_data.get("client_side_issues", []):
            if issue.get("severity") == "CRITICAL":
                critical += 1
            else:
                high += 1
        
        # Deserialization issues (NEW)
        for issue in file_data.get("deserialization_issues", []):
            if issue.get("severity") == "CRITICAL":
                critical += 1
            else:
                high += 1
        
        # Cryptography issues (NEW)
        for issue in file_data.get("weak_hashing", []):
            if issue.get("severity") == "CRITICAL":
                critical += 1
            else:
                high += 1
        
        for issue in file_data.get("weak_encryption", []):
            critical += 1
        
        for issue in file_data.get("predictable_random", []):
            high += 1
        
        for issue in file_data.get("unsalted_passwords", []):
            critical += 1
        
        for issue in file_data.get("ecb_mode", []):
            critical += 1
        
        for issue in file_data.get("jwt_issues", []):
            critical += 1
        
        # Authentication issues (NEW)
        for issue in file_data.get("weak_session_timeout", []):
            if issue.get("severity") == "HIGH":
                high += 1
            else:
                medium += 1
        
        for issue in file_data.get("missing_session_rotation", []):
            medium += 1
        
        for issue in file_data.get("insecure_cookie_flags", []):
            if issue.get("severity") == "HIGH":
                high += 1
            else:
                medium += 1
        
        for issue in file_data.get("missing_mfa", []):
            medium += 1
        
        for issue in file_data.get("weak_password_policy", []):
            if issue.get("severity") == "MEDIUM":
                medium += 1
            else:
                low += 1
        
        for issue in file_data.get("auth_bypass", []):
            critical += 1
    
    # Add framework-specific findings to risk score
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

# --- Process entire project ---
def process_project(root_path, security_analysis=True):
    """Process project with optional comprehensive security analysis"""
    project_info = scan_project(root_path)
    detailed_files = {}
    security_data = {}
    
    for file_entry in project_info["files"]:
        path = file_entry["path"]
        lang = file_entry["language"]

        # Extract structure
        if lang == "python":
            detailed_files[path] = extract_python_structure(path)
        elif lang == "javascript":
            detailed_files[path] = extract_javascript_structure(path)
        elif lang == "php":
            detailed_files[path] = extract_php_structure(path)
        elif lang == "json":
            detailed_files[path] = extract_json_structure(path)
        elif lang == "env":
            detailed_files[path] = extract_env_structure(path)
        else:
            detailed_files[path] = {"functions": [], "classes": [], "globals": [], "imports": []}

        # Perform security analysis
        if security_analysis and lang != "unknown":
            security_data[path] = analyze_file_security(path, lang)

    result = {
        "project_languages": list(project_info["languages"]),
        "files": detailed_files
    }
    
    if security_analysis:
        # Run framework-specific security checks
        framework_findings = []
        try:
            from security_checks import run_all_security_checks
            framework_findings = run_all_security_checks(detailed_files)
            result["framework_security_findings"] = framework_findings
        except ImportError:
            result["framework_security_findings"] = []
        except Exception as e:
            result["framework_security_findings"] = [{
                "error": f"Error running framework checks: {str(e)}"
            }]
        
        result["security_analysis"] = security_data
        result["taint_flows"] = build_taint_flow_analysis(security_data)
        result["risk_assessment"] = calculate_risk_score(security_data, framework_findings)
    
    return result

# ============================================================================
# COMPREHENSIVE SECURITY REPORT GENERATOR
# ============================================================================

def generate_security_report(analysis_result: dict, root_path: str = "") -> str:
    """Generate comprehensive security report with all required sections"""
    
    from enhanced_analysis import (
        generate_file_tree, deduplicate_findings, 
        generate_intelligent_findings_table, generate_data_flow_diagram,
        generate_exploit_scenarios
    )
    
    report = []
    report.append("=" * 80)
    report.append("🛡️  ELITE SECURITY ANALYSIS REPORT")
    report.append("Advanced Static & Dynamic Code Security Analyzer")
    report.append("Purple Team Edition - Red Team + Blue Team Perspective")
    report.append("=" * 80)
    report.append("")
    
    # A) EXECUTIVE SUMMARY
    report.append("=" * 80)
    report.append("A) EXECUTIVE SUMMARY - HIGH-LEVEL RISK OVERVIEW")
    report.append("=" * 80)
    risk = analysis_result.get("risk_assessment", {})
    
    # Visual risk indicator
    risk_level = risk.get('risk_level', 'UNKNOWN')
    risk_icons = {'CRITICAL': '🔥', 'HIGH': '⚠️', 'MEDIUM': '🟡', 'LOW': '🟢'}
    icon = risk_icons.get(risk_level, '❓')
    
    report.append(f"{icon} Overall Risk Level: **{risk_level}**")
    report.append(f"📊 Total Security Findings: {risk.get('total_findings', 0)}")
    report.append(f"   🔥 CRITICAL: {risk.get('critical', 0)}")
    report.append(f"   ⚠️  HIGH: {risk.get('high', 0)}")
    report.append(f"   🟡 MEDIUM: {risk.get('medium', 0)}")
    report.append(f"   🟢 LOW: {risk.get('low', 0)}")
    report.append(f"📝 Languages Analyzed: {', '.join(analysis_result.get('project_languages', [])) or 'None'}")
    report.append("")
    
    # B) FILE TREE HIERARCHY
    report.append("=" * 80)
    report.append("B) FILE TREE HIERARCHY WITH RISK INDICATORS")
    report.append("=" * 80)
    if root_path and os.path.exists(root_path):
        tree = generate_file_tree(root_path, analysis_result.get('security_analysis', {}))
        report.append(tree)
    else:
        report.append("File tree not available for this analysis.")
        report.append("")
    
    # C) INTELLIGENT FINDINGS TABLE (DEDUPLICATED)
    report.append("=" * 80)
    report.append("C) HIGH-RISK FINDINGS TABLE (INTELLIGENT DEDUPLICATION)")
    report.append("=" * 80)
    report.append("")
    
    # Deduplicate findings
    deduplicated = deduplicate_findings(analysis_result.get('security_analysis', {}))
    findings_table = generate_intelligent_findings_table(deduplicated)
    report.append(findings_table)
    
    # D) DATA FLOW MAP & TAINT ANALYSIS
    report.append("=" * 80)
    report.append("D) DATA FLOW MAP & TAINT ANALYSIS")
    report.append("=" * 80)
    report.append("")
    
    taint_flows = analysis_result.get("taint_flows", [])
    data_flow_diagram = generate_data_flow_diagram(taint_flows)
    report.append(data_flow_diagram)
    
    # E) DANGEROUS FUNCTIONS OVERVIEW
    report.append("=" * 80)
    report.append("E) DANGEROUS FUNCTIONS OVERVIEW (BY LANGUAGE)")
    report.append("=" * 80)
    report.append("")
    
    dangerous_by_lang = defaultdict(list)
    for file_path, data in analysis_result.get("security_analysis", {}).items():
        for func in data.get("dangerous_functions", []):
            dangerous_by_lang[func["language"]].append(func)
    
    if dangerous_by_lang:
        report.append("Summary by Language:")
        report.append("")
        for lang, funcs in dangerous_by_lang.items():
            # Count by category
            categories = defaultdict(int)
            for func in funcs:
                categories[func['category']] += 1
            
            report.append(f"📌 {lang.upper()} - {len(funcs)} total findings:")
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                report.append(f"   • {category}: {count}")
            report.append("")
    else:
        report.append("✓ No dangerous functions detected.")
    report.append("")
    
    # F) SECRETS DETECTION
    report.append("=" * 80)
    report.append("F) HARDCODED SECRETS & SENSITIVE DATA")
    report.append("=" * 80)
    report.append("")
    
    all_secrets = []
    for file_path, data in analysis_result.get("security_analysis", {}).items():
        all_secrets.extend(data.get("secrets", []))
    
    if all_secrets:
        report.append(f"🔑 Found {len(all_secrets)} potential secrets:\n")
        
        # Group by type
        secrets_by_type = defaultdict(list)
        for secret in all_secrets:
            secrets_by_type[secret['type']].append(secret)
        
        for secret_type, secrets in sorted(secrets_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            report.append(f"   {secret_type.upper()}: {len(secrets)} found")
        
        report.append("")
        report.append("Top secrets (first 15):")
        report.append("")
        
        for i, secret in enumerate(all_secrets[:15], 1):
            report.append(f"{i}. 🔑 {secret['type'].upper()}")
            report.append(f"   File: {os.path.basename(secret['file'])}")
            if "line" in secret:
                report.append(f"   Line: {secret['line']}")
            report.append(f"   Value: {secret['value'][:60]}{'...' if len(secret['value']) > 60 else ''}")
            if "decoded" in secret:
                report.append(f"   ⚠️  Decoded Content: {secret['decoded'][:100]}")
                report.append(f"   Suspicious Keywords: {', '.join(secret['keywords'])}")
            if "entropy" in secret:
                report.append(f"   Entropy Score: {secret['entropy']} (HIGH)")
            report.append("")
    else:
        report.append("✓ No hardcoded secrets detected.")
    report.append("")
    
    # G) FRAMEWORK-SPECIFIC SECURITY FINDINGS
    report.append("=" * 80)
    report.append("G) FRAMEWORK-SPECIFIC SECURITY FINDINGS")
    report.append("=" * 80)
    report.append("")
    
    framework_findings = analysis_result.get("framework_security_findings", [])
    
    if framework_findings:
        # Group by severity
        findings_by_severity = defaultdict(list)
        for finding in framework_findings:
            severity = finding.get("severity", "medium").upper()
            findings_by_severity[severity].append(finding)
        
        report.append(f"📋 Total Framework Security Findings: {len(framework_findings)}\n")
        
        # Show critical findings first
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = findings_by_severity.get(severity, [])
            if findings:
                icon = {'CRITICAL': '🔥', 'HIGH': '⚠️', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(severity, '❓')
                report.append(f"{icon} {severity} - {len(findings)} findings:")
                report.append("")
                
                for i, finding in enumerate(findings[:15], 1):  # Show first 15 per severity
                    report.append(f"{i}. {finding.get('issue', 'Unknown issue')}")
                    report.append(f"   File: {os.path.basename(finding.get('file', 'Unknown'))}")
                    report.append(f"   Type: {finding.get('type', 'Unknown')}")
                    if 'line' in finding:
                        report.append(f"   Line: {finding['line']}")
                    if 'recommendation' in finding:
                        report.append(f"   Fix: {finding['recommendation']}")
                    report.append("")
                
                if len(findings) > 15:
                    report.append(f"   ... and {len(findings) - 15} more {severity} findings")
                    report.append("")
    else:
        report.append("✓ No framework-specific security issues detected or module not loaded.")
    report.append("")
    
    # H) CRYPTOGRAPHY MISUSE ANALYSIS
    report.append("=" * 80)
    report.append("H) CRYPTOGRAPHY MISUSE ANALYSIS")
    report.append("=" * 80)
    report.append("")
    
    # Collect all cryptography-related issues
    weak_hashing_findings = []
    weak_encryption_findings = []
    predictable_random_findings = []
    unsalted_password_findings = []
    ecb_mode_findings = []
    jwt_issues_findings = []
    
    for file_path, data in analysis_result.get("security_analysis", {}).items():
        weak_hashing_findings.extend(data.get("weak_hashing", []))
        weak_encryption_findings.extend(data.get("weak_encryption", []))
        predictable_random_findings.extend(data.get("predictable_random", []))
        unsalted_password_findings.extend(data.get("unsalted_passwords", []))
        ecb_mode_findings.extend(data.get("ecb_mode", []))
        jwt_issues_findings.extend(data.get("jwt_issues", []))
    
    total_crypto_issues = (len(weak_hashing_findings) + len(weak_encryption_findings) + 
                           len(predictable_random_findings) + len(unsalted_password_findings) + 
                           len(ecb_mode_findings) + len(jwt_issues_findings))
    
    if total_crypto_issues > 0:
        report.append(f"📋 Total Cryptography Issues: {total_crypto_issues}\n")
        
        # Weak Hashing
        if weak_hashing_findings:
            report.append(f"🔐 WEAK HASHING ALGORITHMS - {len(weak_hashing_findings)} findings:")
            report.append("")
            for i, finding in enumerate(weak_hashing_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Pattern: {finding.get('pattern', 'N/A')}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Weak Encryption
        if weak_encryption_findings:
            report.append(f"🔒 WEAK ENCRYPTION ALGORITHMS - {len(weak_encryption_findings)} findings:")
            report.append("")
            for i, finding in enumerate(weak_encryption_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Pattern: {finding.get('pattern', 'N/A')}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Predictable Random
        if predictable_random_findings:
            report.append(f"🎲 PREDICTABLE RANDOM GENERATORS - {len(predictable_random_findings)} findings:")
            report.append("")
            for i, finding in enumerate(predictable_random_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Unsalted Password Hashing
        if unsalted_password_findings:
            report.append(f"🔑 UNSALTED PASSWORD HASHING - {len(unsalted_password_findings)} findings:")
            report.append("")
            for i, finding in enumerate(unsalted_password_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # ECB Mode
        if ecb_mode_findings:
            report.append(f"🚨 ECB MODE ENCRYPTION - {len(ecb_mode_findings)} findings:")
            report.append("")
            for i, finding in enumerate(ecb_mode_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Pattern: {finding.get('pattern', 'N/A')}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # JWT Issues
        if jwt_issues_findings:
            report.append(f"🎫 JWT SECURITY ISSUES - {len(jwt_issues_findings)} findings:")
            report.append("")
            for i, finding in enumerate(jwt_issues_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Type: {finding.get('type', 'N/A')}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
    else:
        report.append("✓ No cryptography misuse issues detected.")
    report.append("")
    
    # I) AUTHENTICATION & SESSION SECURITY ANALYSIS
    report.append("=" * 80)
    report.append("I) AUTHENTICATION & SESSION SECURITY ANALYSIS")
    report.append("=" * 80)
    report.append("")
    
    # Collect all authentication-related issues
    weak_session_findings = []
    missing_rotation_findings = []
    cookie_flag_findings = []
    missing_mfa_findings = []
    weak_password_findings = []
    auth_bypass_findings = []
    
    for file_path, data in analysis_result.get("security_analysis", {}).items():
        weak_session_findings.extend(data.get("weak_session_timeout", []))
        missing_rotation_findings.extend(data.get("missing_session_rotation", []))
        cookie_flag_findings.extend(data.get("insecure_cookie_flags", []))
        missing_mfa_findings.extend(data.get("missing_mfa", []))
        weak_password_findings.extend(data.get("weak_password_policy", []))
        auth_bypass_findings.extend(data.get("auth_bypass", []))
    
    total_auth_issues = (len(weak_session_findings) + len(missing_rotation_findings) + 
                        len(cookie_flag_findings) + len(missing_mfa_findings) + 
                        len(weak_password_findings) + len(auth_bypass_findings))
    
    if total_auth_issues > 0:
        report.append(f"📋 Total Authentication & Session Issues: {total_auth_issues}\n")
        
        # Authentication Bypass (Most Critical)
        if auth_bypass_findings:
            report.append(f"🚨 AUTHENTICATION BYPASS - {len(auth_bypass_findings)} findings:")
            report.append("")
            for i, finding in enumerate(auth_bypass_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                if finding.get('pattern'):
                    report.append(f"   Pattern: {finding['pattern']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Insecure Cookie Flags
        if cookie_flag_findings:
            report.append(f"🍪 INSECURE COOKIE FLAGS - {len(cookie_flag_findings)} findings:")
            report.append("")
            for i, finding in enumerate(cookie_flag_findings[:10], 1):
                severity_icon = "🔥" if finding.get('severity') == 'HIGH' else "⚠️"
                report.append(f"{i}. {severity_icon} {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Type: {finding.get('type', 'N/A')}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Weak Session Timeout
        if weak_session_findings:
            report.append(f"⏱️  WEAK SESSION TIMEOUT - {len(weak_session_findings)} findings:")
            report.append("")
            for i, finding in enumerate(weak_session_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                if finding.get('line'):
                    report.append(f"   Line: {finding['line']}")
                if finding.get('timeout_seconds'):
                    report.append(f"   Timeout: {finding['timeout_seconds']} seconds")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Missing Session Rotation
        if missing_rotation_findings:
            report.append(f"🔄 MISSING SESSION ROTATION - {len(missing_rotation_findings)} findings:")
            report.append("")
            for i, finding in enumerate(missing_rotation_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Missing MFA
        if missing_mfa_findings:
            report.append(f"🔐 MISSING MULTI-FACTOR AUTHENTICATION - {len(missing_mfa_findings)} findings:")
            report.append("")
            for i, finding in enumerate(missing_mfa_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Weak Password Policy
        if weak_password_findings:
            report.append(f"🔑 WEAK PASSWORD POLICY - {len(weak_password_findings)} findings:")
            report.append("")
            for i, finding in enumerate(weak_password_findings[:10], 1):
                report.append(f"{i}. ℹ️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
    else:
        report.append("✓ No authentication or session security issues detected.")
    report.append("")
    
    # J) INPUT VALIDATION & SANITIZATION ANALYSIS
    report.append("=" * 80)
    report.append("J) INPUT VALIDATION & SANITIZATION ANALYSIS")
    report.append("=" * 80)
    report.append("")
    
    # Collect all validation-related issues
    validation_findings = []
    boundary_findings = []
    sanitization_findings = []
    client_side_findings = []
    deserialization_findings = []
    
    for file_path, data in analysis_result.get("security_analysis", {}).items():
        validation_findings.extend(data.get("validation_issues", []))
        boundary_findings.extend(data.get("boundary_issues", []))
        sanitization_findings.extend(data.get("sanitization_issues", []))
        client_side_findings.extend(data.get("client_side_issues", []))
        deserialization_findings.extend(data.get("deserialization_issues", []))
    
    total_validation_issues = (len(validation_findings) + len(boundary_findings) + 
                               len(sanitization_findings) + len(client_side_findings) + 
                               len(deserialization_findings))
    
    if total_validation_issues > 0:
        report.append(f"📋 Total Validation & Sanitization Issues: {total_validation_issues}\n")
        
        # Sanitization Issues (Most Critical)
        if sanitization_findings:
            report.append(f"🚨 UNSANITIZED SINKS - {len(sanitization_findings)} findings:")
            report.append("")
            for i, finding in enumerate(sanitization_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Language: {finding['language']}")
                if 'sink' in finding:
                    report.append(f"   Dangerous Sink: {finding['sink']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Deserialization Issues
        if deserialization_findings:
            report.append(f"🔓 UNSAFE DESERIALIZATION - {len(deserialization_findings)} findings:")
            report.append("")
            for i, finding in enumerate(deserialization_findings[:10], 1):
                report.append(f"{i}. 🔥 {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                if 'pattern' in finding:
                    report.append(f"   Pattern: {finding['pattern']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Client-Side Validation Issues
        if client_side_findings:
            report.append(f"🌐 CLIENT-SIDE VALIDATION ISSUES - {len(client_side_findings)} findings:")
            report.append("")
            for i, finding in enumerate(client_side_findings[:10], 1):
                report.append(f"{i}. ⚠️  {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Validation Issues
        if validation_findings:
            report.append(f"✅ MISSING INPUT VALIDATION - {len(validation_findings)} findings:")
            report.append("")
            for i, finding in enumerate(validation_findings[:10], 1):
                report.append(f"{i}. {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Language: {finding['language']}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
        
        # Boundary Check Issues
        if boundary_findings:
            report.append(f"🔢 MISSING BOUNDARY CHECKS - {len(boundary_findings)} findings:")
            report.append("")
            for i, finding in enumerate(boundary_findings[:10], 1):
                report.append(f"{i}. {finding['message']}")
                report.append(f"   File: {os.path.basename(finding['file'])}")
                report.append(f"   Fix: {finding['recommendation']}")
                report.append("")
    else:
        report.append("✓ No validation or sanitization issues detected.")
    report.append("")
    
    # K) POTENTIAL EXPLOIT SCENARIOS (Red Team View)
    report.append("=" * 80)
    report.append("K) POTENTIAL EXPLOIT SCENARIOS - RED TEAM PERSPECTIVE")
    report.append("=" * 80)
    report.append("")
    
    exploit_scenarios = generate_exploit_scenarios(deduplicated, taint_flows)
    
    if exploit_scenarios:
        report.append(f"Identified {len(exploit_scenarios)} potential exploit scenarios:\n")
        
        for i, scenario in enumerate(exploit_scenarios, 1):
            severity_icons = {
                'CRITICAL': '🔥',
                'HIGH': '⚠️',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }
            icon = severity_icons.get(scenario['severity'], '❓')
            
            report.append(f"{i}. {icon} {scenario['type']} [{scenario['severity']}]")
            report.append(f"   File: {os.path.basename(scenario['file'])}")
            
            from enhanced_analysis import format_line_numbers
            report.append(f"   Lines: {format_line_numbers(scenario['lines'])}")
            report.append(f"   ")
            report.append(f"   📝 Description:")
            report.append(f"   {scenario['description']}")
            report.append(f"   ")
            report.append(f"   💻 Exploit Example:")
            for line in scenario['exploit_example'].split('\n')[:5]:
                report.append(f"   {line}")
            report.append(f"   ")
            report.append(f"   🛡️  Fix:")
            report.append(f"   {scenario['fix']}")
            report.append("")
    else:
        report.append("✓ No obvious exploit scenarios detected.")
    report.append("")
    
    # L) DEFENSIVE MEASURES (Blue Team View)
    report.append("=" * 80)
    report.append("L) DEFENSIVE MEASURES - BLUE TEAM PERSPECTIVE")
    report.append("=" * 80)
    report.append("Recommended security controls:")
    report.append("")
    report.append("1. INPUT VALIDATION")
    report.append("   - Implement strict allowlists for all user input")
    report.append("   - Use parameterized queries for database operations")
    report.append("   - Validate and sanitize file paths")
    report.append("")
    report.append("2. DANGEROUS FUNCTION MITIGATION")
    report.append("   - Replace eval/exec with safe alternatives")
    report.append("   - Use subprocess with shell=False")
    report.append("   - Implement content security policies")
    report.append("")
    report.append("3. SECRET MANAGEMENT")
    report.append("   - Remove all hardcoded secrets")
    report.append("   - Use environment variables or secret vaults (HashiCorp Vault, AWS Secrets Manager)")
    report.append("   - Implement secret rotation")
    report.append("")
    report.append("4. CRYPTOGRAPHY")
    report.append("   - Replace MD5/SHA1 with SHA-256 or better")
    report.append("   - Use secure random number generators")
    report.append("   - Implement proper key management")
    report.append("")
    report.append("5. FILE & NETWORK SECURITY")
    report.append("   - Implement strict file access controls")
    report.append("   - Validate all download sources")
    report.append("   - Use TLS for all network communications")
    report.append("")
    
    # M) TECHNOLOGY DEEP EXPLANATION
    report.append("=" * 80)
    report.append("M) TECHNICAL DEEP-DIVE EXPLANATION - TECHNOLOGY VIEW")
    report.append("=" * 80)
    report.append("How this analyzer works:")
    report.append("")
    report.append("1. STATIC ANALYSIS ENGINE")
    report.append("   - Parses AST (Abstract Syntax Tree) for Python, JavaScript, PHP")
    report.append("   - Pattern matching using regex for dangerous function signatures")
    report.append("   - Language-specific lexers for deep code understanding")
    report.append("")
    report.append("2. TAINT ANALYSIS")
    report.append("   - Identifies sources: user inputs (HTTP params, CLI args, env vars)")
    report.append("   - Tracks sinks: dangerous functions (eval, exec, system)")
    report.append("   - Builds data flow graph to correlate sources → sinks")
    report.append("   - Flags unsanitized paths as HIGH RISK")
    report.append("")
    report.append("3. SECRET DETECTION")
    report.append("   - Regex patterns for known secret formats (API keys, tokens)")
    report.append("   - Shannon entropy calculation for high-entropy strings")
    report.append("   - Base64 decoding and content analysis")
    report.append("   - Suspicious keyword detection in decoded payloads")
    report.append("")
    report.append("4. BEHAVIORAL ANALYSIS")
    report.append("   - File operation tracking (read/write/delete)")
    report.append("   - Network activity detection (HTTP requests, downloads)")
    report.append("   - Process execution monitoring")
    report.append("   - Persistence mechanism identification")
    report.append("")
    report.append("5. INPUT VALIDATION & SANITIZATION ANALYSIS (NEW)")
    report.append("   - Missing input validation detection across all languages")
    report.append("   - Boundary check verification (buffer overflow prevention)")
    report.append("   - Sanitization before dangerous sinks analysis")
    report.append("   - Client-side vs server-side validation detection")
    report.append("   - Unsafe deserialization pattern identification")
    report.append("")
    
    # N) CRITICAL IMMEDIATE FIXES
    report.append("=" * 80)
    report.append("N) CRITICAL IMMEDIATE FIXES - MUST-DO ACTIONS")
    report.append("=" * 80)
    
    fixes = []
    
    # Generate specific fixes based on findings
    if risk.get("critical", 0) > 0:
        fixes.append("🔴 CRITICAL: Address all code execution and command injection vulnerabilities immediately")
    
    if all_secrets:
        fixes.append("🔴 CRITICAL: Remove all hardcoded secrets and implement proper secret management")
    
    if sanitization_findings:
        fixes.append("🔴 CRITICAL: Add sanitization/escaping before all dangerous sinks")
    
    if deserialization_findings:
        fixes.append("🔴 CRITICAL: Replace unsafe deserialization with safe alternatives")
    
    if client_side_findings:
        fixes.append("🔴 CRITICAL: Implement server-side validation - never trust client-side only")
    
    if taint_flows:
        fixes.append("🔴 HIGH: Implement input validation for all taint flows")
    
    if validation_findings:
        fixes.append("🟡 MEDIUM: Add input validation and type checking across all entry points")
    
    fixes.extend([
        "🟡 MEDIUM: Conduct security code review with focus on dangerous functions",
        "🟡 MEDIUM: Implement logging and monitoring for security events",
        "🟡 MEDIUM: Set up automated security scanning in CI/CD pipeline",
        "🟢 LOW: Document all security assumptions and threat models"
    ])
    
    for fix in fixes:
        report.append(f"  {fix}")
    report.append("")
    
    # GOLDEN INSIGHT
    report.append("=" * 80)
    report.append("💡 GOLDEN SECURITY INSIGHT")
    report.append("=" * 80)
    report.append("The most overlooked vulnerability is not in the code itself, but in the")
    report.append("ASSUMPTIONS developers make about their input sources. Every external")
    report.append("input—whether HTTP, CLI, file, or environment variable—is potentially")
    report.append("malicious. The security principle 'Never trust user input' extends to")
    report.append("'Never trust ANY external input'. Implement defense-in-depth: validate")
    report.append("at entry, sanitize during processing, and verify before use in sinks.")
    report.append("")
    report.append("Advanced insight: Look for second-order vulnerabilities where data is")
    report.append("stored safely but retrieved and used unsafely later. Taint tracking")
    report.append("must persist across database operations, file I/O, and session storage.")
    report.append("=" * 80)
    report.append("")
    
    return "\n".join(report)

# --- Main execution ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python input_processing.py <project_folder> [OPTIONS]")
        print("\nOptions:")
        print("  -pdf              Generate PDF report with charts and visualizations")
        print("  -json             Generate JSON output only")
        print("  --no-security     Disable security analysis (structure only)")
        print("\nExamples:")
        print("  python input_processing.py /path/to/project")
        print("  python input_processing.py /path/to/project -pdf")
        print("  python input_processing.py /path/to/project -json")
        print("  python input_processing.py /path/to/project -pdf -json")
        sys.exit(1)
    
    root = sys.argv[1]
    security_analysis = "--no-security" not in sys.argv
    json_output = "-json" in sys.argv
    pdf_output = "-pdf" in sys.argv
    
    print(f"[*] Analyzing project: {root}")
    print(f"[*] Security analysis: {'enabled' if security_analysis else 'disabled'}")
    if pdf_output:
        print(f"[*] PDF output: enabled")
    if json_output:
        print(f"[*] JSON output: enabled")
    print("")
    
    result = process_project(root, security_analysis=security_analysis)
    
    # Generate PDF if requested
    if pdf_output and security_analysis:
        try:
            from pdf_report_generator import SecurityReportPDF
            
            print("[*] Generating comprehensive PDF report...")
            
            # Run Quality Analysis
            print("[*] Running Quality Analysis...")
            try:
                from quality_analyzer import analyze_quality
                quality_results = analyze_quality(root)
                print(f"[+] Quality Analysis Complete: {quality_results['summary']['total_issues']} issues found")
            except Exception as e:
                print(f"[!] Warning: Quality analysis failed: {e}")
                quality_results = None
            
            # Run Anti-Pattern Detection
            print("[*] Running Anti-Pattern Detection...")
            try:
                from antipattern_detector import detect_antipatterns
                antipattern_results = detect_antipatterns(root)
                print(f"[+] Anti-Pattern Detection Complete: {antipattern_results['summary']['total_issues']} issues found")
            except Exception as e:
                print(f"[!] Warning: Anti-pattern detection failed: {e}")
                antipattern_results = None
            
            # Add quality and anti-pattern results to the main result
            if quality_results:
                result['quality_analysis'] = quality_results
            if antipattern_results:
                result['antipattern_analysis'] = antipattern_results
            
            # Generate PDF with all results
            pdf_filename = "security_analysis_report.pdf"
            project_name = os.path.basename(os.path.abspath(root))
            pdf_gen = SecurityReportPDF(pdf_filename)
            pdf_gen.generate(result, project_name)
            
            print(f"[+] Comprehensive PDF report generated: {pdf_filename}")
            
            # Print summary
            total_issues = 0
            if quality_results:
                total_issues += quality_results['summary']['total_issues']
            if antipattern_results:
                total_issues += antipattern_results['summary']['total_issues']
            if result.get('risk_assessment'):
                total_issues += result['risk_assessment'].get('total_findings', 0)
            
            print(f"[+] Total issues found across all analyzers: {total_issues}")
            
        except ImportError as e:
            print(f"[!] PDF generation requires additional libraries:")
            print(f"    pip install reportlab matplotlib")
            print(f"[!] Error: {e}")
        except Exception as e:
            print(f"[!] Error generating PDF: {e}")
            import traceback
            traceback.print_exc()
    
    # Generate JSON if requested
    if json_output:
        output_file = "security_analysis.json"
        with open(output_file, "w", encoding="utf-8") as f:
            _json.dump(result, f, indent=4, default=str)
        print(f"[+] JSON output saved to: {output_file}")
        
        if not pdf_output:
            # Print JSON to console if no PDF
            print("\n" + "="*80)
            print(_json.dumps(result, indent=2, default=str))
    
    # Generate text report if no specific output format requested
    if not json_output and not pdf_output and security_analysis:
        report = generate_security_report(result, root)
        
        # Handle Unicode output for Windows
        try:
            print(report)
        except UnicodeEncodeError:
            # Fallback for Windows console
            print(report.encode('utf-8', errors='replace').decode('utf-8', errors='replace'))
        
        # Also save JSON output by default
        output_file = "security_analysis.json"
        with open(output_file, "w", encoding="utf-8") as f:
            _json.dump(result, f, indent=4, default=str)
        print(f"\n[+] Detailed JSON output saved to: {output_file}")
    elif not security_analysis:
        print(_json.dumps(result, indent=4, default=str))
