# Advanced Static & Dynamic Code Security Analyzer

A comprehensive security analysis tool that detects vulnerabilities, dangerous functions, hardcoded secrets, taint flows, and potential exploit scenarios across multiple programming languages.

## 🎯 Features

### 1. **Dangerous Function Detection**
Identifies risky functions across multiple languages:
- **Python**: `eval`, `exec`, `pickle.load`, `os.system`, `subprocess`
- **JavaScript/Node.js**: `eval`, `Function`, `child_process.exec`, `vm.runInContext`
- **PHP**: `eval`, `system`, `unserialize`, `shell_exec`
- **Java**: `Runtime.exec()`, `ObjectInputStream.readObject()`
- **C/C++**: `strcpy`, `system`, `gets`
- **Bash**: `eval`, command substitution, dangerous piping

### 2. **Taint Analysis (Data Flow Tracking)**
- Identifies user input sources (taint sources)
- Tracks data flow to dangerous sinks
- Detects unsanitized input reaching critical functions
- Correlates sources and sinks within files

### 3. **Hardcoded Secret Detection**
Finds:
- API keys (AWS, GitHub, Google, Stripe)
- JWT tokens
- Private keys (RSA, PEM)
- Database connection strings
- Passwords and credentials
- High-entropy strings (potential secrets)
- Suspicious Base64-encoded payloads

### 4. **File & Network Operations**
Monitors:
- File write/read/delete operations
- Network requests (HTTP, socket connections)
- Download operations
- Potential data exfiltration

### 5. **Comprehensive Reporting**
Generates reports with:
- **Executive Summary**: Risk level and finding counts
- **Dangerous Functions**: Categorized by language
- **Taint Flow Graph**: Visual representation of data flows
- **Secret Findings**: All detected sensitive data
- **Exploit Scenarios** (Red Team): Potential attack vectors
- **Defensive Measures** (Blue Team): Security controls
- **Technology Deep Dive**: How the analyzer works
- **Critical Fixes**: Prioritized action items
- **Golden Security Insight**: Advanced security wisdom

## 🚀 Installation

### Prerequisites
```bash
pip install esprima phply
```

### Dependencies
- **Python 3.7+**
- `esprima` - JavaScript/TypeScript AST parsing
- `phply` - PHP lexer and parser

## 📖 Usage

### Basic Security Analysis
```bash
python "d:\project\input processing.py" /path/to/project
```

### JSON Output Only
```bash
python "d:\project\input processing.py" /path/to/project --json
```

### Disable Security Analysis (Structure Only)
```bash
python "d:\project\input processing.py" /path/to/project --no-security
```

## 📊 Output Formats

### 1. Human-Readable Report (Default)
Comprehensive formatted report with all sections displayed in terminal.

### 2. JSON Output
Detailed JSON file (`security_analysis.json`) containing:
```json
{
  "project_languages": ["python", "javascript"],
  "files": { ... },
  "security_analysis": {
    "file_path": {
      "dangerous_functions": [...],
      "secrets": [...],
      "taint_sources": [...],
      "file_network_ops": [...]
    }
  },
  "taint_flows": [...],
  "risk_assessment": {
    "total_findings": 15,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 3,
    "risk_level": "CRITICAL"
  }
}
```

## 🔍 Detection Examples

### Dangerous Function Detection
```python
# ⚠️ DETECTED: Code Execution
user_input = input("Enter code: ")
eval(user_input)  # CRITICAL

# ⚠️ DETECTED: Command Injection
os.system("ls " + user_path)  # HIGH RISK
```

### Taint Flow Analysis
```python
# Source: User Input
username = request.args.get('user')  # Taint source

# Sink: Dangerous Function
eval(f"process_{username}()")  # HIGH RISK TAINT FLOW
```

### Secret Detection
```python
# ⚠️ DETECTED: AWS Key
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# ⚠️ DETECTED: High Entropy String
token = "aGVsbG93b3JsZHRoaXNpc2F0ZXN0"  # Base64 analyzed
```

## 🛡️ Security Categories

### Risk Levels
- **CRITICAL**: Code execution, command injection, leaked keys
- **HIGH**: SQL injection, deserialization, weak crypto
- **MEDIUM**: File operations, insecure configurations
- **LOW**: Best practice violations

### Detection Categories
1. **Code Execution**: `eval`, `exec`, dynamic imports
2. **Command Injection**: System calls, shell commands
3. **Deserialization**: Pickle, YAML, object streams
4. **SQL Injection**: Direct query construction
5. **Buffer Overflow**: Unsafe string operations (C/C++)
6. **Weak Cryptography**: MD5, SHA1, weak random
7. **File Operations**: Arbitrary read/write/delete
8. **Network Operations**: HTTP requests, downloads

## 🎓 Advanced Features

### Entropy Analysis
Calculates Shannon entropy to detect:
- Random-looking strings (potential keys)
- Encoded payloads
- Obfuscated data

### Base64 Decoding
Safely decodes Base64 strings and analyzes for:
- Malicious keywords (`eval`, `exec`, `system`)
- Encoded commands
- Hidden payloads

### Taint Propagation
Tracks user input from:
- HTTP parameters (`request.args`, `req.query`)
- CLI arguments (`sys.argv`, `process.argv`)
- Environment variables (`os.environ`, `process.env`)
- File contents
- Database queries

## 📚 Supported Languages

| Language | Structure Extraction | Security Analysis |
|----------|---------------------|-------------------|
| Python   | ✅ Full AST         | ✅ Complete       |
| JavaScript | ✅ Full AST       | ✅ Complete       |
| TypeScript | ⚠️ Partial        | ✅ Complete       |
| PHP      | ✅ Full AST         | ✅ Complete       |
| Java     | ⚠️ Pattern-based   | ✅ Complete       |
| C/C++    | ⚠️ Pattern-based   | ✅ Complete       |
| Bash     | ⚠️ Pattern-based   | ✅ Complete       |
| JSON     | ✅ Full parsing     | ✅ Secret detection |
| .env     | ✅ Full parsing     | ✅ Secret detection |

## 🔧 Integration

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Security Analysis
  run: |
    python "d:\project\input processing.py" . --json
    # Fail if critical findings
    if [ $(jq '.risk_assessment.critical' security_analysis.json) -gt 0 ]; then
      exit 1
    fi
```

### Pre-commit Hook
```bash
#!/bin/bash
python "d:\project\input processing.py" . --json
critical=$(jq '.risk_assessment.critical' security_analysis.json)
if [ "$critical" -gt 0 ]; then
  echo "❌ Critical security issues found!"
  exit 1
fi
```

## 🎯 Use Cases

1. **Security Audits**: Comprehensive codebase security review
2. **Penetration Testing**: Identify exploit opportunities
3. **Code Review**: Automated security check before merge
4. **Compliance**: Meet security standards (OWASP, PCI-DSS)
5. **Malware Analysis**: Detect malicious code patterns
6. **DevSecOps**: Integrate into CI/CD pipeline

## ⚡ Performance

- **Fast**: Pattern-based detection for speed
- **Scalable**: Handles large codebases
- **Efficient**: AST parsing only when needed
- **Parallel**: Can process multiple files

## 🤝 Best Practices

1. **Run regularly**: Integrate into development workflow
2. **Review findings**: Not all detections are exploitable
3. **Prioritize fixes**: Start with CRITICAL and HIGH
4. **Track progress**: Monitor risk score over time
5. **Educate team**: Use reports for security training

## 🔐 Golden Security Insight

> "The most overlooked vulnerability is not in the code itself, but in the ASSUMPTIONS developers make about their input sources. Every external input—whether HTTP, CLI, file, or environment variable—is potentially malicious."

**Defense-in-depth approach:**
1. ✅ Validate at entry
2. ✅ Sanitize during processing
3. ✅ Verify before use in sinks

## 📝 License

This tool is provided as-is for security analysis purposes. Use responsibly.

## 🙏 Credits

Created by: Advanced Security Analysis Agent
Purpose: Purple Team Operations (Red + Blue Team)


