# Code Quality & Maintainability Analyzer

## 📋 Overview

The Quality Analyzer is a comprehensive code quality tool that detects common maintainability issues across multiple programming languages. It seamlessly integrates with the existing PDF Report Generator to provide unified security and quality reports.

## 🎯 Features

### 1. **Empty Catch Blocks** 🟠
Detects exception handlers that suppress errors without proper handling:
- Empty `try-except` blocks in Python
- Empty `try-catch` blocks in JavaScript, Java, C#, C++, PHP
- Identifies both completely empty blocks and those with only `pass` or comments

**Why it matters:** Empty catch blocks hide errors, making debugging extremely difficult and potentially masking critical issues.

### 2. **Infinite Loops** 🔴
Identifies loops that may run indefinitely without exit conditions:
- `while True:` without break (Python)
- `while(true)` without break (JavaScript, Java, C#, C++)
- `for(;;)` without break (C-style languages)
- `for {}` without break (Go)

**Why it matters:** Infinite loops can cause application hangs, resource exhaustion, and system crashes.

### 3. **Dead/Unreachable Code** 🟡
Finds code that will never execute:
- Code after `return` statements
- Code after `break`/`continue` in loops
- Unreachable code paths

**Why it matters:** Dead code clutters the codebase, confuses developers, and can hide bugs.

### 4. **Inconsistent Naming** 🔵
Detects violations of language-specific naming conventions:
- **Python:** Functions/variables should use `snake_case`, classes `PascalCase`
- **JavaScript/Java:** Functions/variables should use `camelCase`, classes `PascalCase`
- **C#:** Methods use `PascalCase`, variables use `camelCase`

**Why it matters:** Consistent naming improves code readability and maintainability.

## 🚀 Usage

### Standalone Usage

Run quality analysis on a directory:

```python
from quality_analyzer import analyze_quality

# Analyze current directory
results = analyze_quality(".")

# Analyze specific directory
results = analyze_quality("/path/to/your/project")

# Access findings
findings = results['findings']
empty_catch = findings['empty_catch_blocks']
infinite_loops = findings['infinite_loops']
dead_code = findings['dead_code']
naming_issues = findings['inconsistent_naming']

# Access summary
summary = results['summary']
print(f"Total issues: {summary['total_issues']}")
```

### Command Line Usage

```bash
# Analyze current directory
python quality_analyzer.py

# Analyze specific directory
python quality_analyzer.py /path/to/project
```

### Integration with PDF Report

```python
from quality_analyzer import analyze_quality
from pdf_report_generator import SecurityReportPDF

# Run your existing security analysis
security_results = run_security_analysis(".")

# Run quality analysis
quality_results = analyze_quality(".")

# Combine results
combined_results = {
    'security_analysis': security_results.get('security_analysis', {}),
    'risk_assessment': security_results.get('risk_assessment', {}),
    'taint_flows': security_results.get('taint_flows', []),
    'framework_security_findings': security_results.get('framework_security_findings', []),
    'project_languages': security_results.get('project_languages', []),
    
    # Add quality analysis
    'quality_analysis': quality_results
}

# Generate comprehensive PDF report
report = SecurityReportPDF("complete_report.pdf")
report.generate(combined_results, project_name="My Project")
```

### Quick Demo

Use the demo script to test the analyzer:

```bash
python demo_quality_report.py
```

This will:
1. Run quality analysis on the current directory
2. Generate a PDF report with quality findings
3. Show integration examples

## 📊 Output Format

### Results Structure

```python
{
    'findings': {
        'empty_catch_blocks': [
            {
                'file': 'path/to/file.py',
                'line': 42,
                'type': 'Empty except block',
                'severity': 'medium',
                'language': 'python',
                'code_snippet': 'except Exception:',
                'recommendation': 'Add proper exception handling or at least log the error'
            },
            # ... more findings
        ],
        'infinite_loops': [...],
        'dead_code': [...],
        'inconsistent_naming': [...]
    },
    'summary': {
        'total_issues': 100,
        'total_empty_catch': 25,
        'total_infinite_loops': 10,
        'total_dead_code': 40,
        'total_naming_issues': 25,
        'issues_by_severity': {
            'high': 10,
            'medium': 25,
            'low': 65
        },
        'issues_by_language': {
            'python': 60,
            'javascript': 30,
            'java': 10
        },
        'issues_by_file': {...}
    }
}
```

## 🎨 PDF Report Features

The quality findings are beautifully integrated into the PDF report with:

- **Color-coded severity levels**
  - 🔴 Red for critical issues (infinite loops)
  - 🟠 Orange for high priority (empty catches)
  - 🟡 Yellow for medium priority (dead code)
  - 🔵 Blue for low priority (naming)

- **Detailed tables** showing:
  - File location
  - Line number
  - Issue type
  - Code snippet
  - Language

- **Actionable recommendations** for each issue type

- **Statistical breakdown**:
  - Issues by language
  - Issues by severity
  - Percentage distribution

## 🔧 Supported Languages

| Language | Empty Catch | Infinite Loops | Dead Code | Naming |
|----------|-------------|----------------|-----------|---------|
| Python | ✅ | ✅ | ✅ | ✅ |
| JavaScript | ✅ | ✅ | ✅ | ✅ |
| TypeScript | ✅ | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ | ✅ |
| C# | ✅ | ✅ | ✅ | Limited |
| C++ | ✅ | ✅ | ✅ | Limited |
| C | ✅ | ✅ | ✅ | Limited |
| Go | Limited | ✅ | ✅ | Limited |
| PHP | ✅ | Limited | ✅ | Limited |

## 📝 Examples

### Testing the Analyzer

A test file is included with intentional quality issues:

```bash
python quality_analyzer.py test_quality_samples.py
```

This will detect all the intentional issues in the test file.

### Empty Catch Block Detection

```python
# Will be detected
try:
    risky_operation()
except Exception:
    pass  # Empty!

# Won't be detected (has handling)
try:
    risky_operation()
except Exception as e:
    logger.error(f"Error: {e}")
```

### Infinite Loop Detection

```python
# Will be detected
while True:
    print("Forever!")
    # No break/return

# Won't be detected (has break)
while True:
    if should_stop():
        break
```

### Dead Code Detection

```python
# Will be detected
def example():
    return True
    print("Dead code!")  # Never executed

# Won't be detected
def example():
    if condition:
        return True
    print("Reachable!")
    return False
```

### Naming Convention Detection

```python
# Python - Will be detected
def MyFunction():  # Should be my_function
    MyVariable = 10  # Should be my_variable

# Python - Won't be detected
def my_function():  # Good
    my_variable = 10  # Good
    
class MyClass:  # Good
    pass
```

## 🔄 Integration Flow

```
┌─────────────────────┐
│  Run Analysis       │
│  ├─ Security       │
│  └─ Quality        │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Combine Results    │
│  ├─ Security Data   │
│  └─ Quality Data    │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Generate PDF       │
│  ├─ Security Sect.  │
│  ├─ Quality Sect.   │
│  └─ Recommendations │
└─────────────────────┘
```

## ⚙️ Configuration

The analyzer automatically:
- Skips common directories: `.git`, `node_modules`, `__pycache__`, `venv`, `build`, `dist`
- Handles encoding errors gracefully
- Processes files in parallel where possible
- Limits output to prevent overwhelming reports

## 🐛 Known Limitations

1. **AST Parsing**: Some files with syntax errors won't be fully analyzed
2. **False Positives**: Intentional infinite loops in servers/event loops may be flagged
3. **Naming**: Generic naming detection may miss context-specific conventions
4. **Comments**: Dead code detection doesn't account for commented-out code

## 🤝 Contributing

To add support for new languages:

1. Add patterns to `_detect_empty_catch_blocks()`
2. Add loop patterns to `_detect_infinite_loops()`
3. Add naming conventions to `_detect_inconsistent_naming()`
4. Update the supported languages table in this README

## 📄 License

Part of the Security Analysis PDF Report Generator project.

## 🔗 Related Files

- `quality_analyzer.py` - Main analyzer module
- `pdf_report_generator.py` - PDF generation with quality section
- `demo_quality_report.py` - Integration example
- `test_quality_samples.py` - Test file with sample issues

## 📞 Support

For issues or questions about the quality analyzer, please check:
1. The demo script: `demo_quality_report.py`
2. The test samples: `test_quality_samples.py`
3. The integration example in the demo

---

**Built with ❤️ for better code quality and maintainability**

