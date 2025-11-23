# Quality Analyzer Integration Guide

## 🎯 Quick Start

You now have a complete Code Quality & Maintainability Analyzer integrated with your PDF Report Generator!

## 📦 What Was Added

### 1. **quality_analyzer.py** - Main Analysis Module
   - Detects empty catch blocks
   - Identifies infinite loops
   - Finds dead/unreachable code
   - Checks naming consistency
   - Supports Python, JavaScript, Java, C#, C++, Go, PHP

### 2. **PDF Report Integration** - Enhanced Report Generator
   - New section: "CODE QUALITY & MAINTAINABILITY ANALYSIS"
   - Beautiful color-coded tables for each issue type
   - Statistical breakdowns by language and severity
   - Actionable recommendations

### 3. **Demo Script** - demo_quality_report.py
   - Complete working example
   - Shows integration pattern
   - Generates sample reports

### 4. **Test File** - test_quality_samples.py
   - Contains intentional quality issues
   - Perfect for testing the analyzer

## 🚀 How to Use It

### Option 1: Quick Demo

```bash
# Run the demo to see it in action
python demo_quality_report.py
```

This generates: `quality_analysis_report.pdf`

### Option 2: Add to Your Existing Security Analyzer

If you have an existing main analysis script, add these lines:

```python
# At the top of your file
from quality_analyzer import analyze_quality

# After your security analysis
security_results = your_security_analyzer.analyze(".")

# Add quality analysis
quality_results = analyze_quality(".")

# Combine for PDF generation
combined_results = {
    **security_results,  # Your existing results
    'quality_analysis': quality_results  # NEW: Quality results
}

# Generate PDF (now includes quality section)
from pdf_report_generator import SecurityReportPDF
report = SecurityReportPDF("complete_report.pdf")
report.generate(combined_results, project_name="Your Project")
```

### Option 3: Standalone Quality Analysis

```python
from quality_analyzer import analyze_quality

# Analyze your project
results = analyze_quality(".")

# Access findings
findings = results['findings']
print(f"Empty catch blocks: {len(findings['empty_catch_blocks'])}")
print(f"Infinite loops: {len(findings['infinite_loops'])}")
print(f"Dead code: {len(findings['dead_code'])}")
print(f"Naming issues: {len(findings['inconsistent_naming'])}")
```

## 📋 Integration Checklist

- ✅ `quality_analyzer.py` created - Core analyzer
- ✅ `pdf_report_generator.py` updated - Added quality section
- ✅ `demo_quality_report.py` created - Working example
- ✅ `test_quality_samples.py` created - Test cases
- ✅ Documentation created
- ✅ No linting errors

## 🎨 What the PDF Report Now Includes

### New Section: Code Quality & Maintainability
1. **Summary Statistics**
   - Total issues by category
   - Color-coded counts

2. **Empty Catch Blocks** (🟠 Orange)
   - File, line number, code snippet
   - Recommendations for proper error handling

3. **Infinite Loops** (🔴 Red)
   - Location and pattern
   - Suggestions for adding exit conditions

4. **Dead/Unreachable Code** (🟡 Yellow)
   - Unreachable code locations
   - Clean-up recommendations

5. **Naming Inconsistencies** (🔵 Blue)
   - Inconsistent identifiers
   - Expected vs actual conventions
   - Language-specific guidance

6. **Language Statistics**
   - Issues breakdown by programming language
   - Percentage distribution

### Updated Recommendations Section
Now includes quality-related recommendations alongside security ones!

## 🔧 Customization

### Adjust Detection Sensitivity

In `quality_analyzer.py`, you can modify:

```python
# Skip additional directories
dirs[:] = [d for d in dirs if d not in [
    '.git', 'node_modules', '__pycache__',
    'your_custom_dir'  # Add your own
]]

# Adjust how far to look for break statements
for j in range(i + 1, min(i + 20, len(lines))):  # Change 20 to your preference
```

### Customize PDF Styling

In `pdf_report_generator.py` -> `add_quality_findings_section()`:

```python
# Change colors
colors.HexColor('#e67e22')  # Empty catch (orange)
colors.HexColor('#c0392b')  # Infinite loops (red)
colors.HexColor('#f39c12')  # Dead code (yellow)
colors.HexColor('#3498db')  # Naming (blue)

# Adjust table limits
for i, finding in enumerate(empty_catch[:20], 1):  # Change 20 to show more/less
```

## 📊 Example Output

### Console Output
```
🔍 Starting Code Quality Analysis on: .

✓ Quality Analysis Complete!
  - Empty Catch Blocks: 15
  - Infinite Loops: 3
  - Dead Code: 22
  - Naming Issues: 45

By Severity:
  • HIGH: 3
  • MEDIUM: 15
  • LOW: 67

By Language:
  • python: 60
  • javascript: 20
  • java: 5
```

### PDF Report
- Executive summary updated with quality metrics
- Dedicated quality section with beautiful tables
- Color-coded findings
- Actionable recommendations
- Statistical breakdowns

## 🧪 Testing

### Test the Analyzer

```bash
# Test on sample file with known issues
python quality_analyzer.py test_quality_samples.py
```

Expected output: Should find 10+ issues in the test file

### Test PDF Generation

```bash
# Generate a demo report
python demo_quality_report.py
```

Expected output: Creates `quality_analysis_report.pdf`

## 🔄 Integration with CI/CD

### GitHub Actions Example

```yaml
name: Code Quality Check

on: [push, pull_request]

jobs:
  quality-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install reportlab matplotlib
      
      - name: Run Quality Analysis
        run: |
          python quality_analyzer.py .
      
      - name: Generate Report
        run: |
          python demo_quality_report.py .
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: quality-report
          path: quality_analysis_report.pdf
```

## 📞 Common Issues & Solutions

### Issue: "No module named 'reportlab'"
**Solution:**
```bash
pip install reportlab matplotlib
```

### Issue: "No findings in report"
**Solution:** 
- Check that you're analyzing the correct directory
- Verify files aren't in skip list (node_modules, .git, etc.)
- Check file extensions are supported

### Issue: "Too many false positives for infinite loops"
**Solution:**
- Infinite loops in event handlers/servers are intentional
- Add comments explaining the loop purpose
- The detection looks for break/return within 20 lines

### Issue: "Naming conventions don't match my style"
**Solution:**
Modify the conventions in `quality_analyzer.py`:
```python
conventions = {
    'python': {
        'function': 'snake_case',  # Change this
        'variable': 'snake_case',
        'class': 'PascalCase',
        'constant': 'UPPER_CASE'
    },
    # ... other languages
}
```

## 🎯 Next Steps

1. **Test the analyzer**
   ```bash
   python demo_quality_report.py
   ```

2. **Review the generated PDF**
   - Check quality section formatting
   - Verify findings are accurate
   - Review recommendations

3. **Integrate with your main analyzer**
   - Add quality analysis call
   - Combine results
   - Update your main script

4. **Customize as needed**
   - Adjust colors/styling
   - Modify detection patterns
   - Add language support

5. **Set up automation**
   - Add to CI/CD pipeline
   - Schedule regular scans
   - Track improvements over time

## 📚 Documentation Files

- `QUALITY_ANALYZER_README.md` - Complete feature documentation
- `INTEGRATION_GUIDE.md` - This file
- `demo_quality_report.py` - Working example
- `test_quality_samples.py` - Test cases

## 🎉 You're All Set!

Your PDF report generator now includes comprehensive code quality analysis alongside security findings. Run the demo to see it in action!

```bash
python demo_quality_report.py
```

---

**Questions? Check the README or review the demo script for examples.**

