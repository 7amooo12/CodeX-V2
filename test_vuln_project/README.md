# Test Vulnerability Project

This repo is automatically generated to test the vulnerability scanner.

Files:
- requirements.txt (Python deps)
- package.json (Node deps)
- pom.xml (Maven deps)
- src/python_app.py
- src/node_app.js

How to test:
1. Run your scanner and point it at the `test_vuln_project` folder.
   Example:
     python3 your_scanner.py
   then when prompted enter:
     ./test_vuln_project

2. Optional: Set GITHUB_TOKEN environment variable for GitHub advisory lookups:
     export GITHUB_TOKEN=ghp_xxx

Notes:
- This project contains intentionally dated package versions to exercise
  dependency discovery and vulnerability detection.
