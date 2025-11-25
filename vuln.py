#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate a small test project with vulnerable/outdated package versions
to test the vulnerability scanner.
Creates folder: test_vuln_project
"""

import os
from pathlib import Path
import json
import textwrap

ROOT = Path.cwd() / "test_vuln_project"
SRC = ROOT / "src"
JAVA = ROOT / "java-app"

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Created {path.relative_to(Path.cwd())}")

# 1) requirements.txt (Python) -- include some older versions
requirements = textwrap.dedent("""\
    # intentionally include versions that are often flagged by scanners
    requests==2.19.1
    urllib3==1.22
    django==2.0.5
""")

# 2) package.json (Node) -- include lodash old version (prototype pollution history)
package_json = {
    "name": "test-vuln-app",
    "version": "0.1.0",
    "description": "Small test project to trigger vuln scanner",
    "dependencies": {
        "lodash": "4.17.11",
        "express": "4.16.0"
    },
    "devDependencies": {}
}

# 3) pom.xml (Maven) -- include commons-collections older version
pom_xml = textwrap.dedent("""\
    <project xmlns="http://maven.apache.org/POM/4.0.0"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                                 http://maven.apache.org/xsd/maven-4.0.0.xsd">
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>vuln-java-app</artifactId>
      <version>0.0.1-SNAPSHOT</version>
      <dependencies>
        <!-- older commons-collections with historical vulnerabilities -->
        <dependency>
          <groupId>commons-collections</groupId>
          <artifactId>commons-collections</artifactId>
          <version>3.2.1</version>
        </dependency>
      </dependencies>
    </project>
""")

# 4) small python app file
py_app = textwrap.dedent("""\
    # sample python file
    import requests

    def hello():
        r = requests.get('https://httpbin.org/get')
        return r.status_code

    if __name__ == '__main__':
        print('hello', hello())
""")

# 5) small node app file
node_app = textwrap.dedent("""\
    // sample node file
    const _ = require('lodash');

    function hello() {
      const obj = { a: 1 };
      const copy = _.clone(obj);
      console.log('hello', copy);
    }

    hello();
""")

# 6) README.md
readme = textwrap.dedent("""\
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
""")

# 7) expected_mock_responses.json (optional helper for offline testing)
mock_responses = {
    "requests==2.19.1": {
        "osv": [{"id": "OSV-TEST-1", "summary": "Mock vuln for requests 2.19.1", "references": []}],
        "nvd": [{"cve": "CVE-XXXX-1111", "description": "Mock NVD entry"}],
        "github": {"data": {"securityVulnerabilities": []}}
    },
    "lodash==4.17.11": {
        "osv": [{"id": "OSV-LODASH-1", "summary": "Prototype pollution - mock", "references": []}],
        "nvd": [{"cve": "CVE-2018-16487", "description": "Prototype pollution in lodash (mock)"}],
        "github": {"data": {"securityVulnerabilities": []}}
    },
    "commons-collections==3.2.1": {
        "osv": [{"id": "OSV-CC-1", "summary": "Mock RCE pre-serialized gadget", "references": []}],
        "nvd": [{"cve": "CVE-2007-1234", "description": "Mock historical CVE"}],
        "github": {"data": {"securityVulnerabilities": []}}
    }
}

def main():
    write(ROOT / "requirements.txt", requirements)
    write(ROOT / "package.json", json.dumps(package_json, indent=2))
    write(JAVA / "pom.xml", pom_xml)
    write(SRC / "python_app.py", py_app)
    write(SRC / "node_app.js", node_app)
    write(ROOT / "README.md", readme)
    write(ROOT / "expected_mock_responses.json", json.dumps(mock_responses, indent=2, ensure_ascii=False))

    print("\nDone. Open the folder `test_vuln_project` and run your scanner against it.")
    print("مثال: python3 vulnerability_scanner.py  ./test_vuln_project")

if __name__ == "__main__":
    main()
