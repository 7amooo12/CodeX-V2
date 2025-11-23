"""
Test file containing examples of anti-patterns for testing
This file is intentionally written with security anti-patterns
"""

import requests
import sqlite3
import os


# ============================================
# 1. PASSWORD/SECRET VARIABLES (CRITICAL)
# ============================================

# BAD: Hardcoded password
password = "SuperSecret123!"
api_key = "sk_live_123456789abcdef"
secret = "my_secret_value"

# BAD: Another hardcoded credential
DATABASE_PASSWORD = "admin123"


# ============================================
# 2. SQL CONCATENATION (CRITICAL)
# ============================================

def get_user_data_unsafe(username):
    """BAD: SQL injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # BAD: String concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    return cursor.fetchall()


def update_user_unsafe(user_id, email):
    """BAD: SQL injection with f-string"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # BAD: F-string formatting
    query = f"UPDATE users SET email = '{email}' WHERE id = {user_id}"
    cursor.execute(query)
    
    conn.commit()


# ============================================
# 3. API WITHOUT TIMEOUT (MEDIUM)
# ============================================

def fetch_data_unsafe():
    """BAD: No timeout specified"""
    # BAD: Missing timeout
    response = requests.get("https://api.example.com/data")
    return response.json()


def post_data_unsafe(data):
    """BAD: Another request without timeout"""
    # BAD: No timeout
    response = requests.post("https://api.example.com/submit", json=data)
    return response.status_code


def multiple_requests_unsafe():
    """BAD: Multiple API calls without timeout"""
    # BAD: All missing timeouts
    r1 = requests.get("https://api.example.com/endpoint1")
    r2 = requests.post("https://api.example.com/endpoint2", data={})
    r3 = requests.put("https://api.example.com/endpoint3", json={})
    
    return r1, r2, r3


# ============================================
# 4. UNSAFE FILE PATHS (HIGH)
# ============================================

def read_user_file_unsafe(filename):
    """BAD: User input in file path"""
    # BAD: Direct use of user input
    with open(filename, 'r') as f:
        return f.read()


def delete_file_unsafe(user_path):
    """BAD: Unsanitized file deletion"""
    # BAD: User can provide any path
    os.remove(user_path)


def write_user_data_unsafe(filepath, data):
    """BAD: Path concatenation with user input"""
    # BAD: String concatenation for path
    full_path = "/var/data/" + filepath
    with open(full_path, 'w') as f:
        f.write(data)


# ============================================
# 5. DEAD CODE (LOW)
# ============================================

def unused_function():
    """This function is never called"""
    return "I'm never used!"


def another_unused_function(x, y):
    """Another unused function"""
    return x + y


unused_variable = "This is never used"
another_unused = 42


# ============================================
# COMBINED ISSUES
# ============================================

def problematic_api_call(user_id):
    """Multiple issues in one function"""
    
    # Issue 1: Hardcoded API key
    api_key = "secret_key_12345"
    
    # Issue 2: SQL concatenation
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    
    # Issue 3: API call without timeout
    response = requests.get(f"https://api.example.com/users/{user_id}")
    
    return response.json()


def unsafe_file_operations(filename):
    """File operations with user input"""
    
    # Issue: Unsafe file operations
    user_input = input("Enter filename: ")
    
    # BAD: Direct use of user input
    with open(user_input, 'r') as f:
        content = f.read()
    
    # BAD: Another unsafe operation
    os.remove(user_input)
    
    return content


# Good examples for comparison
# ============================

def get_user_data_safe(username):
    """GOOD: Parameterized query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # GOOD: Using placeholders
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    return cursor.fetchall()


def fetch_data_safe():
    """GOOD: With timeout"""
    # GOOD: Timeout specified
    response = requests.get("https://api.example.com/data", timeout=30)
    return response.json()


def read_file_safe(filename):
    """GOOD: Validated file path"""
    # GOOD: Whitelist validation
    allowed_dir = "/var/safe_files/"
    
    # Sanitize and validate
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Invalid filename")
    
    safe_path = os.path.join(allowed_dir, filename)
    
    with open(safe_path, 'r') as f:
        return f.read()


# GOOD: Using environment variables
import os
db_password = os.getenv('DATABASE_PASSWORD', '')
api_key_from_env = os.getenv('API_KEY', '')


if __name__ == "__main__":
    print("This file contains intentional anti-patterns for testing")
    print("Run antipattern_detector.py on this file to detect them!")

