#!/usr/bin/env python3
"""
This file is for testing the CodeGuardian upload functionality
Contains various vulnerabilities for detection testing
"""

import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests
from flask import Flask, request, render_template_string, redirect
import yaml

app = Flask(__name__)

# VULNERABILITY 1: Hard-coded credentials
DATABASE_PASSWORD = "admin123"  # Hard-coded password
API_KEY = "sk-1234567890abcdef"  # Hard-coded API key
SECRET_KEY = "mysecretkey"  # Weak secret key

# VULNERABILITY 2: SQL Injection
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY 3: Command Injection
def backup_files(backup_name):
    # Vulnerable to command injection
    command = f"tar -czf {backup_name}.tar.gz /var/www/html"
    os.system(command)  # Dangerous use of os.system
    
def process_file(filename):
    # Another command injection vulnerability
    subprocess.call(f"cat {filename}", shell=True)

# VULNERABILITY 4: Path Traversal
@app.route('/download/<path:filename>')
def download_file(filename):
    # Vulnerable to path traversal
    file_path = f"/uploads/{filename}"
    return open(file_path, 'rb').read()

# VULNERABILITY 5: Template Injection
@app.route('/greet/<name>')
def greet_user(name):
    # Vulnerable to template injection
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# VULNERABILITY 6: Unsafe Deserialization
def load_user_data(data):
    # Vulnerable to pickle deserialization
    return pickle.loads(data)

# VULNERABILITY 7: Weak Cryptography
def hash_password(password):
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 8: YAML Deserialization
def load_config(config_data):
    # Vulnerable to YAML deserialization
    return yaml.load(config_data, Loader=yaml.Loader)

# VULNERABILITY 9: Information Disclosure
@app.route('/debug')
def debug_info():
    # Exposing sensitive debug information
    return {
        'database_password': DATABASE_PASSWORD,
        'api_key': API_KEY,
        'environment': os.environ,
        'current_user': os.getlogin()
    }

# VULNERABILITY 10: Insecure Random
import random

def generate_session_id():
    # Using weak random number generator
    return str(random.randint(1000000, 9999999))

# VULNERABILITY 11: Hardcoded URLs and HTTP
def fetch_user_profile(user_id):
    # Using HTTP instead of HTTPS
    url = f"http://api.example.com/users/{user_id}"
    # No SSL verification
    response = requests.get(url, verify=False)
    return response.json()

# VULNERABILITY 12: Buffer Overflow Potential
def process_large_data(data):
    # Potential memory issues with large data
    buffer = [0] * 1000000
    for i, byte in enumerate(data):
        if i < len(buffer):
            buffer[i] = byte
    return buffer

# VULNERABILITY 13: Race Condition
import threading
import time

shared_counter = 0
lock = threading.Lock()

def increment_counter():
    global shared_counter
    # Race condition - not using lock properly
    temp = shared_counter
    time.sleep(0.001)  # Simulate processing time
    shared_counter = temp + 1

# VULNERABILITY 14: Improper Error Handling
def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except:
        # Catching all exceptions without proper handling
        pass
    # Function may return None unexpectedly

# VULNERABILITY 15: Insecure File Permissions
def create_config_file(config_data):
    # Creating file with insecure permissions
    with open('/tmp/app_config.txt', 'w') as f:
        f.write(config_data)
    os.chmod('/tmp/app_config.txt', 0o777)  # World writable

# VULNERABILITY 16: XML External Entity (XXE)
import xml.etree.ElementTree as ET

def parse_xml_data(xml_string):
    # Vulnerable to XXE attacks
    root = ET.fromstring(xml_string)
    return root.text

# VULNERABILITY 17: Insecure Randomness for Security
def generate_password_reset_token():
    # Using time-based seed for security-critical random
    import random
    random.seed(int(time.time()))
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))

# VULNERABILITY 18: Logging Sensitive Data
import logging

def login_user(username, password):
    # Logging sensitive information
    logging.info(f"Login attempt: username={username}, password={password}")
    
    if username == "admin" and password == DATABASE_PASSWORD:
        logging.info(f"Successful login with credentials: {username}:{password}")
        return True
    return False

# VULNERABILITY 19: Unsafe URL Construction
def redirect_user(redirect_url):
    # Open redirect vulnerability
    return redirect(redirect_url)

# VULNERABILITY 20: Insecure Comparison
def check_admin_token(provided_token):
    admin_token = "admin_secret_token_123"
    # Timing attack vulnerable comparison
    if provided_token == admin_token:
        return True
    return False

if __name__ == '__main__':
    # VULNERABILITY 21: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000) 