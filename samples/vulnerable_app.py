"""
INTENTIONALLY VULNERABLE - sample file used to test the SAST scanner.
DO NOT deploy this anywhere.
"""
import os
import sqlite3
import hashlib
import pickle
import subprocess
import requests
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (SECRET-001) - placeholders to avoid GitHub secret scanning
API_KEY = "PLACEHOLDER_FAKE_KEY_XXXXXXXXXXXXXXXX"
AWS_SECRET = "PLACEHOLDER_FAKE_AWS_XXXXXXXXXXXXXXXX"
DB_PASSWORD = "PLACEHOLDER_FAKE_DB_PASSWORD_1234567"


@app.route("/login")
def login():
    # SQL injection (SQLI-001)
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    result = conn.execute(query).fetchall()
    return str(result)


@app.route("/run")
def run_cmd():
    # Command injection (CMDI-001)
    cmd = request.args.get("cmd")
    os.system("ls " + cmd)
    subprocess.call("echo " + cmd, shell=True)
    return "ok"


@app.route("/load")
def load_data():
    # Insecure deserialization (DESER-001)
    data = request.args.get("data")
    obj = pickle.loads(data.encode())
    return str(obj)


@app.route("/eval")
def eval_expr():
    # Eval injection (EVAL-001)
    expr = request.args.get("expr")
    result = eval(expr)
    return str(result)


@app.route("/read")
def read_file():
    # Path traversal (PATH-001)
    filename = request.args.get("file")
    with open("/var/data/" + filename) as f:
        return f.read()


@app.route("/fetch")
def fetch_url():
    # SSRF (SSRF-001)
    url = request.args.get("url")
    r = requests.get(url)
    return r.text


def hash_password(pw):
    # Weak crypto (CRYPTO-001)
    return hashlib.md5(pw.encode()).hexdigest()


def old_hash(data):
    return hashlib.sha1(data).hexdigest()


if __name__ == "__main__":
    # Debug enabled (DEBUG-001)
    app.run(debug=True, host="0.0.0.0", port=5000)
