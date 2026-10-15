import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# VULN 1: secreto hardcodeado
API_KEY = os.environ.get("API_KEY", "test-key-not-a-real-secret")

# VULN 2: command injection (shell=True + input de usuario)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)

# VULN 3: uso de eval sobre input externo
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)