import re
from flask import Flask, request, abort

app = Flask(__name__)

# Common attack patterns
SQL_INJECTION_PATTERNS = [
    r"(\b(union|select|insert|delete|update|drop|alter)\b.*\b(from|into|table)\b)",
    r"[';]-{2}",
]
XSS_PATTERNS = [
    r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
    r"on\w+=",
]

def waf_middleware():
    query = request.args.get('q', '')
    # Check for SQL injection
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            with open('waf_log.txt', 'a') as log:
                log.write(f"Blocked SQL Injection: {query}\n")
            abort(403, description="Blocked: Potential SQL Injection detected")
    # Check for XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            with open('waf_log.txt', 'a') as log:
                log.write(f"Blocked XSS: {query}\n")
            abort(403, description="Blocked: Potential XSS detected")
    return None

@app.before_request
def apply_waf():
    waf_middleware()

@app.route('/')
def home():
    return "Welcome to the test app!"

@app.route('/submit', methods=['GET'])
def submit():
    query = request.args.get('q', '')
    return f"You submitted: {query}"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
