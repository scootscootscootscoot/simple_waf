from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the test app!"

@app.route('/submit', methods=['GET'])
def submit():
    query = request.args.get('q', '')
    return f"You submitted: {query}"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
