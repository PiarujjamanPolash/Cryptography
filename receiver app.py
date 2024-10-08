from flask import Flask, request, render_template_string, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

app = Flask(__name__)

RECEIVER_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>File Integrity Receiver</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .received-file { margin-top: 20px; padding: 10px; border: 1px solid #ddd; }
        .status { margin-top: 10px; padding: 10px; }
        .status.verified { background-color: #dff0d8; border-color: #d6e9c6; color: #3c763d; }
        .status.error { background-color: #f2dede; border-color: #ebccd1; color: #a94442; }
    </style>
</head>
<body>
    <div class="container">
        <h1>File Integrity Receiver</h1>
        {% if files %}
            {% for file in files %}
            <div class="received-file">
                <h3>Received File #{{ loop.index }}</h3>
                <div class="status {{ 'verified' if file.verified else 'error' }}">
                    {{ file.status }}
                </div>
                <p>Hash: {{ file.hash }}</p>
            </div>
            {% endfor %}
        {% else %}
            <p>No files received yet.</p>
        {% endif %}
    </div>
</body>
</html>
'''

class Receiver:
    def __init__(self):
        self.received_files = []

    def verify_file(self, data):
        try:
            # Extract data
            file_content = base64.b64decode(data['file_content'])
            signature = base64.b64decode(data['signature'])
            public_key = RSA.import_key(data['public_key'])
            received_hash = data['hash']

            # Step 1: Verify the signature and hash
            file_hash = SHA256.new(file_content)

            # Verify signature
            try:
                pkcs1_15.new(public_key).verify(file_hash, signature)
                signature_valid = True
            except (ValueError, TypeError):
                signature_valid = False

            # Verify hash
            calculated_hash = file_hash.hexdigest()
            hash_matches = calculated_hash == received_hash

            # Step 2: Determine if file was modified
            if signature_valid and hash_matches:
                status = "File integrity verified - Not modified in transit"
                verified = True
            else:
                status = "WARNING: File may have been modified in transit"
                verified = False

            self.received_files.append({
                'verified': verified,
                'status': status,
                'hash': calculated_hash
            })

            return {
                'status': status,
                'verified': verified
            }

        except Exception as e:
            return {
                'status': f"Error verifying file: {str(e)}",
                'verified': False
            }

receiver = Receiver()

@app.route('/')
def home():
    return render_template_string(RECEIVER_HTML, files=receiver.received_files)

@app.route('/receive', methods=['POST'])
def receive_file():
    if not request.is_json:
        return jsonify({'error': 'Expected JSON data'}), 400

    data = request.json
    required_fields = ['file_content', 'signature', 'public_key', 'hash']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    result = receiver.verify_file(data)
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5001)