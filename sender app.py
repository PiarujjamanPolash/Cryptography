from flask import Flask, request, render_template_string
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os
import requests
from urllib.parse import urljoin

app = Flask(__name__)

SENDER_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>File Integrity Sender</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="file"], input[type="text"] { width: 100%; padding: 8px; }
        button { padding: 10px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        .result { margin-top: 20px; padding: 10px; border: 1px solid #ddd; }
        .error { color: #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>File Integrity Sender</h1>
        <form action="/send" method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label for="file">Select File to Send:</label>
                <input type="file" id="file" name="file" required>
            </div>
            <div class="form-group">
                <label for="receiver_url">Receiver URL:</label>
                <input type="text" id="receiver_url" name="receiver_url"
                       placeholder="https://devpolash2.pythonanywhere.com" required>
                <small>Base URL of the receiver (system will append '/receive' if needed)</small>
            </div>
            <button type="submit">Send File</button>
        </form>
        {% if result %}
        <div class="result {% if error %}error{% endif %}">
            <h2>Result:</h2>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

class Sender:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.load_or_generate_keys()

    def load_or_generate_keys(self):
        key_file = 'sender_private.pem'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.private_key = RSA.import_key(f.read())
        else:
            self.private_key = RSA.generate(2048)
            with open(key_file, 'wb') as f:
                f.write(self.private_key.export_key('PEM'))

        self.public_key = self.private_key.publickey()

    def process_file(self, file_content):
        file_hash = SHA256.new(file_content)
        signature = pkcs1_15.new(self.private_key).sign(file_hash)

        return {
            'file_content': base64.b64encode(file_content).decode(),
            'signature': base64.b64encode(signature).decode(),
            'public_key': self.public_key.export_key().decode(),
            'hash': file_hash.hexdigest()
        }

sender = Sender()

def normalize_url(url):
    # Ensure URL ends with '/receive'
    if not url.endswith('/receive'):
        return urljoin(url.rstrip('/') + '/', 'receive')
    return url

@app.route('/')
def home():
    return render_template_string(SENDER_HTML)

@app.route('/send', methods=['POST'])
def send_file():
    if 'file' not in request.files:
        return render_template_string(SENDER_HTML, result='No file selected', error=True)

    file = request.files['file']
    receiver_url = request.form['receiver_url'].strip()

    if file.filename == '':
        return render_template_string(SENDER_HTML, result='No file selected', error=True)

    try:
        # Normalize the URL
        normalized_url = normalize_url(receiver_url)

        # Read and process the file
        file_content = file.read()
        processed_data = sender.process_file(file_content)

        # Send to Server 2
        response = requests.post(
            normalized_url,
            json=processed_data,
            timeout=10,
            verify=False  # Only if the receiver uses self-signed certificate
        )
        response.raise_for_status()

        try:
            result = f"File sent successfully to {normalized_url}\nReceiver response:\n{response.json()}"
        except ValueError:
            result = f"File sent to {normalized_url}, but receiver returned non-JSON response:\n{response.text}"

    except requests.RequestException as e:
        result = f"Error sending file to receiver ({normalized_url}): {str(e)}"
        return render_template_string(SENDER_HTML, result=result, error=True)
    except Exception as e:
        result = f"Error processing file: {str(e)}"
        return render_template_string(SENDER_HTML, result=result, error=True)

    return render_template_string(SENDER_HTML, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)