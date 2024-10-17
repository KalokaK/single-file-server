from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import logging
import json

app = Flask(__name__)
logging.basicConfig(filename="app.log")
# Define a simple API key for authentication
API_KEY_PATH = "api.key"

# File to store the content
FILE_PATH = "data.txt"

# Helper functions for encryption and decryption using AES
def encrypt_data(key: bytes, data: str) -> bytes:
    # AES requires a 16-byte IV (initialization vector), which should be unique for each encryption
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to the encrypted data for decryption

def decrypt_data(key: bytes, encrypted_data: bytes) -> str:
    iv = encrypted_data[:16]  # The first 16 bytes are the IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data.decode()

# POST endpoint to save data (with encryption)
@app.route('/save', methods=['POST'])
def save_data():
    logging.debug(request.headers)

    data = request.get_json()
    # {'interaction': 'Retrying memory save operation on October 17, 2024.', 
    # 'encryptionKey': 'BhspQHYH5IEPlp/84R+FrbhfEEB5cDbQSYae4WIRkl0='}
    message = data['interaction']
    encryption_key = data['encryptionKey']

    api_key = request.headers.get('X-API-KEY')
    encryption_key = base64.b64decode(encryption_key)

    if api_key != app.config["API_KEY"]:
        return abort(403, description="Invalid API key")

    if not encryption_key or len(encryption_key) != 32:  # AES-256 requires a 32-byte key
        return abort(400, description="Invalid encryption key. Must be 32 bytes.")

    data = message
    if data:
        # Encrypt the data with the user-provided key
        encrypted_data = encrypt_data(encryption_key, str(data))

        # Save the encrypted data to the file
        with open(FILE_PATH, 'wb') as file:
            file.write(encrypted_data)
        return jsonify({"message": "Data saved and encrypted successfully"}), 200
    else:
        return jsonify({"message": "No data provided"}), 400

# GET endpoint to retrieve data (with decryption)
@app.route('/get', methods=['GET'])
def get_data():
    
    data = request.get_json()
    encryption_key = data['encryptionKey']

    api_key = request.headers.get('X-API-KEY')
    encryption_key = base64.b64decode(encryption_key)

    if api_key != app.config["API_KEY"]:
        return abort(403, description="Invalid API key")

    if not encryption_key or len(encryption_key) != 32:
        return abort(400, description="Invalid encryption key. Must be 32 bytes.")

    try:
        # Read the encrypted data from the file
        with open(FILE_PATH, 'rb') as file:
            encrypted_data = file.read()

        # Decrypt the data with the user-provided key
        decrypted_data = decrypt_data(encryption_key, encrypted_data)
        return jsonify({"data": decrypted_data}), 200
    except FileNotFoundError:
        return jsonify({"message": "File not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error decrypting data: {str(e)}"}), 500


if __name__ == '__main__':
    with open(API_KEY_PATH, "r") as fp:
        app.config["API_KEY"] = fp.read()[:-1]

    app.run(host='0.0.0.0', port=5001, use_debugger=False, use_reloader=False, passthrough_errors=True)
