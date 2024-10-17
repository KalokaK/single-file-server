from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# Define a simple API key for authentication
API_KEY_PATH = "api.key"

# File to store the content
FILE_PATH = "data.txt"

# POST endpoint to save data
@app.route('/save', methods=['POST'])
def save_data():
    api_key = request.headers.get('X-API-KEY')
    
    if api_key != app.config["API_KEY"]:
        return abort(403, description="Invalid API key")

    data = request.get_json()

    if data:
        # Save the content to the file
        with open(FILE_PATH, 'w') as file:
            file.write(str(data))
        return jsonify({"message": "Data saved successfully"}), 200
    else:
        return jsonify({"message": "No data provided"}), 400

# GET endpoint to retrieve data
@app.route('/get', methods=['GET'])
def get_data():
    api_key = request.headers.get('X-API-KEY')

    if api_key != app.config["API_KEY"]:
        return abort(403, description="Invalid API key")

    try:
        # Read the content from the file
        with open(FILE_PATH, 'r') as file:
            data = file.read()
        return jsonify({"data": data}), 200
    except FileNotFoundError:
        return jsonify({"message": "File not found"}), 404

if __name__ == '__main__':
    with open(API_KEY_PATH, "r") as fp:
        app.config["API_KEY"] = fp.read()

    app.run(host='0.0.0.0', port=5001)
