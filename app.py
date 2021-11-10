from flask import Flask, jsonify, request
from google.cloud import datastore

app = Flask(__name__)
client = datastore.Client()

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)