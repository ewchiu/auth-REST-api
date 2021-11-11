from flask import Flask, jsonify, request
from google.cloud import datastore
from uuid import uuid4
from google.auth.transport import requests
from google.oauth2 import id_token
import google.auth
import requests_oauthlib
import client_secret
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = str(uuid4)
client = datastore.Client()

CLIENT_ID = client_secret.client_id
CLIENT_SECRET = client_secret.client_secret
REDIRECT_URI = client_secret.redirect_uris

oauth = requests_oauthlib.OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=[
	'https://www.googleapis.com/auth/userinfo.email', 
	'https://www.googleapis.com/auth/userinfo.profile', 
	'openid'
])
oauth_url = 'https://accounts.google.com/o/oauth2/'

@app.route('/')
def index():
	auth_url, state = oauth.authorization_url(f'{oauth_url}auth', 
		access_type='offline', 
		prompt="select_account"
		)
	return f'<h1>Hello, please sign in and retrieve your JWT</h1> <a href={auth_url}>Sign in</a>'

@app.route('/oauth')
def oauth():
	token = oauth.fetch_token(f'{oauth_url}token', 
		auth_response=request.url, 
		client_secret=CLIENT_SECRET
	)
	return jsonify({'jwt': token['id_token']}), 200

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)