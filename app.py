from flask import Flask, jsonify, request, redirect, session, url_for
from google.cloud import datastore
from uuid import uuid4
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import requests
import requests_oauthlib
import os
import constants

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

app = Flask(__name__)
app.secret_key = str(uuid4)

client = datastore.Client()

SCOPES = [
	'https://www.googleapis.com/auth/userinfo.email', 
	'https://www.googleapis.com/auth/userinfo.profile', 
	'openid'
]
API_SERVICE_NAME = 'userinfo'
API_VERSION = 'v2'

oauth_url = 'https://accounts.google.com/o/oauth2/'

@app.route('/')
def index():
	if 'credentials' not in session:
		return redirect('authorize')

	return f'<h1>you are already signed in, navigate here using the API</h1>'

@app.route('/authorize')
def authorize():
	# Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
	flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
	CLIENT_SECRETS_FILE, scopes=SCOPES)

	flow.redirect_uri = url_for('oauth2callback', _external=True)

	authorization_url, state = flow.authorization_url(
		# Enable offline access so that you can refresh an access token without
		# re-prompting the user for permission. Recommended for web server apps.
		access_type='offline',
		# Enable incremental authorization. Recommended as a best practice.
		include_granted_scopes='true')

	# Store the state so the callback can verify the auth server response.
	session['state'] = state

	return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
	# Specify the state when creating the flow in the callback so that it can
	# verified in the authorization server response.
	state = session['state']

	flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
		CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
	flow.redirect_uri = url_for('oauth2callback', _external=True)

	# Use the authorization server's response to fetch the OAuth 2.0 tokens
	token = flow.fetch_token(authorization_response=request.url)

	# Store credentials in the session.
	credentials = flow.credentials
	params = credentials_to_dict(credentials)
	session['credentials'] = params
	
	params['grant_type'] = 'authorization_code'
	response = requests.post("https://oauth2.googleapis.com/token", data=params).json()
	print("token response: " + str(response))
	token = response['access_token']
	return f"<h1>your JWT is: {token['id_token']}"


def credentials_to_dict(credentials):
	return {'token': credentials.token,
			'refresh_token': credentials.refresh_token,
			'token_uri': credentials.token_uri,
			'client_id': credentials.client_id,
			'client_secret': credentials.client_secret,
			'scopes': credentials.scopes
			}




if __name__ == '__main__':
	# When running locally, disable OAuthlib's HTTPs verification.
	# ACTION ITEM for developers:
	#     When running in production *do not* leave this option enabled.
	os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

	app.run(host='127.0.0.1', port=8080, debug=True)