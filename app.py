from flask import Flask, jsonify, request, redirect, session, url_for
from google.cloud import datastore
from uuid import uuid4
from google.oauth2 import id_token
from google.auth.transport import requests as reqs
import google_auth_oauthlib.flow
import client_secret
import os

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

app = Flask(__name__)
app.secret_key = str(uuid4)

client = datastore.Client()

SCOPES = [
	'https://www.googleapis.com/auth/userinfo.profile', 
	'openid'
]
API_SERVICE_NAME = 'userinfo'
API_VERSION = 'v2'

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
		access_type='offline'
		)

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
	session['credentials'] = credentials_to_dict(credentials)
	
	req = reqs.Request()
	id = id_token.verify_oauth2_token(token['id_token'], req, client_secret.client_id)

	return f"<p>your JWT is: {token['id_token']}</p> <p>decoded JWT: {id}</p>"

@app.route("/boats", methods=['POST','GET'])
def boats_get_post():

    # create new boat
	if request.method == "POST":
		content = request.get_json()
		jwt = request.headers.get('Authorization')

		if jwt:
			req = reqs.Request()

			try:
				sub = id_token.verify_oauth2_token(jwt, req, client_secret.client_id)
				sub = sub['sub']
			except:
				return 'The provided JWT could not be verified', 401

		else:
			return 'Please specify the JWT', 401

		if 'name' not in content or 'type' not in content or 'length' not in content or 'public' not in content or len(content) != 4:
			error = {"Error": "The request object is missing at least one of the required attributes"}
			return jsonify(error), 400

        # create new boat in Datastore
		new_boats = datastore.entity.Entity(key=client.key("boats"))
		new_boats.update({"name": content["name"], "type": content["type"], 
			"length": content["length"], "public": content["public"], "owner": sub})
		client.put(new_boats)

        # formats response object
		added_boat = {"id": new_boats.key.id, "name": content["name"], "type": content["type"],
			"length": content["length"], "public": content["public"], "owner": sub}

		return jsonify(added_boat), 201

    # get list of boats
	elif request.method == 'GET':
		display_public = False
		req = reqs.Request()
		jwt = request.headers.get('Authorization')

		if jwt:
			req = reqs.Request()

			try:
				sub = id_token.verify_oauth2_token(jwt, req, client_secret.client_id)
				sub = sub['sub']
			except Exception as e:
				display_public = True
				print(f'Error in auth {e}')
		
		else:
			display_public = True

		query = client.query(kind="boats")
		
		if display_public:
			query.add_filter("public", "=", True)
		else:
			query.add_filter("owner", "=", sub)

		results = list(query.fetch())

		for e in results:
			e["id"] = e.key.id

		return jsonify(results), 200

	else:
		return 'Method not recognized'

@app.route("/owners/<id>/boats", methods=['GET'])
def owner_get_boats(id):
	if request.method == 'GET':
		query = client.query(kind="boats")
		query.add_filter("public", "=", True)
		query.add_filter("owner", "=", id)
		results = list(query.fetch())

		for e in results:
			e["id"] = e.key.id

		return jsonify(results), 200

@app.route('/boats/<id>', methods=['DELETE'])
def delete_boat(id):
	if request.method == 'DELETE':
		boat_key = client.key('boats', int(id))
		boat = client.get(key=boat_key)

		jwt = request.headers.get('Authorization')

		if jwt:
			req = reqs.Request()

			try:
				sub = id_token.verify_oauth2_token(jwt, req, client_secret.client_id)
				sub = sub['sub']
			except Exception as e:
				print(e)
				return 'The provided JWT could not be verified', 401

		else:
			return 'Please specify the JWT', 401

		if not boat:
			error = {"Error": "No boat with this boat_id exists"}
			return jsonify(error), 403

		elif boat['owner'] != sub:
			error = {"Error": "You are not the owner of this boat"}
			return jsonify(error), 403

		client.delete(boat_key)
		return '', 204

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
	# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

	app.run(host='0.0.0.0', debug=True)