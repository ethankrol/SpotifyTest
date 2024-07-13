import json
import secrets
import urllib.parse
from datetime import datetime, timedelta

import requests
from flask import Flask,redirect,request,jsonify,session, render_template
from dotenv import load_dotenv
import os
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

load_dotenv()

client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
auth_url = os.getenv('AUTH_URL')
token_url = os.getenv('TOKEN_URL')
api_base_url = os.getenv('API_BASE_URL')
redirect_uri = os.getenv('REDIRECT_URI')

@app.route('/')
def index():
    return "welcome to my spotify <a href='/login'>login with spotify</a>"

@app.route('/login')
def login():
    scope = 'user-read-private user-read-email user-top-read'
    param = {
        'client_id' : client_id,
        'response_type' : 'code',
        'scope' : scope,
        'redirect_uri' : redirect_uri,
        'show_dialog' : True
    }

    login_url = f'{auth_url}?{urllib.parse.urlencode(param)}'
    return redirect(login_url)

@app.route('/callback')
def callback():
    if 'error' in request.args:
        return jsonify({"error": request.args['error']})

    if 'code' in request.args:
        req_body = {
            'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri' : redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret
        }

        response = requests.post(token_url, data=req_body)
        token_info = response.json()

        session['access_token'] = token_info['access_token']
        session['refresh_token'] = token_info['refresh_token']
        session['expires_at'] = datetime.now().timestamp() + token_info['expires_in']

        return redirect('/artists')

@app.route('/artists')
def get_top_artists():
    if 'access_token' not in session:
        return redirect('/login')

    if datetime.now().timestamp() > session['expires_at']:
        print('Token expired, refreshing...')
        return redirect('/refresh-token')

    headers= {
        'Authorization' : f"Bearer {session['access_token']}"
    }

    response = requests.get(api_base_url + 'me/top/artists?limit=50&time_range=long_term', headers = headers)
    artists = response.json()
    json_data = json.dumps(artists)
    data = json.loads(json_data)
    names = [item['name'] for item in data['items']]

    return render_template('top_artists.html', names=names)

@app.route('/refresh-token')
def refresh_token():
    if 'refresh_token' not in session:
        return redirect('/login')
    if datetime.now().timestamp() > session['expires_at']:
        print('token expired, refreshing...')
        req_body = {
            'grant_type' : 'refresh_token',
            'refresh_token' : session['refresh_token'],
            'client_id' : client_id,
            'client_secret' : client_secret
        }
    response = requests.post(token_url, data=req_body)
    new_token_info = response.json()

    session['access_token'] = new_token_info['access_token']
    session['expires_at'] = datetime.now().timestamp() + 10

    return redirect('/artists')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)

"""def get_token():
    auth_string = client_id + ":" + client_secret
    auth_bytes = auth_string.encode("utf-8")
    auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")
    url = "https://accounts.spotify.com/api/token"
    headers = {
        "Authorization" : "Basic " + auth_base64,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {"grant_type" : "client_credentials"}
    result = post(url, headers=headers, data=data)
    json_result = json.loads(result.content)
    token = json_result["access_token"]
    return token

def get_auth_header(token):
    return {"Authorization" : "Bearer " + token}

def get_top_artists(token):
    url = "https://api.spotify.com/v1/me/top/artists?limit=50&time_range=long_term"
    header = get_auth_header(token)

    result = get(url,headers=header)
    json_result = json.loads(result.content)
    print(json_result)



token = get_token()
get_top_artists(token)"""