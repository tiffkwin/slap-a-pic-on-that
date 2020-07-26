import os
from flask import Flask, session, request, redirect, render_template
from flask_session import Session
import requests
import spotipy
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_TYPE'] = 'filesystem'

Session(app)

scope='user-read-email'
CACHE_PATH="cache.txt"
REDIRECT_URI = 'http://127.0.0.1:5000'
CLIENT_ID = os.getenv('SPOTIPY_CLIENT_ID')
CLIENT_SECRET = os.getenv('SPOTIPY_CLIENT_SECRET')

auth_manager = spotipy.oauth2.SpotifyOAuth(scope=scope, cache_path=CACHE_PATH)
spotify = spotipy.Spotify(auth_manager=auth_manager)

@app.route('/')
def index():
    if request.args.get("code"):
        payload = {
            'grant_type': 'authorization_code',
            'code': request.args.get("code"),
            'redirect_uri': REDIRECT_URI}
        print(payload)

        auth_str = bytes('{}:{}'.format(CLIENT_ID, CLIENT_SECRET), 'utf-8')
        b64_auth_str = base64.b64encode(auth_str).decode('utf-8')

        headers = {
            'Authorization': 'Basic {}'.format(b64_auth_str)
        }

        r = requests.post('https://accounts.spotify.com/api/token', data=payload, headers=headers)
        print(r.json())
        session['token_info'] = r.json()['access_token']
        return redirect('/welcome')

    if not session.get('token_info'):
        auth_url = auth_manager.get_authorize_url()
        return render_template("index.html", auth_url=auth_url)

    
@app.route('/welcome')
def welcome():
    headers = {
            'Authorization': 'Bearer {}'.format(session['token_info'])
        }
    r = requests.get('https://api.spotify.com/v1/me', headers=headers)
    data = r.json()
    print(data)

    return render_template('dashboard.html', name=data['display_name'])

@app.route('/sign_out')
def sign_out():
    session.clear()
    return redirect('/')


@app.route('/playlists')
def playlists():
    if not session.get('token_info'):
        return redirect('/')
    else:
        return spotify.current_user_playlists()

if __name__ == '__main__':
    app.run(debug=True)

# with open("IMG_9521.jpeg", "rb") as image_file:
#     encoded_string = base64.b64encode(image_file.read())
#     print(encoded_string)