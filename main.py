#!/usr/bin/env python


import logging
import os
from datetime import datetime
from distutils.util import strtobool

from flask import Flask, request, abort, redirect, url_for, make_response

from providers.providers import Providers
from oauth2_session import Oauth2Sessions


configs = {
    'provider': os.environ['PROVIDER'],
    'client_id': os.environ['CLIENT_ID'],
    'redirect_uri': os.environ['REDIRECT_URI'],
    'scope': os.environ['SCOPE'],
    'accept_users': os.environ['ACCEPT_USERS'].split(','),
    'max_sessions': int(os.environ['MAX_SESSIONS']),
    'debug': bool(strtobool(os.environ.get('DEBUG', 'False')))
}

if configs['debug']:
    logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
provider = Providers[configs['provider']](configs)
sessions = Oauth2Sessions(configs['max_sessions'])
accepted_sessions = Oauth2Sessions(configs['max_sessions'])


@app.route('/oauth2/auth')
def auth():
    session = accepted_sessions.get(
        request.cookies.get('session_id', '')
    )

    if session:
        if check_expires_at(session):
            return make_response('', 204)
        else:
            accepted_sessions.delete(session)

    abort(401)


def check_expires_at(session):
    if not session.expires_at:
        return False

    if session.expires_at > datetime.utcnow():
        return True

    if provider.refresh_token(session):
        return True

    return False


@app.route('/oauth2/start')
def start():
    if 'X-Original-URI' not in request.headers:
        abort(400)

    session = sessions.create()
    session.original_uri = request.headers.get('X-Original-URI')

    uri = provider.get_authorize_uri(session)

    # https://flask.palletsprojects.com/en/2.0.x/api/#flask.redirect
    # https://flask.palletsprojects.com/en/2.0.x/api/#flask.Response.set_cookie
    resp = redirect(uri)
    resp.set_cookie(
        'session_id',
        value=session.id,
        #max_age=
        #expires=
        #path=
        #domain=
        #secure=
        httponly=True
        #samesite=
    )

    return resp


@app.route('/oauth2/callback')
def callback():
    session = sessions.get(
        request.cookies.get('session_id', '')
    )

    if not session:
        abort(401)

    sessions.delete(session)

    if not session.original_uri:
        abort(400)

    if not provider.get_token(request.args, session):
        abort(401)

    if not provider.check_user(session):
        abort(403)

    accepted_sessions.add(session)

    return redirect(session.original_uri)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=configs['debug'])
