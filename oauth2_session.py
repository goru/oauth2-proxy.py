import base64
import hashlib
import random
import string
import uuid

from collections import OrderedDict
from datetime import datetime, timedelta


class Oauth2Sessions:


    def __init__(self, max_sessions):
        self.max_sessions = max_sessions
        self.sessions = OrderedDict()


    def create(self):
        session = Oauth2Session()
        self.sessions[session.id] = session

        # max sessions
        if len(self.sessions) > self.max_sessions:
            self.sessions.popitem(last=False)

        return session


    def get(self, session_id):
        if session_id not in self.sessions:
            return None
        return self.sessions[session_id]


    def delete(self, session):
        del self.sessions[session.id]


class Oauth2Session:


    def __init__(self):
        self.id = str(uuid.uuid4())
        # https://openid-foundation-japan.github.io/rfc6749.ja.html#anchor58
        self.state = self.random_string(32)
        # https://openid-foundation-japan.github.io/rfc5849.ja.html#nonce
        self.nonce = self.random_string(32)
        # https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
        # https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
        self.code_verifier = self.random_string(128)
        self.code_challenge = self.generate_code_challenge(self.code_verifier)
        self.code_challenge_method = 's256'

        self.expires_in = None
        self.expires_at = None
        self.access_token = None
        self.refresh_token = None

        self.original_uri = None


    def random_string(self, n):
        return ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])


    def generate_code_challenge(self, verifier):
        m = hashlib.sha256()
        m.update(verifier.encode('utf-8'))
        # https://docs.python.org/ja/3/library/base64.html#base64.urlsafe_b64encode
        return base64.urlsafe_b64encode(m.digest()).decode().replace('=', '')


    def set_expires_in(self, expires_in):
        self.expires_in = expires_in
        self.expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
