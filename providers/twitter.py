import logging

import requests


logger = logging.getLogger(__name__)


# https://developer.twitter.com/en/docs/authentication/oauth-2-0/user-access-token
class TwitterProvider:


    def __init__(self, configs):
        self.client_id = configs['client_id']
        self.redirect_uri = configs['redirect_uri']
        self.scope = configs['scope']
        self.accept_users = configs['accept_users']


    def get_authorize_uri(self, session):
        uri = (f'https://twitter.com/i/oauth2/authorize?response_type=code&'
            + f'client_id={self.client_id}&redirect_uri={self.redirect_uri}&'
            + f'scope={self.scope}&state={session.state}&'
            + f'code_challenge={session.code_challenge}&'
            + f'code_challenge_method={session.code_challenge_method}')
        logger.info(uri)
        return uri


    def get_token(self, args, session):
        if not {'state', 'code'}.issubset(args.keys()):
            return False
        if args['state'] != session.state:
            return False

        resp = requests.post('https://api.twitter.com/2/oauth2/token',
            data={
                'code': args['code'],
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'redirect_uri': self.redirect_uri,
                'code_verifier': session.code_verifier
            }
        )
        logger.info(resp.json())

        session.set_expires_in(resp.json()['expires_in'])
        session.access_token = resp.json()['access_token']
        session.refresh_token = resp.json()['refresh_token']

        return True


    def check_user(self, session):
        resp = requests.get('https://api.twitter.com/2/users/me',
            headers={
                'Authorization': f'Bearer {session.access_token}'
            }
        )
        logger.info(resp.json())

        if resp.json()['data']['id'] not in self.accept_users:
            return False

        return True


    def refresh_token(self, session):
        resp = requests.post('https://api.twitter.com/2/oauth2/token',
            data={
                'refresh_token': session.refresh_token,
                'grant_type': 'refresh_token',
                'client_id': self.client_id
            }
        )
        logger.info(resp.json())

        session.set_expires_in(resp.json()['expires_in'])
        session.access_token = resp.json()['access_token']
        session.refresh_token = resp.json()['refresh_token']

        return True
