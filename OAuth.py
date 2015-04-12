
import webapp2
import httplib2
import urllib
import json
import base64
import random
import time
import hmac
import binascii
import hashlib
import logging

from webapp2_extras import sessions

app_id = 'wsproiektua2'
consumer_key= 'kn5h9Ugc1cqbdgKVytnGtLgHX'
consumer_secret = '9DywYgURVynwo491diML5g9p3BL9DHAwA3yofZhFHUqpj4CeyS'
callback_url = 'https://' + app_id + '.appspot.com/oauth_callback'

class BaseHandler(webapp2.RequestHandler):

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

config = {}
config['webapp2_extras.sessions'] = {'secret_key': 'my-super-secret-key'}

class OAuthHandler(BaseHandler):

    def get(self):
        logging.debug('ENTERING OAuthHandler --->')

        request_url = self.request.url
        code = request_url.split('code=')[1]

        http = httplib2.Http()
        metodoa = 'POST'
        url = 'https://api.twitter.com/oauth2/token'
        parametroak = {'code': code,
                       'grant_type': 'authorization_code',
                       'client_id': consumer_key,
                       'client_secret': consumer_secret}
        parametroak = urllib.urlencode(parametroak)

        erantzuna, edukia = http.request(url,metodoa,body=parametroak,headers=[])


        json_edukia = json.loads(edukia)
        print (json_edukia)
        self.session['access_token'] = json_edukia['access_token']

        self.redirect('/')