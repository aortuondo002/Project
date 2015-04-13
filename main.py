#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
import jinja2
from google.appengine.api import users
import os
import json

from webapp2_extras import sessions


app_id = 'wsproiektua'
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


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)



class MainHandler(BaseHandler):
    def get(self):
        user= users.get_current_user()
        if user:
            url = users.create_logout_url(self.request.uri)
            url_linktext = 'Logout'
        else:
            url = users.create_login_url(self.request.uri)
            url_linktext = 'Login'

        template_values = {
            'user': user,
            'url': url,
            'url_linktext': url_linktext
        }

        template = JINJA_ENVIRONMENT.get_template('jinja_template')
        self.response.write(template.render(template_values))




class OAuthHandler(BaseHandler):

    def get(self):
        logging.debug('ENTERING OAuthHandler --->')

        request_url = self.request.url
        code = request_url.split('code=')[1]

        http = httplib2.Http()
        metodoa = 'POST'
        url = 'https://api.twitter.com/oauth2/token'
        parametroak = {'grant_type': 'client_credentials'}
        parametroak = urllib.urlencode(parametroak)
        erantzuna, edukia = http.request(url,metodoa,body=parametroak,headers=[])
        json_edukia = json.loads(edukia)
        self.session['access_token'] = json_edukia['access_token']
        self.redirect('/RefreshLast3Tweets')


class RefreshLast3Tweets(BaseHandler):

    def get(self):
        logging.debug('ENTERING RefreshLast3Tweets --->')
        http = httplib2.Http()
        metodoa='GET'
        errekurtsoa= 'https://api.twitter.com/1.1/statuses/user_timeline.json?'
        parametroak = {'screen_name':users.get_current_user(),
                       'count':3,
                       'include_rts': False}
        parametroak = urllib.urlencode(parametroak)
        erantzuna = http.request(errekurtsoa,metodoa,body=parametroak,headers=None)
        print erantzuna

class SendTweetToTwitter(BaseHandler):

    def get(self):
        logging.debug('ENTERING SendTweetToTwitter --->')
        http = httplib2.Http()
        metodoa = 'POST'
        errekurtsoa = 'https://api.twitter.com/1.1/statuses/update.json'
        parametroak = {'status': self.request.get('tweet')}


def createAuthHeader(method, base_url, oauth_header, http_params, oauth_token_secret):
    oauth_header.update({'oauth_consumer_key': consumer_key,
                          'oauth_nonce': str(random.randint(0, 999999999)),
                          'oauth_signature_method': "HMAC-SHA1",
                          'oauth_timestamp': str(int(time.time())),
                          'oauth_version': "1.0"})
    oauth_header['oauth_signature'] = urllib.quote(createRequestSignature(method, base_url, oauth_header, http_params, oauth_token_secret), "")

    authorization_header = "OAuth "
    for each in sorted(oauth_header.keys()):
        if each == sorted(oauth_header.keys())[-1]:
            authorization_header = authorization_header \
                                 + each + "=" + "\"" \
                                 + oauth_header[each] + "\""
        else:
            authorization_header = authorization_header \
                                 + each + "=" + "\"" \
                                 + oauth_header[each] + "\"" + ", "

    return authorization_header


def createRequestSignature(method, base_url, oauth_header, http_params, oauth_token_secret):
    encoded_params = ''
    params = {}
    params.update(oauth_header)
    if http_params:
        params.update(http_params)
    for each in sorted(params.keys()):
        key = urllib.quote(each, "")
        value = urllib.quote(params[each], "")
        if each == sorted(params.keys())[-1]:
            encoded_params = encoded_params + key + "=" + value
        else:
            encoded_params = encoded_params + key + "=" + value + "&"

    signature_base = method.upper() + \
                   "&" + urllib.quote(base_url, "") + \
                   "&" + urllib.quote(encoded_params, "")

    signing_key = ''
    if oauth_token_secret == None:
        signing_key = urllib.quote(consumer_secret, "") + "&"
    else:
        signing_key = urllib.quote(consumer_secret, "") + "&" + urllib.quote(oauth_token_secret, "")

    hashed = hmac.new(signing_key, signature_base, hashlib.sha1)
    oauth_signature = binascii.b2a_base64(hashed.digest())

    return oauth_signature


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/oauth_callback', OAuthHandler),
    ('/RefreshLast3Tweets', RefreshLast3Tweets),
    ('/SendTweetToTwitter', SendTweetToTwitter),
], config=config, debug=True)
