__author__ = 'Aitor'

import webapp2
import jinja2
from google.appengine.api import users
import os
import json
from time import gmtime

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)



class MainHandler(webapp2.RequestHandler):
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


app=webapp2.WSGIApplication([
    ('/', MainHandler),
    ],debug=True)
