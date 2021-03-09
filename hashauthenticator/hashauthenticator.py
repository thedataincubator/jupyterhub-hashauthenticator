import csv

from jupyterhub import orm
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import admin_only
from oauthenticator.google import GoogleOAuthenticator
from tornado import gen
from tornado.httputil import url_concat
from tornado.web import Finish, HTTPError
from traitlets import Unicode, Integer, Bool, default

from .passwordhash import generate_password_digest


class PasswordHandler(BaseHandler):

  def initialize(self, get_password, admin_suffix):
    self.get_password = get_password
    self.admin_suffix = admin_suffix

  @admin_only
  def get(self):
    users = sorted((u.name, self.get_password(u.name))
                   for u in self.db.query(orm.User)
                   if not (self.admin_suffix and u.name.endswith(self.admin_suffix)))
    self.set_header('content-type', 'text/plain')
    csv.writer(self).writerows(users)


def make_hash_authenticator(class_name, AdminAuthenticator=None):
  admin_auth = True
  if not AdminAuthenticator:
    AdminAuthenticator = Authenticator
    admin_auth = False

  class NewAuthenticator(AdminAuthenticator):
    secret_key = Unicode(
      config=True,
      help="Key used to encrypt usernames to produce passwords."
    )

    password_length = Integer(
      default_value=6,
      config=True,
      help="Password length."
    )

    show_logins = Bool(
      default_value=False,
      config=True,
      help="Display login information to admins at /hub/login_list."
    )

    admin_suffix = Unicode(
      default_value='@',
      config=True,
      help="A suffix to separate users logged in through the admin authenticator."
    )

    @default('login_service')
    def default_login_service(self):
      # Show the username/password entry
      return ''

    def get_password(self, username):
      return generate_password_digest(username, self.secret_key, self.password_length)

    @gen.coroutine
    def authenticate(self, handler, data):
      if not data:
        if not admin_auth:
          # We should never be in this state
          raise HTTPError(503, "Incorrect authentication")

        retval = yield super().authenticate(handler, data)
        if retval is None:
          return None
        if isinstance(retval, str):
          retval = {'name': retval}

        retval['name'] += self.admin_suffix
        retval['admin'] = True
        if self.allowed_users:
          self.allowed_users.add(retval['name'])
        # The whitelist is deprecated, but we'll support it if present.
        if self.whitelist:
          self.whitelist.add(retval['name'])
        return retval

      username = data['username']
      password = data['password']

      if admin_auth and username.endswith(self.admin_suffix):
        handler.redirect(url_concat(self.login_url(handler.hub.base_url),
                                    {'next': handler.get_argument('next', '')}))
        raise Finish

      if password == self.get_password(username):
        return username

      return None

    def get_handlers(self, app):
      extra_handers = []
      if self.show_logins:
        extra_handers = [('/login_list', PasswordHandler,
                         {'get_password': self.get_password,
                          'admin_suffix': self.admin_suffix if admin_auth else None})]

      return super().get_handlers(app) + extra_handers

  NewAuthenticator.__name__ = class_name
  return NewAuthenticator


HashAuthenticator = make_hash_authenticator('HashAuthenticator')
GoogleHashAuthenticator = make_hash_authenticator('GoogleHashAuthenticator', GoogleOAuthenticator)
