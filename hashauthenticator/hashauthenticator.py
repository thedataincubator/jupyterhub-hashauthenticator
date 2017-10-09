from jupyterhub.auth import Authenticator
from tornado import gen
from traitlets import Unicode, Integer
from passwordhash import generate_password_digest

class HashAuthenticator(Authenticator):
  secret_key = Unicode(
    config=True,
    help="Key used to encrypt usernames to produce passwords."
  )

  password_length = Integer(
    default_value=6,
    config=True,
    help="Password length.")

  @gen.coroutine
  def authenticate(self, handler, data):
    username = data['username']
    password = data['password']

    expected_password = generate_password_digest(username, self.secret_key, self.password_length)

    if password == expected_password:
      return username

    return None
