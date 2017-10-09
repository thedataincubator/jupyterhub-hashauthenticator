import hashlib, binascii

def generate_password_digest(username, secret_key, length=6):
  dk = hashlib.pbkdf2_hmac('sha256', username.encode(), secret_key.encode(), 25000)
  password_digest = binascii.hexlify(dk).decode()

  return password_digest[:length]
