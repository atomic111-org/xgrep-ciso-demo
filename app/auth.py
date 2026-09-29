"""Authentication helpers.

Demonstrates weak password hashing, a hardcoded signing secret, and a JWT
verification that accepts the 'none' algorithm.
"""
import hashlib
import os

import jwt

# Signing secret is loaded from the environment, never committed to source control.
JWT_SIGNING_SECRET = os.environ["JWT_SECRET"]


def hash_password(password):
    # SINK: MD5 is cryptographically broken for password storage.
    return hashlib.md5(password.encode()).hexdigest()


def issue_token(username, password):
    digest = hash_password(password)
    return jwt.encode({"sub": username, "pw": digest}, JWT_SIGNING_SECRET, algorithm="HS256")


def verify_token(token):
    # SINK: verify_signature disabled + 'none' allowed -> forged tokens accepted.
    return jwt.decode(
        token,
        JWT_SIGNING_SECRET,
        algorithms=["HS256"],
    )
