import requests
from flask import Response, jsonify, request, _request_ctx_stack
from functools import wraps
from jose import jwt

from .auth_error import AuthError
from flask_auth0 import AUTH0_DOMAIN, AUTH0_ALGORITHMS, AUTH0_API_AUDIENCE


def handle_auth_error(error: AuthError) -> Response:
    response: Response = jsonify(error.error)
    response.status_code = error.status_code

    return response


def get_token_auth_header() -> str:
    """Retrieves the Access Token from the active flask request's Authorization Header"""
    auth = request.headers.get('Authorization', None)

    if not auth:
        raise AuthError({'code': 'authorization_header_missing',
                         'description': 'Authorization header is expected'}, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise AuthError({'code': 'invalid_header',
                         'description': 'Authorization must start with Bearer'}, 401)

    elif len(parts) == 1:
        raise AuthError({'code': 'invalid_header',
                         'description': 'Token not found'}, 401)

    elif len(parts) > 2:
        raise AuthError({'code': 'invalid_header',
                         'description': 'Authorization header must be Bearer token'}, 401)

    return parts[1]


def requires_auth(f):
    """Determines if the active Access Token is valid"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jwks = requests.get('https://{}/.well-known/jwks.json'.format(AUTH0_DOMAIN)).json()
        unverified_header = jwt.get_unverified_headers(token)
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = key

        if rsa_key:
            try:
                payload = jwt.decode(token, rsa_key, algorithms=AUTH0_ALGORITHMS, audience=AUTH0_API_AUDIENCE,
                                     issuer='https://{}/'.format(AUTH0_DOMAIN))
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "Token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description": 'Incorrect claims, please check the audience and issuer'}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description": 'Unable to parse authentication token.'}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)

        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)
    return decorated


def requires_scope(required_scope: str) -> bool:
    """Determines if the required scope exists on the active Access Token"""
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False
