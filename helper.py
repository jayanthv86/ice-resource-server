from functools import wraps
from base64 import b64encode
from jose import jwt
from flask import Flask, jsonify, request, _app_ctx_stack, json
import requests

ALGORITHMS = ["RS256"]
SCOPES = 'username'  # Custom scopes that you want to pass as part of the request when requesting access token

AUTH_SERVER_ID = 'aus4fkma8RksuPc5o2p6'  # Replace with your okta authroziation server id
AUTH_SERVER_DOMAIN = 'https://jay.okta.com'  # Replace with your okta org
AUTH_DOMAIN_ENDPOINT = '{}/oauth2/{}'.format(AUTH_SERVER_DOMAIN, AUTH_SERVER_ID)
API_AUDIENCE = 'http://localhost:8080/'  # whatever your API domain is called and should be added as audience to the API
GROUP_ID = '00g6mimmbi1qUHePI2p6'
API_KEY = '00HrCnReE5yRq2iPrj-6Igzs6qLX06iXy2ebQOpeVe'


def handle_error(error, status_code):
    resp = jsonify(error)
    resp.status_code = status_code
    return resp


def get_access_token(url, headers, data):
    r = requests.post(url, headers=headers, data=data)
    return r


def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        return handle_error({"code": "authorization_header_missing",
                             "description":
                                 "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        return handle_error({"code": "invalid_header",
                             "description":
                                 "Authorization header must start with"
                                 "Bearer"}, 401)
    elif len(parts) == 1:
        return handle_error({"code": "invalid_header",
                             "description": "Token not found"}, 401)
    elif len(parts) > 2:
        return handle_error({"code": "invalid_header",
                             "description": "Authorization header must be"
                                            "Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    token_scopes = unverified_claims["scp"]
    for token_scope in token_scopes:
        if token_scope == required_scope:
            return True
    return False


def is_admin():
    """Determines if the user is admin or not
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    user_id = unverified_claims["uid"]
    url = "{0}/api/v1/users/{1}".format(AUTH_SERVER_DOMAIN, user_id)

    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        'authorization': "SSWS 00HrCnReE5yRq2iPrj-6Igzs6qLX06iXy2ebQOpeVe",
        'cache-control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers)
    json_data = json.loads(response.text)
    return json_data.get('profile').get('ice_admin')


def requires_auth(f):
    """Determines if the access token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = requests.get("{}/v1/keys".format(AUTH_DOMAIN_ENDPOINT))
        jwks = jsonurl.json()
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            return token
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer=AUTH_DOMAIN_ENDPOINT
                )
            except jwt.ExpiredSignatureError:
                return handle_error({"code": "token_expired",
                                     "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                return handle_error({"code": "invalid_claims",
                                     "description": "incorrect claims,"
                                                    "please check the audience and issuer"}, 401)
            except Exception:
                return handle_error({"code": "invalid_header",
                                     "description": "Unable to parse authentication"
                                                    "token."}, 400)

            _app_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        return handle_error({"code": "invalid_header",
                             "description": "Unable to find appropriate key"}, 400)

    return decorated


def generate_basic_auth(cred_dict):
    """Builds Basic auth header
    """
    username = cred_dict.get('client_id')
    password = cred_dict.get('client_secret')
    if not (username and password):
        return None
    basic_auth = b64encode(bytes('{}:{}'.format(username, password))).decode('ascii')
    return {'Accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + basic_auth}


def get_oauth_body_client_credentials():
    payload = "grant_type=client_credentials&scope={}".format(SCOPES)
    return payload


def get_oauth_body_password(cred_dict):
    payload = "grant_type=password&username={}&password={}&scope={}".format(cred_dict.get('username', ''),
                                                                            cred_dict.get('password', ''), SCOPES)
    return payload
