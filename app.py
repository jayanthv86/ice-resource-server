#!flask/bin/python
from flask import Flask, jsonify, request
import requests
from flask_cors import CORS, cross_origin
import datetime
import json
from helper import requires_auth, requires_scope, GROUP_ID, API_KEY, AUTH_SERVER_DOMAIN, is_admin

validity = 30
end_promo = datetime.datetime.now() + datetime.timedelta(minutes=30)
promos = dict()
promos['PUBLIC'] = [{'target': 'PUBLIC', 'code': '10OFFICE', 'validFor': validity, 'endDate': end_promo.strftime("%Y-%m-%d %H:%M:%S"), 'description': "Okta Ice is cool. 10% off for everybody"},
                    {'target': 'PUBLIC', 'code': 'WILLYVANILLY', 'validFor': validity, 'endDate': end_promo.strftime("%Y-%m-%d %H:%M:%S"), 'description': "15% off the new Vanilla collection" }]
promos['PREMIUM'] = [{'target': 'PREMIUM', 'code': '20PREMIUM', 'validFor': validity, 'endDate': end_promo.strftime("%Y-%m-%d %H:%M:%S"), 'description': "Premium Customers get 20% off" },
                     {'target': 'PREMIUM', 'code': 'NUTS4CHOCO', 'validFor': validity, 'endDate': end_promo.strftime("%Y-%m-%d %H:%M:%S"), 'description': "Premium customers get 30% off the Choco Nuts flavor" }]
promos['ROBOT'] = [{'target': 'ROBOT', 'code': 'BOT', 'validFor': validity, 'endDate': end_promo.strftime("%Y-%m-%d %H:%M:%S"), 'description': "Chatbot gets 30% off" }]


app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret' # Change to uuid

CUSTOM_SCOPE_TOCHECK = 'username' #Custom scopes you want to check at the end point

@app.route('/')
def index():
    """Unprotected API
    """
    return "Hello, World!"

@app.route('/promos/PUBLIC')
@cross_origin()
def public_promos():
    """Unprotected endpoint"""
    return jsonify(promos['PUBLIC']), 200

@app.route('/promos/PREMIUM')
@cross_origin()
@requires_auth
def premium_promos():
    """Protected endpoint"""
    if requires_scope('promos:read'):
        return jsonify(promos['PREMIUM']), 200
    else:
        return jsonify({}), 200


@app.route('/users')
@cross_origin()
def admin_users():
    """Unprotected endpoint"""
    status = request.args.get('status')
    new_list = []
    if is_admin():
        url = '{0}/api/v1/groups/{1}/users'.format(AUTH_SERVER_DOMAIN, GROUP_ID)

        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "SSWS {0}".format(API_KEY),
            'cache-control': "no-cache",
        }
        response = requests.request("GET", url, headers=headers)
        if not status:
            return jsonify(response.json()), 200
        elif status == 'active':
            for user in response.json():
                if user['status'] == 'ACTIVE':
                    new_list.append(user)
        elif status == 'pending':
            for user in response.json():
                if user['status'] == 'STAGED':
                    new_list.append(user)
        return jsonify(new_list), 200
    else:
        return jsonify({}), 200


@app.route('/signup', methods=['POST'])
@cross_origin()
def sign_up():
    form_data = json.loads(request.data)
    user_data = form_data.get('user', {})
    first_name = user_data.get('firstName')
    last_name = user_data.get('lastName')
    email = user_data.get('login')
    password = user_data.get('password')
    success_email = user_data.get('send_email')
    if not(first_name and last_name and email and password):
        return jsonify({}), 400
    url = "{0}/api/v1/users".format(AUTH_SERVER_DOMAIN)

    querystring = {"activate": "false"}
    payload = json.dumps({"profile":
                   {"firstName": first_name, "lastName": last_name, "email": email, "login": email, "ice_user": True},
               "credentials": {"password": {"value": password}}})
    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        'authorization': "SSWS {0}".format(API_KEY),
        'cache-control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
    if response.status_code:
        print(response.json())
        user_id = response.json()['id']
    else:
        user_id = None

    if success_email and user_id:
        send_success_email(user_id)
    return jsonify({}), 200


def send_success_email(user_id):
    url = "{0}/api/v1/users/{1}/lifecycle/activate".format(AUTH_SERVER_DOMAIN, user_id)

    querystring = {"sendEmail": "true"}

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "SSWS {0}".format(API_KEY),
        'cache-control': "no-cache",
        }

    response = requests.request("POST", url, headers=headers, params=querystring)


def deactivate_user(user_id):
    url = "{0}/api/v1/users/{1}/lifecycle/deactivate".format(AUTH_SERVER_DOMAIN, user_id)

    querystring = {"sendEmail": "true"}

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "SSWS {0}".format(API_KEY),
        'cache-control': "no-cache",
        }

    response = requests.request("POST", url, headers=headers, params=querystring)


@app.route('/activate', methods=['GET'])
@cross_origin()
def activate():
    user_id = request.args.get('user')
    print(user_id)
    send_success_email(user_id)
    return jsonify({}), 200

@app.route('/deactivate', methods=['GET'])
@cross_origin()
def deactivate():
    user_id = request.args.get('user')
    print(user_id)
    deactivate_user(user_id)
    return jsonify({}), 200

if __name__ == '__main__':
    app.run(debug=True)