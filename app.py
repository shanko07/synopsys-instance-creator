import base64
import io
import json
import secrets
import string
import urllib

import pandas as pd
import requests
from flask import Flask, Response, render_template, request, send_from_directory

app = Flask(__name__)


# pd.DataFrame(columns=['first', 'last', 'email']).to_excel('excel_template.xlsx', index=False)

@app.route('/file/<filename>', methods=['GET'])
def return_file(filename):
    return send_from_directory(directory='./', path=filename)


@app.route('/users', methods=['POST'])
def receive_users():
    payload = request.json
    excel_file = base64.b64decode(payload['file'])
    df = pd.read_excel(excel_file)
    firstnames = df['first'].tolist()
    lastnames = df['last'].tolist()
    emails = df['email'].tolist()
    peeps = []
    for f, l, e in zip(firstnames, lastnames, emails):
        peeps.append({'first': f, 'last': l, 'email': e, 'formtype': 'User'})

    return Response(status=200, response=json.dumps({"status": "success", "data": peeps}))


@app.route('/', methods=['GET', 'POST'])
def root():
    if request.method == 'GET':
        return render_template('interface.html')
    else:
        stuff = json.loads(request.data)

        users = [form for form in stuff['forms'] if form['formtype'] == 'User']
        instances = [form for form in stuff['forms'] if form['formtype'] != 'User']

        users = process_users(users)
        error_data, cred_data = process_instances(users, instances)
        bytes = create_spreadsheet(cred_data)

        if len(error_data) == 0:
            # return Response(status=200, response=json.dumps({"status": "success", "creds": cred_data, "file": base64.b64encode(bytes)}))
            return Response(status=200, response=base64.b64encode(bytes), headers={
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'})
        else:
            return Response(status=400, response=json.dumps({"status": "error", "details": error_data}))


def create_spreadsheet(cred_data):
    df = pd.DataFrame(columns=['first', 'last', 'email', 'username', 'password'])
    for product in cred_data:
        if product is not None:
            # has at least one instance
            if len(product.keys()) > 0:
                users = product[list(product.keys())[0]]
                df = df.append(users)
                break

    buffer = io.BytesIO()
    df.to_excel(buffer, index=False, header=True)

    buffer.seek(0)
    # assume bytes_io is a `BytesIO` object
    byte_str = buffer.read()
    return byte_str


def generate_password():
    alphabet = string.ascii_letters + string.digits + "!#$%&()*+,-.:;<=>?@[]^_`{|}~"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(not c.isalnum() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break

    return password


def process_users(users):
    for user in users:
        user['password'] = generate_password()

    return users


def process_instances(users, instances):
    bdinstances = [instance for instance in instances if instance['formtype'] == 'Black Duck']
    cdxinstances = [instance for instance in instances if instance['formtype'] == 'Code Dx']
    covinstances = [instance for instance in instances if instance['formtype'] == 'Coverity']
    polinstances = [instance for instance in instances if instance['formtype'] == 'Polaris']
    seekerinstances = [instance for instance in instances if instance['formtype'] == 'Seeker']

    bdinfo = create_blackduck_users(users, bdinstances)
    covinfo = create_cov_users(users, covinstances)
    polinfo = create_polaris_users(users, polinstances)
    seekerinfo = create_seeker_users(users, seekerinstances)
    cdxinfo = create_codedx_users(users, cdxinstances)

    errordata = []

    if bdinfo is None:
        errordata.append("error in creating Black Duck users")
    if covinfo is None:
        errordata.append("error in creating Coverity users")
    if seekerinfo is None:
        errordata.append("error in creating Seeker users")
    if cdxinfo is None:
        errordata.append("error in creating Code Dx users")
    if polinfo is None:
        errordata.append("error in creating Polaris users")

    with open('creds.txt', 'w') as file:
        file.write(json.dumps(bdinfo, indent=2))
        file.write(json.dumps(seekerinfo, indent=2))
        file.write(json.dumps(covinfo, indent=2))
        file.write(json.dumps(cdxinfo, indent=2))
        file.write(json.dumps(polinfo, indent=2))

    return errordata, [bdinfo, seekerinfo, covinfo, cdxinfo, polinfo]


def create_blackduck_users(users, instances):
    user_info = {}

    for instance in instances:
        user_info[instance['url']] = []
        headers = {'Authorization': 'token ' + instance['token'],
                   'Content-Type': 'application/vnd.blackducksoftware.user-4+json',
                   'Accept': 'application/vnd.blackducksoftware.user-4+json'}
        rsp = requests.post(urllib.parse.urljoin(instance['url'], '/api/tokens/authenticate'), headers=headers)
        bt = rsp.json()['bearerToken']

        for user in users:
            headers = {'Authorization': 'Bearer ' + bt}
            payload = {
                "userName": user['first'] + '_' + user['last'],
                "firstName": user['first'],
                "lastName": user['last'],
                "email": user['email'],
                "active": True,
                "password": user['password'],
                "type": "INTERNAL"
            }
            rsp = requests.post(urllib.parse.urljoin(instance['url'], '/api/users'), headers=headers, json=payload)
            if rsp.status_code == 201:
                user_info[instance['url']].append({'first': user['first'], 'last': user['last'], 'email': user['email'],
                                                   'username': payload['userName'], 'password': user['password']})

                headers = {
                    'Authorization': 'Bearer ' + bt,
                    'Accept': 'application/vnd.blackducksoftware.user-4+json'
                }
                payload = {
                    "offset": 0,
                    "limit": 100,
                    "filter": "scope:server"
                }
                roles = requests.get(instance['url'] + '/api/roles', headers=headers, json=payload)
                roles = roles.json()

                for item in roles['items']:
                    if item['name'] != 'Super User' and item['name'] != "System Administrator":
                        headers = {
                            'Authorization': 'Bearer ' + bt,
                            'Content-Type': 'application/vnd.blackducksoftware.user-4+json',
                            'Accept': 'application/vnd.blackducksoftware.user-4+json'
                        }
                        payload = {
                            "role": item['_meta']['href'],
                            "scope": "server"
                        }
                        my_url = rsp.headers['Location'] + '/roles'
                        requests.post(my_url, headers=headers,
                                      json=payload)

            else:
                return None

    return user_info


def create_cov_users(users, instances):
    user_info = {}

    for instance in instances:
        user_info[instance['url']] = []

        for user in users:
            headers = {'Content-Type': 'application/json'}
            payload = {
                "name": user['first'] + '_' + user['last'],
                "password": user['password'],
                "roleAssignments": [
                    {
                        "group": None,
                        "roleAssignmentType": "user",
                        "roleName": "sysAdmin",
                        "scope": "global",
                        "username": user['first'] + '_' + user['last']
                    }]
            }
            my_url = urllib.parse.urljoin(instance['url'], '/api/v2/users')

            rsp = requests.post(my_url,
                                auth=(instance['user'], instance['token']), headers=headers,
                                json=payload, allow_redirects=True)
            if rsp.status_code == 201:
                user_info[instance['url']].append({'first': user['first'], 'last': user['last'], 'email': user['email'],
                                                   'username': payload['name'], 'password': user['password']})

            else:
                return None

    return user_info


def create_polaris_users(users, instances):
    user_info = {}

    for instance in instances:
        user_info[instance['url']] = []

        for user in users:
            my_url = urllib.parse.urljoin(instance['url'], '/api/auth/v1/authenticate')
            auth_response = requests.post(my_url,
                                          data={'accesstoken': instance['token']})
            jwt = auth_response.json()['jwt']

            my_url = urllib.parse.urljoin(instance['url'], '/api/auth/v1/organizations')
            org_response = requests.get(my_url, headers={'Authorization': 'Bearer ' + jwt})
            org_id = org_response.json()['data'][0]['id']

            payload = {
                "data": {
                    "type": "users",
                    "attributes": {
                        "email": user['email'],
                        "enabled": True,
                        "first-time": True,
                        "name": user['first'] + ' ' + user['last'],
                        "owner": True,
                        "password-login": {
                            "password": user['password']
                        },
                        "system": False,
                        "username": user['first'] + '_' + user['last'],
                        "organization-admin": True
                    },
                    "relationships": {
                        "organization": {
                            "data": {
                                "type": "organizations",
                                "id": org_id
                            }
                        }
                    }
                }
            }

            my_url = urllib.parse.urljoin(instance['url'], '/api/auth/v1/users')
            user_response = requests.post(my_url, headers={'Authorization': 'Bearer ' + jwt,
                                                           'Content-Type': 'application/vnd.api+json'}, json=payload)
            if user_response.status_code == 201:
                user_info[instance['url']].append({'first': user['first'], 'last': user['last'], 'email': user['email'],
                                                   'username': payload['data']['attributes']['username'],
                                                   'password': user['password']})
            else:
                return None

            ra_link = user_response.json()['data']['relationships']['roleassignments']['links']['self']
            user_id = user_response.json()['data']['id']

            ra_response = requests.get(ra_link, headers={'Authorization': 'Bearer ' + jwt})
            role_assignment_id = ra_response.json()['data'][0]['id']

            my_url = urllib.parse.urljoin(instance['url'], '/api/auth/v1/roles')
            roles_response = requests.get(my_url, headers={'Authorization': 'Bearer ' + jwt})
            for role in roles_response.json()['data']:
                if role['attributes']['rolename'] == 'Administrator':
                    role_id = role['id']

            payload = {"data": {"id": role_assignment_id,
                                "attributes": {"expires-by": None, "object": f"urn:x-swip:organizations:{org_id}"},
                                "relationships": {"role": {"data": {"type": "roles", "id": role_id}},
                                                  "user": {"data": {"type": "users", "id": user_id}},
                                                  "group": {"data": None}, "organization": {
                                        "data": {"type": "organizations", "id": org_id}}},
                                "type": "role-assignments"}}

            my_url = urllib.parse.urljoin(instance['url'], '/api/auth/v1/role-assignments')
            requests.patch(my_url + f'/{role_assignment_id}',
                           headers={'Authorization': 'Bearer ' + jwt, 'Content-Type': 'application/vnd.api+json'},
                           json=payload)

    return user_info


def create_codedx_users(users, instances):
    user_info = {}

    for instance in instances:
        user_info[instance['url']] = []

        for user in users:
            headers = {'Authorization': 'Bearer ' + instance['token'],
                       'Content-Type': 'application/json',
                       'Accept': 'application/json'}
            payload = {
                'name': user['first'] + '_' + user['last'],
                'password': user['password'],
                'enabled': 'true',
                'clientType': 'saml'
            }

            rsp = requests.post(urllib.parse.urljoin(instance['url'], '/codedx/api/admin/users/local'), headers=headers,
                                json=payload)
            if rsp.status_code == 200:
                user_info[instance['url']].append({'first': user['first'], 'last': user['last'], 'email': user['email'],
                                                   'username': payload['name'], 'password': user['password']})

                headers = {'Authorization': 'Bearer ' + instance['token'],
                           'Content-Type': 'application/json',
                           'Accept': 'application/json'}
                payload = {
                    'isAdmin': 'true'
                }

                rsp = requests.put(urllib.parse.urljoin(instance['url'], f'/codedx/api/admin/users/{rsp.json()["id"]}'),
                                   headers=headers,
                                   json=payload)

            else:
                return None

    return user_info


def create_seeker_users(users, instances):
    user_info = {}

    for instance in instances:
        user_info[instance['url']] = []

        for user in users:
            auth_string = instance['token']
            if not auth_string.startswith('Bearer '):
                auth_string = 'Bearer ' + auth_string
            headers = {'Authorization': auth_string,
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'Accept': 'application/json'}
            payload = {
                'username': user['first'] + '_' + user['last'],
                'password': user['password'],
                'globalRoles': 'DevSecOps,SysAdmin',
                'groupNames': 'everyone'
            }
            rsp = requests.post(urllib.parse.urljoin(instance['url'], '/rest/api/latest/users'), headers=headers,
                                data=payload)
            if rsp.status_code == 200:
                user_info[instance['url']].append({'first': user['first'], 'last': user['last'], 'email': user['email'],
                                                   'username': payload['username'], 'password': user['password']})

            else:
                return None

    return user_info


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.run(port=5000)
