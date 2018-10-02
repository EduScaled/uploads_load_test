import os
import json
import random
from locust import HttpLocust, TaskSet, task
from pyquery import PyQuery

""" Settings which needs to be set """

event = "74b34901-eaf9-45ac-aa28-5a61be30fb09"

credentials = []
with open("credentials", "r") as cf:
    for l in cf:
        data = l.split(':')
        credentials.append({
            "login": data[0].strip(),
            "password": data[1].strip()
        })

files_to_upload = [
    'files_to_upload/1mb', 
    'files_to_upload/3mb',
    'files_to_upload/5mb',
    'files_to_upload/10mb',
    # 'files_to_upload/100mb', 
    # 'files_to_upload/300mb',
]

################################################################################################################

url = "/load-event/{}/".format(event)

authform_kv = {
    "YII_CSRF_TOKEN": "input[name='YII_CSRF_TOKEN']",
    "action": "form",
    "returnUrl": "#returnUrl",
    "simple": "#simple",
} 

confirm_kv = {
    "action": "form",
    "csrfmiddlewaretoken": "input[name='csrfmiddlewaretoken']",
    "authorize": "input[name='authorize']",
}

trace_name_selector = "input[name='trace_name']"

already_authrorized_url_pattern = "/oauth2/authorize/confirm"

class ResponseParsingException(Exception):
    pass

def validate_form_data(pq, kv):
    """
    The method checks that required form parameters are exists in given html page.
    """
    found_objects, not_found_fields = [], []
    for k in kv.keys():
        objs = pq(kv[k])
        if len(objs) > 0:
            found_objects.append({k: objs})
        else:
            not_found_fields.append(k)
    if not_found_fields:
        raise ResponseParsingException(",".join(not_found_fields))
    else:
        return found_objects

def parse_html(response, kv):
    """
    The method parses form parameters and returns dict with that data.
    """
    pq = PyQuery(response.content)
    objs = validate_form_data(pq, kv)
    data = {}
    for obj in objs:
        attribute = "value" if list(obj)[0] != "action" else "action"
        for k,v in obj.items():
            data.update({k: v[0].attrib[attribute]})  

    return data

def is_already_authorized(url):
    return True if already_authrorized_url_pattern in url else False

def get_trace_name(response):
    """
    The method gets first trace id found on page.
    """
    pq = PyQuery(response.content)
    traces = pq(trace_name_selector)
    if len(traces) < 1:
        raise ResponseParsingException(trace_name_selector)
    return traces[0].attrib["value"]

def login(l):
    """
    The method authenticates user using SSO.
    """

    login_url = "/login/unti/"
    response_login = l.client.get(login_url)

    if not is_already_authorized(response_login.url):
        post_auth_data = parse_html(response_login, authform_kv)
        post_auth_data.update({
            "auth_models_forms_AuthForm[Login]": random.choice(credentials)["login"],
            "auth_models_forms_AuthForm[Password]": random.choice(credentials)["password"]
        })
        response_auth = l.client.post(response_login.url, data=post_auth_data)
        redirect_url = json.loads(response_auth.content.decode("utf-8"))["redirectUrl"]

    response_confirm_url = redirect_url if not is_already_authorized(response_login.url) else response_login.url
    response_confirm = l.client.get(response_confirm_url)
    post_confirm_data = parse_html(response_confirm, confirm_kv)
    response_confirm = l.client.post(response_confirm_url, data=post_confirm_data)

class Tasks(TaskSet):

    def on_start(self):
        login(self)

    @task
    def upload(self):
        get_response = self.client.get(url)
        post_data = {
            'csrfmiddlewaretoken': get_response.cookies['csrftoken'],
            'trace_name': get_trace_name(get_response),
            'add_btn': True,
        }
        files = {
            'file_field': open(random.choice(files_to_upload), 'rb')
        }
        post_response = self.client.post(url, data=post_data, files=files)

class Locust(HttpLocust):
    task_set = Tasks
    min_wait = os.environ.get('LOCUST_MIN_WAIT', 500)
    max_wait = os.environ.get('LOCUST_MAX_WAIT', 1000)