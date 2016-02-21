#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Foreman management features

Copyright 2016 Guido Günther <agx@sigxcpu.org>

This software may be freely redistributed under the terms of the GNU
general public license.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import copy

DOCUMENTATION = '''
---
module: foremanhost
short_description: Manages machines in the foreman
description:
     - Manages virtual machines in the I(Foreman).
options:
  name:
    description:
      - name of the machine being managed.
    required: true
  hostgroup:
    description:
      - put the machine to the given hostgroup
    required: false
    default: null
  api_url:
    description:
      - foreman connection url
    required: true
  api_user:
    description:
      - foreman connection user
    required: true
  api_password:
    description:
      - foreman connection password (can also be passwed via
        ANSIBLE_FOREMAN_PW)
    required: false
  state:
    description:
      - state of the machine (e.g.'present')
    required: true
  ssl_verify:
    description:
      - Wether to verify SSL certs of the Foreman API
    required: false
  json:
    description:
      - additional JSON used to define the machine
    required: false
    default: {}
author:
    - "Guido Günther"
'''

EXAMPLES = '''
# a playbook task line:
- foreman: name=foobar state=present

# a playbook example of defining and launching machine in the Foreman
tasks:
  - foremanhost:
      name: foobar
      state: present
      json: "{{ lookup('template', 'example.json') }}"
      api_user: foreman
      api_password: admin
      api_url: http://localhost:3000/
'''

try:
    import requests
except ImportError:
    HAS_REQUESTE = False
else:
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True

FOREMAN_FAILED = 1
FOREMAN_SUCCESS = 0


def merge_json(name, hostgroup_id, customjson):
    if customjson:
        customdata = json.loads(customjson)
    ret = copy.deepcopy(customdata)
    if 'host' not in ret:
        ret['host'] = {}
    ret['host']['name'] = name
    if hostgroup_id is not None:
        ret['host']['hostgroup_id'] = hostgroup_id
    return ret


# Post Data to Foreman
def do_post(url, data, params):
    data = None if data is None else json.dumps(data)
    ret = requests.post(url,
                        data=data,
                        **params)
    ret.raise_for_status()
    return dict(status=ret.status_code, text=ret.text)


def do_get(url, params):
    ret = requests.get(url, **params)
    ret.raise_for_status()
    return dict(status=ret.status_code, text=ret.text)


def do_delete(url, data, params):

    ret = requests.delete(url, **params)
    ret.raise_for_status()
    return dict(status=ret.status_code, text=ret.text)


def is_exists(e):
    """
    Check if the error returned indicates an already existing entity
    """
    if e.response.status_code != 422:
        return False
    err = json.loads(e.response.text)
    try:
        err_msg = err["error"]["errors"]
        # Be careful to avoid IndexError so we can rethrow
        # requests exceptoin
        if ("name" in err_msg("name") and
            err_msg["name"] == [u'has already been taken']):
            return True
    except IndexError:
        return False
    return False


def is_absent(e):
    """
    Check if the error returned indicates an missing entity
    """
    if e.response.status_code == 404:
        return True
    return False


def item_to_id(base_url, field, name, params):
    url = base_url + "?search=%s=\"%s\"" % (field, name)
    ret = do_get(url, params)
    results = json.loads(ret['text'])['results']
    if results == []:
        return None
    if len(results) > 1:
        raise ValueError("Found more than item for '%s'" % name)
    return "%s" % results[0]['id']


def core(module):
    name = module.params.get('name', None)
    hostgroup = module.params.get('hostgroup', None)
    state = module.params.get('state', 'present')
    customjson = module.params.get('json', None)
    api_url = module.params.get('api_url', None)
    api_user = module.params.get('api_user', None)
    api_pw = module.params.get('api_password', os.getenv("ANSIBLE_FOREMAN_PW"))
    ssl_verify = module.params.get('ssl_verify', True)
    ret = {}
    hostgroup_id = None

    host_url = "%s/api/v2/hosts" % api_url
    params = {'headers': {'Content-Type': 'application/json'},
              'auth':    HTTPBasicAuth(api_user, api_pw),
              'verify':  ssl_verify,
    }

    if state == 'present':
        if hostgroup:
            hostgroup_url = "%s/api/v2/hostgroups" % api_url
            hostgroup_id = item_to_id(hostgroup_url, 'title', hostgroup, params)
            if not hostgroup_id:
                raise ValueError("Hostgroup '%s' not found for '%s'" % (hostgroup, name))
        fulljson = merge_json(name, hostgroup_id, customjson)
        try:
            ret = do_post(host_url, fulljson, params)
            ret['changed'] = True
        except requests.exceptions.HTTPError as e:
            if is_exists(e):
                ret['changed'] = False
            else:
                raise
    elif state == 'absent':
        host_id = item_to_id(host_url, 'name', name, params)
        if host_id is None:
            ret['changed'] = False
            return FOREMAN_SUCCESS, ret
        try:
            url = os.path.join(host_url, host_id)
            ret = do_delete(url, None, params)
            ret['changed'] = True
        except requests.exceptions.HTTPError as e:
            if is_absent(e):
                ret['changed'] = False
            else:
                raise
    else:
        raise ValueError("Unknown state %s" % state)

    return FOREMAN_SUCCESS, ret


def main():
    module = AnsibleModule(argument_spec=dict(
        name=dict(required=True),
        hostgroup=dict(),
        json=dict(),
        state=dict(default='present', choices=['present', 'absent']),
        api_url=dict(required=True),
        api_user=dict(required=True),
        api_password=dict(),
        ssl_verify=dict(),
    ))

    if not HAS_REQUESTS:
        module.fail_json(
            msg='The `requests` module is not importable. Check the requirements.'
        )

    rc = FOREMAN_FAILED
    try:
        rc, result = core(module)
    except Exception as e:
        module.fail_json(msg=str(e))

    if rc != 0:  # something went wrong emit the msg
        module.fail_json(rc=rc, msg=result)
    else:
        module.exit_json(**result)


# import module snippets
from ansible.module_utils.basic import *
main()
