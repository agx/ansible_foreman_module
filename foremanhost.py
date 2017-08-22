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
import json
import time

from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: foremanhost
short_description: Manages virtual machines supported in the Foreman
description:
     - Manages virtual machines in the I(Foreman).
options:
  name:
    description:
      - name of the machine being managed.
    required: true
    default: null
  hostgroup:
    description:
      - put the machine to the given hostgroup
    required: false
    default: null
  subnet:
    description:
      - put the machint into the given subnet
  ipv4addr:
    description:
      - assign the given address to the VM
  comment:
    description:
      - Comment to attach to the VM
  environment:
    description:
      - Environment to put the vm into
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
  api_retries:
     description:
      - number of retries if a request fails with a api_error
  api_errors:
     description:
      - List of errors to retry requests for e.g. ['ERF12-1261']
  state:
    description:
      - state of the machine ('present', 'absent', 'poweredOn', 'poweredOff')
    required: true
  power_timeout:
    description:
      - max time in seconds to wait for power on/off
  ssl_verify:
    description:
      - Wether to verify SSL certs of the Foreman API
    required: false
    default: True
author:
    - "Guido Günther"
'''

EXAMPLES = '''
# a playbook task line:
- foremanhost: name=foobar state=present

# a playbook example of defining and creating a VM via Foreman
tasks:
  - foremanhost:
      name: foobar
      subnet: asubnet
      state: present
      api_user: foreman
      api_password: admin
      api_url: http://localhost:3000/
'''

try:
    import requests
except ImportError:
    HAS_REQUESTS = False
else:
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True

FOREMAN_FAILED = 1
FOREMAN_SUCCESS = 0
POWERSTATES = ['poweredOn', 'poweredOff']

headers = None
api_url = None
module = None


def build_primary_interface(ipv4addr):
    """
    Build a Foreman interface definition

    >>> iface = build_primary_interface('127.0.0.1')
    >>> iface['0']['ip']
    '127.0.0.1'
    >>> iface['0']['provision']
    True
    >>> iface['0']['primary']
    True
    """
    if not ipv4addr:
        return None

    iface = {
        "ip": ipv4addr,
        "primary": True,
        "provision": True,
    }
    return {'0': iface}


def merge_json(name, hostgroup_id, image_id, compute_resource_id, subnet_id, env_id, interfaces, comment):
    ret = {}

    ret['host'] = {
        "build": True,
        "enabled": True,
        "managed": True,
        "compute_attributes": {
            "start": "1"
        },
    }
    ret['host']['name'] = name
    ret['host']['hostgroup_id'] = int(hostgroup_id)
    if image_id:
        ret['host']['image_id'] = int(image_id)
    ret['host']['provision_method'] = "image"
    ret['host']['compute_resource_id'] = int(compute_resource_id)
    if env_id:
        ret['host']['environment_id'] = int(env_id)
    if subnet_id:
        ret['host']['subnet_id'] = subnet_id
    if interfaces:
        ret['host']['interfaces_attributes'] = interfaces
    if comment:
        ret['host']['comment'] = comment
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


def do_put(url, data, params):
    ret = requests.put(url,
                       data=data,
                       **params)
    ret.raise_for_status()
    return dict(status=ret.status_code, text=ret.text)


def do_delete(url, params):
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
        # requests exception
        if ("name" in err_msg and
                err_msg["name"] == [u'has already been taken']):
            return True
    except IndexError:
        return False
    return False


def is_absent(e):
    """
    Check if the error returned indicates a missing entity
    """
    if e.response.status_code == 404:
        return True
    return False


def item_to_id(base_url, field, name):
    ret = find_item(base_url, field, name)
    return '%d' % ret['id'] if ret else None


def find_item(base_url, field, name):
    url = base_url + "?search=%s=\"%s\"" % (field, name)
    ret = do_get(url, headers)
    results = json.loads(ret['text'])['results']
    if results == []:
        return None
    if len(results) > 1:
        raise ValueError("Found more than item for '%s'" % name)
    return results[0]


def find_image(compute_resource_id, image):
    image_url = "%s/api/v2/compute_resources/%s/images" % (api_url, compute_resource_id)
    image_id = item_to_id(image_url, 'name', image)
    if not image_id:
        raise ValueError("Image '%s' not found" % image)
    return image_id


def find_compute_resource(compute_resource):
    compute_resource_url = "%s/api/v2/compute_resources/" % api_url
    compute_resource_id = item_to_id(compute_resource_url, 'name', compute_resource)
    if not compute_resource_id:
        raise ValueError("Compute resource '%s' not found" % compute_resource)
    return compute_resource_id


def find_subnet(name):
    subnet_url = "%s/api/v2/subnets/" % api_url
    subnet = find_item(subnet_url, 'name', name)
    if not subnet:
        raise ValueError("Subnet '%s' not found" % subnet)
    return subnet


def find_env(env):
    env_url = "%s/api/v2/environments/" % api_url
    env_id = item_to_id(env_url, 'name', env)
    if not env_id:
        raise ValueError("Env '%s' not found" % env)
    return env_id


def find_subnet_domains(subnet_id):
    subnet_domain_url = "%s/api/subnets/%s/domains" % (api_url, subnet_id)
    ret = do_get(subnet_domain_url, headers)
    return json.loads(ret['text'])['results']


def find_host(host, subnet):
    host_url = "%s/api/v2/hosts" % api_url

    domains = find_subnet_domains(subnet['id'])
    if domains == []:
        return None
    if len(domains) > 1:
        raise ValueError("Found more than one domain for subnet '%s'" % subnet['name'])
    fqdn = "%s.%s" % (host, domains[0]['name'])

    host_id = item_to_id(host_url, 'name', fqdn)
    if not host_id:
        raise ValueError("Host '%s' not found" % host)
    return host_id


def get_host_params(hid):
    hostparam_url = "%s/api/v2/hosts/%s/parameters" % (api_url, hid)
    ret = do_get(hostparam_url, headers)
    return json.loads(ret['text'])['results']


def get_host_power(hid):
    host_power_url = "%s/api/v2/hosts/%s/power" % (api_url, hid)
    ret = do_put(host_power_url, '{"power_action": "status"}', headers)
    return json.loads(ret['text'])['power']


def set_host_power(hid, state):
    host_power_url = "%s/api/v2/hosts/%s/power" % (api_url, hid)
    try:
        ret = do_put(host_power_url, '{"power_action": "%s"}' % state, headers)
    except requests.exceptions.HTTPError as e:
        msg = e.response.json().get('error', {}).get('message', None)
        if msg:
            module.fail_json(msg=msg)
        else:
            raise
    return json.loads(ret['text'])['power']


def wait_host_power(hid, states, timeout):
    while timeout > 0:
        timeout -= 2
        time.sleep(2)
        cur_state = get_host_power(hid)
        module.debug("cur_state: %s, want: %s" % (cur_state, states))
        if cur_state in states:
            return cur_state
    return None


def param_by_name(name, params):
    """
    Lookup a parameter by name in the parameter list returned by foreman

    >>> param_by_name("foo", [{"name":  "foo",
    ...                        "value": "fasel"}])['value']
    'fasel'

    >>> param_by_name("foo", [{"name":  "bla",
    ...                        "value": "fasel"},
    ...                       {"name":  "bli",
    ...                        "value": "bla"}])
    Traceback (most recent call last):
    ...
    ValueError: No Param with name foo found in ['bla', 'bli']
    """
    for p in params:
        if p['name'] == name:
            return p
    raise ValueError("No Param with name %s found in %s" % (name, [n['name'] for n in params]))


def add_param(hid, name, value):
    hostparam_url = "%s/api/v2/hosts/%s/parameters" % (api_url, hid)
    p = {
        "parameter": {
            "name": name,
            "value": value,
        },
    }
    do_post(hostparam_url, p, headers)


def del_param(hid, name, foreman_params):
    param_id = param_by_name(name, foreman_params)['id']
    hostparam_url = "%s/api/v2/hosts/%s/parameters/%s" % (api_url, hid, param_id)
    do_delete(hostparam_url, headers)


def update_param(hid, name, value, foreman_params):
    param_id = param_by_name(name, foreman_params)['id']
    hostparam_url = "%s/api/v2/hosts/%s/parameters/%s" % (api_url, hid, param_id)
    p = {
        "parameter": {
            "name": name,
            "value": value,
        },
    }
    do_put(hostparam_url, json.dumps(p), headers)


def ensure_params(hid, parameters):
    """Make sure the params given match the ones tagged onto the
    foreman host"""
    foreman_params = get_host_params(hid)
    new = parameters.keys()
    old = [p['name'] for p in foreman_params]
    changed = False

    add_params = set(new) - set(old)
    del_params = set(old) - set(new)
    mod_params = set(new).intersection(old)

    for name in add_params:
        add_param(hid, name, parameters[name])
        changed = True

    for name in mod_params:
        cur_value = param_by_name(name, foreman_params)['value']
        if parameters[name] != cur_value:
            update_param(hid, name, parameters[name], foreman_params)
            changed = True

    for name in del_params:
        del_param(hid, name, foreman_params)
        changed = True

    return changed


def is_error(e, conds):
    """
    Check if a Foreman error matches a given error number
    """
    if conds is None:
        return False

    for cond in conds:
        if (cond in e.response.json()['error'] or
            ('full_messages' in e.response.json()['error'] and
             cond in e.response.json()['error']['full_messages'][0])):
            return True
    return False


def do_post_retries(url, jsn, conds, retries=0):
    """
    Retry posts on certain Foreman error numbers
    """
    tries = 0
    wait = 5
    while True:
        try:
            tries += 1
            ret = do_post(url, jsn, headers)
            ret['api_tries'] = tries
            return ret
        except requests.exceptions.HTTPError as e:
            if is_error(e, conds):
                if tries - 1 < retries:  # still tries left
                    time.sleep(wait)
                    wait *= 2
                    continue
            raise


def maybe_create_host(name, hostgroup, env, ipv4addr, comment, compute_resource, subnetname, image, api_errors, api_retries, module):
    host_url = "%s/api/v2/hosts" % api_url
    image_id = None
    env_id = None
    subnet = None
    changed = False
    hid = None
    ret = {}
    facts = {}

    hostgroup_url = "%s/api/v2/hostgroups" % api_url
    if not hostgroup:
        raise ValueError("Hostgroup must be given")
    if not compute_resource:
        raise ValueError("Compute resource must be given")
    if not subnetname:
        raise ValueError("subnet must be given")
    hostgroup_id = item_to_id(hostgroup_url, 'title', hostgroup)
    if not hostgroup_id:
        raise ValueError("Hostgroup '%s' not found for '%s'" % (hostgroup, name))
    compute_resource_id = find_compute_resource(compute_resource)
    if image:
        image_id = find_image(compute_resource_id, image)
    if env:
        env_id = find_env(env)
    subnet = find_subnet(subnetname)
    interfaces = build_primary_interface(ipv4addr)
    fulljson = merge_json(name,
                          hostgroup_id,
                          image_id,
                          compute_resource_id,
                          subnet['id'],
                          env_id,
                          interfaces,
                          comment=comment)
    try:
        ret = do_post_retries(host_url, fulljson, api_errors, api_retries)
        j = json.loads(ret['text'])
        hid = j['id']
        facts['foremanhost_ip'] = j['ip']
        changed = True
    except requests.exceptions.HTTPError as e:
        if is_exists(e):
            hid = item_to_id(host_url, 'name', name)
        else:
            try:
                if 'full_messages' in e.response.json()['error']:
                    msg = 'Failed to create host %s: %s' % (name, e.response.json()['error']['full_messages'])
                else:
                    msg = 'Failed to create host %s: %s' % (name, e.response.json()['error'])
                module.fail_json(msg=msg)
            # Catch any failures to get an error message
            except Exception as f:
                module.fail_json(
                    msg='Failed to create host %s: %s (failed to parse detailed error output: %s)' % (name, e, f)
                )

    if not hid:
        if not subnet:
            subnet = find_subnet(subnetname)
        hid = find_host(name, subnet)

    if not hid:
        raise ValueError("Host %s not found" % name)

    return ret, hid, changed, facts


def ensure_power_state(hid, state, power_timeout):
    changed = False
    # Host is there, make sure power state matches
    cur_state = get_host_power(hid)
    if state == 'present':
        state = 'poweredOn'
    if cur_state != state:
        waitfor, action = (['poweredOff', 'off'], 'stop') if cur_state in ['poweredOn', 'running'] else (['poweredOn', 'running'], 'start')
        module.debug("cur_state: %s, waitfor: %s, action: %s" % (cur_state, waitfor, action))
        if set_host_power(hid, action):
            new_state = wait_host_power(hid, waitfor, power_timeout)
            if new_state:
                ret = new_state
            else:
                module.fail_json(
                    msg="Host did not enter power state %s in %d seconds" % (waitfor[0], power_timeout)
                )
        changed = True
    else:
        ret = cur_state
    return ret, changed


def core(module):
    global headers
    global api_url

    name = module.params.get('name', None)
    hostgroup = module.params.get('hostgroup', None)
    image = module.params.get('image', None)
    compute_resource = module.params.get('compute_resource', None)
    subnetname = module.params.get('subnet', None)
    env = module.params.get('environment', None)
    state = module.params.get('state', 'present')
    parameters = module.params.get('params') or {}
    ipv4addr = module.params.get('ipv4addr', None)
    comment = module.params.get('comment', None)
    api_url = module.params.get('api_url', None)
    api_user = module.params.get('api_user', None)
    api_pw = module.params.get('api_password', os.getenv("ANSIBLE_FOREMAN_PW"))
    api_retries = module.params.get('api_retries', 0)
    api_errors = module.params.get('api_errors', None)
    ssl_verify = module.params.get('ssl_verify', True)
    power_timeout = module.params.get('power_timeout') or 60

    hid = None
    changed = False
    facts = {}
    ret = {}

    host_url = "%s/api/v2/hosts" % api_url
    headers = {'headers': {'Content-Type': 'application/json'},
               'auth': HTTPBasicAuth(api_user, api_pw),
               'verify': ssl_verify,
               }

    if state in ['present'] + POWERSTATES:
        hid = item_to_id(host_url, 'name', name)
        if not hid:
            ret, hid, changed, facts = maybe_create_host(name,
                                                         hostgroup,
                                                         env,
                                                         ipv4addr,
                                                         comment,
                                                         compute_resource,
                                                         subnetname,
                                                         image,
                                                         api_errors,
                                                         api_retries,
                                                         module)
        else:
            ret['power_state'], changed = ensure_power_state(hid, state, power_timeout)
        if ensure_params(hid, parameters):
            changed = True
    elif state == 'absent':
        host_id = item_to_id(host_url, 'name', name)
        if host_id is None:
            ret['changed'] = False
            return FOREMAN_SUCCESS, ret
        try:
            url = os.path.join(host_url, host_id)
            ret = do_delete(url, headers)
            changed = True
        except requests.exceptions.HTTPError as e:
            if is_absent(e):
                changed = False
            else:
                raise
    else:
        raise ValueError("Unknown state %s" % state)

    ret['changed'] = changed
    if facts:
        ret['ansible_facts'] = facts
    return FOREMAN_SUCCESS, ret


def main():
    global module
    module = AnsibleModule(argument_spec=dict(  # noqa:F405
        name=dict(required=True),
        hostgroup=dict(type='str'),
        image=dict(type='str'),
        compute_resource=dict(type='str'),
        subnet=dict(type='str'),
        environment=dict(type='str'),
        params=dict(type='dict'),
        ipv4addr=dict(type='str'),
        comment=dict(type='str'),
        state=dict(default='present', choices=['present', 'absent'] + POWERSTATES),
        power_timeout=dict(type='int'),
        api_url=dict(required=True),
        api_user=dict(required=True),
        api_password=dict(no_log=True),
        api_retries=dict(type='int'),
        api_errors=dict(type='list'),
        ssl_verify=dict(type='bool'),
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


if __name__ == '__main__':
    # import module snippets
    main()
