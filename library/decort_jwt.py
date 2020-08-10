#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2020 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: decort_jwt
short_description: Obtain access token to be used for authentication to DECORT cloud controller
description:
     - Obtain JWT (JSON Web Token) from the specified Oauth2 provider. This JWT can be used in subsequent DECS modules'
       invocations to authenticate them to the DECS cloud controller.
version_added: "2.4"
author: "Sergey Shubin (sergey.shubin@digitalenergy.online)"
notes:
     - Environment variables can be used to pass parameters to the module (see options below for details).
     - Specified Oauth2 provider must be trusted by the DECORT cloud controller on which JWT will be used.
     - 'If you register module output as I(my_jwt), the JWT value is accessed as I(my_jwt.jwt)'
requirements:
     - python >= 2.6
     - PyJWT module
     - requests module
     - decort_utils utility library (module)
     - DECORT cloud platform version 3.4.2 or higher
options:
    app_id:
        description:
        - 'Application ID for authenticating to the Oauth2 provider specified in I(oauth2_url).'
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_ID
           environment variable.'
        required: no
    app_secret:
        description:
        - 'Application API secret used for authenticating to the Oauth2 provider specified in I(oauth2_url).'
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_SECRET
           environment variable.'
        required: no
    oauth2_url:
        description:
        - 'URL of the oauth2 authentication provider to obtain JWT from.'
        - If not specified in the playbook, the value will be taken from DECORT_OAUTH2_URL environment variable.
    validity:
        description:
        - Validity of the JWT in seconds. Default value is 3600 (one hour).
        required: no
    verify_ssl:
        description:
        - 'Controls SSL verification mode when making API calls to DECS controller. Set it to False if you
         want to disable SSL certificate verification.'
        - `Intended use case is when you run module in a trusted environment that uses self-signed certificates. 
         Note that disabling SSL verification in any other scenario can lead to security issues, so please use 
         with caution.'
        default: True
        required: no
'''

EXAMPLES = '''
- name: Obtain JWT and store it as my_jwt for authenticating subsequent task to DECORT cloud controller
  decort_jwt:
    app_id: "{{ my_app_id }}"
    app_secret: "{{ my_app_secret }}"
    oauth2_url: https://sso.decs.online
    delegate_to: localhost
    register: my_jwt
'''

RETURN = '''
jwt:
    description: JSON Web Token that can be used to access DECS cloud controller
    returned: always
    type: string
    sample: None
'''

import requests

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

def decort_jwt_parameters():
    """Build and return a dictionary of parameters expected by decort_jwt module in a form accepted
    by AnsibleModule utility class"""

    return dict(
        app_id=dict(type='str',
                    required=True,
                    fallback=(env_fallback, ['DECORT_APP_ID'])),
        app_secret=dict(type='str',
                        required=True,
                        fallback=(env_fallback, ['DECORT_APP_SECRET']),
                        no_log=True),
        oauth2_url=dict(type='str',
                        required=True,
                        fallback=(env_fallback, ['DECORT_OAUTH2_URL'])),
        validity=dict(type='int',
                      required=False,
                      default=3600),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

def main():
    module_parameters = decort_jwt_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,)

    result = {'failed': False, 'changed': False}

    token_get_url = amodule.params['oauth2_url'] + "/v1/oauth/access_token"
    req_data = dict(grant_type="client_credentials",
                    client_id=amodule.params['app_id'],
                    client_secret=amodule.params['app_secret'],
                    response_type="id_token",
                    validity=amodule.params['validity'],)
    # TODO: Need standard code snippet to handle server timeouts gracefully
    # Consider a few retries before giving up or use requests.Session & requests.HTTPAdapter
    # see https://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request

    # catch requests.exceptions.ConnectionError to handle incorrect oauth2_url case
    try:
        token_get_resp = requests.post(token_get_url, data=req_data, verify=amodule.params['verify_ssl'])
    except requests.exceptions.ConnectionError as errco:
        result.update(failed=True)
        result['msg'] = "Failed to connect to {}: {}".format(token_get_url, errco)
        amodule.fail_json(**result)
    except requests.exceptions.Timeout as errti:
        result.update(failed=True)
        result['msg'] = "Timeout when trying to connect to {}: {}".format(token_get_url, errti)
        amodule.fail_json(**result)

    # alternative -- if resp == requests.codes.ok
    if token_get_resp.status_code != 200:
        result.update(failed=True)
        result['msg'] = "Failed to obtain JWT access token from oauth2_url {} for app_id {}: {} {}".format(
            token_get_url, amodule.params['app_id'],
            token_get_resp.status_code, token_get_resp.reason)
        amodule.fail_json(**result)

    # Common return values: https://docs.ansible.com/ansible/2.3/common_return_values.html
    result['jwt'] = token_get_resp.content.decode('utf8')
    amodule.exit_json(**result)

if __name__ == '__main__':
    main()
