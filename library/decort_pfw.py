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
module: decort_pfw
short_description: Manage network Port Forward rules for Compute instances in DECORT cloud
description: >
     This module can be used to create new port forwarding rules in DECORT cloud platform, 
     modify and delete them.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT module
     - requests module
     - decort_utils utility library (module)
     - DECORT cloud platform version 3.4.2 or higher
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECORT cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECORT cloud controller on which this JWT will be used.'
options:
    account_id:
        description:
        - ID of the account, which owns this disk. This is the alternative to I(account_name) option.
        - If both I(account_id) and I(account_name) specified, then I(account_name) is ignored.
        default: 0
        required: no
    account_name:
        description:
        - 'Name of the account, which will own this disk.'
        - 'This parameter is ignored if I(account_id) is specified.'
        default: empty string
        required: no
    app_id:
        description:
        - 'Application ID for authenticating to the DECORT controller when I(authenticator=oauth2).'
        - 'Required if I(authenticator=oauth2).'
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_ID
           environment variable.'
        required: no
    app_secret:
        description:
        - 'Application API secret used for authenticating to the DECORT controller when I(authenticator=oauth2).'
        - This parameter is required when I(authenticator=oauth2) and ignored in other modes.
        - 'If not found in the playbook or command line arguments, the value will be taken from DECORT_APP_SECRET
           environment variable.'
        required: no
    authenticator:
        description:
        - Authentication mechanism to be used when accessing DECORT controller and authorizing API call.
        default: jwt
        choices: [ jwt, oauth2, legacy ]
        required: yes
    controller_url:
        description:
        - URL of the DECORT controller that will be contacted to manage the RG according to the specification.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    compute_id:
        description:
        - ID of the Compute instance to manage network port forwarding rules for.
        required: yes
    jwt:
        description:
        - 'JWT (access token) for authenticating to the DECORT controller when I(authenticator=jwt).'
        - 'This parameter is required if I(authenticator=jwt) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_JWT environment variable.
        required: no
    oauth2_url:
        description:
        - 'URL of the oauth2 authentication provider to use when I(authenticator=oauth2).'
        - 'This parameter is required when when I(authenticator=oauth2).'
        - 'If not specified in the playbook, the value will be taken from DECORT_OAUTH2_URL environment variable.'
    password:
        description:
        - 'Password for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required if I(authenticator=legacy) and ignored in other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_PASSWORD environment variable.
        required: no
    rules:
        description:
        - 'Set of rules to configure for the Compute instance identidied by I(compute_id) in the virtual
          network segment identidied by I(vins_id).'
        - The set is specified as a list of dictionaries with the following structure:
        - '  - (int) public_port_start - starting port number on the ViNS external interface.'
        - '  - (int) public_port_end - optional end port number of the ViNS external interface. If not specified
               or set equal to I(public_port_start), a one-to-one rule is created. Otherwise a ranged rule will
               be created, which maps specified external port range to local ports starting from I(local_port).'
        - '  - (int) local_port - port number on the local interface of the Compute. For ranged rule it is
               interpreted as a base port to translate public port range to internal port range.'
        - '  - (string) proto - protocol, specify either I(tcp) or I(udp).'
        - 'Note that rules are meaningful only if I(state=present). If I(state=absent) is specified, rules set
           will be ignored, and all rules for the specified Compute will be deleted.'
    state:
        description:
        - 'Specify the desired state of the port forwarding rules set for the Compute instance identified by
          I(compute_id).'
        - 'If I(state=present), the rules will be applied according to the I(rules) parameter.'
        - 'If I(state=absent), all rules for the specified Compute instance will be deleted regardless of
           I(rules) parameter.'
        default: present
        choices: [ absent, present ]
    verify_ssl:
        description:
        - 'Controls SSL verification mode when making API calls to DECORT controller. Set it to False if you
         want to disable SSL certificate verification. Intended use case is when you run module in a trusted
         environment that uses self-signed certificates. Note that disabling SSL verification in any other
         scenario can lead to security issues, so please know what you are doing.'
        default: True
        required: no
    vins_id:
        description:
        - ID of the virtual network segment (ViNS), where port forwarding rules will be set up.
        - This ViNS must have connection to external network.
        - Compute instance specified by I(compute_id) must be connected to this ViNS.
    workflow_callback:
        description:
        - 'Callback URL that represents an application, which invokes this module (e.g. up-level orchestrator or
          end-user portal) and may except out-of-band updates on progress / exit status of the module run.'
        - API call at this URL will be used to relay such information to the application.
        - 'API call payload will include module-specific details about this module run and I(workflow_context).'
        required: no
    workflow_context:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        - 'This context data is expected to uniquely identify the task carried out by this module invocation so
           that up-level orchestrator could match returned information to the its internal entities.'
        required: no
'''

EXAMPLES = '''
- name: configure one-toone rule for SSH protocol on Compute ID 100 connected to ViNS ID 5.
    decort_pfw:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://cloud.digitalenergy.online"
      compute_id: 100
      vins_id: 5
      rules:
        - public_port_start: 10022
          local_port: 22
          proto: tcp
      state: present
    delegate_to: localhost
    register: my_pfw
'''

RETURN = '''
facts:
    description: facts about created PFW rules
    returned: always
    type: dict
    sample:
      facts:
        compute_id: 100
        vins_id: 5
        rules:
          - 
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *


def decort_pfw_package_facts(comp_id, vins_id, pfw_facts, check_mode=False):
    """Package a dictionary of PFW rules facts according to the decort_pfw module specification. 
    This dictionary will be returned to the upstream Ansible engine at the completion of 
    the module run.

    @param (dict) pfw_facts: dictionary with PFW facts as returned by API call to .../???/get
    @param (bool) check_mode: boolean that tells if this Ansible module is run in check mode
    """

    ret_dict = dict(state="CHECK_MODE",
                    compute_id=0,
                    vins_id=0,
                    rules=[],
                    )

    if check_mode:
        # in check mode return immediately with the default values
        return ret_dict

    if pfw_facts is None:
        # if void facts provided - change state value to ABSENT and return
        ret_dict['state'] = "ABSENT"
        return ret_dict

    ret_dict['compute_id'] = comp_id
    ret_dict['vins_id'] = vins_id
    
    if len(pfw_facts) != 0:
        ret_dict['state'] = 'PRESENT'
        ret_dict['rules'] = pfw_facts
    else:
        ret_dict['state'] = 'ABSENT'

    return ret_dict

def decort_pfw_parameters():
    """Build and return a dictionary of parameters expected by decort_pfw module in a form accepted
    by AnsibleModule utility class."""

    return dict(
        app_id=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_APP_ID'])),
        app_secret=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECORT_APP_SECRET']),
                        no_log=True),
        authenticator=dict(type='str',
                           required=True,
                           choices=['legacy', 'oauth2', 'jwt']),
        compute_id=dict(type='int', required=True),
        controller_url=dict(type='str', required=True),
        jwt=dict(type='str',
                 required=False,
                 fallback=(env_fallback, ['DECORT_JWT']),
                 no_log=True),
        oauth2_url=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECORT_OAUTH2_URL'])),
        password=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_PASSWORD']),
                      no_log=True),
        rules=dict(type='list', required=False, default=[]),
        state=dict(type='str',
                   default='present',
                   choices=['absent', 'present']),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        verify_ssl=dict(type='bool', required=False, default=True),
        vins_id=dict(type='int', required=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

def main():
    module_parameters = decort_pfw_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,
                            mutually_exclusive=[
                                ['oauth2', 'password'],
                                ['password', 'jwt'],
                                ['jwt', 'oauth2'],
                            ],
                            required_together=[
                                ['app_id', 'app_secret'],
                                ['user', 'password'],
                            ],
                            )

    decon = DecortController(amodule)

    pfw_facts = None # will hold PFW facts as returned by pfw_configure

    #
    # Validate module arguments:
    # 1) specified Compute instance exists in correct state
    # 2) specified ViNS exists
    # 3) ViNS has GW function
    # 4) Compute is connected to this ViNS
    #

    validated_comp_id, comp_facts, rg_id = decon.compute_find(amodule.params['compute_id'])
    if not validated_comp_id:
        decon.result['failed'] = True
        decon.result['msg'] = "Cannot find specified Compute ID {}.".format(amodule.params['compute_id'])
        amodule.fail_json(**decon.result)

    validated_vins_id, vins_facts = decon.vins_find(amodule.params['vins_id'])
    if not validated_vins_id:
        decon.result['failed'] = True
        decon.result['msg'] = "Cannot find specified ViNS ID {}.".format(amodule.params['vins_id'])
        amodule.fail_json(**decon.result)

    gw_vnf_facts = vins_facts['vnfs'].get('GW')
    if not gw_vnf_facts or gw_vnf_facts['status'] == "DESTROYED":
        decon.result['failed'] = True
        decon.result['msg'] = "ViNS ID {} does not have a configured external connection.".format(validated_vins_id)
        amodule.fail_json(**decon.result)

    #
    # Initial validation of module arguments is complete
    # 

    if amodule.params['state'] == 'absent':
        # ignore amodule.params['rules'] and remove all rules associated with this Compute
        pfw_facts = decon.pfw_configure(comp_facts, vins_facts, None) 
    else:
        # manage PFW rules accodring to the module arguments
        pfw_facts = decon.pfw_configure(comp_facts, vins_facts, amodule.params['rules'])
    
    #
    # complete module run
    #
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        # prepare PFW facts to be returned as part of decon.result and then call exit_json(...)
        decon.result['facts'] = decort_pfw_package_facts(comp_facts['id'], vins_facts['id'], pfw_facts, amodule.check_mode)
        amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
