#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
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
module: decort_vins
short_description: Manage Virtual Network Segments (ViNS) in DECORT cloud
description: >
     This module can be used to create new ViNS in DECORT cloud platform, obtain or 
     modify its characteristics, and delete it.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT Python module
     - requests Python module
     - netaddr Python module
     - decort_utils utility library (module)
     - DECORT cloud platform version 3.6.1 or higher
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECORT cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECORT cloud controller on which this JWT will be used.'
options:
    account_id:
        description:
        - 'ID of the account under which this ViNS will be created (for new ViNS) or is located (for already
          existing ViNS). This is the alternative to I(account_name) option.'
        - If both I(account_id) and I(account_name) specified, then I(account_name) is ignored.
        required: no
    account_name:
        description:
        - 'Name of the account under which this ViNS will be created (for new RGs) or is located (for already
           existing ViNS).'
        - 'This parameter is ignored if I(account_id) is specified.'
        required: no
    annotation:
        description:
        - Optional text description of this virtual network segment.
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
    ext_net_id:
        description:
        - 'Controls ViNS connection to an external network. This argument is optional with default value of -1,
          which means no external connection.'
        - Specify 0 to connect ViNS to external network and let platform select external network Id automatically.
        - Specify positive value to request ViNS connection to the external network with corresponding ID.
        - You may also control external IP address selection with I(ext_ip_addr) argument.
        default: -1
        required: no
    ext_ip_addr:
        description:
        - IP address to assign to the external interface of this ViNS when connecting to the external net.
        - If empty string is passed, the platform will assign free IP address automatically.
        - 'Note that if invalid IP address or an address already occupied by another client is specified, 
           the module will abort with an error.'
        - 'This argument is used only for new connection to the specified network. You cannot select another 
           external IP address without changing external network ID.'
        - ViNS connection to the external network is controlled by I(ext_net_id) argument.
        default: empty string
        required: no
    ipcidr:
        description:
        - Internal ViNS network address in a format XXX.XXX.XXX.XXX/XX (includes address and netmask).
        - If empty string is passed, the platform will assign network address automatically.
        - 'When selecting this address manually, note that this address must be unique amomng all ViNSes in 
           the target account.'
        default: empty string
        required: no
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
    rg_id:
        description:
        - 'ID of the resource group (RG), where this ViNS will be created (for a new ViNS) or located 
           (for already existing ViNS).'
        - If ViNS is created at the account level, I(rg_id) should be omitted or set to 0.
        - If both I(rg_id) and I(rg_name) are specified, then I(rg_name) is ignored.
        default: 0
        required: no
    rg_name:
        description:
        - 'Name of the resource group (RG), where this ViNS will be created (for new ViNS) or 
          located (for already existing ViNS).'
        - If ViNS is created at the account level, I(rg_name) should be omitted or set to emtpy string.
        - If both I(rg_name) and I(rg_id) are specified, then I(rg_name) is ignored. 
        default: empty string
        required: no
    state:
        description:
        - Specify the desired state of the ViNS at the exit of the module.
        - 'Regardless of I(state), if ViNS exists and is in one of [DEPLOYING, DESTROYING, MIGRATING] states,
          do nothing.'
        - 'If desired I(state=present):'
        - ' - ViNS does not exist or is in DESTROYED state, create new ViNS according to the specifications.'
        - ' - ViNS is in DELETED state, restore it and change quotas if necessary. Note that on successful 
              restore ViNS will be left in DISABLED state.'
        - ' - ViNS is in one of [CREATED, ENABLED, DISABLED] states, do nothing.'
        - ' - ViNS in any other state, abort with an error.'
        - 'If desired I(state=enabled):'
        - ' - ViNS does not exist or is in DESTROYED state, create new ViNS according to the specifications.'
        - ' - ViNS is in DELETED state, restore and enable it.'
        - ' - ViNS is in one of [CREATED, ENABLED] states, do nothing.'
        - ' - viNS is in any other state, abort with an error.'
        - 'If desired I(state=absent):'
        - ' - ViNS is in one of [CREATED, ENABLED, DISABLED, DELETED] states, destroy it.'
        - ' - ViNS in DESTROYED state, do nothing.' 
        - ' - ViNS in any other state, abort with an error.'
        - 'If desired I(state=disabled):'
        - ' - ViNS is in one of [CREATED, ENABLED] states, disable it.'
        - ' - ViNS is DISABLED state, do nothing.'
        - ' - ViNS does not exist or is in one of [ENABLING, DISABLING, DELETING, DELETED, DESTROYING, DESTROYED] 
              states, abort with an error.'
        default: present
        choices: [ absent, disabled, enabled, present ]
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_USER environment variable.
        required: no
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
        - ID of the ViNs to manage. If ViNS is identified by ID it must be present.
        - If ViNS ID is specified, I(account_id), I(account_name), I(rg_id) and I(rg_name) are ignored.
    vins_name:
        description:
        - Name of the ViNS.
        - ViNS can exist at either account or resource group level.
        - ViNS name is unique only within its parent (i.e. account or resource group).
        - 'To create ViNS at account level omit both I(rg_id) and I(rg_name), or set them to 0 and empty
           string respectively.'
        required: yes
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
- name: create a new ViNS named "MyViNS" if it does not exist yet under RG "MyRG" in the account "MyAccount".
    decort_vins:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://cloud.digitalenergy.online"
      vins_name: "MyViNS"
      rg_name: "MyRG"
      account_name: "MyAccount"
      state: present
    delegate_to: localhost
    register: my_vins
'''

RETURN = '''
facts:
    description: facts about the virtual network segment
    returned: always
    type: dict
    sample:
      facts:
        id: 5
        name: MyViNS
        int_net_addr: 192.168.1.0
        ext_net_addr: 10.50.11.118
        state: CREATED
        account_id: 7
        rg_id: 19
        gid: 1001
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
import paramiko

from ansible.module_utils.decort_utils import *


def decort_vins_package_facts(arg_vins_facts, arg_check_mode=False):
    """Package a dictionary of ViNS facts according to the decort_vins module specification. 
    This dictionary will be returned to the upstream Ansible engine at the completion of 
    the module run.

    @param arg_vins_facts: dictionary with viNS facts as returned by API call to .../vins/get
    @param arg_check_mode: boolean that tells if this Ansible module is run in check mode
    """

    ret_dict = dict(id=0,
                    name="none",
                    state="CHECK_MODE",
                    )

    if arg_check_mode:
        # in check mode return immediately with the default values
        return ret_dict

    if arg_vins_facts is None:
        # if void facts provided - change state value to ABSENT and return
        ret_dict['state'] = "ABSENT"
        return ret_dict

    ret_dict['id'] = arg_vins_facts['id']
    ret_dict['name'] = arg_vins_facts['name']
    ret_dict['state'] = arg_vins_facts['status']
    ret_dict['account_id'] = arg_vins_facts['accountId']
    ret_dict['rg_id'] = arg_vins_facts['rgId']
    ret_dict['int_net_addr'] = arg_vins_facts['network']
    ret_dict['gid'] = arg_vins_facts['gid']

    if arg_vins_facts['vnfs'].get('GW'):
        gw_config = arg_vins_facts['vnfs']['GW']['config']
        ret_dict['ext_ip_addr'] = gw_config['ext_net_ip']
        ret_dict['ext_net_id'] = gw_config['ext_net_id']
    else:
        ret_dict['ext_ip_addr'] = ""
        ret_dict['ext_net_id'] = -1

    # arg_vins_facts['vnfs']['GW']['config']
    #   ext_ip_addr -> ext_net_ip
    #   ???         -> ext_net_id
    # tech_status   -> techStatus

    return ret_dict


def decort_vins_parameters():
    """Build and return a dictionary of parameters expected by decort_vins module in a form accepted
    by AnsibleModule utility class."""

    return dict(
        account_id=dict(type='int', required=False),
        account_name=dict(type='str', required=False, default=''),
        annotation=dict(type='str', required=False, default=''),
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
        controller_url=dict(type='str', required=True),
        # datacenter=dict(type='str', required=False, default=''),
        ext_net_id=dict(type='int', required=False, default=-1),
        ext_ip_addr=dict(type='str', required=False, default=''),
        ipcidr=dict(type='str', required=False, default=''),
        mgmtaddr=dict(type='str',required=False, default=''),
        custom_config=dict(type='bool',required=False, default=False),
        config_save=dict(type='bool',required=False, default=False),
        connect_to=dict(type='list', default=[], required=False),
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
        state=dict(type='str',
                   default='present',
                   choices=['absent', 'disabled', 'enabled', 'present']),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        rg_id=dict(type='int', required=False, default=0),
        rg_name=dict(type='str', required=False, default=''),
        verify_ssl=dict(type='bool', required=False, default=True),
        vins_id=dict(type='int', required=False, default=0),
        vins_name=dict(type='str', required=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )


# Workflow digest:
# 1) authenticate to DECORT controller & validate authentication by issuing API call - done when creating DECORTController
# 2) check if the ViNS with this id or name exists under specified account / resource group
# 3) if ViNS does not exist -> deploy
# 4) if ViNS exists: check desired state, desired configuration -> initiate action(s) accordingly
# 5) report result to Ansible

def main():
    module_parameters = decort_vins_parameters()

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

    vins_id = 0
    vins_level = ""  # "ID" if specified by ID, "RG" - at resource group, "ACC" - at account level
    vins_facts = None  # will hold ViNS facts
    validated_rg_id = 0
    rg_facts = None  # will hold RG facts
    validated_acc_id = 0
    acc_facts = None  # will hold Account facts

    if amodule.params['vins_id']:
        # expect existing ViNS with the specified ID
        # This call to vins_find will abort the module if no ViNS with such ID is present
        vins_id, vins_facts = decon.vins_find(amodule.params['vins_id'])
        if not vins_id:
            decon.result['failed'] = True
            decon.result['msg'] = "Specified ViNS ID {} not found.".format(amodule.params['vins_id'])
            decon.fail_json(**decon.result)
        vins_level = "ID"
        validated_acc_id = vins_facts['accountId']
        validated_rg_id = vins_facts['rgId']
   
    elif amodule.params['rg_id']:
        # expect ViNS @ RG level in the RG with specified ID
        vins_level = "RG"
        # This call to rg_find will abort the module if no RG with such ID is present
        validated_rg_id, rg_facts = decon.rg_find(0,  # account ID set to 0 as we search for RG by RG ID
                                                  amodule.params['rg_id'], arg_rg_name="")
        # This call to vins_find may return vins_id=0 if no ViNS found
        vins_id, vins_facts = decon.vins_find(vins_id=0, vins_name=amodule.params['vins_name'],
                                              account_id=0,
                                              rg_id=amodule.params['rg_id'],
                                              check_state=False)
        # TODO: add checks and setup ViNS presence flags accordingly
        pass
    elif amodule.params['account_id'] or amodule.params['account_name'] != "":
        # Specified account must be present and accessible by the user, otherwise abort the module
        validated_acc_id, acc_facts = decon.account_find(amodule.params['account_name'], amodule.params['account_id'])
        if not validated_acc_id:
            decon.result['failed'] = True
            decon.result['msg'] = ("Current user does not have access to the requested account "
                                   "or non-existent account specified.")
            decon.fail_json(**decon.result)
        if amodule.params['rg_name'] != "":  # at this point we know that rg_id=0
            # expect ViNS @ RG level in the RG with specified name under specified account
            # RG with the specified name must be present under the account, otherwise abort the module
            validated_rg_id, rg_facts = decon.rg_find(validated_acc_id, 0, amodule.params['rg_name'])
            if (not validated_rg_id or
                    rg_facts['status'] in ["DESTROYING", "DESTROYED", "DELETING", "DELETED", "DISABLING", "ENABLING"]):
                decon.result['failed'] = True
                decon.result['msg'] = "RG name '{}' not found or has invalid state.".format(amodule.params['rg_name'])
                decon.fail_json(**decon.result)
            # This call to vins_find may return vins_id=0 if no ViNS with this name found under specified RG
            vins_id, vins_facts = decon.vins_find(vins_id=0, vins_name=amodule.params['vins_name'],
                                                  account_id=0,  # set to 0, as we are looking for ViNS under RG
                                                  rg_id=validated_rg_id,
                                                  check_state=False)
            vins_level = "RG"
            # TODO: add checks and setup ViNS presence flags accordingly
        else:  # At this point we know for sure that rg_name="" and rg_id=0
            # So we expect ViNS @ account level
            # This call to vins_find may return vins_id=0 if no ViNS found
            vins_id, vins_facts = decon.vins_find(vins_id=0, vins_name=amodule.params['vins_name'],
                                                  account_id=validated_acc_id,
                                                  rg_id=0,
                                                  check_state=False)
            vins_level = "ACC"
            # TODO: add checks and setup ViNS presence flags accordingly
    else:
        # this is "invalid arguments combination" sink
        # if we end up here, it means that module was invoked with vins_id=0 and rg_id=0
        decon.result['failed'] = True
        if amodule.params['account_id'] == 0 and amodule.params['account_name'] == "":
            decon.result['msg'] = "Cannot find ViNS by name when account name is empty and account ID is 0."
        if amodule.params['rg_name'] == "":
            # rg_name without account specified
            decon.result['msg'] = "Cannot find ViNS by name when RG name is empty and RG ID is 0."
        decon.fail_json(**decon.result)
    #
    # Initial validation of module arguments is complete
    #
    # At this point non-zero vins_id means that we will be managing pre-existing ViNS
    # Otherwise we are about to create a new one as follows:
    # - if validated_rg_id is non-zero, create ViNS @ RG level
    # - if validated_rg_id is zero, create ViNS @ account level
    #
    # When managing existing ViNS we need to account for both "static" and "transient"
    # status. Full range of ViNS statii is as follows:
    #
    # "MODELED", "CREATED", "ENABLED", "ENABLING", "DISABLED", "DISABLING", "DELETED", "DELETING", "DESTROYED", "DESTROYING"
    #
    # if cconfig_save is true, only config save without other updates
    vins_should_exist = False

    if vins_id:
        vins_should_exist = True
        if vins_facts['status'] in ["MODELED", "DISABLING", "ENABLING", "DELETING", "DESTROYING"]:
            # error: nothing can be done to existing ViNS in the listed statii regardless of
            # the requested state
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing ViNS ID {} because of its current "
                                   "status '{}'").format(vins_id, vins_facts['status'])
        elif vins_facts['status'] == "DISABLED":
            if amodule.params['state'] == 'absent':
                decon.vins_delete(vins_id, permanently=True)
                vins_facts['status'] = 'DESTROYED'
                vins_should_exist = False
            elif amodule.params['state'] in ('present', 'disabled'):
                # update ViNS, leave in disabled state
                decon.vins_update(vins_facts,
                                  amodule.params['ext_net_id'], amodule.params['ext_ip_addr'])
            elif amodule.params['state'] == 'enabled':
                # update ViNS and enable
                decon.vins_update(vins_facts,
                                  amodule.params['ext_net_id'], amodule.params['ext_ip_addr'])
                decon.vins_state(vins_facts, 'enabled')
        elif vins_facts['status'] in ["CREATED", "ENABLED"]:
            if amodule.params['state'] == 'absent':
                decon.vins_delete(vins_id, permanently=True)
                vins_facts['status'] = 'DESTROYED'
                vins_should_exist = False
            elif amodule.params['state'] in ('present', 'enabled'):
                # update ViNS
                decon.vins_update(vins_facts,
                                  amodule.params['ext_net_id'], amodule.params['ext_ip_addr'],
                                  
                                  )
                decon.vins_update_mgmt(
                                        vins_facts,
                                        amodule.params['mgmtaddr'],
                                        )
                decon.vins_update_ifaces(
                                        vins_facts,
                                        amodule.params['connect_to'],
                )
            elif amodule.params['state'] == 'disabled':
                # disable and update ViNS
                decon.vins_state(vins_facts, 'disabled')
                decon.vins_update(vins_facts,
                                  amodule.params['ext_net_id'], amodule.params['ext_ip_addr'])
        elif vins_facts['status'] == "DELETED":
            if amodule.params['state'] in ['present', 'enabled']:
                # restore and enable
                decon.vins_restore(arg_vins_id=vins_id)
                decon.vins_state(vins_facts, 'enabled')
                vins_should_exist = True
            elif amodule.params['state'] == 'absent':
                # destroy permanently
                decon.vins_delete(vins_id, permanently=True)
                vins_facts['status'] = 'DESTROYED'
                vins_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for ViNS ID {} in the "
                                       "current status '{}'").format(vins_id,
                                                                     amodule.params['state'],
                                                                     vins_facts['status'])
                vins_should_exist = False
        elif vins_facts['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'enabled'):
                # need to re-provision ViNS; some attributes may be changed, some stay the same.
                # account and RG - stays the same
                # vins_name - stays the same
                # IPcidr - take from module arguments
                # ext IP address - take from module arguments
                # annotation - take from module arguments
                vins_id = decon.vins_provision(vins_facts['name'],
                                               validated_acc_id, validated_rg_id,
                                               amodule.params['ipcidr'],
                                               amodule.params['ext_net_id'], amodule.params['ext_ip_addr'],
                                               amodule.params['annotation'])
                vins_should_exist = True
            elif amodule.params['state'] == 'absent':
                # nop
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for ViNS ID {} because of its "
                                       "current status '{}'").format(vins_id,
                                                                     vins_facts['status'])
                vins_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for ViNS ID {} in the "
                                       "current status '{}'").format(vins_id,
                                                                     amodule.params['state'],
                                                                     vins_facts['status'])
    else:
        # Preexisting ViNS was not found.
        vins_should_exist = False  # we will change it back to True if ViNS is created or restored
        # If requested state is 'absent' - nothing to do
        if amodule.params['state'] == 'absent':
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do as target state 'absent' was requested for "
                                   "non-existent ViNS name '{}'").format(amodule.params['vins_name'])
        elif amodule.params['state'] in ('present', 'enabled'):
            decon.check_amodule_argument('vins_name')
            # as we already have account ID and RG ID we can create ViNS and get vins_id on success
            vins_id = decon.vins_provision(amodule.params['vins_name'],
                                           validated_acc_id, validated_rg_id,
                                           amodule.params['ipcidr'],
                                           amodule.params['ext_net_id'], amodule.params['ext_ip_addr'],
                                           amodule.params['annotation'])
            vins_should_exist = True
        elif amodule.params['state'] == 'disabled':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "ViNS name '{}'").format(amodule.params['state'],
                                                            amodule.params['vins_name'])
    #
    # conditional switch end - complete module run
    #
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        # prepare ViNS facts to be returned as part of decon.result and then call exit_json(...)
        if vins_should_exist:
            if decon.result['changed']:
                # If we arrive here, there is a good chance that the ViNS is present - get fresh ViNS
                # facts from # the cloud by ViNS ID.
                # Otherwise, ViNS facts from previous call (when the ViNS was still in existence) will
                # be returned.
                _, vins_facts = decon.vins_find(vins_id)
        decon.result['facts'] = decort_vins_package_facts(vins_facts, amodule.check_mode)
        # add password to facts if mgmtaddr is present
        # need reworking
        if amodule.params['mgmtaddr'] != "":
            decon.result['facts'].update({'password': vins_facts['VNFDev']['config']['mgmt']['password']})
        amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
