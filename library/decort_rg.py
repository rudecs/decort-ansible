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
module: decort_rg
short_description: Manage resource groups (RGs) in DECORT cloud
description: >
     This module can be used to create a new resource group in DECORT cloud platform, modify its
     characteristics, and delete it.
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
     - New RGs provisioned with this module will be deployed to the first location under specified DECORT 
       controller (if there is more than one location).
options:
    account_id:
        description:
        - ID of the account under which this RG will be created. This is the alternative to I(account_name)
          option. If both I(account_id) and I(account_name) specified, the latter is ignored.
    account_name:
        description:
        - 'Name of the account under which this RG will be created (for new RGs) or is located.'
        - 'This parameter is ignored if I(account_id) is specified.'
        required: no
    annotation:
        description:
        - Optional text description of this resource group.
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
        - If not specified in the playbook, the value will be taken from DECORT_OAUTH2_URL environment variable.
    password:
        description:
        - 'Password for authenticating to the DECORT controller when I(authenticator=legacy).'
        - 'This parameter is required if I(authenticator=legacy) and ignored in other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECORT_PASSWORD environment variable.
        required: no
    quotas:
        description:
        - Dictionary that defines resource quotas to be set on a newly created RG.
        - 'This parameter is optional and only used when creating new RG. It is ignored for any operations on an
          existing RG.'
        - 'The following keys are valid to set the resource quotas:'
        - ' - I(cpu) (integer) - limit on the total number of CPUs that can be consumed by all compute instances 
          in this RG.'
        - ' - I(ram) (integer) - limit on the total amount of RAM in GB that can be consumed by compute instances
          in this RG.'
        - ' - I(disk) (integer) - limit on the total volume of disk space in GB that can be consumed by all
          compute instances in this RG.'
        - ' - I(ext_ips) (integer) - maximum number of external IP addresses that can be allocated to the compute
          instances and virtual network segments (ViNS) in this RG.'
        - 'Each of the above keys is optional. For example, you may specify I(cpu) and I(ram) while omitting the
        other two keys. Then the quotas will be set on RAM and CPU leaving disk volume and the number of external
        IP addresses unlimited.'
        required: no
    rg_name:
        description:
        - Name of the RG to manage.
        required: yes
    state:
        description:
        - Specify the desired state of the resource group at the exit of the module.
        - 'Regardless of I(state), if RG exists and is in one of [DEPLOYING, DESTROYING, MIGRATING, ] states,
          do nothing.'
        - 'If desired I(state=present):'
        - ' - RG does not exist or is in DESTROYED state, create new RG according to the specifications.'
        - ' - RG is in one of [CREATED, DISABLED] states, change quotas if necessary.'
        - ' - RG is in DELETED state, restore it and change quotas if necessary. RG will be left in DISABLED state.'
        - ' - RG in any other state, abort with an error.'
        - 'If desired I(state=enabled):'
        - ' - RG does not exist or is in DESTROYED state, create new RG according to the specifications.'
        - ' - RG is in CREATED state, change quotas if necessary.'
        - ' - RG is in DELETED state, restore it, change quotas if necessary and enable.'
        - ' - RG is in any other state, abort with an error.'
        - 'If desired I(state=absent):'
        - ' - RG is in one of [CREATED, DISABLED, DELETED] states, destroy it.'
        - ' - RG in DESTROYED state, do nothing.' 
        - ' - RG in any other state, abort with an error.'
        - 'If desired I(state=disabled):'
        - ' - RG does not exist or is in one of [ENABLING, DISABLING, DELETING, DELETED, DESTROYING, DESTROYED] 
              states, abort with an error.'
        - ' - RG is DISABLED state, change quotas if necessary.'
        - ' - RG is in CREATED state, change quotas if necessary and disable the RG.'
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
- name: create a new RG named "MyFirstRG" if it does not exist yet, set quotas on CPU and the number of exteranl IPs.
    decort_rg:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://cloud.digitalenergy.online"
      rg_name: "MyFirstRG"
      account_name: "MyMainAccount"
      quotas:
        cpu: 16
        ext_ips: 4
      annotation: "My first RG created with Ansible module"
      state: present
    delegate_to: localhost
    register: my_rg
'''

RETURN = '''
facts:
    description: facts about the resource group
    returned: always
    type: dict
    sample:
      facts:
        id: 100
        name: MyFirstRG
        state: CREATED
        account_id: 10
        gid: 1001
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *


def decort_rg_package_facts(arg_rg_facts, arg_check_mode=False):
    """Package a dictionary of RG facts according to the decort_rg module specification. This dictionary will
    be returned to the upstream Ansible engine at the completion of the module run.

    @param arg_rg_facts: dictionary with RG facts as returned by API call to .../rg/get
    @param arg_check_mode: boolean that tells if this Ansible module is run in check mode
    """

    ret_dict = dict(id=0,
                    name="none",
                    state="CHECK_MODE",
                    )

    if arg_check_mode:
        # in check mode return immediately with the default values
        return ret_dict

    if arg_rg_facts is None:
        # if void facts provided - change state value to ABSENT and return
        ret_dict['state'] = "ABSENT"
        return ret_dict

    ret_dict['id'] = arg_rg_facts['id']
    ret_dict['name'] = arg_rg_facts['name']
    ret_dict['state'] = arg_rg_facts['status']
    ret_dict['account_id'] = arg_rg_facts['accountId']
    ret_dict['gid'] = arg_rg_facts['gid']

    return ret_dict

def decort_rg_parameters():
    """Build and return a dictionary of parameters expected by decort_rg module in a form accepted
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
        quotas=dict(type='dict', required=False),
        state=dict(type='str',
                   default='present',
                   choices=['absent', 'disabled', 'enabled', 'present']),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        rg_name=dict(type='str', required=True,),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

# Workflow digest:
# 1) authenticate to DECORT controller & validate authentication by issuing API call - done when creating DECORTController
# 2) check if the RG with the specified id or rg_name:name exists
# 3) if RG does not exist -> deploy
# 4) if RG exists: check desired state, desired configuration -> initiate action accordingly
# 5) report result to Ansible

def main():
    module_parameters = decort_rg_parameters()

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

    # We need valid Account ID to manage RG.
    # Account may be specified either by account_id or account_name. In both cases we
    # have to validate account presence and accesibility by the current user.
    validated_acc_id = 0
    if decon.check_amodule_argument('account_id', False):
        validated_acc_id, _ = decon.account_find("", amodule.params['account_id'])
    else:
        decon.check_amodule_argument('account_name') # if no account_name, this function will abort module
        validated_acc_id, _ = decon.account_find(amodule.params['account_name'])

    if not validated_acc_id:
        # we failed to locate account by either name or ID - abort with an error
        decon.result['failed'] = True
        decon.result['msg'] = ("Current user does not have access to the requested account "
                                "or non-existent account specified.")
        decon.fail_json(**decon.result)

    # Check if the RG with the specified parameters already exists
    rg_id, rg_facts = decon.rg_find(validated_acc_id,
                                    0, arg_rg_name=amodule.params['rg_name'],
                                    arg_check_state=False)
    rg_should_exist = True

    if rg_id:
        if rg_facts['status'] in ["MODELED", "DISABLING", "ENABLING", "DELETING", "DESTROYING"]:
            # error: nothing can be done to existing RG in the listed statii regardless of
            # the requested state
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing RG ID {} because of its current "
                                   "status '{}'").format(rg_id, rg_facts['status'])
        elif rg_facts['status'] == "DISABLED":
            if amodule.params['state'] == 'absent':
                decon.rg_delete(arg_rg_id=rg_id, arg_permanently=True)
                rg_facts['status'] = 'DESTROYED'
                rg_should_exist = False
            elif amodule.params['state'] in ('present', 'disabled'):
                # update quotas
                decon.rg_quotas(rg_facts, amodule.params['quotas'])
            elif amodule.params['state'] == 'enabled':
                # update quotas and enable
                decon.rg_quotas(rg_facts, amodule.params['quotas'])
                decon.rg_state(rg_facts, 'enabled')
        elif rg_facts['status'] == "CREATED":
            if amodule.params['state'] == 'absent':
                decon.rg_delete(arg_rg_id=rg_id, arg_permanently=True)
                rg_facts['status'] = 'DESTROYED'
                rg_should_exist = False
            elif amodule.params['state'] in ('present', 'enabled'):
                # update quotas
                decon.rg_quotas(rg_facts, amodule.params['quotas'])
            elif amodule.params['state'] == 'disabled':
                # disable and update quotas
                decon.rg_state(rg_facts, 'disabled')
                decon.rg_quotas(rg_facts, amodule.params['quotas'])
        elif rg_facts['status'] == "DELETED":
            if amodule.params['state'] in ['present', 'enabled']:
                # restore and enable
                # TODO: check if restore RG API returns the new RG ID of the restored RG instance.
                decon.rg_restore(arg_rg_id=rg_id)
                decon.rg_state(rg_facts, 'enabled')
                # TODO: Not sure what to do with the quotas after RG is restored. May need to update rg_facts.
                rg_should_exist = True
            elif amodule.params['state'] == 'absent':
                # destroy permanently
                decon.rg_delete(arg_rg_id=rg_id, arg_permanently=True)
                rg_facts['status'] = 'DESTROYED'
                rg_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for RG ID {} in the "
                                       "current status '{}'").format(rg_id,
                                                                     amodule.params['state'],
                                                                     rg_facts['status'])
                rg_should_exist = False
        elif rg_facts['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'enabled'):
                # need to re-provision RG
                decon.check_amodule_argument('rg_name')
                # As we already have validated account ID we can create RG and get rg_id on success
                # pass empty string for location code, rg_provision will select the 1st location  
                rg_id = decon.rg_provision(validated_acc_id,
                                            amodule.params['rg_name'], decon.decort_username,
                                            amodule.params['quotas'],
                                            "", # this is location code. TODO: add module argument
                                            amodule.params['annotation'])
                rg_should_exist = True
            elif amodule.params['state'] == 'absent':
                # nop
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for RG ID {} because of its "
                                       "current status '{}'").format(rg_id,
                                                                     rg_facts['status'])
                rg_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for RG ID {} in the "
                                       "current status '{}'").format(rg_id,
                                                                     amodule.params['state'],
                                                                     rg_facts['status'])
    else:
        # Preexisting RG was not found.
        rg_should_exist = False  # we will change it back to True if RG is explicitly created or restored
        # If requested state is 'absent' - nothing to do
        if amodule.params['state'] == 'absent':
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do as target state 'absent' was requested for "
                                   "non-existent RG name '{}'").format(amodule.params['rg_name'])
        elif amodule.params['state'] in ('present', 'enabled'):
            # Target RG does not exist yet - create it and store the returned ID in rg_id variable for later use
            # To create RG we need account name (or account ID) and RG name - check
            # that these parameters are present and proceed.
            decon.check_amodule_argument('rg_name')
            # as we already have account ID we can create RG and get rg_id on success
            # pass empty string for location code, rg_provision will select the 1st location 
            rg_id = decon.rg_provision(validated_acc_id,
                                        amodule.params['rg_name'], decon.decort_username,
                                        amodule.params['quotas'],
                                        "", # this is location code. TODO: add module argument
                                        amodule.params['annotation'])
            rg_should_exist = True            
        elif amodule.params['state'] == 'disabled':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "RG name '{}' ").format(amodule.params['state'],
                                                            amodule.params['rg_name'])
    #
    # conditional switch end - complete module run
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        # prepare RG facts to be returned as part of decon.result and then call exit_json(...)
        # rg_facts = None
        if rg_should_exist:
            if decon.result['changed']:
                # If we arrive here, there is a good chance that the RG is present - get fresh RG facts from
                # the cloud by RG ID.
                # Otherwise, RG facts from previous call (when the RG was still in existence) will be returned.
                _, rg_facts = decon.rg_find(arg_account_id=0, arg_rg_id=rg_id)
        decon.result['facts'] = decort_rg_package_facts(rg_facts, amodule.check_mode)
        amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
