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

class decort_rg(DecortController):
    def __init__(self,amodule):
        super(decort_rg, self).__init__(amodule)

        self.validated_acc_id = 0
        self.validated_rg_id = 0
        self.validated_rg_facts = None

        if self.amodule.params['account_id']:
            self.validated_acc_id, _ = self.account_find("", amodule.params['account_id'])
        elif amodule.params['account_name']:
            self.validated_acc_id, _ = self.account_find(amodule.params['account_name'])
        if not self.validated_acc_id:
            # we failed to locate account by either name or ID - abort with an error
            self.result['failed'] = True
            self.result['msg'] = ("Current user does not have access to the requested account "
                                    "or non-existent account specified.")
            self.fail_json(**self.result)

        if amodule.params['rg_id'] > 0:
            self.validated_rg_id = amodule.params['rg_id']

        # Check if the RG with the specified parameters already exists
        self.validated_rg_id, self.rg_facts = self.rg_find(self.validated_acc_id,
                                                            arg_rg_id = self.validated_rg_id, 
                                                            arg_rg_name=amodule.params['rg_name'],
                                                            arg_check_state=False)

        if amodule.params['state'] != "absent":
            self.rg_should_exist = True
        else:
            self.rg_should_exist = False

    def access(self):
        should_change_access = False
        acc_granted = False
        for rg_item in self.rg_facts['acl']:
            if rg_item['userGroupId'] == self.amodule.params['access']['user']:
                acc_granted = True
                if rg_item['right'] != self.amodule.params['access']['right']:
                    should_change_access = True
                if self.amodule.params['access']['action'] == 'revoke':
                    should_change_access = True
        if acc_granted == False and self.amodule.params['access']['action'] == 'grant':
            should_change_access = True

        if should_change_access == True:
            self.rg_access(self.validated_rg_id, self.amodule.params['access'])
            self.rg_facts['access'] = self.amodule.params['access']
        self.rg_should_exist = True
        return

    def error(self):
        self.result['failed'] = True
        self.result['changed'] = False
        if self.validated_rg_id > 0:
            self.result['msg'] = ("Invalid target state '{}' requested for rg ID {} in the "
                                   "current status '{}'.").format(self.validated_rg_id,
                                                                  self.amodule.params['state'],
                                                                  self.rg_facts['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent rg name '{}' "
                                   "in account ID {} ").format(self.amodule.params['state'],
                                                               self.amodule.params['rg_name'],
                                                               self.validated_acc_id)
        return
    
    def update(self):
        resources = self.rg_facts['Resources']['Reserved']
        incorrect_quota = dict(Requested=dict(),
                               Reserved=dict(),)
        query_key_map = dict(cpu='cpu',
                             ram='ram',
                             disk='disksize',
                             ext_ips='extips', 
                             net_transfer='exttraffic',)
        if self.amodule.params['quotas']:
            for quota_item in self.amodule.params['quotas']:
                if self.amodule.params['quotas'][quota_item] < resources[query_key_map[quota_item]]:
                    incorrect_quota['Requested'][quota_item]=self.amodule.params['quotas'][quota_item]
                    incorrect_quota['Reserved'][quota_item]=resources[query_key_map[quota_item]]

        if incorrect_quota['Requested']:
            self.result['msg'] = ("Cannot limit less than already reserved'{}'").format(incorrect_quota)
            self.result['failed'] = True
        
        if self.result['failed'] != True:
            self.rg_update(self.rg_facts, self.amodule.params['quotas'], 
                           self.amodule.params['resType'], self.amodule.params['rename'])
            self.rg_should_exist = True
        return
    
    def setDefNet(self):
        if self.amodule.params['def_netId'] != self.rg_facts['def_net_id']:
            self.rg_setDefNet(self.validated_rg_id,
                              self.amodule.params['def_netType'],
                              self.amodule.params['def_netId'])
        self.rg_should_exist = True
        return

    def create(self):
        self.validated_rg_id = self.rg_provision(self.validated_acc_id,
                                        self.amodule.params['rg_name'], 
                                        self.amodule.params['owner'],
                                        self.amodule.params['annotation'],
                                        self.amodule.params['resType'],
                                        self.amodule.params['def_netType'],
                                        self.amodule.params['ipcidr'],
                                        self.amodule.params['extNetId'],
                                        self.amodule.params['extNetIp'],
                                        self.amodule.params['quotas'],
                                        "", # this is location code. TODO: add module argument
                                        )

        self.validated_rg_id, self.rg_facts = self.rg_find(self.validated_acc_id,
                                        self.validated_rg_id, 
                                        arg_rg_name="",
                                        arg_check_state=False)
        self.rg_should_exist = True 
        return
    
    def enable(self):
        self.rg_enable(self.validated_rg_id, 
                       self.amodule.params['state'])
        if self.amodule.params['state'] == "enabled":
            self.rg_facts['status'] = 'CREATED'
        else:
            self.rg_facts['status'] = 'DISABLED'
        self.rg_should_exist = True
        return
    
    def restore(self):
        self.rg_restore(self.validated_rg_id)
        self.rg_facts['status'] = 'DISABLED'
        self.rg_should_exist = True
        return
        
    def destroy(self):

        self.rg_delete(self.validated_rg_id, self.amodule.params['permanently'])
        if self.amodule.params['permanently'] == True:
            self.rg_facts['status'] = 'DESTROYED'
        else:
            self.rg_facts['status'] = 'DELETED'
        self.rg_should_exist = False
        return

    def package_facts(self, check_mode=False):
        """Package a dictionary of RG facts according to the decort_rg module specification. This dictionary will
        be returned to the upstream Ansible engine at the completion of the module run.

        @param arg_rg_facts: dictionary with RG facts as returned by API call to .../rg/get
        @param arg_check_mode: boolean that tells if this Ansible module is run in check mode
        """

        ret_dict = dict(id=0,
                        name="none",
                        state="CHECK_MODE",
                        )

        if check_mode:
            # in check mode return immediately with the default values
            return ret_dict

        #if arg_rg_facts is None:
        #    # if void facts provided - change state value to ABSENT and return
        #    ret_dict['state'] = "ABSENT"
        #    return ret_dict

        ret_dict['id'] = self.rg_facts['id']
        ret_dict['name'] = self.rg_facts['name']
        ret_dict['state'] = self.rg_facts['status']
        ret_dict['account_id'] = self.rg_facts['accountId']
        ret_dict['gid'] = self.rg_facts['gid']
        ret_dict['resourceLimits'] = self.rg_facts['resourceLimits']

        return ret_dict

    def parameters():
        """Build and return a dictionary of parameters expected by decort_rg module in a form accepted
        by AnsibleModule utility class."""

        return dict(
            account_id=dict(type='int', required=False),
            account_name=dict(type='str', required=False, default=''),
            access=dict(type='dict'),
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
            def_netType=dict(type='str', choices=['PRIVATE','PUBLIC', 'NONE'], default='PRIVATE'),
            def_netId=dict(type='int', default=0),
            extNetId=dict(type='int', default=0),
            extNetIp=dict(type='str', default=""),
            owner=dict(type='str', default=""),
            ipcidr=dict(type='str', default=""),
            jwt=dict(type='str',
                     required=False,
                     fallback=(env_fallback, ['DECORT_JWT']),
                    no_log=True),
            oauth2_url=dict(type='str',
                            required=False,
                            fallback=(env_fallback, ['DECORT_OAUTH2_URL'])),
            rename=dict(type='str', default=""),
            password=dict(type='str',
                          required=False,
                          fallback=(env_fallback, ['DECORT_PASSWORD']),
                          no_log=True),
            quotas=dict(type='dict', required=False),
            resType=dict(type='list'),
            state=dict(type='str',
                       default='present',
                       choices=['absent', 'disabled', 'enabled', 'present']),
            permanently=dict(type='bool',
                             default='False'),
            user=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_USER'])),
            rg_name=dict(type='str', required=False,),
            rg_id=dict(type='int', required=False, default=0),
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
    module_parameters = decort_rg.parameters()

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

    decon = decort_rg(amodule)
    #amodule.check_mode=True
    if decon.validated_rg_id > 0:
        if decon.rg_facts['status'] in ["MODELED", "DISABLING", "ENABLING", "DELETING", "DESTROYING", "CONFIRMED"]:
            decon.error()
        elif decon.rg_facts['status'] in ("CREATED"):
            if amodule.params['state'] == 'absent':
                decon.destroy()
            elif amodule.params['state'] == "disabled":
                decon.enable()
            if amodule.params['state'] in ['present', 'enabled']:
                if amodule.params['quotas'] or amodule.params['resType'] or amodule.params['rename'] != "":
                    decon.update()
                if amodule.params['access']:
                    decon.access()
                if amodule.params['def_netId'] > 0:
                    decon.setDefNet()

        elif decon.rg_facts['status'] == "DELETED":
            if amodule.params['state'] == 'absent' and amodule.params['permanently'] == True:
                decon.destroy()
            elif amodule.params['state'] == 'present':
                decon.restore()
        elif decon.rg_facts['status'] in ("DISABLED"):
            if amodule.params['state'] == 'absent':
                decon.destroy()
            elif amodule.params['state'] == ("enabled"):
                decon.enable()

    else:
        if amodule.params['state'] in ('present', 'enabled'):
            decon.create() 
            if amodule.params['access']:
                decon.access()
        elif amodule.params['state'] in ('disabled'):
            decon.error()
        

    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        if decon.rg_should_exist:
            decon.result['facts'] = decon.package_facts(amodule.check_mode)
            amodule.exit_json(**decon.result)
        else:
            amodule.exit_json(**decon.result)

if __name__ == "__main__":
    main()
