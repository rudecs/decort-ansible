#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Alexey Dankov (alexey Dankov@digitalenergy.online)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decort_utils import *

class decort_bservice(DecortController):
    def __init__(self,arg_amodule):
        super(decort_bservice, self).__init__(arg_amodule)

        validated_acc_id = 0
        validated_rg_id = 0
        validated_rg_facts = None
        self.bservice_info = None
        if arg_amodule.params['name'] == "" and arg_amodule.params['id'] == 0:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = "Cannot manage Basic Services when its ID is 0 and name is empty."
            self.fail_json(**self.result)
        if not arg_amodule.params['id']:
            if not arg_amodule.params['rg_id']: # RG ID is not set -> locate RG by name -> need account ID
                validated_acc_id, _ = self.account_find(arg_amodule.params['account_name'],
                                                        arg_amodule.params['account_id'])
                if not validated_acc_id:
                    self.result['failed'] = True
                    self.result['changed'] = False
                    self.result['msg'] = ("Current user does not have access to the account ID {} / "
                                          "name '{}' or non-existent account specified.").format(arg_amodule.params['account_id'],
                                                                                                 arg_amodule.params['account_name'])
                    self.fail_json(**self.result)
                    # fail the module -> exit
            # now validate RG
            validated_rg_id, validated_rg_facts = self.rg_find(validated_acc_id,
                                                               arg_amodule.params['rg_id'],)
            if not validated_rg_id:
                self.result['failed'] = True
                self.result['changed'] = False
                self.result['msg'] = "Cannot find RG ID {} / name '{}'.".format(arg_amodule.params['rg_id'],
                                                                                arg_amodule.params['rg_name'])
                self.fail_json(**self.result)
        
        arg_amodule.params['rg_id'] = validated_rg_id
        arg_amodule.params['rg_name'] = validated_rg_facts['name']
        self.acc_id = validated_rg_facts['accountId']
        
        self.bservice_id,self.bservice_info = self.bservice_find(
            self.acc_id,
            validated_rg_id,
            arg_amodule.params['name'],
            arg_amodule.params['id']
        )

        if self.bservice_id == 0:
            self.bservice_should_exist = False
        else:
            self.bservice_should_exist = True

    def nop(self):
        """No operation (NOP) handler for B-service.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual Compute state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.k8s_id:
            self.result['msg'] = ("No state change required for B-service ID {} because of its "
                                   "current status '{}'.").format(self.bservice_id, self.bservice_info['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent B-service instance.").format(self.amodule.params['state'])
        return                         

    def error(self):
        self.result['failed'] = True
        self.result['changed'] = False
        if self.bservice_id:
            self.result['msg'] = ("Invalid target state '{}' requested for B-service ID {} in the "
                                   "current status '{}'.").format(self.bservice_id,
                                                                  self.amodule.params['state'],
                                                                  self.bservice_info['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent B-service name '{}' "
                                   "in RG ID {} / name '{}'").format(self.amodule.params['state'],
                                                                    self.amodule.params['name'],
                                                                    self.amodule.params['rg_id'],
                                                                    self.amodule.params['rg_name'])
        return

    def create(self):
        self.bservice_id = self.bservice_id = self.bservice_provision(
            self.amodule.params['name'],
            self.amodule.params['rg_id'],
            self.amodule.params['sshuser'],
            self.amodule.params['sshkey']
        )
        if self.bservice_id:
            _, self.bservice_info = self.bservice_get_by_id(self.bservice_id)
        self.bservice_state(self.bservice_info,'enabled',self.amodule.params['started'])
        return

    def action(self,d_state,started=False):
        self.bservice_state(self.bservice_info,d_state,started)
        return

    def restore(self):

        self.result['failed'] = True
        self.result['msg'] = "Restore B-Service ID {} manualy.".format(self.bservice_id)
        pass

    def destroy(self):
        self.bservice_delete(self.bservice_id)
        self.bservice_info['status'] = 'DELETED'
        self.bservice_should_exist = False
        return

    def package_facts(self,check_mode=False):
        
        ret_dict = dict(
            name="",
            state="CHECK_MODE",
            account_id=0,
            rg_id=0,
            config=None,
        )

        if check_mode:
            # in check mode return immediately with the default values
            return ret_dict

        ret_dict['id'] = self.bservice_info['id']
        ret_dict['name'] = self.bservice_info['name']
        ret_dict['techStatus'] = self.bservice_info['techStatus']
        ret_dict['state'] = self.bservice_info['status']
        ret_dict['rg_id'] = self.bservice_info['rgId']
        ret_dict['account_id'] = self.acc_id
        ret_dict['groupsName'] = self.bservice_info['groupsName']
        ret_dict['groupsIds'] = self.bservice_info['groups']
        return ret_dict
    @staticmethod
    def build_parameters():
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
                    choices=['absent', 'disabled', 'enabled', 'present','check']),
            started=dict(type='bool', required=False, default=True),
            user=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_USER'])),
            name=dict(type='str', required=True),
            sshuser=dict(type='str', required=False,default=None),
            sshkey=dict(type='str', required=False,default=None),
            id=dict(type='int', required=False, default=0),
            rg_id=dict(type='int', default=0),
            rg_name=dict(type='str',default=""),
            description=dict(type='str', default="Created by decort ansible module"),
            verify_ssl=dict(type='bool', required=False, default=True),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),)
def main():
    module_parameters = decort_bservice.build_parameters()

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
                            required_one_of=[
                                ['id', 'name'],
                                ['rg_id','rg_name']
                            ],
                            )

    subj = decort_bservice(amodule)
    
    if amodule.params['state'] == 'check':
        subj.result['changed'] = False
        if subj.bservice_id:
            subj.result['failed'] = False
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
            # we exit the module at this point
        else:
            subj.result['failed'] = True
            subj.result['msg'] = ("Cannot locate B-service name '{}'. Other arguments are: B-service ID {}, "
                                  "RG name '{}', RG ID {}, Account '{}'.").format(amodule.params['name'],
                                                                                amodule.params['id'],
                                                                                amodule.params['rg_name'],
                                                                                amodule.params['rg_id'],
                                                                                amodule.params['account_name'])
            amodule.fail_json(**subj.result)
            pass
    
    
    #MAIN MANAGE PART

    if subj.bservice_id:
        if subj.bservice_info['status'] in ("DELETING","DESTROYNG","RECONFIGURING","DESTROYING",
                                         "ENABLING","DISABLING","RESTORING","MODELED"):
            subj.error()
        elif subj.bservice_info['status'] == "DELETED":
            if amodule.params['state'] in ('disabled', 'enabled', 'present'):
                subj.restore(subj.bservice_id)
                subj.action(amodule.params['state'],amodule.params['started'])
            if amodule.params['state'] == 'absent':
                subj.nop()
        elif subj.bservice_info['techStatus'] in ("STARTED","STOPPED"):
            if amodule.params['state'] == 'disabled':
                subj.action(amodule.params['state'],amodule.params['started'])
            elif amodule.params['state'] == 'absent':
                subj.destroy()
            else:
                subj.action(amodule.params['state'],amodule.params['started'])
        elif subj.bservice_info['status'] == "DISABLED":
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present','enabled'):
                subj.action(amodule.params['state'],amodule.params['started'])
            else:
                subj.nop()
        elif subj.bservice_info['status'] == "DESTROED":
            if amodule.params['state'] in ('present','enabled'):
                subj.create()
                subj.action(amodule.params['state'],amodule.params['started'])
            if amodule.params['state'] == 'absent':    
                subj.nop()
    else:
        if amodule.params['state'] == 'absent':
            subj.nop()
        if amodule.params['state'] in ('present','started'):
            subj.create()
        elif amodule.params['state'] in ('stopped', 'disabled','enabled'):
            subj.error()
    
    if subj.result['failed']:
        amodule.fail_json(**subj.result)
    else:
        if subj.bservice_should_exist:
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
        else:
            amodule.exit_json(**subj.result)
if __name__ == "__main__":
    main()