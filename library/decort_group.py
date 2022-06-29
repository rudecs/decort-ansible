#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Alexey Dankov (alexey.dankov@digitalenergy.online)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decort_utils import *

class decort_group(DecortController):
    def __init__(self,arg_amodule):
        super(decort_group, self).__init__(arg_amodule)
        self.group_should_exist = False
        validated_bservice_id = None
        #find and validate B-Service

        validated_bservice_id, bservice_info = self.bservice_get_by_id(arg_amodule.params['bservice_id'])
        if not validated_bservice_id:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = ("Cannot find B-service ID {}.").format(arg_amodule.params['bservice_id'])
            self.fail_json(**self.result)
        #find group
        self.bservice_id = validated_bservice_id
        self.bservice_info = bservice_info
        self.group_id,self.group_info = self.group_find(
            bs_id=validated_bservice_id,
            bs_info=bservice_info,
            group_id=arg_amodule.params['id'],
            group_name=arg_amodule.params['name'],
            )

        if self.group_id:
            self.group_should_exist = True
        
        return
    def nop(self):
        """No operation (NOP) handler for B-service.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual Compute state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.group_id:
            self.result['msg'] = ("No state change required for B-service ID {} because of its "
                                   "current status '{}'.").format(self.group_id, self.group_info['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent B-service instance.").format(self.amodule.params['state'])
        return                         

    def error(self):
        self.result['failed'] = True
        self.result['changed'] = False
        if self.group_id:
            self.result['msg'] = ("Invalid target state '{}' requested for Group ID {} in the "
                                   "current status '{}'.").format(self.group_id,
                                                                  self.amodule.params['state'],
                                                                  self.group_info['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent Group name '{}' "
                                   "in B-service {}").format(self.amodule.params['state'],
                                                                    self.amodule.params['name'],
                                                                    self.amodule.params['bservice_id'],
                                )
        return

    def create(self):

        if self.amodule.params['driver'] not in ["KVM_X86","KVM_PPC"]:
            self.result['failed'] = True
            self.result['msg'] = ("Unsupported driver '{}' is specified for "
                                  "Group.").format(self.amodule.params['driver'])
            self.amodule.fail_json(**self.result)

        self.group_id=self.group_provision(
           self.bservice_id,
           self.amodule.params['name'],
           self.amodule.params['count'],
           self.amodule.params['cpu'],
           self.amodule.params['ram'],
           self.amodule.params['boot_disk'],
           self.amodule.params['image_id'],
           self.amodule.params['driver'],
           self.amodule.params['role'],
           self.amodule.params['networks'],
           self.amodule.params['timeoutStart'], 
        )
        
        if self.amodule.params['state'] in ('started','present'):
            self.group_state(self.bservice_id,self.group_id,self.amodule.params['state'])
        return

    def action(self):
        #change desired state
        if (
            self.group_info['techStatus'] == 'STARTED' and self.amodule.params['state'] == 'stopped') or (
            self.group_info['techStatus'] == 'STOPPED' and self.amodule.params['state'] in ('started','present')
            ):
            self.group_state(self.bservice_id,self.group_id,self.amodule.params['state'])
        self.group_resize_count(self.bservice_id,self.group_info,self.amodule.params['count'])
        self.group_update_hw(
            self.bservice_id,
            self.group_info,
            self.amodule.params['cpu'],
            self.amodule.params['boot_disk'],
            self.amodule.params['name'],
            self.amodule.params['role'],
            self.amodule.params['ram'],
        )
        self.group_update_net(
            self.bservice_id,
            self.group_info,
            self.amodule.params['networks']
        )
        return

    def destroy(self):

        self.group_delete(
            self.bservice_id,
            self.group_id
        )

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
        if self.result['changed'] == True:
            self.group_id,self.group_info = self.group_find(
                self.bservice_id,
                self.bservice_info,
                self.group_id
            )

        ret_dict['account_id'] = self.group_info['accountId']
        ret_dict['rg_id'] = self.group_info['rgId']
        ret_dict['id'] = self.group_info['id']
        ret_dict['name'] = self.group_info['name']
        ret_dict['techStatus'] = self.group_info['techStatus']
        ret_dict['state'] = self.group_info['status']
        ret_dict['Computes'] = self.group_info['computes']
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
                    choices=['absent', 'started', 'stopped', 'present','check']),
            user=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_USER'])),
            name=dict(type='str', required=True),
            id=dict(type='int', required=False, default=0),
            image_id=dict(type='int', required=False),
            image_name=dict(type='str', required=False),
            driver=dict(type='str', required=False,default="KVM_X86"),
            boot_disk=dict(type='int', required=False),
            bservice_id=dict(type='int', required=True),
            count=dict(type='int', required=True),
            timeoutStart=dict(type='int', required=False),
            role=dict(type='str', required=False),
            cpu=dict(type='int', required=False),
            ram=dict(type='int', required=False),
            networks=dict(type='list', default=[], required=False),
            description=dict(type='str', default="Created by decort ansible module"),
            verify_ssl=dict(type='bool', required=False, default=True),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),)
def main():
    module_parameters = decort_group.build_parameters()

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
                            ],
                            )

    subj = decort_group(amodule)
    
    if amodule.params['state'] == 'check':
        subj.result['changed'] = False
        if subj.group_id:
            # cluster is found - package facts and report success to Ansible
            subj.result['failed'] = False
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
            # we exit the module at this point
        else:
            subj.result['failed'] = True
            subj.result['msg'] = ("Cannot locate Group name '{}'. "
                                  "B-service ID {}").format(amodule.params['name'],
                                                     amodule.params['bservice_id'],)
            amodule.fail_json(**subj.result)       

    if subj.group_id:
        if subj.group_info['status'] in ("DELETING","DESTROYNG","CREATING","DESTROYING",
                                         "ENABLING","DISABLING","RESTORING","MODELED",
                                         "DISABLED","DESTROYED"):
            subj.error()
        elif subj.group_info['status'] in ("DELETED","DESTROYED"):
            if amodule.params['state'] == 'absent':
                subj.nop()
            if amodule.params['state'] in ('present','started','stopped'):
                subj.create()
        elif subj.group_info['techStatus'] in ("STARTED","STOPPED"):
            if amodule.params['state'] == 'absent':
                subj.destroy()
            else:
                subj.action()

    else:
        if amodule.params['state'] == 'absent':
            subj.nop()
        if amodule.params['state'] in ('present','started','stopped'):
            subj.create()
    
    if subj.result['failed']:
        amodule.fail_json(**subj.result)
    else:
        if subj.group_should_exist:
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
        else:
            amodule.exit_json(**subj.result)

if __name__ == "__main__":
    main()