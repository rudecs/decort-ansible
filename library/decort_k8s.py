#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2021 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

#
# Author: Aleksandr Malyavin (aleksandr.malyavin@digitalenergy.online)
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decort_utils import *

class decort_k8s(DecortController):
    def __init__(self,arg_amodule):
        super(decort_k8s, self).__init__(arg_amodule)

        validated_acc_id = 0
        validated_rg_id = 0
        validated_rg_facts = None
        validated_k8ci_id = 0

        if arg_amodule.params['name'] == "" and arg_amodule.params['id'] == 0:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = "Cannot manage k8s cluster when its ID is 0 and name is empty."
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
                # fail the module - exit
            

            #validate k8ci ID

            validated_k8ci_id = self.k8s_k8ci_find(arg_amodule.params['k8ci_id'])  
            if not validated_k8ci_id:
                self.result['failed'] = True
                self.result['changed'] = False
                self.result['msg'] = "Cannot find K8CI ID {}.".format(arg_amodule.params['k8ci_id'])
                self.fail_json(**self.result)

            self.rg_id = validated_rg_id
            arg_amodule.params['rg_id'] = validated_rg_id
            arg_amodule.params['rg_name'] = validated_rg_facts['name']
            self.acc_id = validated_rg_facts['accountId']
            arg_amodule.params['k8ci_id'] = validated_k8ci_id

            self.k8s_id,self.k8s_info = self.k8s_find(k8s_id=arg_amodule.params['id'],
                                                      k8s_name=arg_amodule.params['name'],
                                                      rg_id=validated_rg_id,
                                                      check_state=False)
            if self.k8s_id:
                self.k8s_should_exist = True
                self.acc_id = self.k8s_info['accountId']
            # check workers and groups for add or remove?
        
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

        #if self.k8s_facts is None:
        #    #if void facts provided - change state value to ABSENT and return
        #    ret_dict['state'] = "ABSENT"
        #    return ret_dict

        ret_dict['id'] = self.k8s_info['id']
        ret_dict['name'] = self.k8s_info['name']
        ret_dict['techStatus'] = self.k8s_info['techStatus']
        ret_dict['state'] = self.k8s_info['status']
        ret_dict['rg_id'] = self.rg_id
        ret_dict['account_id'] = self.acc_id
        if self.amodule.params['getConfig'] and self.k8s_info['techStatus'] == "STARTED":
            ret_dict['config'] = self.k8s_getConfig()
        return ret_dict
    
    def nop(self):
        """No operation (NOP) handler for k8s cluster management by decort_k8s module.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual k8s cluster state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.k8s_id:
            self.result['msg'] = ("No state change required for K8s  ID {} because of its "
                                   "current status '{}'.").format(self.k8s_id, self.k8s_info['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent K8s instance.").format(self.amodule.params['state'])
        return                         

    def error(self):
        self.result['failed'] = True
        self.result['changed'] = False
        if self.k8s_id:
            self.result['msg'] = ("Invalid target state '{}' requested for K8s cluster ID {} in the "
                                   "current status '{}'.").format(self.k8s_id,
                                                                  self.amodule.params['state'],
                                                                  self.k8s_info['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent K8s Cluster name '{}' "
                                   "in RG ID {} / name '{}'").format(self.amodule.params['state'],
                                                                    self.amodule.params['name'],
                                                                    self.amodule.params['rg_id'],
                                                                    self.amodule.params['rg_name'])
        return

    def create(self):
        self.k8s_provision(self.amodule.params['name'],
                                    self.amodule.params['k8ci_id'],
                                    self.amodule.params['rg_id'],
                                    self.amodule.params['master_count'],
                                    self.amodule.params['master_cpu'],
                                    self.amodule.params['master_ram_mb'],
                                    self.amodule.params['master_disk_gb'],
                                    self.amodule.params['workers'][0],
                                    self.amodule.params['extnet_id'],
                                    self.amodule.params['with_lb'],
                                    self.amodule.params['description'],)
        
        self.k8s_id,self.k8s_info = self.k8s_find(k8s_id=self.amodule.params['id'],
                                                      k8s_name=self.amodule.params['name'],
                                                      rg_id=self.rg_id,
                                                      check_state=False)
        
        if self.k8s_id:
                self.k8s_should_exist = True
        if self.k8s_id and self.amodule.params['workers'][1]:
            self.k8s_workers_modify(self.k8s_info,self.amodule.params['workers'])
        return
    
    def destroy(self):
        self.k8s_delete(self.k8s_id)
        self.k8s_info['status'] = 'DELETED'
        self.k8s_should_exist = False
        return    
    
    def action(self,disared_state,started=True):
        
        self.k8s_state(self.k8s_info, disared_state,started)
        self.k8s_id,self.k8s_info = self.k8s_find(k8s_id=self.amodule.params['id'],
                                                      k8s_name=self.amodule.params['name'],
                                                      rg_id=self.rg_id,
                                                      check_state=False)
        if started == True and self.k8s_info['techStatus'] == "STOPPED":
            self.k8s_state(self.k8s_info, disared_state,started)
            self.k8s_info['techStatus'] == "STARTED"
        self.k8s_workers_modify(self.k8s_info,self.amodule.params['workers'])

        return
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
                    choices=['absent', 'disabled', 'enabled', 'present','check']),
            permanent=dict(type='bool', default=False),
            started=dict(type='bool', default=True),
            user=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_USER'])),
            name=dict(type='str', required=True),
            id=dict(type='int', required=False, default=0),
            getConfig=dict(type='bool',required=False, default=False),
            rg_id=dict(type='int', default=0),
            rg_name=dict(type='str',default=""),
            k8ci_id=dict(type='int', required=True),
            wg_name=dict(type='str', required=False),
            master_count=dict(type='int', default=1),
            master_cpu=dict(type='int', default=2),
            master_ram_mb=dict(type='int', default=2048),
            master_disk_gb=dict(type='int', default=10),
            worker_count=dict(type='int', default=1),
            worker_cpu=dict(type='int', default=1),
            worker_ram_mb=dict(type='int', default=1024),
            worker_disk_gb=dict(type='int', default=10),
            workers=dict(type='list'),
            extnet_id=dict(type='int',  default=0),
            description=dict(type='str', default="Created by decort ansible module"),
            with_lb=dict(type='bool', default=True),
            verify_ssl=dict(type='bool', required=False, default=True),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),)

def main():
    module_parameters = decort_k8s.build_parameters()

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

    subj = decort_k8s(amodule)

    if amodule.params['state'] == 'check':
        subj.result['changed'] = False
        if subj.k8s_id:
            # cluster is found - package facts and report success to Ansible
            subj.result['failed'] = False
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
            # we exit the module at this point
        else:
            subj.result['failed'] = True
            subj.result['msg'] = ("Cannot locate K8s cluster name '{}'. "
                                  "RG ID {}").format(amodule.params['name'],
                                                     amodule.params['rg_id'],)
            amodule.fail_json(**subj.result)                          

    if subj.k8s_id:
        if subj.k8s_info['status'] in ("DELETING","DESTROYNG","CREATING","DESTROYING",
                                         "ENABLING","DISABLING","RESTORING","MODELED"):
            subj.error()
        elif subj.k8s_info['status'] == "DELETED":
            if amodule.params['state'] in ('disabled', 'enabled', 'present'):
                subj.k8s_restore(subj.k8s_id)
                subj.action(amodule.params['state'])
            if amodule.params['state'] == 'absent':
                subj.nop()
        elif subj.k8s_info['techStatus'] in ("STARTED","STOPPED"):
            if amodule.params['state'] == 'disabled':
                subj.action(amodule.params['state'])
            elif amodule.params['state'] == 'absent':
                subj.destroy()
            else:
                subj.action(amodule.params['state'],amodule.params['started'])
        elif subj.k8s_info['status'] == "DISABLED":
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present','enabled'):
                subj.action(amodule.params['state'],amodule.params['started'])
            else:
                subj.nop()
        elif subj.k8s_info['status'] == "DESTROED":
            if amodule.params['state'] in ('present','enabled'):
                subj.create()
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
        if subj.k8s_should_exist:
            subj.result['facts'] = subj.package_facts(amodule.check_mode)
            amodule.exit_json(**subj.result)
        else:
            amodule.exit_json(**subj.result)

if __name__ == "__main__":
    main()
