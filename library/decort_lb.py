#!/usr/bin/python
#
# Digital Enegry Cloud Orchestration Technology (DECORT) modules for Ansible
# Copyright: (c) 2018-2022 Digital Energy Cloud Solutions LLC
#
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
    TODO
'''

EXAMPLES = '''
    TODO
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *

class decort_lb(DecortController):
    def __init__(self,arg_amodule) -> None:
        super(decort_lb,self).__init__(arg_amodule)    

        self.lb_id = 0
        self.lb_facts = None
        self.vins_id = 0
        self.vins_facts = None
        self.rg_id = 0
        self.rg_facts = None
        self.acc_id = 0
        self.acc_facts = None
        self.default_server_check = "enabled"
        self.default_alg = "roundrobin"
        self.default_settings = {
                "downinter": 10000,
                "fall": 2,
                "inter": 5000,
                "maxconn": 250,
                "maxqueue": 256,
                "rise": 2,
                "slowstart": 60000,
                "weight": 100,
        }        
        if arg_amodule.params['lb_id']:
            self.lb_id, self.lb_facts = self.lb_find(arg_amodule.params['lb_id'])
            if not self.lb_id:
                self.result['failed'] = True
                self.result['msg'] = "Specified LB ID {} not found."\
                .format(arg_amodule.params['lb _id'])
                self.fail_json(**self.result)
            self.acc_id = self.lb_facts['accountId']
            self.rg_id = self.lb_facts['rgId']
            self.vins_id = self.lb_facts['vinsId']
            return
                
        if arg_amodule.params['rg_id']:
            self.rg_id, self.rg_facts = self.rg_find(0,arg_amodule.params['rg_id'], arg_rg_name="")
            if not self.rg_id:
                self.result['failed'] = True
                self.result['msg'] = "Specified RG ID {} not found.".format(arg_amodule.params['vins_id'])
                self.fail_json(**self.result)

        if arg_amodule.params['vins_id']:
            self.vins_id, self.vins_facts = self.vins_find(arg_amodule.params['vins_id'])
            if not self.vins_id:
                self.result['failed'] = True
                self.result['msg'] = "Specified ViNS ID {} not found.".format(arg_amodule.params['vins_id'])
                self.fail_json(**self.result)

        elif arg_amodule.params['account_id'] or arg_amodule.params['account_name'] != "":
            
            if arg_amodule.params['rg_name']:
                self.result['failed'] = True
                self.result['msg'] = ("RG name must be specified with account present")
                self.fail_json(**self.result)
            self.acc_id, self.acc_facts = self.account_find(arg_amodule.params['account_name'], 
                                                            arg_amodule.params['account_id'])
            if not self.acc_id:
                self.result['failed'] = True
                self.result['msg'] = ("Current user does not have access to the requested account "
                                    "or non-existent account specified.")
                self.fail_json(**self.result)
            self.rg_id, self.rg_facts = self.rg_find(self._acc_id,0, arg_rg_name=arg_amodule.params['rg_name'])
        
        if self.rg_id and self.vins_id:
            self.lb_id, self.lb_facts = self.lb_find(0,arg_amodule.params['lb_name'],self.rg_id)
        return
    
    def create(self):
        self.lb_id = self.lb_provision(self.amodule.params['lb_name'],
                                    self.rg_id,self.vins_id,
                                    self.amodule.params['ext_net_id'],
                                    self.amodule.params['annotation'])
        if self.amodule.params['backends'] or self.amodule.params['frontends']:
            self.lb_id, self.lb_facts = self.lb_find(0,self.amodule.params['lb_name'],self.rg_id)
            self.lb_update(
                self.lb_facts['backends'],
                self.lb_facts['frontends'],
                self.amodule.params['backends'],
                self.amodule.params['servers'],
                self.amodule.params['frontends']
            )        
        return
    
    def action(self,d_state='',restore=False):
        if restore == True:
            self.lb_restore(arg_vins_id=self.lb_id)
            self.lb_state(self.vins_facts, 'enabled')
            self.lb_facts['status'] = "ENABLED"
            self.lb_facts['techStatus'] = "STARTED"    
        
        self.lb_update(
            self.lb_facts['backends'],
            self.lb_facts['frontends'],
            self.amodule.params['backends'],
            self.amodule.params['servers'],
            self.amodule.params['frontends']
        )

        if d_state != '':
            self.lb_state(self.lb_facts, d_state)
        return

    def delete(self):
        self.lb_delete(self.lb_id, self.amodule.params['permanently'])
        self.lb_facts['status'] = 'DESTROYED'
        return
    def nop(self):
        """No operation (NOP) handler for LB management by decort_lb module.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual LB state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.lb_id:
            self.result['msg'] = ("No state change required for LB  ID {} because of its "
                                   "current status '{}'.").format(self.lb_id, self.vins_facts['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent LB instance.").format(self.amodule.params['state'])
        return
    def error(self):
        self.result['failed'] = True
        self.result['changed'] = False
        if self.vins_id:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = ("Invalid target state '{}' requested for LB ID {} in the "
                                    "current status '{}'").format(self.lb_id,
                                                                    self.amodule.params['state'],
                                                                    self.lb_facts['status'])
        else:
            self.result['failed'] = True
            self.result['changed'] = False
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "LB name '{}'").format(self.amodule.params['state'],
                                                            self.amodule.params['lb_name'])   
        return
    def package_facts(self, arg_check_mode=False):
        """Package a dictionary of LB facts according to the decort_lb module specification. 
        This dictionary will be returned to the upstream Ansible engine at the completion of 
        the module run.

        @param arg_check_mode: boolean that tells if this Ansible module is run in check mode
        """

        ret_dict = dict(id=0,
                        name="none",
                        state="CHECK_MODE",
                        )

        if arg_check_mode:
            # in check mode return immediately with the default values
            return ret_dict

        if self.vins_facts is None:
            # if void facts provided - change state value to ABSENT and return
            ret_dict['state'] = "ABSENT"
            return ret_dict

        ret_dict['id'] = self.lb_facts['id']
        ret_dict['name'] = self.lb_facts['name']
        ret_dict['state'] = self.lb_facts['status']
        #ret_dict['account_id'] = self.lb_facts['accountId']
        ret_dict['rg_id'] = self.lb_facts['rgId']
        ret_dict['gid'] = self.lb_facts['gid']
        if self.amodule.params['state']!="absent":
            ret_dict['backends'] = self.lb_facts['backends']
            ret_dict['frontends'] = self.lb_facts['frontends']
        return ret_dict
    @staticmethod
    def build_parameters():
        """Build and return a dictionary of parameters expected by decort_vins module in a form accepted
        by AnsibleModule utility class."""

        return dict(
            account_id=dict(type='int', required=False),
            account_name=dict(type='str', required=False, default=''),
            annotation=dict(type='str', required=False, default='Managed by Ansible module decort_lb'),
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
                    choices=['absent', 'disabled', 'enabled', 'present','restart']),
            user=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECORT_USER'])),
            rg_id=dict(type='int', required=False, default=0),
            rg_name=dict(type='str', required=False, default=''),
            vins_name=dict(type='str', required=False, default=''),
            vins_id=dict(type='int', required=False, default=0),
            verify_ssl=dict(type='bool', required=False, default=True),
            lb_id=dict(type='int', required=False, default=0),
            lb_name=dict(type='str', required=True),
            backends=dict(type='list',required=False,default=[]),
            frontends=dict(type='list',required=False,default=[]),
            servers=dict(type='list',required=False,default=[]),
            permanently=dict(type='bool', required=False, default=False),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),
        )

def main():
    module_parameters = decort_lb.build_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,
                            mutually_exclusive=[
                                ['oauth2', 'password'],
                                ['password', 'jwt'],
                                ['jwt', 'oauth2'],
                            ],
                            required_together=[
                                ['app_id', 'app_secret'],
                                ['user', 'password']
                            ],
                            required_one_of=[
                                ['rg_id','rg_name'],
                                ['lb_id','lb_name'],
                                ['vins_id','vins_name']
                            ]
                            )
    decon = decort_lb(amodule)
    if decon.lb_id:
        if decon.lb_facts['status'] in ["MODELED", "DISABLING", "ENABLING", "DELETING","DESTROYING","RESTORING"]:
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing LB ID {} because of its current "
                                "status '{}'").format(decon.lb_id, decon.lb_facts['status'])
        elif decon.lb_facts['status'] == "DISABLED":
                if amodule.params['state'] == 'absent':
                    decon.delete()
                elif amodule.params['state'] in ('present', 'disabled'):
                    decon.action()
                elif amodule.params['state'] == 'enabled':
                    decon.action('enabled')
        elif decon.lb_facts['status'] in ["CREATED", "ENABLED"]:
                if amodule.params['state'] == 'absent':
                    decon.delete()
                elif amodule.params['state'] in ('present', 'enabled'):
                    decon.action()
                elif amodule.params['state'] == 'disabled':
                    decon.action('disabled')
                elif amodule.params['state'] in ('stopped', 'started','restart'):
                    decon.action(amodule.params['state'])
        elif decon.lb_facts['status'] == "DELETED":
            if amodule.params['state'] in ['present', 'enabled']:
                decon.action(restore=True)
            elif amodule.params['state'] == 'absent':
                decon.delete()
            elif amodule.params['state'] == 'disabled':
                decon.error()
        elif decon.lb_facts['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'enabled'):
                decon.create()
            elif amodule.params['state'] == 'absent':
                decon.nop()
            elif amodule.params['state'] == 'disabled':
                decon.error()
    else:
        if amodule.params['state'] == 'absent':
            decon.nop()
        elif amodule.params['state'] in ('present', 'enabled'):
            decon.create()
        elif amodule.params['state'] == 'disabled':
            decon.error()

    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        if decon.result['changed'] and amodule.params['state'] != 'absent':
            _, decon.lb_facts = decon.lb_find(decon.lb_id)
        if decon.lb_id:
            decon.result['facts'] = decon.package_facts(amodule.check_mode)
        amodule.exit_json(**decon.result)
if __name__ == "__main__":
    main()