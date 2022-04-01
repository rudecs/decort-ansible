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


def decort_k8s_package_facts(arg_k8s_facts, arg_check_mode=False):
    """Package a dictionary of k8s facts according to the decort_k8s module specification. This dictionary will
    be returned to the upstream Ansible engine at the completion of the module run.

    @param arg_k8s_facts: dictionary with k8s facts as returned by API call to .../k8s/get
    @param arg_check_mode: boolean that tells if this Ansible module is run in check mode
    """

    ret_dict = dict(id=0,
                    name="none",
                    state="CHECK_MODE",
                    )

    if arg_check_mode:
        # in check mode return immediately with the default values
        return ret_dict

    if arg_k8s_facts is None:
        # if void facts provided - change state value to ABSENT and return
        ret_dict['state'] = "ABSENT"
        return ret_dict

    ret_dict['id'] = arg_k8s_facts['id']
    ret_dict['name'] = arg_k8s_facts['name']
    ret_dict['techStatus'] = arg_k8s_facts['techStatus']
    ret_dict['state'] = arg_k8s_facts['status']

    return ret_dict

def decort_k8s_parameters():
    """Build and return a dictionary of parameters expected by decort_k8s module in a form accepted
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
        permanent=dict(type='bool', default=False),
        started=dict(type='bool', default=True),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECORT_USER'])),
        k8s_name=dict(type='str', required=True),
        rg_id=dict(type='int', required=True),
        k8ci_id=dict(type='int', required=True),
        wg_name=dict(type='str', required=True),
        master_count=dict(type='int', default=1),
        master_cpu=dict(type='int', default=2),
        master_ram_mb=dict(type='int', default=2048),
        master_disk_gb=dict(type='int', default=10),
        worker_count=dict(type='int', default=1),
        worker_cpu=dict(type='int', default=1),
        worker_ram_mb=dict(type='int', default=1024),
        worker_disk_gb=dict(type='int', default=0),
        extnet_id=dict(type='int',  default=0),
        description=dict(type='str', default="Created by decort ansible module"),
        with_lb=dict(type='bool', default=True),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )


def main():
    module_parameters = decort_k8s_parameters()

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
    k8s_id, k8s_facts = decon.k8s_find(arg_k8s_name=amodule.params['k8s_name'],
                                    arg_check_state=False)
    k8s_should_exist = True

    if k8s_id:
        if k8s_facts['status'] in ["MODELED", "DISABLING", "ENABLING", "DELETING", "DESTROYING", "CREATING",
                                   "RESTORING"] and amodule.params['state'] != "present":
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing k8s ID {} because of its current "
                                   "status '{}'").format(k8s_id, k8s_facts['status'])
        elif k8s_facts['status'] in ["DISABLED", "ENABLED", "CREATED", "DELETED"] and amodule.params['state'] == "absent":
            if amodule.params['permanent'] is True:
                decon.k8s_delete(k8s_id, True)
                k8s_facts['status'] = 'DESTROYED'
                k8s_should_exist = False
            else:
                decon.k8s_delete(k8s_id)
                k8s_facts['status'] = 'DELETED'
                k8s_should_exist = True
        elif k8s_facts['status'] == "ENABLED":
            if amodule.params['started'] is True:
                decon.k8s_state(k8s_facts, amodule.params['state'], amodule.params['started'])
            else:
                decon.k8s_state(k8s_facts, amodule.params['state'], amodule.params['started'])
        elif k8s_facts['status'] == amodule.params['state'].upper():
            decon.k8s_state(k8s_facts, amodule.params['state'])
        elif k8s_facts['status'] in ["ENABLED", "CREATED"] and amodule.params['state'] == "disabled":
            decon.k8s_state(k8s_facts, 'disabled')
        elif k8s_facts['status'] in ["DISABLED", "CREATED"]:
            if amodule.params['state'] == 'enabled':
                decon.k8s_state(k8s_facts, 'enabled', amodule.params['started'])
            elif amodule.params['state'] == "disabled":
                decon.k8s_state(k8s_facts, 'disabled')
            k8s_should_exist = True
        elif k8s_facts['status'] == "DELETED":
            if amodule.params['state'] in ('enabled', 'present'):
                decon.k8s_restore(k8s_id)
                k8s_should_exist = True
            elif amodule.params['state'] == 'disabled':
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for k8s ID {} in the "
                                       "current status '{}'").format(k8s_id,
                                                                     amodule.params['state'],
                                                                     k8s_facts['status'])
                k8s_should_exist = False
        elif k8s_facts['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'enabled'):
                k8s_should_exist = True
            elif amodule.params['state'] == 'absent':
                # nop
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for k8s ID {} because of its "
                                       "current status '{}'").format(k8s_id,
                                                                     k8s_facts['status'])
                k8s_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for k8s ID {} in the "
                                       "current status '{}'").format(k8s_id,
                                                                     amodule.params['state'],
                                                                     k8s_facts['status'])
    else:
        k8s_should_exist = False
        if amodule.params['state'] == 'absent':
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do as target state 'absent' was requested for "
                                   "non-existent k8s name '{}'").format(amodule.params['k8s_name'])
        elif amodule.params['state'] in ('present', 'enabled'):
            decon.check_amodule_argument('k8s_name')
            k8s_id = decon.k8s_provision(amodule.params['k8s_name'],
                                         amodule.params['wg_name'],
                                         amodule.params['k8ci_id'],
                                         amodule.params['rg_id'],
                                         amodule.params['master_count'],
                                         amodule.params['master_cpu'],
                                         amodule.params['master_ram_mb'],
                                         amodule.params['master_disk_gb'],
                                         amodule.params['worker_count'],
                                         amodule.params['worker_cpu'],
                                         amodule.params['worker_ram_mb'],
                                         amodule.params['worker_disk_gb'],
                                         amodule.params['extnet_id'],
                                         amodule.params['with_lb'],
                                         amodule.params['description'],
                                         )
            k8s_should_exist = True
        elif amodule.params['state'] == 'disabled':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "k8s name '{}' ").format(amodule.params['state'],
                                                            amodule.params['k8s_name'])
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        if k8s_should_exist:
            if decon.result['changed']:
                _, k8s_facts = decon.k8s_find(arg_k8s_id=k8s_id)
        decon.result['facts'] = decort_k8s_package_facts(k8s_facts, amodule.check_mode)
        amodule.exit_json(**decon.result)

if __name__ == "__main__":
    main()
