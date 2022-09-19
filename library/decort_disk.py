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
module: decort_disk
short_description: Manage Disks (virtualized storage resources) in DECORT cloud
description: >
     This module can be used to create new disk in DECORT cloud platform, obtain or 
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
    annotation:
        description:
        - Optional text description of this disk.
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
    id:
        description:
        - `ID of the disk to manage. If I(id) is specified it is assumed, that this disk already
          exists. In other words, you cannot create new disk by specifying its ID, use I(name)
          when creating new disk.`
        - `If non-zero I(id) is specified, then I(name), I(account_id) and I(account_name) 
          are ignored.`
        default: 0
        required: no
    name:
        description:
        - `Name of the disk to manage. To manage disk by name you also need to specify either
          I(account_id) or I(account_name).`
        - If non-zero I(id) is specified, I(name) is ignored.
        - `Note that the platform does not enforce uniqueness of disk names, so if more than one
          disk with this name exists under the specified account, module will return the first
          occurence.`
        default: empty string
        required: no
    force_detach:
        description:
        - `By default it is not allowed to delete or destroy disk that is currently attached to a compute
          instance (e.g. virtual machine or bare metal server). Set this argument to true to change this
          behavior.`
        - This argument is meaningful for I(state=absent) operations only and ignored otherwise.
        default: false
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
    place_with:
        description:
        - `This argument can be used to simplify data disks creation along with a new compute, by placing
          disks in the same storage, where corresponding OS image is deployed.`
        - `Specify ID of an OS image, and the newly created disk will be provisioned from the same
          storage, where this OS image is located. You may optionally specify I(pool) to control
          actual disk placement within that storage, or leave I(pool=default) to let platform manage
          it automatically.`
        - This parameter is used when creating new disks and ignored for all other operations.
        - This is an alternative to specifying I(sep_id).
        default: 0
        required: no
    pool:
        description:
        - Name of the pool where to place new disk. Once disk is created, its pool cannot be changed.
        - This parameter is used when creating new disk and igonred for all other operations.
        default: empty string
        required: no
    sep_id:
        description:
        - `ID of the Storage Endpoint Provider (SEP) where to place new disk. Once disk is created, 
          its SEP cannot be changed.`
        - `You may think of SEP as an identifier of a storage system connected to DECORT platform. There
          may be several different storage systems and, consequently, several SEPs available to choose from.`
        - This parameter is used when creating new disk and igonred for all other operations.
        - See also I(place_with) for an alternative way to specify disk placement.
        default: 0
        required: no
    size:
        description:
        - Size of the disk in GB. This parameter is mandatory when creating new disk.
        - `If specified for an existing disk, and it is greater than current disk size, platform will try to resize
          the disk on the fly. Downsizing disk is not allowed.`
        required: no
    limitIO:
        description:
        - Disk input / output limit, used to limit the speed of interaction with the disk.
        required: no
    type:
        description:
        - Type of the disk. 
        - `Disks can be of the following types: "D"-Data, "B"-Boot, "T"-Tmp.`
        default: "D"
        required: no
    state:
        description:
        - Specify the desired state of the disk at the exit of the module.
        - 'If desired I(state=present):'
        - ' - Disk does not exist or is in [DESTROYED, PURGED] states, create new disk according to the specifications.'
        - ' - Disk is in DELETED state, restore it and change size if necessary.'
        - ' - Disk is in one of [CREATED, ASSIGNED] states, do nothing.'
        - ' - Disk in any other state, abort with an error.'
        - 'If desired I(state=absent):'
        - ' - Disk is in one of [CREATED, ASSIGNED, DELETED] states, destroy it.'
        - ' - Disk not found or in [DESTROYED, PURGED] states, do nothing.' 
        - ' - Disk in any other state, abort with an error.'
        default: present
        choices: [ absent, present ]
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
- name: create new Disk named "MyDataDisk01" of size 50 GB, on SEP ID 1, in default pool, under the account "MyAccount".
    decort_vins:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://cloud.digitalenergy.online"
      name: "MyDataDisk01"
      sep_id: 1
      size: 50
      account_name: "MyAccount"
      state: present
    delegate_to: localhost
    register: my_disk
'''

RETURN = '''
facts:
    description: facts about the disk
    returned: always
    type: dict
    sample:
      facts:
        id: 50
        name: data01
        size: 10
        sep_id: 1
        pool: datastore
        state: ASSIGNED
        account_id: 7
        attached_to: 18
        gid: 1001
'''



from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decort_utils import *

class decort_disk(DecortController):
    def __init__(self,amodule):
        super(decort_disk, self).__init__(amodule)

        self.validated_account_id = 0
        self.validated_disk_id = 0
        self.disk_facts = None # will hold Disk facts
        self.acc_facts = None # will hold Account facts

        # limitIO check for exclusive parameters
        if amodule.params['limitIO']:
            limit = amodule.params['limitIO']
            if limit['total_bytes_sec'] > 0 and limit['read_bytes_sec'] > 0 or \
                    limit['total_bytes_sec'] > 0 and limit['write_bytes_sec'] > 0:
                self.result['failed'] = True
                self.result['msg'] = ("total and read/write of bytes_sec cannot be set at the same time.")
                amodule.fail_json(**self.result)
            elif limit['total_iops_sec'] > 0 and limit['read_iops_sec'] > 0 or \
                    limit['total_iops_sec'] > 0 and limit['write_iops_sec'] > 0:
                self.result['failed'] = True
                self.result['msg'] = ("total and read/write of iops_sec cannot be set at the same time.")
                amodule.fail_json(**self.result)
            elif limit['total_bytes_sec_max'] > 0 and limit['read_bytes_sec_max'] > 0 or \
                    limit['total_bytes_sec_max'] > 0 and limit['write_bytes_sec_max'] > 0:
                self.result['failed'] = True
                self.result['msg'] = ("total and read/write of bytes_sec_max cannot be set at the same time.")
                amodule.fail_json(**self.result)
            elif limit['total_iops_sec_max'] > 0 and limit['read_iops_sec_max'] > 0 or \
                    limit['total_iops_sec_max'] > 0 and limit['write_iops_sec_max'] > 0:
                self.result['failed'] = True
                self.result['msg'] = ("total and read/write of iops_sec_max cannot be set at the same time.")
                amodule.fail_json(**self.result)


        if amodule.params['account_id']:
            self.validated_account_id = amodule.params['account_id']
        elif amodule.params['account_name']:
            self.validated_account_id, _ = self.account_find(amodule.params['account_name'])
        elif not amodule.params['id'] and not amodule.params['account_name']:
            self.result['failed'] = True
            self.result['msg'] = ("Cannot found disk without account id or name.")
            amodule.fail_json(**self.result)

        if self.validated_account_id == 0 and not amodule.params['id']:
            # we failed either to find or access the specified account - fail the module
            self.result['failed'] = True
            self.result['msg'] = ("Cannot find account '{}'").format(amodule.params['account_name'])
            amodule.fail_json(**self.result)

        if amodule.params['id'] or amodule.params['name']:
            self.validated_disk_id, self.disk_facts = self.decort_disk_find(amodule)

        else:
            self.result['failed'] = True
            self.result['msg'] = ("Cannot find or create disk without disk name or disk id")
            amodule.fail_json(**self.result)
        
        if amodule.params['place_with'] > 0:
            image_id, image_facts = self.image_find(amodule.params['place_with'], "", 0)
            amodule.params['sep_id']= image_facts['sepId']




    def decort_disk_create(self, amodule):
        if not self.disk_facts:
            self.disk_id = self.disk_create(accountId=self.validated_account_id, gid=amodule.params['gid'], 
                                            name=amodule.params['name'], description=amodule.params['description'], 
                                            size=amodule.params['size'], type=amodule.params['type'], 
                                            iops=amodule.params['iops'], 
                                            sep_id=amodule.params['sep_id'], pool=amodule.params['pool'])
            self.result['msg'] = ("Disk with id '{}' successfully created.").format(self.disk_id)

        elif self.disk_facts['status'] in ["DESTROYED", "PURGED"]:
            if not amodule.params['limitIO']:
                amodule.params['limitIO'] = self.disk_facts['iotune']
            if amodule.params['sep_id'] == 0:
                validated_sep_id = self.disk_facts['sepId']
            else:
                validated_sep_id = amodule.params['sep_id']

            if amodule.params['pool'] == 0:
                validated_pool = self.disk_facts['pool']
            else:
                validated_pool = amodule.params['pool']

            if amodule.params['size'] == 0:
                validated_size = self.disk_facts['sizeMax']
            else:
                validated_size = amodule.params['size']

            if amodule.params['gid'] == 0:
                validated_gid = self.disk_facts['gid']
            else:
                validated_gid = amodule.params['gid']

            self.disk_id = self.disk_create(accountId=self.validated_account_id, gid=validated_gid, 
                                            name=self.disk_facts['name'], description=amodule.params['description'], 
                                            size=validated_size, type=self.disk_facts['type'], 
                                            iops=self.disk_facts['iotune']['total_iops_sec'], 
                                            sep_id=validated_sep_id, pool=validated_pool)
            if not amodule.params['limitIO']:
                amodule.params['limitIO'] = self.disk_facts['iotune']
            self.result['msg'] = ("Disk with id '{}' successfully recreated.").format(self.disk_id)

        self.result['failed'] = False
        self.result['changed'] = True
        return self.disk_id

    def decort_disk_delete(self, amodule):
        self.disk_id = self.disk_delete(disk_id=self.validated_disk_id,
                                        detach=amodule.params['force_detach'],
                                        permanently=amodule.params['permanently'],
                                        reason=amodule.params['reason'])
        return


    def decort_disk_find(self, amodule):
        if amodule.params['name'] and not amodule.params['id']:
            self.disk_id, self.disk_facts = self.disk_find(disk_id=self.validated_disk_id,
                                                name=amodule.params['name'], 
                                                account_id=self.validated_account_id)
        elif self.validated_disk_id > 0:
            self.disk_id, self.disk_facts = self.disk_find(disk_id=self.validated_disk_id,
                                                            name=self.disk_facts['name'],
                                                            account_id=0)
        elif amodule.params['id']:
            self.disk_id, self.disk_facts = self.disk_find(disk_id=amodule.params['id'],
                                                            name=amodule.params['name'],
                                                            account_id=0)

        if not self.disk_id and not amodule.params['name']:
                    self.result['failed'] = True
                    self.result['msg'] = "Specified Disk ID {} not found.".format(amodule.params['id'])
                    amodule.fail_json(**self.result)
        self.result['facts'] = decort_disk.decort_disk_package_facts(self.disk_facts)
        return self.disk_id, self.disk_facts                                              

    def decort_disk_limitIO(self, amodule):
        self.limits = amodule.params['limitIO']

        self.disk_limitIO(limits = self.limits,
                        diskId = self.validated_disk_id)
        self.disk_facts['iotune'] = amodule.params['limitIO']
        self.result['facts'] = decort_disk.decort_disk_package_facts(self.disk_facts)
        return
    
    def decort_disk_rename(self, amodule):
        self.disk_rename(diskId = self.validated_disk_id,
                        name = amodule.params['name'])
        self.disk_facts['name'] = amodule.params['name']
        self.result['facts'] = decort_disk.decort_disk_package_facts(self.disk_facts)
        self.result['msg'] = ("Disk with id '{}',successfully renamed to '{}'.").format(self.validated_disk_id, amodule.params['name'])
        return

    def decort_disk_package_facts(disk_facts, check_mode=False):
        ret_dict = dict(id=0,
                        name="none",
                        state="CHECK_MODE",
                        size=0,
                        account_id=0,
                        sep_id=0,
                        pool="none",
                        attached_to=0,
                        gid=0
                        )

        if check_mode:
            # in check mode return immediately with the default values
            return ret_dict

        if disk_facts is None:
            # if void facts provided - change state value to ABSENT and return
            ret_dict['state'] = "ABSENT"
            return ret_dict

        ret_dict['id'] = disk_facts['id']
        ret_dict['name'] = disk_facts['name']
        ret_dict['size'] = disk_facts['sizeMax']
        ret_dict['state'] = disk_facts['status']
        ret_dict['account_id'] = disk_facts['accountId']
        ret_dict['sep_id'] = disk_facts['sepId']
        ret_dict['pool'] = disk_facts['pool']
        ret_dict['attached_to'] = disk_facts['vmid']
        ret_dict['gid'] = disk_facts['gid']
        ret_dict['iotune'] = disk_facts['iotune']

        return ret_dict

    def decort_disk_parameters():
        """Build and return a dictionary of parameters expected by decort_disk module in a form accepted
        by AnsibleModule utility class."""

        return dict(
            account_id=dict(type='int', required=False, default=0),
            account_name=dict(type='str', required=False, default=''),
            annotation=dict(type='str', required=False, default='Disk by decort_disk'),
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
            id=dict(type='int', required=False, default=0),
            name=dict(type='str', required=False),
            force_detach=dict(type='bool', required=False, default=False),
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
            place_with=dict(type='int', default=0),
            pool=dict(type='str', default=''),
            sep_id=dict(type='int', default=0),
            gid=dict(type='int', default=0),
            size=dict(type='int', default=0),
            type=dict(type='str', 
                      required=False, 
                      default="D",
                      choices=['B', 'D', 'T']),
            iops=dict(type='int', default=2000),
            limitIO=dict(type='dict',
                options=dict(
                    total_bytes_sec=dict(default=0,type='int'),
                    read_bytes_sec=dict(default=0,type='int'),
                    write_bytes_sec=dict(default=0,type='int'),
                    total_iops_sec=dict(default=0,type='int'),
                    read_iops_sec=dict(default=0,type='int'),
                    write_iops_sec=dict(default=0,type='int'),
                    total_bytes_sec_max=dict(default=0,type='int'),
                    read_bytes_sec_max=dict(default=0,type='int'),
                    write_bytes_sec_max=dict(default=0,type='int'),
                    total_iops_sec_max=dict(default=0,type='int'),
                    read_iops_sec_max=dict(default=0,type='int'),
                    write_iops_sec_max=dict(default=0,type='int'),
                    size_iops_sec=dict(default=0,type='int'),)),
            permanently=dict(type='bool', required=False, default=False),
            reason=dict(type='int', required=False),
            description=dict(type='str', required=False,
                             default="Disk created with Ansible Decort_disk module."),
            state=dict(type='str',
                       default='present',
                       choices=['absent', 'present']),
            user=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECORT_USER'])),
            verify_ssl=dict(type='bool', required=False, default=True),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),
        )

def main():
    module_parameters = decort_disk.decort_disk_parameters()

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

    decon = decort_disk(amodule)

    if decon.validated_disk_id == 0 and amodule.params['state'] == 'present':
        # if sep_id or place_with not specified, then exit with error
        if amodule.params['sep_id'] == 0 or amodule.params['place_with'] == 0:
            decon.result['msg'] = ("To create a disk, you must specify sep_id or place_with.")\
            .format(decon.validated_disk_id)
            amodule.fail_json(**decon.result)
    # if id cannot cannot be found and have a state 'present', then create a new disk 
        decon.validated_disk_id = decon.decort_disk_create(amodule)
        _, decon.disk_facts = decon.decort_disk_find(amodule)
        decon.result['changed'] = True
        decon.result['msg'] = ("Disk with id '{}' successfully created.").format(decon.validated_disk_id)
    
    elif decon.validated_disk_id == 0 and amodule.params['state'] == 'absent' and amodule.params['name']:
    # if disk with specified name cannot be found and have a state 'absent', then nothing to do, 
    # specified disk already deleted
        decon.result['msg'] = ("Disk with name '{}' has already been deleted or your account does not have"
        "access to it.")\
            .format(amodule.params['name'])
        amodule.exit_json(**decon.result)

    elif decon.validated_disk_id == 0 and amodule.params['state'] == 'absent' and amodule.params['id']:
    # if disk with specified id cannot be found and have a state 'absent', then nothing to do, 
    # specified disk already deleted
        decon.result['msg'] = ("Disk with name '{}' has already been deleted or your account does not have"
                                "access to it.")\
            .format(decon.validated_disk_id)
        amodule.exit_json(**decon.result)

    elif decon.disk_facts['status'] == "CREATED":
        if amodule.params['state'] == 'present':
        # if disk status in condition "CREATED" and state "present", nothing to do,
        # specified disk already created
            decon.result['msg'] = "Specified Disk ID {} already created.".format(decon.validated_disk_id)

        if amodule.params['state'] == 'absent':
        # if disk status in condition "CREATED" and state "absent", delete the disk
            decon.validated_disk_id = decon.decort_disk_delete(amodule)
            decon.disk_facts['status'] = "DESTROYED"
            decon.result['msg'] = ("Disk with id '{}' successfully deleted.").format(decon.disk_facts['id'])
            decon.result['facts'] = decon.decort_disk_package_facts(decon.disk_facts)
            amodule.exit_json(**decon.result)

    elif decon.disk_facts['status'] in ["MODELED", "CREATING" ]:
        # if disk in status "MODELED" or "CREATING", 
        # then we cannot do anything, while disk in this status
        decon.result['changed'] = False
        decon.result['msg'] = ("Cannot do anything with disk id '{}',please wait until disk will be created.")\
            .format(decon.validated_disk_id)
        amodule.fail_json(**decon.result)

    elif decon.disk_facts['status'] == "DELETED":
        if amodule.params['state'] == 'present':
            # if disk in "DELETED" status and "present" state, restore
            decon.disk_restore(decon.validated_disk_id)
            _, decon.disk_facts = decon.decort_disk_find(amodule)
            decon.result['changed'] = True
            decon.result['msg'] = ("Disk with id '{}',restored successfully.").format(decon.validated_disk_id)

        elif amodule.params['state'] == 'absent':
            # if disk in "DELETED" status and "absent" state, nothing to do
            decon.result['msg'] = "Specified Disk ID {} already destroyed.".format(decon.validated_disk_id)
            amodule.exit_json(**decon.result)
    
    elif decon.disk_facts['status'] in ["DESTROYED", "PURGED"]:
        if amodule.params['state'] == 'present':
            decon.validated_disk_id = decon.decort_disk_create(amodule)
            _, decon.disk_facts = decon.decort_disk_find(amodule)

        elif amodule.params['state'] == 'absent':
            decon.result['msg'] = "Specified Disk ID {} already destroyed.".format(decon.validated_disk_id)
            amodule.exit_json(**decon.result)

    if amodule.params['state'] == "present":
        if decon.disk_facts['sizeMax'] != amodule.params['size']:
            if decon.disk_facts['sizeMax'] > amodule.params['size'] and amodule.params['size'] != 0:
                decon.result['failed'] = True
                decon.result['msg'] = ("Disk id '{}', cannot reduce disk size.").format(decon.validated_disk_id)
                amodule.fail_json(**decon.result)
            elif decon.disk_facts['sizeMax'] < amodule.params['size']:
                decon.disk_resize(disk_facts=decon.disk_facts,
                                    new_size=amodule.params['size'])
                decon.result['changed'] = True
                decon.result['msg'] = ("Disk with id '{}',resized successfully.").format(decon.validated_disk_id)

        if amodule.params['limitIO'] and amodule.params['limitIO'] != decon.disk_facts['iotune']:
            decon.decort_disk_limitIO(amodule)
            decon.result['changed'] = True
            decon.result['msg'] = ("Disk with id '{}',limited successfully.").format(decon.validated_disk_id)
    
    if amodule.params['name'] and amodule.params['id']:
        if amodule.params['name'] != decon.disk_facts['name']:
            decon.decort_disk_rename(amodule)
            decon.result['changed'] = True
            decon.result['msg'] = ("Disk with id '{}',renamed successfully from '{}' to '{}'.")\
                .format(decon.validated_disk_id, decon.disk_facts['name'], amodule.params['name'])

    amodule.exit_json(**decon.result)

if __name__ == "__main__":
    main()
